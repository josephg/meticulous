use super::Ctx;
use super::scan::mtime_ns;
use crate::cli::{ExportArgs, ImportArgs};
use crate::config::Archive;
use crate::db::{ContentRow, Db, FileRow, State};
use crate::hash::Algo;
use crate::marks::Resolver;
use crate::util::{escape_manifest_path, now, path_bytes, path_display, unescape_manifest_path};
use crate::worker::{self, Done, Job, Settings, Work};
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const MARKS_FILE: &str = "PARITY_MARKS.txt";

/// Write MANIFEST.txt, MANIFEST.tsv and PARITY_MARKS.txt (called whenever the DB changed).
pub fn write_sidecar_files(archive: &Archive, db: &Db) -> Result<()> {
    let tmp = archive.manifest_path().with_extension("txt.tmp");
    {
        let mut w = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        write_manifest(db, &mut w, archive.config.algo)?;
        w.flush()?;
    }
    std::fs::rename(&tmp, archive.manifest_path())?;
    let tmp = archive.manifest_tsv_path().with_extension("tsv.tmp");
    {
        let mut w = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        write_manifest_tsv(db, &mut w)?;
        w.flush()?;
    }
    std::fs::rename(&tmp, archive.manifest_tsv_path())?;
    let marks = db.marks()?;
    let mut v: Vec<_> = marks.into_iter().collect();
    v.sort();
    let mut s = format!("# parity marks (mode<TAB>dir); default {}\n", archive.config.parity_default.name());
    for (p, m) in v {
        s.push_str(&format!("{}\t{}\n", m.name(), path_display(&p)));
    }
    std::fs::write(archive.dir().join(MARKS_FILE), s)?;
    Ok(())
}

/// coreutils-style "<hex>  <path>" for every non-missing file. Paths are
/// written as raw bytes (what `sha256sum -c` expects), coreutils-escaped.
pub fn write_manifest(db: &Db, w: &mut dyn Write, _algo: Algo) -> Result<()> {
    for f in db.files_under(Path::new(""))? {
        if f.state == State::Missing {
            continue;
        }
        let (esc, bytes) = escape_manifest_path(path_bytes(&f.path));
        if esc {
            w.write_all(b"\\")?;
        }
        w.write_all(hex::encode(&f.content_hash).as_bytes())?;
        w.write_all(b"  ")?;
        w.write_all(&bytes)?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

/// Machine-readable companion to MANIFEST.txt used by `fsck --rebuild-db`:
/// `hex<TAB>size<TAB>mtime_ns<TAB>state<TAB>escaped-path` for every file (missing included).
pub fn write_manifest_tsv(db: &Db, w: &mut dyn Write) -> Result<()> {
    writeln!(w, "# checksummer index export: hash\tsize\tmtime_ns\tstate\tpath (coreutils-escaped)")?;
    for f in db.files_under(Path::new(""))? {
        let (_, bytes) = escape_manifest_path(path_bytes(&f.path));
        write!(w, "{}\t{}\t{}\t{}\t", hex::encode(&f.content_hash), f.size, f.mtime_ns, f.state.name())?;
        w.write_all(&bytes)?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

/// Parse a MANIFEST.txt line into (hex, raw path bytes).
pub fn parse_manifest_line(line: &[u8]) -> Option<(String, Vec<u8>)> {
    let (escaped, line) = match line.strip_prefix(b"\\") {
        Some(l) => (true, l),
        None => (false, line),
    };
    let sep = line.windows(2).position(|w| w == b"  ")?;
    let h = std::str::from_utf8(&line[..sep]).ok()?.to_string();
    let p = &line[sep + 2..];
    Some((h, if escaped { unescape_manifest_path(p) } else { p.to_vec() }))
}

/// Parse a MANIFEST.tsv line into (hex, size, mtime_ns, state, raw path bytes).
pub fn parse_manifest_tsv_line(line: &[u8]) -> Option<(String, u64, i64, State, Vec<u8>)> {
    if line.starts_with(b"#") {
        return None;
    }
    let mut parts = line.splitn(5, |&b| b == b'\t');
    let h = std::str::from_utf8(parts.next()?).ok()?.to_string();
    let size: u64 = std::str::from_utf8(parts.next()?).ok()?.parse().ok()?;
    let mtime: i64 = std::str::from_utf8(parts.next()?).ok()?.parse().ok()?;
    let state = State::parse(std::str::from_utf8(parts.next()?).ok()?);
    let p = unescape_manifest_path(parts.next()?);
    Some((h, size, mtime, state, p))
}

pub fn export(ctx: &mut Ctx, args: &ExportArgs) -> Result<()> {
    let mut out: Box<dyn Write> = match &args.output {
        Some(p) => Box::new(std::io::BufWriter::new(std::fs::File::create(p)?)),
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    match args.format.as_str() {
        "sum" => write_manifest(&ctx.db, &mut out, ctx.archive.config.algo)?,
        "json" => {
            for f in ctx.db.files_under(Path::new(""))? {
                let c = ctx.db.get_content(&f.content_hash)?;
                let has_parity = c.map(|c| c.has_parity).unwrap_or(false);
                writeln!(
                    out,
                    "{}",
                    serde_json::json!({
                        "path": path_display(&f.path),
                        "hash": format!("{}:{}", ctx.archive.config.algo, hex::encode(&f.content_hash)),
                        "size": f.size,
                        "mtime_ns": f.mtime_ns,
                        "state": f.state.name(),
                        "parity": has_parity,
                        "last_verified_at": f.last_verified_at,
                    })
                )?;
            }
        }
        other => bail!("unknown export format '{other}' (sum|json)"),
    }
    out.flush()?;
    if let (Some(p), false) = (&args.output, ctx.quiet) {
        eprintln!("wrote {}", p.display());
    }
    Ok(())
}

struct Listed {
    hash: Vec<u8>,
    rel: PathBuf,
}

fn parse_list_line(line: &str) -> Option<(String, String)> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.starts_with('#') || line.starts_with("%%%%") {
        return None;
    }
    let (escaped, line) = match line.strip_prefix('\\') {
        Some(l) => (true, l),
        None => (false, line),
    };
    // "<hex>  <path>" or "<hex> *<path>" (binary mode); also accept "algo:hex  path".
    let (h, rest) = line.split_once(' ')?;
    let rest = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('*')).unwrap_or(rest);
    let h = h.rsplit(':').next().unwrap_or(h);
    if h.is_empty() || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let path = if escaped { String::from_utf8_lossy(&unescape_manifest_path(rest.as_bytes())).into_owned() } else { rest.to_string() };
    Some((h.to_ascii_lowercase(), path))
}

pub fn import(ctx: &mut Ctx, args: &ImportArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let base = match &args.relative_to {
        Some(p) => p.clone(),
        None => std::path::absolute(&args.file)?.parent().map(|p| p.to_path_buf()).unwrap_or_default(),
    };
    let native = ctx.archive.config.algo;
    let mut listed: Vec<Listed> = Vec::new();
    let mut bad_lines = 0;
    let mut lens = std::collections::HashSet::new();
    for line in text.lines() {
        match parse_list_line(line) {
            Some((h, p)) => {
                let bytes = hex::decode(&h).unwrap_or_default();
                lens.insert(bytes.len());
                let rel = match crate::util::to_relative(&ctx.archive.root, &base.join(&p)) {
                    Ok(r) => r,
                    Err(_) => {
                        eprintln!("skipping (outside archive): {p}");
                        continue;
                    }
                };
                listed.push(Listed { hash: bytes, rel });
            }
            None => bad_lines += 1,
        }
    }
    if listed.is_empty() {
        bail!("no checksum lines recognised in {}", args.file.display());
    }
    if lens.len() != 1 {
        bail!("mixed digest lengths in list; split it per algorithm");
    }
    let len = *lens.iter().next().unwrap();
    let algo = match args.algo {
        Some(a) => a,
        None => match len {
            16 => Algo::Md5,
            20 => Algo::Sha1,
            32 if native.digest_len() == 32 => native,
            _ => bail!("cannot infer the list's hash algorithm from digest length {len}; pass --algo"),
        },
    };
    if algo.digest_len() != len {
        bail!("--algo {algo} has {}-byte digests but the list has {len}-byte digests", algo.digest_len());
    }
    ctx.say(format!("importing {} entries ({algo}) from {}{}", listed.len(), args.file.display(), if bad_lines > 0 { format!(", {bad_lines} unparsed lines") } else { String::new() }));

    let settings = Settings::from_archive(&ctx.archive, args.jobs, ctx.quiet);
    let mut resolver = Resolver::new(ctx.db.marks()?, ctx.archive.config.parity_default);
    let (mut ok, mut mismatch, mut missing, mut added, mut trusted, mut errors) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    struct Tag {
        listed: Vec<u8>,
        existing: Option<FileRow>,
    }
    let mut jobs: Vec<Job<Tag>> = Vec::new();
    let mut foreign_jobs: Vec<(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    ctx.db.begin()?;
    for l in listed {
        let abs = ctx.archive.abs(&l.rel);
        let meta = match std::fs::metadata(&abs) {
            Ok(m) if m.is_file() => m,
            _ => {
                println!("missing: {}", path_display(&l.rel));
                missing += 1;
                continue;
            }
        };
        let existing = ctx.db.get_file(&l.rel)?;
        if algo == native {
            if let Some(row) = &existing {
                if row.content_hash == l.hash {
                    ok += 1;
                } else {
                    println!("MISMATCH: {} (index has {}, list has {})", path_display(&l.rel), hex::encode(&row.content_hash), hex::encode(&l.hash));
                    mismatch += 1;
                }
                continue;
            }
            if args.trust {
                let t = now();
                ctx.db.upsert_content(&ContentRow {
                    hash: l.hash.clone(),
                    algo,
                    size: meta.len(),
                    block_size: None,
                    blocks_per_stripe: None,
                    parity_ppm: None,
                    has_parity: false,
                    created_at: t,
                })?;
                ctx.db.upsert_file(&FileRow {
                    id: 0,
                    path: l.rel.clone(),
                    content_hash: l.hash.clone(),
                    size: meta.len(),
                    mtime_ns: mtime_ns(&meta),
                    inode: Some(meta.ino()),
                    state: State::Ok,
                    added_at: t,
                    updated_at: t,
                    last_verified_at: None,
                })?;
                ctx.db.log_event(&l.rel, "added", Some("imported (trusted) from checksum list"))?;
                trusted += 1;
                continue;
            }
            let parity = resolver.covers_file(&l.rel);
            jobs.push(Job { rel: l.rel.clone(), abs, size: meta.len(), work: Work::Hash { parity }, tag: Tag { listed: l.hash, existing } });
        } else {
            // Foreign algorithm: must read the file to compare; also index it natively if new.
            foreign_jobs.push((l.rel, abs, l.hash));
        }
    }
    ctx.db.commit()?;

    // Native-algo jobs: hash, compare, and index if new.
    let s2 = settings.clone();
    ctx.db.begin()?;
    worker::run(jobs, &settings, |job, done| {
        match done {
            Done::Failed(m) | Done::ReadError(m) => {
                eprintln!("error: {}: {m}", path_display(&job.rel));
                errors += 1;
            }
            Done::HashedNoTable { .. } | Done::Blocks(_) => unreachable!(),
            Done::Hashed { hash, bytes, layout } => {
                if hash != job.tag.listed {
                    println!("MISMATCH: {} (file is {}, list says {}) — left unindexed", path_display(&job.rel), hex::encode(&hash), hex::encode(&job.tag.listed));
                    mismatch += 1;
                    if layout.is_some() {
                        super::scan::discard_sidecar(ctx, &hash);
                    }
                    return Ok(());
                } else {
                    ok += 1;
                }
                if job.tag.existing.is_none() {
                    let meta = std::fs::metadata(&job.abs)?;
                    let t = now();
                    ctx.db.upsert_content(&ContentRow {
                        hash: hash.clone(),
                        algo: s2.algo,
                        size: bytes,
                        block_size: layout.map(|l| l.block_size),
                        blocks_per_stripe: layout.map(|l| l.blocks_per_stripe),
                        parity_ppm: layout.map(|l| l.parity_ppm),
                        has_parity: layout.is_some(),
                        created_at: t,
                    })?;
                    ctx.db.upsert_file(&FileRow {
                        id: 0,
                        path: job.rel.clone(),
                        content_hash: hash,
                        size: meta.len(),
                        mtime_ns: mtime_ns(&meta),
                        inode: Some(meta.ino()),
                        state: State::Ok,
                        added_at: t,
                        updated_at: t,
                        last_verified_at: Some(t),
                    })?;
                    ctx.db.log_event(&job.rel, "added", Some("indexed during import"))?;
                    added += 1;
                }
            }
        }
        Ok(())
    })?;
    ctx.db.commit()?;

    // Foreign-algo entries: compute both hashes in one read.
    if !foreign_jobs.is_empty() {
        ctx.say(format!("verifying {} entries with {algo} (and indexing with {native})", foreign_jobs.len()));
        ctx.db.begin()?;
        for (rel, abs, listed_hash) in foreign_jobs {
            let existing = ctx.db.get_file(&rel)?;
            match hash_two(&abs, algo, native) {
                Err(e) => {
                    eprintln!("error: {}: {e:#}", path_display(&rel));
                    errors += 1;
                }
                Ok((foreign, nat, bytes)) => {
                    if foreign != listed_hash {
                        println!(
                            "MISMATCH: {} ({algo} differs from list){}",
                            path_display(&rel),
                            if existing.is_none() { " — left unindexed" } else { "" }
                        );
                        mismatch += 1;
                        if existing.is_none() {
                            continue;
                        }
                    } else {
                        ok += 1;
                    }
                    match existing {
                        Some(row) if row.content_hash != nat => {
                            println!("note: {} also differs from the index ({native})", path_display(&rel));
                        }
                        Some(_) => {}
                        None => {
                            let meta = std::fs::metadata(&abs)?;
                            let t = now();
                            ctx.db.upsert_content(&ContentRow {
                                hash: nat.clone(),
                                algo: native,
                                size: bytes,
                                block_size: None,
                                blocks_per_stripe: None,
                                parity_ppm: None,
                                has_parity: false,
                                created_at: t,
                            })?;
                            ctx.db.upsert_file(&FileRow {
                                id: 0,
                                path: rel.clone(),
                                content_hash: nat,
                                size: meta.len(),
                                mtime_ns: mtime_ns(&meta),
                                inode: Some(meta.ino()),
                                state: State::Ok,
                                added_at: t,
                                updated_at: t,
                                last_verified_at: Some(t),
                            })?;
                            ctx.db.log_event(&rel, "added", Some(&format!("indexed during {algo} import")))?;
                            added += 1;
                        }
                    }
                }
            }
        }
        ctx.db.commit()?;
        if added > 0 {
            println!("note: files indexed from a foreign-algorithm list have no parity yet; run `checksummer parity sync`");
        }
    }
    println!("import complete: {ok} match, {mismatch} MISMATCH, {missing} missing, {added} newly indexed, {trusted} trusted, {errors} errors");
    if mismatch > 0 {
        println!("note: mismatching files that were not yet indexed were left out; decide per file (restore from backup, or `checksummer scan` to index the current content)");
    }
    if mismatch > 0 || missing > 0 || errors > 0 {
        ctx.problems = true;
    }
    Ok(())
}

fn hash_two(path: &Path, a: Algo, b: Algo) -> Result<(Vec<u8>, Vec<u8>, u64)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut ha = a.hasher();
    let mut hb = b.hasher();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ha.update(&buf[..n]);
        hb.update(&buf[..n]);
        total += n as u64;
    }
    Ok((ha.finish(), hb.finish(), total))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_lines() {
        assert_eq!(parse_list_line("abcd  foo/bar.txt"), Some(("abcd".into(), "foo/bar.txt".into())));
        assert_eq!(parse_list_line("ABCD *foo"), Some(("abcd".into(), "foo".into())));
        assert_eq!(parse_list_line("blake3:ab  x"), Some(("ab".into(), "x".into())));
        assert_eq!(parse_list_line("\\abcd  a\\nb"), Some(("abcd".into(), "a\nb".into())));
        assert_eq!(parse_list_line("# comment"), None);
        assert_eq!(parse_list_line("zz  x"), None);
    }
}
