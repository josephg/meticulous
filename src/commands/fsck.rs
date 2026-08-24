use super::Ctx;
use super::manifest::{MARKS_FILE, parse_manifest_line, parse_manifest_tsv_line};
use super::scan::mtime_ns;
use crate::cli::FsckArgs;
use crate::config::ParityMode;
use crate::db::{ContentRow, Db, FileRow, MemberRow, SetRow, State};
use crate::mts;
use crate::parity;
use crate::util::{now, path_from_bytes};
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub fn run(ctx: &mut Ctx, args: &FsckArgs) -> Result<()> {
    if args.rebuild_db {
        return rebuild(ctx);
    }
    let mut problems = 0u64;
    // 1. SQLite integrity
    let ic = ctx.db.integrity_check()?;
    if ic.is_empty() {
        println!("database integrity: ok");
    } else {
        problems += 1;
        println!("database integrity: PROBLEMS");
        for l in ic {
            println!("  {l}");
        }
    }
    // 2. recorded hashes of the _meticulous files (as of last close)
    let db_path = ctx.archive.db_path();
    for (label, file) in [
        ("database file", db_path.clone()),
        ("database backup", db_path.with_extension("sqlite.bak")),
        ("MANIFEST.txt", ctx.archive.manifest_path()),
        ("MANIFEST.tsv", ctx.archive.manifest_tsv_path()),
    ] {
        match crate::db::check_recorded_hash(&db_path, &file)? {
            Some(true) => println!("{label} hash: ok"),
            Some(false) => {
                println!("{label} hash: MISMATCH — {} differs from what meticulous last wrote (damage, or modified externally)", file.display());
                problems += 1;
            }
            None => println!("{label} hash: not recorded"),
        }
    }
    if ctx.db.hash_ok() == Some(false) {
        println!(
            "  the index will not be written to until this is resolved: restore {} from {} if that one is intact, or `fsck --rebuild-db`",
            db_path.display(),
            db_path.with_extension("sqlite.bak").display()
        );
    }
    if args.fix {
        // fsck --fix is the explicit escape hatch.
        ctx.db.allow_write_despite_hash_mismatch();
    }

    // 3. parity store: one sidecar per parity_set row.
    let sets = ctx.db.all_parity_sets()?;
    let parity_dir = ctx.archive.parity_dir();
    let tmp_dir = parity_dir.join("tmp");
    let mut expected: HashSet<PathBuf> = HashSet::new();
    let mut missing = 0u64;
    let mut damaged = 0u64;
    let mut damaged_kept = 0u64;
    for set in &sets {
        let p = mts::sidecar_path(&parity_dir, &set.id);
        expected.insert(p.clone());
        let members = ctx.db.set_members(&set.id)?;
        if !p.is_file() {
            missing += 1;
            println!(
                "missing sidecar for set {} ({} member(s))",
                hex::encode(&set.id),
                members.iter().filter(|m| !m.dead).count()
            );
            if args.fix {
                // Drop the set rows: the members rejoin the pool at the next
                // scan / parity sync and get freshly encoded.
                ctx.db.delete_parity_set(&set.id)?;
                println!("  removed the set from the index; run `meticulous scan` (or `parity sync`) to re-encode its members");
            }
            continue;
        }
        let problems_here: Vec<String> = match mts::Reader::open(&p) {
            Err(e) => vec![format!("{e:#}")],
            Ok(mut r) => {
                if let Err(e) = super::setops::verify_sidecar_matches(set, &members, &r) {
                    vec![format!("{e:#}")]
                } else if args.deep {
                    r.deep_check()?
                } else if !r.table_ok() {
                    vec!["block hash table damaged".into()]
                } else {
                    vec![]
                }
            }
        };
        if problems_here.is_empty() {
            continue;
        }
        damaged += 1;
        println!("damaged sidecar {}: {}", p.display(), problems_here.join("; "));
        if args.fix {
            // Only discard damaged parity if every live member's files are
            // intact, so the next scan can regenerate the set. Otherwise its
            // undamaged stripes may be the only thing that can repair a
            // damaged member: keep it.
            let mut all_intact = true;
            'members: for m in members.iter().filter(|m| !m.dead) {
                let files = ctx.db.files_by_content(&m.content_hash)?;
                let mut member_ok = false;
                for f in files.iter().filter(|f| f.state != State::Missing) {
                    let abs = ctx.archive.abs(&f.path);
                    if let Ok((h, _)) = parity::hash_file(&abs, set.algo)
                        && h == m.content_hash
                    {
                        member_ok = true;
                        break;
                    }
                }
                if !member_ok {
                    all_intact = false;
                    break 'members;
                }
            }
            if all_intact {
                let _ = std::fs::remove_file(&p);
                ctx.db.delete_parity_set(&set.id)?;
                println!("  removed (every member intact); run `meticulous scan` (or `parity sync`) to regenerate");
            } else {
                damaged_kept += 1;
                println!("  KEPT: a member of this set is itself damaged or missing; the intact stripes may still repair it (`meticulous repair`)");
            }
        }
    }
    // orphans: sidecars for sets no longer in the index, and stale temp files
    let mut orphans = 0u64;
    for e in walkdir::WalkDir::new(&parity_dir).into_iter().flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        let p = e.path().to_path_buf();
        let is_tmp = p.starts_with(&tmp_dir) || p.extension().is_some_and(|x| x == "tmp");
        if is_tmp || !expected.contains(&p) {
            orphans += 1;
            if args.fix {
                let _ = std::fs::remove_file(&p);
                println!("removed orphan {}", p.display());
            } else {
                println!("orphan sidecar {}", p.display());
            }
        }
    }
    let degraded = ctx.db.degraded_sets()?.len();
    println!(
        "parity store: {} set(s) expected ({degraded} degraded), {missing} missing, {damaged} damaged{}, {orphans} orphan{}",
        sets.len(),
        if damaged_kept > 0 { format!(" ({damaged_kept} kept)") } else { String::new() },
        if args.fix && (missing + orphans + damaged - damaged_kept) > 0 { " (fixed)" } else { "" }
    );
    if missing + damaged > 0 && !args.fix {
        println!("hint: `meticulous fsck --fix` clears missing/damaged parity whose members are intact, then `meticulous scan` regenerates it");
    }
    if (missing + damaged + orphans > 0 && !args.fix) || damaged_kept > 0 {
        problems += 1;
    }
    if args.fix {
        ctx.db.mark_dirty();
    }
    if problems > 0 {
        ctx.problems = true;
        println!("fsck: problems found");
    } else {
        println!("fsck: ok");
    }
    Ok(())
}

/// Rebuild index.sqlite from MANIFEST.tsv (preferred: has size/mtime/state) or
/// MANIFEST.txt, plus PARITY_MARKS.txt and the parity-set sidecars (whose
/// member tables reconstruct parity_set/parity_member exactly).
fn rebuild(ctx: &mut Ctx) -> Result<()> {
    let tsv = ctx.archive.manifest_tsv_path();
    let manifest = ctx.archive.manifest_path();
    let db_path = ctx.archive.db_path();
    let source = if tsv.is_file() { tsv.clone() } else if manifest.is_file() { manifest.clone() } else {
        bail!("neither {} nor {} found; cannot rebuild", tsv.display(), manifest.display());
    };
    match crate::db::check_recorded_hash(&db_path, &source)? {
        Some(true) => println!("{} hash: ok", source.display()),
        Some(false) => {
            println!("warning: {} does NOT match its recorded hash — it may itself be damaged; hashes rebuilt from it may be wrong", source.display());
            ctx.problems = true;
        }
        None => println!("note: no recorded hash for {}; cannot verify it", source.display()),
    }
    let broken = db_path.with_extension("sqlite.broken");
    println!("rebuilding {} from {} (old database kept as {})", db_path.display(), source.display(), broken.display());
    let tmp = db_path.with_extension("sqlite.rebuild");
    let _ = std::fs::remove_file(&tmp);
    let mut db = Db::create(&tmp)?;
    let algo = ctx.archive.config.algo;
    let data = std::fs::read(&source)?;
    let parity_dir = ctx.archive.parity_dir();
    let t = now();
    let (mut n, mut missing, mut unknown_meta) = (0u64, 0u64, 0u64);
    let from_tsv = source == tsv;
    db.begin()?;
    for line in data.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let (h, rec_size, rec_mtime, rec_state, pbytes) = if from_tsv {
            let Some((h, s, m, st, p)) = parse_manifest_tsv_line(line) else { continue };
            (h, Some(s), Some(m), st, p)
        } else {
            let Some((h, p)) = parse_manifest_line(line) else { continue };
            (h, None, None, State::Ok, p)
        };
        let Ok(hash) = hex::decode(&h) else { continue };
        let rel = path_from_bytes(&pbytes);
        let abs = ctx.archive.abs(&rel);
        let meta = std::fs::metadata(&abs).ok().filter(|m| m.is_file());
        db.upsert_content(&ContentRow {
            hash: hash.clone(),
            algo,
            size: rec_size.or(meta.as_ref().map(|m| m.len())).unwrap_or(0),
            created_at: t,
        })?;
        // Without recorded metadata we cannot tell later edits from corruption:
        // record mtime 0 so `check` reports such files as "modified" (never as
        // corrupt) until a `scan` re-accepts them.
        let (size, mtime) = match (rec_size, rec_mtime) {
            (Some(s), Some(m)) => (s, m),
            _ => {
                unknown_meta += 1;
                (meta.as_ref().map(|m| m.len()).unwrap_or(0), 0)
            }
        };
        let state = if meta.is_none() {
            missing += 1;
            State::Missing
        } else {
            rec_state
        };
        db.upsert_file(&FileRow {
            id: 0,
            path: rel,
            content_hash: hash,
            size,
            mtime_ns: mtime,
            inode: meta.as_ref().map(|m| m.ino()),
            state,
            added_at: t,
            updated_at: t,
            last_verified_at: None,
        })?;
        n += 1;
    }
    // Parity sets: every valid sidecar's member table reconstructs the rows.
    // A member whose content no longer has a file row is dead (erasure).
    let mut sets_restored = 0u64;
    for e in walkdir::WalkDir::new(&parity_dir).into_iter().flatten() {
        if !e.file_type().is_file() || e.path().extension().is_none_or(|x| x != "mts") {
            continue;
        }
        let Ok(r) = mts::Reader::open(e.path()) else {
            println!("note: unreadable sidecar {} skipped (fsck --fix removes it)", e.path().display());
            continue;
        };
        let layout = r.layout();
        let set = SetRow {
            id: r.set_id().to_vec(),
            algo: r.algo(),
            block_size: layout.block_size,
            blocks_per_stripe: layout.blocks_per_stripe,
            parity_ppm: layout.parity_ppm,
            min_parity_blocks: layout.min_parity_blocks,
            n_members: layout.n_members() as u32,
            n_blocks: layout.n_blocks(),
            data_bytes: layout.total_data_bytes(),
            created_at: t,
        };
        let mut members = Vec::with_capacity(layout.n_members());
        for m in 0..layout.n_members() {
            let hash = r.member_hash(m).to_vec();
            let referenced: bool = db
                .conn()
                .query_row("SELECT EXISTS(SELECT 1 FROM file WHERE content_hash = ?1)", [&hash], |row| {
                    row.get::<_, i64>(0).map(|v| v != 0)
                })?;
            members.push(MemberRow {
                set_id: set.id.clone(),
                ord: m as u32,
                content_hash: hash,
                size: layout.member_size(m),
                first_block: layout.member_first_block(m),
                n_blocks: layout.member_blocks(m),
                dead: !referenced,
            });
        }
        db.insert_parity_set(&set, &members)?;
        sets_restored += 1;
    }
    // marks
    let marks_path = ctx.archive.dir().join(MARKS_FILE);
    if let Ok(s) = std::fs::read_to_string(&marks_path) {
        for line in s.lines() {
            if let Some((m, p)) = line.split_once('\t')
                && let Ok(mode) = ParityMode::parse(m) {
                    db.set_mark(Path::new(p), mode)?;
                }
        }
    }
    db.log_event(Path::new(""), "rebuilt", Some(&format!("database rebuilt from {}: {n} files, {missing} missing, {sets_restored} parity sets", source.display())))?;
    db.commit()?;
    db.finish_without_protect()?;
    // swap files
    if db_path.exists() {
        std::fs::rename(&db_path, &broken).context("moving broken database aside")?;
    }
    std::fs::rename(&tmp, &db_path)?;
    println!("rebuilt: {n} files ({missing} missing on disk), {sets_restored} parity set(s). All files are marked unverified; run `meticulous check`.");
    if unknown_meta > 0 {
        println!(
            "note: {unknown_meta} files were rebuilt without size/mtime (old MANIFEST.txt); `check` will report them as modified until `scan` re-accepts them"
        );
    }
    // Replace the live handle so the normal finish path writes the hash file.
    let mut new_db = Db::open(&db_path)?;
    new_db.allow_write_despite_hash_mismatch();
    let old = std::mem::replace(&mut ctx.db, new_db);
    drop(old);
    ctx.db.mark_dirty();
    let _ = mtime_ns;
    Ok(())
}
