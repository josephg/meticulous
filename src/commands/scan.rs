use super::Ctx;
use crate::cli::{AcceptArgs, ScanArgs};
use crate::csp;
use crate::db::{ContentRow, FileRow, State};
use crate::marks::Resolver;
use crate::util::{confirm, fmt_bytes, now, path_display};
use crate::worker::{self, Done, Job, Settings, Work};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
enum Tag {
    New,
    /// size/mtime changed: re-hashed and accepted as an edit (unless it turns
    /// out to be corruption, see `Tag::ModifiedWithParity`).
    Modified { old: FileRow },
    /// mtime changed but size is the same and the old content has parity:
    /// block-check against the old sidecar first to tell edits from bit rot.
    ModifiedWithParity { old: FileRow },
    /// Existing, unchanged-looking file re-read to add parity / confirm it is back / confirm a size change.
    Recheck { row: FileRow, reason: &'static str },
}

#[derive(Default)]
pub struct Summary {
    pub added: u64,
    pub added_bytes: u64,
    pub modified: u64,
    pub unaccepted: u64,
    pub parity_added: u64,
    pub corrupt: u64,
    pub suspected: u64,
    pub moved: u64,
    pub removed: u64,
    pub missing: u64,
    pub errors: u64,
    pub unchanged: u64,
    pub changed_while_scanning: u64,
    pub symlinks_skipped: u64,
    pub walk_errors: u64,
}

pub struct Entry {
    pub rel: PathBuf,
    pub abs: PathBuf,
    pub size: u64,
    pub mtime_ns: i64,
}

pub fn mtime_ns(m: &std::fs::Metadata) -> i64 {
    m.mtime() * 1_000_000_000 + m.mtime_nsec()
}

/// Result of walking: directories that could not be read (their contents are
/// unknown, NOT removed) and the number of symlinks skipped.
#[derive(Default)]
pub struct WalkReport {
    pub failed_dirs: Vec<PathBuf>,
    pub symlinks_skipped: u64,
}

/// Walk the archive (or the given relative roots) yielding regular files.
/// Symlinks are never followed and are counted, not indexed. Repair temp
/// files (`*.csrepair.*`) are ignored.
pub fn walk(ctx: &Ctx, rels: &[PathBuf], mut f: impl FnMut(Entry) -> Result<()>) -> Result<WalkReport> {
    let exclude = ctx.archive.config.exclude_set()?;
    let csdir = ctx.archive.dir();
    let roots: Vec<PathBuf> = if rels.is_empty() { vec![PathBuf::new()] } else { rels.to_vec() };
    let mut report = WalkReport::default();
    for r in roots {
        let abs_root = ctx.archive.abs(&r);
        let walker = walkdir::WalkDir::new(&abs_root).follow_links(false).sort_by_file_name();
        let mut it = walker.into_iter();
        while let Some(item) = it.next() {
            let entry = match item {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("warning: {e}");
                    report.walk_errors_push(&ctx.archive.root, &e);
                    continue;
                }
            };
            if entry.path() == csdir {
                it.skip_current_dir();
                continue;
            }
            // A visible ZFS snapshot directory at the root would re-index every snapshot.
            if entry.depth() == 1 && entry.file_type().is_dir() && entry.file_name() == ".zfs" && entry.path().parent() == Some(ctx.archive.root.as_path()) {
                it.skip_current_dir();
                continue;
            }
            let rel = match entry.path().strip_prefix(&ctx.archive.root) {
                Ok(p) => p.to_path_buf(),
                Err(_) => continue,
            };
            if !exclude.is_empty() && exclude.is_match(&rel) {
                if entry.file_type().is_dir() {
                    it.skip_current_dir();
                }
                continue;
            }
            if entry.file_type().is_symlink() {
                report.symlinks_skipped += 1;
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }
            if is_repair_temp(&rel) {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("warning: cannot stat {}: {e}", path_display(&rel));
                    report.failed_dirs.push(rel.clone());
                    continue;
                }
            };
            f(Entry { rel, abs: entry.path().to_path_buf(), size: meta.len(), mtime_ns: mtime_ns(&meta) })?;
        }
    }
    Ok(report)
}

impl WalkReport {
    fn walk_errors_push(&mut self, root: &Path, e: &walkdir::Error) {
        if let Some(p) = e.path()
            && let Ok(rel) = p.strip_prefix(root) {
                self.failed_dirs.push(rel.to_path_buf());
                return;
            }
        // Unknown location: be conservative and treat the whole scan as unreliable for removals.
        self.failed_dirs.push(PathBuf::new());
    }
    /// Is `path` inside a directory we failed to read?
    pub fn unreliable(&self, path: &Path) -> bool {
        self.failed_dirs.iter().any(|d| d.as_os_str().is_empty() || path.starts_with(d))
    }
}

fn is_repair_temp(rel: &Path) -> bool {
    rel.file_name()
        .map(|n| n.to_string_lossy().contains(".csrepair."))
        .unwrap_or(false)
}

/// Map content hash -> has_parity for every content row.
pub fn parity_map(ctx: &Ctx) -> Result<HashMap<Vec<u8>, bool>> {
    let mut st = ctx.db.conn().prepare("SELECT hash, has_parity FROM content")?;
    let mut out = HashMap::new();
    for r in st.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)? != 0)))? {
        let (h, p) = r?;
        out.insert(h, p);
    }
    Ok(out)
}

pub fn content_row(settings: &Settings, hash: &[u8], size: u64, layout: Option<csp::Layout>) -> ContentRow {
    ContentRow {
        hash: hash.to_vec(),
        algo: settings.algo,
        size,
        block_size: layout.map(|l| l.block_size),
        blocks_per_stripe: layout.map(|l| l.blocks_per_stripe),
        parity_ppm: layout.map(|l| l.parity_ppm),
        has_parity: layout.is_some(),
        created_at: now(),
    }
}

/// Remove a sidecar that was generated for content we don't want to keep
/// (e.g. it describes a corrupt version of a file) unless some content row claims it.
pub fn discard_sidecar(ctx: &Ctx, hash: &[u8]) {
    if let Ok(None) = ctx.db.get_content(hash) {
        let _ = std::fs::remove_file(csp::sidecar_path(&ctx.archive.parity_dir(), hash));
    }
}

/// Re-stat after hashing: if the file changed underneath us, the hash we
/// computed may not correspond to the metadata we would store. Returns the
/// metadata to record, or None if the file must not be recorded this time.
fn settled_metadata(abs: &Path, seen_size: u64, seen_mtime: i64) -> Option<(u64, i64, Option<u64>)> {
    let m = std::fs::metadata(abs).ok()?;
    if m.len() != seen_size || mtime_ns(&m) != seen_mtime {
        return None;
    }
    Some((m.len(), mtime_ns(&m), Some(m.ino())))
}

pub fn scan(ctx: &mut Ctx, args: &ScanArgs) -> Result<()> {
    let rels = ctx.rel_paths_existing(&args.paths)?;
    let settings = Settings::from_archive(&ctx.archive, args.jobs, ctx.quiet);
    let mut resolver = Resolver::new(ctx.db.marks()?, ctx.archive.config.parity_default);
    let known: HashMap<PathBuf, FileRow> =
        ctx.db.files_under_any(&rels)?.into_iter().map(|f| (f.path.clone(), f)).collect();
    let pmap = parity_map(ctx)?;
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut jobs: Vec<Job<(Tag, u64, i64)>> = Vec::new();
    let mut sum = Summary::default();
    let mut unaccepted: Vec<(PathBuf, FileRow)> = Vec::new();
    let parity_dir = ctx.archive.parity_dir();

    ctx.say(format!(
        "scanning {} ...",
        if rels.is_empty() { ctx.archive.root.display().to_string() } else { rels.iter().map(|p| path_display(p)).collect::<Vec<_>>().join(", ") }
    ));
    let report = walk(ctx, &rels, |e| {
        seen.insert(e.rel.clone());
        let want_parity = !args.no_parity && resolver.covers_file(&e.rel);
        let push = |jobs: &mut Vec<Job<(Tag, u64, i64)>>, work: Work, tag: Tag| {
            jobs.push(Job { rel: e.rel.clone(), abs: e.abs.clone(), size: e.size, work, tag: (tag, e.size, e.mtime_ns) });
        };
        match known.get(&e.rel) {
            None => push(&mut jobs, Work::Hash { parity: want_parity }, Tag::New),
            Some(row) if row.mtime_ns == e.mtime_ns => {
                let has_parity = pmap.get(&row.content_hash).copied().unwrap_or(false);
                if row.size != e.size {
                    // Same mtime, different size: not an edit. Re-read to confirm corruption.
                    push(&mut jobs, Work::Hash { parity: false }, Tag::Recheck { row: row.clone(), reason: "size" });
                } else if row.state == State::Missing {
                    push(&mut jobs, Work::Hash { parity: want_parity && !has_parity }, Tag::Recheck { row: row.clone(), reason: "reappeared" });
                } else if want_parity && !has_parity && row.state == State::Ok {
                    push(&mut jobs, Work::Hash { parity: true }, Tag::Recheck { row: row.clone(), reason: "parity" });
                } else {
                    sum.unchanged += 1;
                }
            }
            Some(row) => {
                if args.no_accept_changes {
                    unaccepted.push((e.rel.clone(), row.clone()));
                } else {
                    let has_parity = pmap.get(&row.content_hash).copied().unwrap_or(false);
                    let sc = csp::sidecar_path(&parity_dir, &row.content_hash);
                    if row.size == e.size && has_parity && sc.is_file() {
                        push(&mut jobs, Work::CheckBlocks { sidecar: sc }, Tag::ModifiedWithParity { old: row.clone() });
                    } else {
                        push(&mut jobs, Work::Hash { parity: want_parity }, Tag::Modified { old: row.clone() });
                    }
                }
            }
        }
        Ok(())
    })?;
    sum.symlinks_skipped = report.symlinks_skipped;
    sum.walk_errors = report.failed_dirs.len() as u64;

    // Files that changed but we were told not to accept.
    if !unaccepted.is_empty() {
        ctx.db.begin()?;
        for (rel, row) in &unaccepted {
            println!("modified (not accepted): {}", path_display(rel));
            if row.state != State::Modified {
                ctx.db.set_state(rel, State::Modified)?;
                ctx.db.log_event(rel, "modified", Some("size/mtime changed; not accepted (--no-accept-changes)"))?;
            }
            sum.unaccepted += 1;
        }
        ctx.db.commit()?;
        ctx.problems = true;
    }

    // Hash everything that needs hashing.
    let mut added_hashes: HashMap<Vec<u8>, PathBuf> = HashMap::new();
    let total_jobs = jobs.len();
    if total_jobs > 0 {
        ctx.say(format!("hashing {} files ({})", total_jobs, fmt_bytes(jobs.iter().map(|j| j.size).sum())));
    }
    ctx.db.begin()?;
    let mut pending = 0usize;
    let settings2 = settings.clone();
    worker::run(jobs, &settings, |job, done| {
        pending += 1;
        if pending.is_multiple_of(500) {
            ctx.db.commit()?;
            ctx.db.begin()?;
        }
        let (tag, seen_size, seen_mtime) = job.tag;
        let rel = &job.rel;
        // Only record results for files that did not change while we read them.
        let settled = settled_metadata(&job.abs, seen_size, seen_mtime);
        let record = |ctx: &mut Ctx, hash: &[u8], bytes: u64, layout: Option<csp::Layout>, old: Option<&FileRow>, state: State| -> Result<bool> {
            let Some((size, mtime, inode)) = settled else {
                if layout.is_some() {
                    discard_sidecar(ctx, hash);
                }
                return Ok(false);
            };
            ctx.db.upsert_content(&content_row(&settings2, hash, bytes, layout))?;
            let t = now();
            ctx.db.upsert_file(&FileRow {
                id: old.map(|o| o.id).unwrap_or(0),
                path: rel.clone(),
                content_hash: hash.to_vec(),
                size,
                mtime_ns: mtime,
                inode,
                state,
                added_at: old.map(|o| o.added_at).unwrap_or(t),
                updated_at: t,
                last_verified_at: Some(t),
            })?;
            Ok(true)
        };
        match (tag, done) {
            (_, Done::Failed(msg)) => {
                eprintln!("error: {}: {msg}", path_display(rel));
                sum.errors += 1;
            }
            (tag, Done::ReadError(msg)) => {
                ctx.read_error(rel, &msg);
                match tag {
                    Tag::Recheck { row, .. } | Tag::Modified { old: row } | Tag::ModifiedWithParity { old: row } => {
                        if row.state != State::Unrecoverable {
                            ctx.db.set_state(rel, State::Unrecoverable)?;
                        }
                        ctx.db.log_event(rel, "read-error", Some(&msg))?;
                    }
                    Tag::New => {}
                }
                sum.errors += 1;
            }
            (Tag::New, Done::Hashed { hash, bytes, layout }) => {
                if !record(ctx, &hash, bytes, layout, None, State::Ok)? {
                    println!("changed while scanning (not recorded, re-run scan): {}", path_display(rel));
                    sum.changed_while_scanning += 1;
                    return Ok(());
                }
                ctx.db.log_event(rel, "added", Some(&format!("{}:{}", settings2.algo, hex::encode(&hash))))?;
                if layout.is_some() {
                    sum.parity_added += 1;
                }
                added_hashes.insert(hash, rel.clone());
                sum.added += 1;
                sum.added_bytes += bytes;
                if !ctx.quiet {
                    println!("added: {}", path_display(rel));
                }
            }
            (Tag::Modified { old }, Done::Hashed { hash, bytes, layout }) => {
                if !record(ctx, &hash, bytes, layout, Some(&old), State::Ok)? {
                    println!("changed while scanning (not recorded, re-run scan): {}", path_display(rel));
                    sum.changed_while_scanning += 1;
                    return Ok(());
                }
                let same = hash == old.content_hash;
                ctx.db.log_event(
                    rel,
                    "modified",
                    Some(&if same { "metadata changed, content identical".to_string() } else { format!("{} -> {}", hex::encode(&old.content_hash), hex::encode(&hash)) }),
                )?;
                if layout.is_some() {
                    sum.parity_added += 1;
                }
                sum.modified += 1;
                println!("modified: {}{}", path_display(rel), if same { " (content unchanged)" } else { "" });
            }
            (Tag::ModifiedWithParity { old }, Done::Blocks(bc)) => {
                let Some((_size, mtime, inode)) = settled else {
                    println!("changed while scanning (not recorded, re-run scan): {}", path_display(rel));
                    sum.changed_while_scanning += 1;
                    return Ok(());
                };
                if bc.ok(&old.content_hash) {
                    // Only the timestamp changed (touch, cp without -p, ...): keep everything, update metadata.
                    ctx.db.upsert_file(&FileRow { mtime_ns: mtime, inode, updated_at: now(), last_verified_at: Some(now()), state: State::Ok, ..old.clone() })?;
                    ctx.db.log_event(rel, "modified", Some("mtime changed, content identical"))?;
                    sum.modified += 1;
                    println!("modified: {} (content unchanged)", path_display(rel));
                } else if bc.repairable() && !bc.bad_blocks.is_empty() {
                    // A few blocks differ and the parity could fix them: far more likely bit rot
                    // (plus a timestamp reset) than an edit. Do NOT accept; keep the old hash,
                    // record the new mtime so `repair` can act on it.
                    ctx.db.upsert_file(&FileRow { mtime_ns: mtime, inode, updated_at: now(), state: State::Corrupt, ..old.clone() })?;
                    ctx.db.log_event(
                        rel,
                        "corrupt",
                        Some(&format!("mtime changed but only {} of {} blocks differ (repairable) — treated as suspected corruption, not accepted", bc.bad_blocks.len(), bc.n_blocks)),
                    )?;
                    println!(
                        "SUSPECTED CORRUPTION: {} — mtime changed but only {} of {} blocks differ; not accepted. `checksummer repair` restores the recorded content; if this really is an edit, `checksummer accept <file>` records the new content.",
                        path_display(rel),
                        bc.bad_blocks.len(),
                        bc.n_blocks
                    );
                    sum.suspected += 1;
                    ctx.problems = true;
                } else {
                    // Most blocks differ: a genuine edit. Accept with the hash we already have;
                    // parity for the new content is generated on the next scan / parity sync.
                    if !record(ctx, &bc.file_hash, bc.actual_size, None, Some(&old), State::Ok)? {
                        sum.changed_while_scanning += 1;
                        return Ok(());
                    }
                    ctx.db.log_event(rel, "modified", Some(&format!("{} -> {}", hex::encode(&old.content_hash), hex::encode(&bc.file_hash))))?;
                    sum.modified += 1;
                    println!("modified: {}", path_display(rel));
                }
            }
            (Tag::Recheck { row, reason }, Done::Hashed { hash, bytes, layout }) => {
                if hash == row.content_hash {
                    if settled.is_none() {
                        if layout.is_some() {
                            discard_sidecar(ctx, &hash);
                        }
                        sum.changed_while_scanning += 1;
                        return Ok(());
                    }
                    if let Some(l) = layout {
                        ctx.db.upsert_content(&content_row(&settings2, &hash, bytes, Some(l)))?;
                        sum.parity_added += 1;
                    }
                    ctx.db.set_verified(rel, now(), State::Ok)?;
                    if reason == "reappeared" {
                        ctx.db.log_event(rel, "reappeared", None)?;
                        println!("reappeared: {}", path_display(rel));
                    } else if !ctx.quiet && layout.is_some() {
                        println!("parity added: {}", path_display(rel));
                    }
                } else {
                    // Unchanged mtime but different content: bit rot.
                    if layout.is_some() {
                        discard_sidecar(ctx, &hash);
                    }
                    let has_parity = pmap.get(&row.content_hash).copied().unwrap_or(false);
                    let st = if has_parity { State::Corrupt } else { State::Unrecoverable };
                    ctx.db.set_state(rel, st)?;
                    ctx.db.log_event(rel, "corrupt", Some(&format!("expected {} got {}", hex::encode(&row.content_hash), hex::encode(&hash))))?;
                    println!(
                        "CORRUPT: {} (content changed but mtime did not{}){}",
                        path_display(rel),
                        if reason == "size" { "; size differs" } else { "" },
                        if has_parity { " — run `checksummer repair`" } else { " — no parity available" }
                    );
                    sum.corrupt += 1;
                    ctx.problems = true;
                }
            }
            (_, Done::HashedNoTable { .. }) | (_, Done::Blocks(_)) | (_, Done::Hashed { .. }) => {
                eprintln!("internal: unexpected result for {}", path_display(rel));
                sum.errors += 1;
            }
        }
        Ok(())
    })?;
    ctx.db.commit()?;

    // Removed files: anything known under the scanned roots that we did not see,
    // EXCEPT files under directories we could not read (unknown, not removed).
    let mut removed: Vec<&FileRow> = known.values().filter(|r| !seen.contains(&r.path) && !report.unreliable(&r.path)).collect();
    removed.sort_by(|a, b| a.path.cmp(&b.path));
    if !report.failed_dirs.is_empty() {
        println!(
            "warning: {} location(s) could not be read; files under them are left untouched in the index",
            report.failed_dirs.len()
        );
        ctx.problems = true;
    }
    if !removed.is_empty() {
        ctx.db.begin()?;
        let mut still: Vec<&FileRow> = Vec::new();
        for r in removed {
            if let Some(newp) = added_hashes.get(&r.content_hash) {
                // Same content appeared elsewhere: a move/rename.
                ctx.db.delete_file(&r.path)?;
                ctx.db.log_event(newp, "moved", Some(&format!("from {}", path_display(&r.path))))?;
                println!("moved: {} -> {}", path_display(&r.path), path_display(newp));
                sum.moved += 1;
            } else {
                still.push(r);
            }
        }
        ctx.db.commit()?;
        if !still.is_empty() {
            println!("\n{} file(s) in the index no longer exist on disk:", still.len());
            for r in &still {
                println!("  {}{}", path_display(&r.path), if r.state == State::Missing { "  (already marked missing)" } else { "" });
            }
            let yes = confirm(&format!("Remove these {} file(s) from the database?", still.len()), ctx.assume, false);
            ctx.db.begin()?;
            for r in &still {
                if yes {
                    ctx.db.delete_file(&r.path)?;
                    ctx.db.log_event(&r.path, "removed", Some("removed from index at user request"))?;
                    sum.removed += 1;
                } else {
                    if r.state != State::Missing {
                        ctx.db.set_state(&r.path, State::Missing)?;
                        ctx.db.log_event(&r.path, "missing", None)?;
                    }
                    sum.missing += 1;
                }
            }
            ctx.db.commit()?;
            if !yes {
                ctx.problems = true;
            }
        }
    }

    // Content rows nobody references any more (after modifications/removals)
    // are dropped. Their sidecars are deliberately KEPT: `fsck` lists them as
    // orphans and `fsck --fix` deletes them, so a mistaken removal can still be
    // undone by re-adding the file (its parity will be picked up again).
    ctx.db.begin()?;
    ctx.db.prune_orphan_content()?;
    ctx.db.commit()?;

    print_summary(&sum);
    if sum.errors > 0 || sum.changed_while_scanning > 0 {
        ctx.problems = true;
    }
    Ok(())
}

fn print_summary(s: &Summary) {
    let mut parts = vec![];
    if s.added > 0 {
        parts.push(format!("{} added ({})", s.added, fmt_bytes(s.added_bytes)));
    }
    if s.modified > 0 {
        parts.push(format!("{} modified", s.modified));
    }
    if s.unaccepted > 0 {
        parts.push(format!("{} modified-not-accepted", s.unaccepted));
    }
    if s.moved > 0 {
        parts.push(format!("{} moved", s.moved));
    }
    if s.removed > 0 {
        parts.push(format!("{} removed", s.removed));
    }
    if s.missing > 0 {
        parts.push(format!("{} missing", s.missing));
    }
    if s.parity_added > 0 {
        parts.push(format!("{} parity generated", s.parity_added));
    }
    if s.corrupt > 0 {
        parts.push(format!("{} CORRUPT", s.corrupt));
    }
    if s.suspected > 0 {
        parts.push(format!("{} SUSPECTED CORRUPTION", s.suspected));
    }
    if s.changed_while_scanning > 0 {
        parts.push(format!("{} changed while scanning (not recorded)", s.changed_while_scanning));
    }
    if s.errors > 0 {
        parts.push(format!("{} errors", s.errors));
    }
    if s.walk_errors > 0 {
        parts.push(format!("{} unreadable locations", s.walk_errors));
    }
    if s.symlinks_skipped > 0 {
        parts.push(format!("{} symlinks skipped", s.symlinks_skipped));
    }
    parts.push(format!("{} unchanged", s.unchanged));
    println!("scan complete: {}", parts.join(", "));
}

/// Used by `parity sync`: hash+parity jobs for covered files lacking parity.
/// Files whose size/mtime no longer match the index are reported, not encoded
/// (run `scan` first); the job carries the on-disk size so the layout is right.
pub struct ParityPlan {
    pub need: Vec<Job<FileRow>>,
    pub uncovered_with_parity: Vec<FileRow>,
    pub modified: Vec<FileRow>,
}

pub fn parity_jobs_for_rows(ctx: &mut Ctx, rows: Vec<FileRow>, resolver: &mut Resolver) -> Result<ParityPlan> {
    let pmap = parity_map(ctx)?;
    let mut need = Vec::new();
    let mut uncovered_with_parity = Vec::new();
    let mut modified = Vec::new();
    for row in rows {
        if row.state == State::Missing {
            continue;
        }
        let covered = resolver.covers_file(&row.path);
        let has = pmap.get(&row.content_hash).copied().unwrap_or(false);
        if covered && !has {
            if row.state != State::Ok {
                continue; // corrupt/unrecoverable/modified: nothing to protect yet
            }
            let abs = ctx.archive.abs(&row.path);
            match std::fs::metadata(&abs) {
                Ok(m) if m.len() == row.size && mtime_ns(&m) == row.mtime_ns => {
                    need.push(Job { rel: row.path.clone(), abs, size: row.size, work: Work::Hash { parity: true }, tag: row });
                }
                Ok(_) => modified.push(row),
                Err(_) => {}
            }
        } else if !covered && has {
            uncovered_with_parity.push(row);
        }
    }
    Ok(ParityPlan { need, uncovered_with_parity, modified })
}

/// `accept PATHS`: re-hash the named files (or every non-ok file under the
/// named directories) and record the on-disk content as the truth, with parity
/// if covered. This is the explicit override for SUSPECTED CORRUPTION /
/// modified-not-accepted / corrupt states when the user knows the content is right.
pub fn accept(ctx: &mut Ctx, args: &AcceptArgs) -> Result<()> {
    if args.paths.is_empty() {
        anyhow::bail!("give the files or directories to accept");
    }
    let rels = ctx.rel_paths_existing(&args.paths)?;
    let settings = Settings::from_archive(&ctx.archive, args.jobs, ctx.quiet);
    let mut resolver = Resolver::new(ctx.db.marks()?, ctx.archive.config.parity_default);
    let explicit: HashSet<PathBuf> = rels.iter().filter(|r| ctx.archive.abs(r).is_file()).cloned().collect();
    let rows = ctx.db.files_under_any(&rels)?;
    let mut jobs: Vec<Job<(FileRow, u64, i64)>> = Vec::new();
    for row in rows {
        if !(explicit.contains(&row.path) || row.state != State::Ok) {
            continue;
        }
        let abs = ctx.archive.abs(&row.path);
        let Ok(m) = std::fs::metadata(&abs) else { continue };
        if !m.is_file() {
            continue;
        }
        let parity = resolver.covers_file(&row.path);
        jobs.push(Job { rel: row.path.clone(), abs, size: m.len(), work: Work::Hash { parity }, tag: (row, m.len(), mtime_ns(&m)) });
    }
    if jobs.is_empty() {
        println!("nothing to accept");
        return Ok(());
    }
    println!("accepting current content of {} file(s)", jobs.len());
    let (mut accepted, mut errors) = (0u64, 0u64);
    let s2 = settings.clone();
    ctx.db.begin()?;
    worker::run(jobs, &settings, |job, done| {
        let (old, seen_size, seen_mtime) = job.tag;
        match done {
            Done::Hashed { hash, bytes, layout } => {
                let Some((size, mtime, inode)) = settled_metadata(&job.abs, seen_size, seen_mtime) else {
                    println!("changed while hashing (not accepted): {}", path_display(&job.rel));
                    errors += 1;
                    return Ok(());
                };
                ctx.db.upsert_content(&content_row(&s2, &hash, bytes, layout))?;
                let t = now();
                ctx.db.upsert_file(&FileRow {
                    content_hash: hash.clone(),
                    size,
                    mtime_ns: mtime,
                    inode,
                    state: State::Ok,
                    updated_at: t,
                    last_verified_at: Some(t),
                    ..old.clone()
                })?;
                ctx.db.log_event(&job.rel, "accepted", Some(&format!("{} -> {} (user accepted current content)", hex::encode(&old.content_hash), hex::encode(&hash))))?;
                println!("accepted: {}", path_display(&job.rel));
                accepted += 1;
            }
            Done::Failed(m) | Done::ReadError(m) => {
                eprintln!("error: {}: {m}", path_display(&job.rel));
                errors += 1;
            }
            _ => unreachable!(),
        }
        Ok(())
    })?;
    ctx.db.commit()?;
    ctx.db.begin()?;
    ctx.db.prune_orphan_content()?;
    ctx.db.commit()?;
    println!("accept complete: {accepted} accepted, {errors} errors");
    if errors > 0 {
        ctx.problems = true;
    }
    Ok(())
}

pub fn sidecar_for(ctx: &Ctx, hash: &[u8]) -> PathBuf {
    csp::sidecar_path(&ctx.archive.parity_dir(), hash)
}
