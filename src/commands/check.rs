use super::Ctx;
use super::scan::{mtime_ns, parity_map, sidecar_for};
use crate::cli::{CheckArgs, RepairArgs};
use crate::db::{FileRow, State};
use crate::parity;
use crate::util::{fmt_bytes, now, parse_duration, parse_size, path_display};
use crate::worker::{self, Done, Job, Settings, Work};
use anyhow::{Context, Result, bail};
use std::path::PathBuf;

#[derive(Default)]
struct Summary {
    ok: u64,
    corrupt: u64,
    repaired: u64,
    unrecoverable: u64,
    modified: u64,
    missing: u64,
    errors: u64,
    bytes: u64,
}

struct Tag {
    row: FileRow,
}

pub fn check(ctx: &mut Ctx, args: &CheckArgs) -> Result<()> {
    let rels = ctx.rel_paths(&args.paths)?;
    let settings = Settings::from_archive(&ctx.archive, args.jobs, ctx.quiet);
    let mut rows = ctx.db.files_under_any(&rels)?;
    let older = args.older_than.as_deref().map(parse_duration).transpose()?;
    let budget = args.budget.as_deref().map(parse_size).transpose()?;
    if let Some(d) = older {
        let cutoff = now() - d.as_secs() as i64;
        rows.retain(|r| r.last_verified_at.is_none_or(|t| t < cutoff));
    }
    if older.is_some() || budget.is_some() {
        // least recently verified first
        rows.sort_by_key(|r| (r.last_verified_at.unwrap_or(i64::MIN), r.path.clone()));
    }
    if let Some(b) = budget {
        let mut acc = 0u64;
        let mut keep = Vec::new();
        for r in rows {
            if acc >= b {
                break;
            }
            acc += r.size;
            keep.push(r);
        }
        rows = keep;
    }
    let pmap = parity_map(ctx)?;
    let mut jobs: Vec<Job<Tag>> = Vec::new();
    let mut sum = Summary::default();
    ctx.db.begin()?;
    for row in rows {
        let abs = ctx.archive.abs(&row.path);
        let meta = match std::fs::metadata(&abs) {
            Ok(m) if m.is_file() => m,
            Ok(_) => {
                eprintln!("error: {} is not a regular file any more", path_display(&row.path));
                sum.errors += 1;
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if row.state != State::Missing {
                    ctx.db.set_state(&row.path, State::Missing)?;
                    ctx.db.log_event(&row.path, "missing", None)?;
                }
                println!("MISSING: {}", path_display(&row.path));
                sum.missing += 1;
                continue;
            }
            Err(e) => {
                // Permission/IO problems are not "missing": report, leave the state alone.
                eprintln!("error: cannot stat {}: {e}", path_display(&row.path));
                sum.errors += 1;
                continue;
            }
        };
        if mtime_ns(&meta) != row.mtime_ns {
            // mtime moved: edited on purpose; not bit rot. Report, don't accept.
            // (A size change with an unchanged mtime is truncation/corruption and
            // falls through to the content check.)
            if row.state != State::Modified {
                ctx.db.set_state(&row.path, State::Modified)?;
                ctx.db.log_event(&row.path, "modified", Some("size/mtime changed since last scan; run `scan` to accept"))?;
            }
            println!("modified: {} (mtime changed; run `checksummer scan` to accept or re-check)", path_display(&row.path));
            sum.modified += 1;
            continue;
        }
        let has_parity = pmap.get(&row.content_hash).copied().unwrap_or(false);
        let sc = sidecar_for(ctx, &row.content_hash);
        let work = if has_parity && sc.is_file() { Work::CheckBlocks { sidecar: sc } } else { Work::Hash { parity: false } };
        jobs.push(Job { rel: row.path.clone(), abs, size: row.size, work, tag: Tag { row } });
    }
    ctx.db.commit()?;

    if jobs.is_empty() {
        println!("nothing to check");
    } else {
        ctx.say(format!("checking {} files ({})", jobs.len(), fmt_bytes(jobs.iter().map(|j| j.size).sum())));
    }
    let mut to_repair: Vec<(FileRow, parity::BlockCheck)> = Vec::new();
    ctx.db.begin()?;
    let mut n = 0usize;
    worker::run(jobs, &settings, |job, done| {
        n += 1;
        if n.is_multiple_of(500) {
            ctx.db.commit()?;
            ctx.db.begin()?;
        }
        let row = job.tag.row;
        sum.bytes += job.size;
        // If the file changed while we were reading it, say so instead of judging stale bytes.
        if let Ok(m) = std::fs::metadata(&job.abs)
            && mtime_ns(&m) != row.mtime_ns {
                println!("modified while checking: {} (run `checksummer scan`)", path_display(&row.path));
                sum.modified += 1;
                return Ok(());
            }
        match done {
            Done::Failed(msg) => {
                eprintln!("error: {}: {msg}", path_display(&row.path));
                sum.errors += 1;
            }
            Done::ReadError(msg) => {
                ctx.read_error(&row.path, &msg);
                if row.state != State::Unrecoverable {
                    ctx.db.set_state(&row.path, State::Unrecoverable)?;
                }
                ctx.db.log_event(&row.path, "read-error", Some(&msg))?;
                sum.corrupt += 1;
                sum.unrecoverable += 1;
            }
            Done::Hashed { hash, .. } | Done::HashedNoTable { hash } if hash == row.content_hash => {
                ctx.db.set_verified(&row.path, now(), State::Ok)?;
                if row.state != State::Ok {
                    ctx.db.log_event(&row.path, "verified", Some("content matches again"))?;
                }
                sum.ok += 1;
            }
            Done::Hashed { hash, .. } => {
                if row.state != State::Unrecoverable {
                    ctx.db.set_state(&row.path, State::Unrecoverable)?;
                }
                ctx.db.log_event(&row.path, "corrupt", Some(&format!("expected {} got {} (no parity)", hex::encode(&row.content_hash), hex::encode(&hash))))?;
                println!("CORRUPT: {} (no parity available)", path_display(&row.path));
                sum.corrupt += 1;
                sum.unrecoverable += 1;
            }
            Done::HashedNoTable { hash } => {
                if row.state != State::Unrecoverable {
                    ctx.db.set_state(&row.path, State::Unrecoverable)?;
                }
                ctx.db.log_event(&row.path, "corrupt", Some(&format!("expected {} got {}; parity sidecar is damaged", hex::encode(&row.content_hash), hex::encode(&hash))))?;
                println!("CORRUPT: {} (its parity sidecar is damaged too — run `checksummer fsck`)", path_display(&row.path));
                sum.corrupt += 1;
                sum.unrecoverable += 1;
            }
            Done::Blocks(bc) => {
                if bc.ok(&row.content_hash) {
                    ctx.db.set_verified(&row.path, now(), State::Ok)?;
                    if row.state != State::Ok {
                        ctx.db.log_event(&row.path, "verified", Some("content matches again"))?;
                    }
                    sum.ok += 1;
                } else {
                    let repairable = bc.repairable();
                    let st = if repairable { State::Corrupt } else { State::Unrecoverable };
                    let what = if bc.extra_bytes > 0 && bc.bad_blocks.len() <= 1 {
                        format!("{} extra bytes appended", bc.extra_bytes)
                    } else if !bc.unreadable_blocks.is_empty() {
                        format!(
                            "{} bad block(s) of {} ({} unreadable: the filesystem returned EIO — on ZFS see `zpool status -v`)",
                            bc.bad_blocks.len(),
                            bc.n_blocks,
                            bc.unreadable_blocks.len()
                        )
                    } else {
                        format!("{} bad block(s) of {}", bc.bad_blocks.len(), bc.n_blocks)
                    };
                    let detail = format!("{what}{}", if repairable { ", repairable" } else { ", exceeds parity" });
                    if row.state != st {
                        ctx.db.set_state(&row.path, st)?;
                    }
                    ctx.db.log_event(&row.path, "corrupt", Some(&detail))?;
                    println!(
                        "CORRUPT: {} — {what}{}",
                        path_display(&row.path),
                        if repairable { " (repairable)" } else { " (NOT repairable: too much damage in a stripe)" }
                    );
                    sum.corrupt += 1;
                    if repairable {
                        to_repair.push((row, bc));
                    } else {
                        sum.unrecoverable += 1;
                    }
                }
            }
        }
        Ok(())
    })?;
    ctx.db.commit()?;

    if args.repair && !to_repair.is_empty() {
        println!("repairing {} file(s)...", to_repair.len());
        for (row, bc) in to_repair {
            match do_repair(ctx, &row, Some(bc), false, false) {
                Ok(n) => {
                    println!("repaired: {} ({n} block(s) rebuilt)", path_display(&row.path));
                    sum.repaired += 1;
                    sum.corrupt -= 1;
                }
                Err(e) => {
                    eprintln!("repair failed: {}: {e:#}", path_display(&row.path));
                    sum.errors += 1;
                }
            }
        }
    }

    println!(
        "check complete: {} ok, {} corrupt{}, {} modified, {} missing, {} errors ({} read)",
        sum.ok,
        sum.corrupt,
        if sum.repaired > 0 { format!(" ({} repaired)", sum.repaired) } else { String::new() },
        sum.modified,
        sum.missing,
        sum.errors,
        fmt_bytes(sum.bytes)
    );
    if sum.corrupt > 0 || sum.modified > 0 || sum.missing > 0 || sum.errors > 0 {
        ctx.problems = true;
    }
    Ok(())
}

/// Repair one file. Returns blocks rebuilt (0 = already intact).
///
/// Safety: a repair rewrites the file to the content recorded in the index.
/// It is refused when the file's size or mtime no longer match the index
/// (i.e. it was edited since the last scan), because then "the recorded
/// content" may simply be an older version the user replaced on purpose.
pub fn do_repair(ctx: &mut Ctx, row: &FileRow, precomputed: Option<parity::BlockCheck>, keep_corrupt: bool, dry_run: bool) -> Result<usize> {
    let abs = ctx.archive.abs(&row.path);
    let meta = std::fs::metadata(&abs).with_context(|| format!("{} is missing", path_display(&row.path)))?;
    if mtime_ns(&meta) != row.mtime_ns {
        bail!(
            "refusing to repair {}: its mtime changed since the last scan ({} on disk vs {} recorded), so it may have been edited on purpose. \
             If it is really damaged, `checksummer scan` will tell edits from corruption (it keeps the recorded content for suspected bit rot); otherwise run `scan` to accept the new content.",
            path_display(&row.path),
            crate::util::fmt_time(mtime_ns(&meta) / 1_000_000_000),
            crate::util::fmt_time(row.mtime_ns / 1_000_000_000)
        );
    }
    let sc_path = sidecar_for(ctx, &row.content_hash);
    let mut sc = parity::open_sidecar(&sc_path, &row.content_hash)
        .with_context(|| format!("no usable parity for {}", path_display(&row.path)))?;
    let bc = match precomputed {
        Some(b) => b,
        None => parity::check_blocks(&abs, &sc)?,
    };
    if bc.ok(&row.content_hash) {
        ctx.db.set_verified(&row.path, now(), State::Ok)?;
        return Ok(0);
    }
    let quarantine = if keep_corrupt { Some(ctx.archive.quarantine_dir().join(&row.path)) } else { None };
    let out = match parity::repair_file(&abs, &mut sc, &bc, quarantine.as_deref(), dry_run) {
        Ok(o) => o,
        Err(e) => {
            // The pre-check showed real damage that parity cannot fix.
            if !dry_run && row.state != State::Unrecoverable {
                ctx.db.set_state(&row.path, State::Unrecoverable)?;
            }
            return Err(e);
        }
    };
    if !dry_run {
        let meta = std::fs::metadata(&abs)?;
        let t = now();
        ctx.db.upsert_file(&FileRow {
            size: meta.len(),
            mtime_ns: mtime_ns(&meta),
            inode: Some(std::os::unix::fs::MetadataExt::ino(&meta)),
            state: State::Ok,
            updated_at: t,
            last_verified_at: Some(t),
            ..row.clone()
        })?;
        ctx.db.log_event(
            &row.path,
            "repaired",
            Some(&format!(
                "{} block(s) rebuilt from parity{}",
                out.blocks_repaired,
                quarantine.as_ref().map(|q| format!("; damaged copy kept at {}", q.display())).unwrap_or_default()
            )),
        )?;
    }
    Ok(out.blocks_repaired)
}

pub fn repair(ctx: &mut Ctx, args: &RepairArgs) -> Result<()> {
    let rels = ctx.rel_paths(&args.paths)?;
    let rows = ctx.db.files_under_any(&rels)?;
    let explicit: Vec<PathBuf> = rels.iter().filter(|r| ctx.archive.abs(r).is_file()).cloned().collect();
    let candidates: Vec<FileRow> = rows
        .into_iter()
        .filter(|r| matches!(r.state, State::Corrupt | State::Unrecoverable) || explicit.contains(&r.path))
        .collect();
    if candidates.is_empty() {
        println!("nothing to repair (no files in state corrupt/unrecoverable under the given paths)");
        return Ok(());
    }
    let mut repaired = 0;
    let mut failed = 0;
    for row in candidates {
        match do_repair(ctx, &row, None, args.keep_corrupt, args.dry_run) {
            Ok(0) => println!("ok: {} (already intact)", path_display(&row.path)),
            Ok(n) => {
                println!("{}: {} ({n} block(s) rebuilt)", if args.dry_run { "would repair" } else { "repaired" }, path_display(&row.path));
                repaired += 1;
            }
            Err(e) => {
                eprintln!("cannot repair {}: {e:#}", path_display(&row.path));
                failed += 1;
            }
        }
    }
    println!("repair complete: {repaired} repaired, {failed} failed");
    if failed > 0 {
        ctx.problems = true;
    }
    Ok(())
}
