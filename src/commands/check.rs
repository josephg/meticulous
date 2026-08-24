use super::Ctx;
use super::scan::mtime_ns;
use super::setops;
use crate::cli::{CheckArgs, RepairArgs};
use crate::db::{FileRow, State};
use crate::mts;
use crate::parity::{self, MemberCtx, MemberOutcome};
use crate::util::{fmt_bytes, now, parse_duration, parse_size, path_display};
use crate::worker::{self, Done, Job, Settings, Work};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Default)]
struct Summary {
    ok: u64,
    corrupt: u64,
    repaired: u64,
    unrecoverable: u64,
    modified: u64,
    missing: u64,
    restorable: u64,
    errors: u64,
    bytes: u64,
}

struct Tag {
    row: FileRow,
    set_id: Option<Vec<u8>>,
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
    let live = ctx.db.live_membership_map()?;
    let parity_dir = ctx.archive.parity_dir();
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
                if live.contains_key(&row.content_hash) {
                    println!(
                        "MISSING: {} — restorable from its parity set: run `meticulous repair {}`",
                        path_display(&row.path),
                        path_display(&row.path)
                    );
                    sum.restorable += 1;
                } else {
                    println!("MISSING: {}", path_display(&row.path));
                }
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
            println!("modified: {} (mtime changed; run `meticulous scan` to accept or re-check)", path_display(&row.path));
            sum.modified += 1;
            continue;
        }
        let (work, set_id) = match live.get(&row.content_hash) {
            Some((sid, ord)) => {
                let sc = mts::sidecar_path(&parity_dir, sid);
                if sc.is_file() {
                    (Work::CheckBlocks { sidecar: sc, ord: *ord as usize }, Some(sid.clone()))
                } else {
                    (Work::Hash, None)
                }
            }
            None => (Work::Hash, None),
        };
        jobs.push(Job { rel: row.path.clone(), abs, size: row.size, work, tag: Tag { row, set_id } });
    }
    ctx.db.commit()?;

    if jobs.is_empty() {
        println!("nothing to check");
    } else {
        ctx.say(format!("checking {} files ({})", jobs.len(), fmt_bytes(jobs.iter().map(|j| j.size).sum())));
    }
    // (set id -> file rows to repair) — grouped so one decode heals them all.
    let mut to_repair: HashMap<Vec<u8>, Vec<FileRow>> = HashMap::new();
    ctx.db.begin()?;
    let mut n = 0usize;
    worker::run(jobs, &settings, |job, done| {
        n += 1;
        if n.is_multiple_of(500) {
            ctx.db.commit()?;
            ctx.db.begin()?;
        }
        let Tag { row, set_id } = job.tag;
        sum.bytes += job.size;
        // If the file changed while we were reading it, say so instead of judging stale bytes.
        if let Ok(m) = std::fs::metadata(&job.abs)
            && mtime_ns(&m) != row.mtime_ns {
                println!("modified while checking: {} (run `meticulous scan`)", path_display(&row.path));
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
                println!("CORRUPT: {} (its parity sidecar is damaged too — run `meticulous fsck`)", path_display(&row.path));
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
                    // Estimated repairability: bad blocks vs. the set's live
                    // margin (dead members counted). `repair` decides for real.
                    let sid = set_id.clone().unwrap_or_default();
                    let margin_ok = match (ctx.db.get_parity_set(&sid)?, ctx.db.set_members(&sid)?) {
                        (Some(set), members) if !members.is_empty() => {
                            let ord = members.iter().position(|m| m.content_hash == row.content_hash).unwrap_or(0) as u32;
                            setops::estimated_margin_ok(&set, &members, ord, &bc.bad_blocks).unwrap_or(false)
                        }
                        _ => false,
                    };
                    let st = if margin_ok { State::Corrupt } else { State::Unrecoverable };
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
                    let detail = format!("{what}{}", if margin_ok { ", likely repairable" } else { ", likely exceeds the set's margin" });
                    if row.state != st {
                        ctx.db.set_state(&row.path, st)?;
                    }
                    ctx.db.log_event(&row.path, "corrupt", Some(&detail))?;
                    println!(
                        "CORRUPT: {} — {what}{}",
                        path_display(&row.path),
                        if margin_ok { " (likely repairable)" } else { " (likely NOT repairable: too much damage in its stripe)" }
                    );
                    sum.corrupt += 1;
                    if margin_ok {
                        to_repair.entry(sid).or_default().push(row);
                    } else {
                        sum.unrecoverable += 1;
                    }
                }
            }
            Done::SetEncoded(_) => unreachable!(),
        }
        Ok(())
    })?;
    ctx.db.commit()?;

    if args.repair && !to_repair.is_empty() {
        println!("repairing {} file(s)...", to_repair.values().map(|v| v.len()).sum::<usize>());
        for (sid, rows) in to_repair {
            match repair_via_set(ctx, &sid, rows, false, false) {
                Ok((r, f)) => {
                    sum.repaired += r;
                    sum.corrupt = sum.corrupt.saturating_sub(r);
                    sum.errors += f;
                }
                Err(e) => {
                    eprintln!("repair failed: {e:#}");
                    sum.errors += 1;
                }
            }
        }
    }

    println!(
        "check complete: {} ok, {} corrupt{}, {} modified, {} missing{}, {} errors ({} read)",
        sum.ok,
        sum.corrupt,
        if sum.repaired > 0 { format!(" ({} repaired)", sum.repaired) } else { String::new() },
        sum.modified,
        sum.missing,
        if sum.restorable > 0 { format!(" ({} restorable)", sum.restorable) } else { String::new() },
        sum.errors,
        fmt_bytes(sum.bytes)
    );
    if sum.corrupt > 0 || sum.modified > 0 || sum.missing > 0 || sum.errors > 0 {
        ctx.problems = true;
    }
    Ok(())
}

/// Repair (or restore) the given file rows, all members of the set `set_id`.
/// Reads the whole set once: sibling blocks are hash-verified sources, and any
/// sibling damage found along the way is repaired too (same safety rules).
/// Returns (files repaired/restored, files failed).
///
/// Safety: a repair rewrites a file to the content recorded in the index. A
/// target whose size/mtime no longer match the index is refused (it may have
/// been edited on purpose — `meticulous scan` classifies that, `accept`
/// overrides). Missing files are restored to their recorded path.
pub fn repair_via_set(ctx: &mut Ctx, set_id: &[u8], targets: Vec<FileRow>, keep_corrupt: bool, dry_run: bool) -> Result<(u64, u64)> {
    let set = ctx.db.get_parity_set(set_id)?.with_context(|| format!("parity set {} is not in the index", hex::encode(set_id)))?;
    let members = ctx.db.set_members(set_id)?;
    setops::layout_from_rows(&set, &members)?; // consistency check
    let sc_path = mts::sidecar_path(&ctx.archive.parity_dir(), set_id);
    let mut sc = mts::Reader::open(&sc_path).with_context(|| format!("no usable parity sidecar for set {}", hex::encode(set_id)))?;
    setops::verify_sidecar_matches(&set, &members, &sc)?;

    // Refuse targets that were edited since the last scan.
    let mut failed = 0u64;
    let mut accepted_targets: Vec<FileRow> = Vec::new();
    for t in targets {
        let abs = ctx.archive.abs(&t.path);
        match std::fs::metadata(&abs) {
            Ok(m) if mtime_ns(&m) != t.mtime_ns => {
                eprintln!(
                    "refusing to repair {}: its mtime changed since the last scan ({} on disk vs {} recorded), so it may have been edited on purpose. \
                     `meticulous scan` tells edits from corruption; `meticulous accept` records the new content.",
                    path_display(&t.path),
                    crate::util::fmt_time(mtime_ns(&m) / 1_000_000_000),
                    crate::util::fmt_time(t.mtime_ns / 1_000_000_000)
                );
                failed += 1;
            }
            _ => accepted_targets.push(t),
        }
    }

    // Build the per-member context.
    let mut ctxs: Vec<MemberCtx> = Vec::with_capacity(members.len());
    let mut written_paths: Vec<Option<FileRow>> = vec![None; members.len()];
    for m in &members {
        if m.dead {
            ctxs.push(MemberCtx::default());
            continue;
        }
        let target = accepted_targets.iter().find(|t| t.content_hash == m.content_hash);
        // A trustworthy source: any file row whose on-disk mtime matches the
        // index (state may be Corrupt, or the size may differ — truncation is
        // damage, and every block is hash-verified during the read anyway).
        // Only an mtime change means "edited on purpose" = pure erasure.
        let mut source: Option<(FileRow, PathBuf)> = None;
        for f in ctx.db.files_by_content(&m.content_hash)? {
            if f.state == State::Missing {
                continue;
            }
            let abs = ctx.archive.abs(&f.path);
            if let Ok(meta) = std::fs::metadata(&abs)
                && meta.is_file()
                && mtime_ns(&meta) == f.mtime_ns
            {
                // Prefer the target row itself as the source when it qualifies.
                let is_target = target.is_some_and(|t| t.path == f.path);
                if source.is_none() || is_target {
                    source = Some((f.clone(), abs.clone()));
                    if is_target {
                        break;
                    }
                }
            }
        }
        let mc = match (&source, target) {
            (Some((srow, sabs)), _) => {
                // Damaged members with a matching source are always writable
                // (sibling auto-repair); quarantine when asked.
                written_paths[m.ord as usize] = Some(srow.clone());
                MemberCtx {
                    source: Some(sabs.clone()),
                    write_to: Some(sabs.clone()),
                    keep_corrupt: if keep_corrupt { Some(ctx.archive.quarantine_dir().join(&srow.path)) } else { None },
                    restore_mtime_ns: None,
                }
            }
            (None, Some(t)) => {
                // Restore a missing/unreadable file to its recorded path.
                written_paths[m.ord as usize] = Some(t.clone());
                MemberCtx {
                    source: None,
                    write_to: Some(ctx.archive.abs(&t.path)),
                    keep_corrupt: None,
                    restore_mtime_ns: Some(t.mtime_ns),
                }
            }
            (None, None) => MemberCtx::default(),
        };
        ctxs.push(mc);
    }

    let out = parity::repair_set(&mut sc, &ctxs, dry_run)?;
    let mut repaired = 0u64;
    for (stripe, erased, par) in &out.unrecoverable_stripes {
        eprintln!(
            "set {}: stripe {stripe} has {erased} damaged/missing blocks but only {par} parity blocks — dead members and modified siblings count against the margin",
            hex::encode(&set_id[..8.min(set_id.len())])
        );
    }
    for (ord, outcome) in out.members.iter().enumerate() {
        let row = written_paths[ord].as_ref();
        match (outcome, row) {
            (MemberOutcome::Repaired { blocks }, Some(row)) => {
                let abs = ctx.archive.abs(&row.path);
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
                ctx.db.log_event(&row.path, "repaired", Some(&format!("{blocks} block(s) rebuilt from the parity set")))?;
                println!("repaired: {} ({blocks} block(s) rebuilt)", path_display(&row.path));
                repaired += 1;
            }
            (MemberOutcome::Restored { bytes }, Some(row)) => {
                let abs = ctx.archive.abs(&row.path);
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
                ctx.db.log_event(&row.path, "restored", Some(&format!("{bytes} bytes rebuilt entirely from the parity set")))?;
                println!("restored: {} ({} rebuilt from siblings + parity)", path_display(&row.path), fmt_bytes(*bytes));
                repaired += 1;
            }
            (MemberOutcome::WouldRepair { blocks }, Some(row)) => {
                println!("would repair: {} ({blocks} block(s))", path_display(&row.path));
                repaired += 1;
            }
            (MemberOutcome::WouldRestore { bytes }, Some(row)) => {
                println!("would restore: {} ({})", path_display(&row.path), fmt_bytes(*bytes));
                repaired += 1;
            }
            (MemberOutcome::Failed { msg }, Some(row)) => {
                eprintln!("cannot repair {}: {msg}", path_display(&row.path));
                if !dry_run && row.state != State::Unrecoverable {
                    ctx.db.set_state(&row.path, State::Unrecoverable)?;
                }
                failed += 1;
            }
            (MemberOutcome::Failed { msg }, None) => {
                eprintln!("set {}: member {ord}: {msg}", hex::encode(&set_id[..8.min(set_id.len())]));
                failed += 1;
            }
            (MemberOutcome::DamagedNotWritable { bad_blocks }, _) => {
                eprintln!(
                    "note: set {}: member {ord} has {bad_blocks} damaged block(s) but no writable file",
                    hex::encode(&set_id[..8.min(set_id.len())])
                );
            }
            _ => {}
        }
    }
    Ok((repaired, failed))
}

pub fn repair(ctx: &mut Ctx, args: &RepairArgs) -> Result<()> {
    let rels = ctx.rel_paths(&args.paths)?;
    let rows = ctx.db.files_under_any(&rels)?;
    let explicit: Vec<PathBuf> = rels.iter().filter(|r| ctx.db.get_file(r).ok().flatten().is_some()).cloned().collect();
    let live = ctx.db.live_membership_map()?;
    let candidates: Vec<FileRow> = rows
        .into_iter()
        .filter(|r| matches!(r.state, State::Corrupt | State::Unrecoverable | State::Missing) || explicit.contains(&r.path))
        .collect();
    if candidates.is_empty() {
        println!("nothing to repair (no files in state corrupt/unrecoverable/missing under the given paths)");
        return Ok(());
    }
    // Group by parity set; files without a live membership cannot be repaired.
    let mut by_set: HashMap<Vec<u8>, Vec<FileRow>> = HashMap::new();
    let mut repaired = 0u64;
    let mut failed = 0u64;
    for row in candidates {
        match live.get(&row.content_hash) {
            Some((sid, _)) => by_set.entry(sid.clone()).or_default().push(row),
            None => {
                if row.state == State::Ok {
                    println!("ok: {} (nothing recorded against it)", path_display(&row.path));
                } else {
                    eprintln!("cannot repair {}: no parity covers its recorded content", path_display(&row.path));
                    failed += 1;
                }
            }
        }
    }
    ctx.db.begin()?;
    for (sid, targets) in by_set {
        match repair_via_set(ctx, &sid, targets, args.keep_corrupt, args.dry_run) {
            Ok((r, f)) => {
                repaired += r;
                failed += f;
            }
            Err(e) => {
                eprintln!("repair failed for set {}: {e:#}", hex::encode(&sid[..8.min(sid.len())]));
                failed += 1;
            }
        }
    }
    ctx.db.commit()?;
    println!(
        "repair complete: {repaired} {}, {failed} failed",
        if args.dry_run { "would be repaired" } else { "repaired" }
    );
    if failed > 0 {
        ctx.problems = true;
    }
    Ok(())
}
