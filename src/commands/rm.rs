//! `meticulous rm` — delete files the safe way: rebuild the parity sets they
//! belong to *first* (without them), then delete the files from disk and the
//! index. The archive never passes through a degraded state, and no stale
//! parity is left behind.

use super::Ctx;
use super::setops;
use crate::cli::RmArgs;
use crate::db::{FileRow, SetRow, State};
use crate::util::{confirm, fmt_bytes, path_display};
use crate::worker::Settings;
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};

pub fn rm(ctx: &mut Ctx, args: &RmArgs) -> Result<()> {
    if args.paths.is_empty() {
        bail!("give the files or directories to delete");
    }
    let rels = ctx.rel_paths(&args.paths)?;
    // Every named path must be known (a file row, or a directory with rows under it).
    let mut rows: Vec<FileRow> = Vec::new();
    let mut seen_ids: HashSet<i64> = HashSet::new();
    for r in &rels {
        let under = ctx.db.files_under(r)?;
        if under.is_empty() {
            bail!("{} is not in the index (delete it with plain rm if it is untracked)", path_display(r));
        }
        for row in under {
            if seen_ids.insert(row.id) {
                rows.push(row);
            }
        }
    }
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    let total_bytes: u64 = rows.iter().map(|r| r.size).sum();

    // Contents that will lose their last reference.
    let doomed_paths: HashSet<&std::path::PathBuf> = rows.iter().map(|r| &r.path).collect();
    let mut dying: HashSet<Vec<u8>> = HashSet::new();
    for row in &rows {
        let refs = ctx.db.files_by_content(&row.content_hash)?;
        if refs.iter().all(|f| doomed_paths.contains(&f.path)) {
            dying.insert(row.content_hash.clone());
        }
    }

    // Sets that contain a dying content as a live member need a rebuild.
    let mut affected: HashMap<Vec<u8>, SetRow> = HashMap::new();
    for h in &dying {
        for m in ctx.db.memberships_of(h)? {
            if !m.dead && !affected.contains_key(&m.set_id)
                && let Some(set) = ctx.db.get_parity_set(&m.set_id)? {
                    affected.insert(m.set_id.clone(), set);
                }
        }
    }

    // Eligibility: every surviving live member must be re-readable.
    let mut blocked: Vec<(String, Vec<String>)> = Vec::new();
    for set in affected.values() {
        if let Err(blockers) = setops::dissolution_entries(ctx, set, &dying)? {
            blocked.push((hex::encode(&set.id[..8.min(set.id.len())]), blockers));
        }
    }
    if !blocked.is_empty() && !args.force {
        for (id, blockers) in &blocked {
            eprintln!("parity set {id} cannot be rebuilt: waiting on {}", blockers.join(", "));
        }
        bail!(
            "refusing to delete: rebuilding the affected parity set(s) first would lose the repair source for the file(s) above. \
             Repair or `meticulous accept` them first, or pass --force to delete anyway (leaves those sets degraded)."
        );
    }

    println!("{} file(s), {}:", rows.len(), fmt_bytes(total_bytes));
    for r in rows.iter().take(20) {
        println!("  {}", path_display(&r.path));
    }
    if rows.len() > 20 {
        println!("  ... and {} more", rows.len() - 20);
    }
    if !affected.is_empty() {
        println!(
            "{} parity set(s) will be rebuilt without these files before deletion",
            affected.len()
        );
    }
    if !confirm(&format!("Delete these {} file(s) from disk and the index?", rows.len()), ctx.assume, false) {
        println!("nothing deleted");
        return Ok(());
    }

    // Phase 1: rebuild affected sets without the dying contents.
    if !affected.is_empty() {
        let settings = Settings::from_archive(&ctx.archive, args.jobs, ctx.quiet);
        let blocked_ids: HashSet<String> = blocked.iter().map(|(id, _)| id.clone()).collect();
        let rebuild: Vec<SetRow> = affected
            .values()
            .filter(|s| !blocked_ids.contains(&hex::encode(&s.id[..8.min(s.id.len())])))
            .cloned()
            .collect();
        let phase = setops::rebuild_excluding(ctx, &settings, rebuild, &dying)?;
        phase.print(ctx.quiet);
        if phase.errors > 0 {
            bail!("parity rebuild failed; nothing was deleted — re-run after fixing the errors above");
        }
    }

    // Phase 2: delete the files (disk, then index).
    let mut deleted = 0u64;
    let mut errors = 0u64;
    ctx.db.begin()?;
    for row in &rows {
        let abs = ctx.archive.abs(&row.path);
        match std::fs::remove_file(&abs) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!("error: cannot delete {}: {e}", path_display(&row.path));
                errors += 1;
                continue;
            }
        }
        ctx.db.delete_file(&row.path)?;
        ctx.db.log_event(&row.path, "removed", Some("deleted via meticulous rm"))?;
        deleted += 1;
        if !ctx.quiet {
            println!("deleted: {}", path_display(&row.path));
        }
    }
    ctx.db.prune_orphan_content()?;
    ctx.db.commit()?;
    println!("rm complete: {deleted} deleted, {errors} errors");
    if errors > 0 || (!blocked.is_empty() && args.force) {
        if !blocked.is_empty() && args.force {
            println!("note: {} set(s) were left degraded (--force); repair/accept their damaged members, then scan", blocked.len());
        }
        ctx.problems = true;
    }
    let _ = State::Ok;
    Ok(())
}
