use super::Ctx;
use super::setops;
use crate::cli::ParityCmd;
use crate::config::ParityMode;
use crate::db::State;
use crate::marks::Resolver;
use crate::util::{fmt_bytes, path_display};
use crate::worker::Settings;
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

pub fn run(ctx: &mut Ctx, cmd: &ParityCmd) -> Result<()> {
    match cmd {
        ParityCmd::Include { dirs } => mark(ctx, dirs, Some(ParityMode::Include)),
        ParityCmd::Exclude { dirs } => mark(ctx, dirs, Some(ParityMode::Exclude)),
        ParityCmd::Unmark { dirs } => mark(ctx, dirs, None),
        ParityCmd::List => list(ctx),
        ParityCmd::Sync { prune, jobs } => sync(ctx, *prune, *jobs),
    }
}

fn mark(ctx: &mut Ctx, dirs: &[PathBuf], mode: Option<ParityMode>) -> Result<()> {
    if dirs.is_empty() {
        bail!("give at least one directory");
    }
    for d in dirs {
        let rel = ctx.rel(d)?;
        let abs = ctx.archive.abs(&rel);
        if !abs.is_dir() {
            bail!("{} is not a directory inside the archive", path_display(&rel));
        }
        match mode {
            Some(m) => {
                ctx.db.set_mark(&rel, m)?;
                println!("{}: {}", if rel.as_os_str().is_empty() { "<root>".to_string() } else { path_display(&rel) }, m.name());
            }
            None => {
                if ctx.db.remove_mark(&rel)? {
                    println!("{}: unmarked", path_display(&rel));
                } else {
                    println!("{}: was not marked", path_display(&rel));
                }
            }
        }
    }
    println!("run `meticulous parity sync` (or `scan`) to generate/prune parity accordingly");
    Ok(())
}

fn list(ctx: &mut Ctx) -> Result<()> {
    let marks = ctx.db.marks()?;
    let mut v: Vec<(&PathBuf, &ParityMode)> = marks.iter().collect();
    v.sort();
    println!("default (unmarked directories): {}", ctx.archive.config.parity_default.name());
    if v.is_empty() {
        println!("no explicit marks");
    } else {
        println!("marks:");
        for (p, m) in v {
            let shown = if p.as_os_str().is_empty() { "<root>".to_string() } else { path_display(p) };
            println!("  {:8} {}", m.name(), shown);
        }
    }
    // Coverage stats
    let mut resolver = Resolver::new(marks.clone(), ctx.archive.config.parity_default);
    let rows = ctx.db.files_under(Path::new(""))?;
    let live = ctx.db.live_membership_map()?;
    let (mut cov_n, mut cov_b, mut have_n, mut have_b, mut stale_n) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for r in rows.iter().filter(|r| r.state != State::Missing) {
        let covered = resolver.covers_file(&r.path);
        let has = live.contains_key(&r.content_hash);
        if covered {
            cov_n += 1;
            cov_b += r.size;
        }
        if has {
            have_n += 1;
            have_b += r.size;
        }
        if has && !covered {
            stale_n += 1;
        }
    }
    println!(
        "coverage: {} files ({}) should have parity; {} files ({}) currently do{}",
        cov_n,
        fmt_bytes(cov_b),
        have_n,
        fmt_bytes(have_b),
        if stale_n > 0 { format!("; {stale_n} have parity but are no longer covered (prune with `parity sync --prune`)") } else { String::new() }
    );
    let sets = ctx.db.all_parity_sets()?;
    let degraded = ctx.db.degraded_sets()?.len();
    let underfull = sets.iter().filter(|s| s.data_bytes * 2 < ctx.archive.config.stripe_size).count();
    println!(
        "sets: {} ({} degraded, {} underfull)",
        sets.len(),
        degraded,
        underfull
    );
    if let Ok(bytes) = dir_size(&ctx.archive.parity_dir()) {
        println!("parity store: {}", fmt_bytes(bytes));
    }
    Ok(())
}

pub fn dir_size(p: &Path) -> Result<u64> {
    let mut total = 0;
    for e in walkdir::WalkDir::new(p).into_iter().flatten() {
        if e.file_type().is_file() {
            total += e.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    Ok(total)
}

fn sync(ctx: &mut Ctx, prune: bool, jobs: Option<usize>) -> Result<()> {
    let settings = Settings::from_archive(&ctx.archive, jobs, ctx.quiet);
    let mut resolver = Resolver::new(ctx.db.marks()?, ctx.archive.config.parity_default);

    let phase = setops::parity_phase(ctx, &settings, &mut resolver)?;
    phase.print(ctx.quiet);
    if phase.skipped_modified > 0 {
        println!(
            "{} file(s) skipped (changed since last scan; run `meticulous scan` first)",
            phase.skipped_modified
        );
    }

    // Contents with live parity that no covered file references any more.
    let live = ctx.db.live_membership_map()?;
    let mut uncovered: Vec<Vec<u8>> = Vec::new();
    for hash in live.keys() {
        let refs = ctx.db.files_by_content(hash)?;
        // Missing-state files still count: their content must stay restorable.
        let still_wanted = refs.iter().any(|f| resolver.covers_file(&f.path));
        if !still_wanted {
            uncovered.push(hash.clone());
        }
    }
    let mut pruned = 0u64;
    if !uncovered.is_empty() {
        if prune {
            ctx.db.begin()?;
            for h in &uncovered {
                ctx.db.mark_members_dead(h)?;
                pruned += 1;
            }
            // Sets whose members are now all dead get dropped; the rest are
            // degraded and will be rebuilt (without the pruned contents) by
            // the next scan/sync parity phase.
            setops::converge_duplicates(ctx)?;
            ctx.db.commit()?;
            println!("pruned parity for {pruned} content item(s); the affected sets rebuild on the next scan/sync");
        } else {
            println!(
                "{} content item(s) have parity but are no longer covered; run `parity sync --prune` to drop them",
                uncovered.len()
            );
        }
    }
    let sets = ctx.db.all_parity_sets()?;
    println!(
        "parity sync complete: {} set(s) ({} degraded), {} built, {} adopted, {} dissolved, {pruned} pruned",
        sets.len(),
        ctx.db.degraded_sets()?.len(),
        phase.built,
        phase.adopted,
        phase.dissolved
    );
    if phase.had_problems() || phase.skipped_modified > 0 {
        ctx.problems = true;
    }
    Ok(())
}
