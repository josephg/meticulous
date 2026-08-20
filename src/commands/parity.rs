use super::Ctx;
use super::scan::{parity_jobs_for_rows, sidecar_for};
use crate::cli::ParityCmd;
use crate::config::ParityMode;
use crate::db::{ContentRow, State};
use crate::marks::Resolver;
use crate::util::{fmt_bytes, now, path_display};
use crate::worker::{self, Done, Settings};
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
    println!("run `checksummer parity sync` (or `scan`) to generate/prune parity accordingly");
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
    let pmap = super::scan::parity_map(ctx)?;
    let (mut cov_n, mut cov_b, mut have_n, mut have_b, mut stale_n) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for r in rows.iter().filter(|r| r.state != State::Missing) {
        let covered = resolver.covers_file(&r.path);
        let has = pmap.get(&r.content_hash).copied().unwrap_or(false);
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
    let rows = ctx.db.files_under(Path::new(""))?;
    let super::scan::ParityPlan { need, uncovered_with_parity: uncovered, modified } = parity_jobs_for_rows(ctx, rows, &mut resolver)?;
    let mut generated = 0u64;
    let mut corrupt = 0u64;
    let mut errors = 0u64;
    for r in &modified {
        println!("skipped (changed since last scan; run `checksummer scan` first): {}", path_display(&r.path));
    }
    if need.is_empty() {
        println!("all covered files already have parity");
    } else {
        println!("generating parity for {} files ({})", need.len(), fmt_bytes(need.iter().map(|j| j.size).sum()));
        let s2 = settings.clone();
        ctx.db.begin()?;
        worker::run(need, &settings, |job, done| {
            let row = job.tag;
            match done {
                Done::Failed(m) => {
                    eprintln!("error: {}: {m}", path_display(&row.path));
                    errors += 1;
                }
                Done::ReadError(m) => {
                    ctx.read_error(&row.path, &m);
                    ctx.db.set_state(&row.path, State::Unrecoverable)?;
                    ctx.db.log_event(&row.path, "read-error", Some(&m))?;
                    errors += 1;
                }
                Done::Hashed { hash, bytes, layout } => {
                    if hash == row.content_hash {
                        ctx.db.upsert_content(&ContentRow {
                            hash: hash.clone(),
                            algo: s2.algo,
                            size: bytes,
                            block_size: layout.map(|l| l.block_size),
                            blocks_per_stripe: layout.map(|l| l.blocks_per_stripe),
                            parity_ppm: layout.map(|l| l.parity_ppm),
                            has_parity: true,
                            created_at: now(),
                        })?;
                        ctx.db.set_verified(&row.path, now(), State::Ok)?;
                        generated += 1;
                    } else {
                        // sidecar describes corrupt content: discard
                        if ctx.db.get_content(&hash)?.is_none() {
                            let _ = std::fs::remove_file(sidecar_for(ctx, &hash));
                        }
                        // Same size+mtime as recorded (checked before queueing) but different bytes: bit rot, no parity.
                        ctx.db.set_state(&row.path, State::Unrecoverable)?;
                        ctx.db.log_event(&row.path, "corrupt", Some("detected while generating parity; no parity available"))?;
                        println!("CORRUPT: {} (content changed but mtime did not; cannot generate parity for damaged content)", path_display(&row.path));
                        corrupt += 1;
                    }
                }
                Done::Blocks(_) | Done::HashedNoTable { .. } => unreachable!(),
            }
            Ok(())
        })?;
        ctx.db.commit()?;
    }
    let mut pruned = 0u64;
    if !uncovered.is_empty() {
        if prune {
            ctx.db.begin()?;
            // Only delete a sidecar if *no* covered file references the content.
            let mut by_hash: std::collections::HashMap<Vec<u8>, ()> = Default::default();
            for r in &uncovered {
                by_hash.insert(r.content_hash.clone(), ());
            }
            for h in by_hash.keys() {
                let refs = ctx.db.files_by_content(h)?;
                if refs.iter().any(|f| f.state != State::Missing && resolver.covers_file(&f.path)) {
                    continue;
                }
                let _ = std::fs::remove_file(sidecar_for(ctx, h));
                ctx.db.set_has_parity(h, false)?;
                pruned += 1;
            }
            ctx.db.commit()?;
            println!("pruned parity for {pruned} content item(s)");
        } else {
            println!(
                "{} file(s) have parity but are no longer covered; run `parity sync --prune` to delete it",
                uncovered.len()
            );
        }
    }
    println!(
        "parity sync complete: {generated} generated, {pruned} pruned, {corrupt} corrupt, {} skipped (modified), {errors} errors",
        modified.len()
    );
    if corrupt > 0 || errors > 0 || !modified.is_empty() {
        ctx.problems = true;
    }
    Ok(())
}
