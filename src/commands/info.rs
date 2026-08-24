use super::Ctx;
use super::setops;
use crate::cli::{ConfigArgs, HistoryArgs, LsArgs};
use crate::config::ParityMode;
use crate::db::State;
use crate::marks::Resolver;
use crate::mts;
use crate::util::{fmt_ago, fmt_bytes, fmt_opt_time, fmt_time, now, parse_duration, parse_parity, parse_size, path_display};
use anyhow::{Result, bail};
use std::path::Path;

pub fn status(ctx: &mut Ctx) -> Result<()> {
    let s = ctx.db.stats()?;
    let cfg = &ctx.archive.config;
    let db_hash_ok = crate::db::check_db_hash_file(&ctx.archive.db_path())?;
    let parity_store = super::parity::dir_size(&ctx.archive.parity_dir()).unwrap_or(0);
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "root": ctx.archive.root.display().to_string(),
                "algo": cfg.algo.name(),
                "files": s.files, "bytes": s.bytes, "by_state": s.by_state,
                "distinct_content": s.distinct_content,
                "parity_sets": s.parity_sets, "parity_sets_degraded": s.parity_sets_degraded,
                "parity_covered_files": s.parity_covered_files, "parity_bytes_covered": s.parity_bytes_covered,
                "parity_store_bytes": parity_store,
                "never_verified": s.never_verified, "oldest_verified": s.oldest_verified,
                "events": s.events, "db_hash_ok": db_hash_ok,
            })
        );
        return Ok(());
    }
    println!("archive:   {}", ctx.archive.root.display());
    println!(
        "config:    algo={} block_size={} parity={}% stripe={} parity_default={}",
        cfg.algo,
        fmt_bytes(cfg.block_size as u64),
        cfg.parity_percent(),
        fmt_bytes(cfg.stripe_size),
        cfg.parity_default.name()
    );
    println!("files:     {} ({}) — {} distinct contents", s.files, fmt_bytes(s.bytes), s.distinct_content);
    let states: Vec<String> = s.by_state.iter().map(|(k, v)| format!("{v} {k}")).collect();
    println!("states:    {}", if states.is_empty() { "-".into() } else { states.join(", ") });
    println!(
        "parity:    {} files covered ({}) in {} set(s){}, parity store {}",
        s.parity_covered_files,
        fmt_bytes(s.parity_bytes_covered),
        s.parity_sets,
        if s.parity_sets_degraded > 0 {
            format!(" — {} DEGRADED (run `meticulous scan` to rebuild)", s.parity_sets_degraded)
        } else {
            String::new()
        },
        fmt_bytes(parity_store)
    );
    println!(
        "verified:  {} never verified; oldest verification {}",
        s.never_verified,
        s.oldest_verified.map(|t| format!("{} ({})", fmt_time(t), fmt_ago(t))).unwrap_or_else(|| "n/a".into())
    );
    println!(
        "database:  {} events; file hash {}",
        s.events,
        match db_hash_ok {
            Some(true) => "ok",
            Some(false) => "MISMATCH (database changed outside meticulous or is damaged; run fsck)",
            None => "not recorded",
        }
    );
    let bad: u64 = s.by_state.iter().filter(|(k, _)| k != "ok").map(|(_, v)| v).sum();
    if bad > 0 || db_hash_ok == Some(false) || s.parity_sets_degraded > 0 {
        ctx.problems = true;
    }
    Ok(())
}

pub fn ls(ctx: &mut Ctx, args: &LsArgs) -> Result<()> {
    let rels = ctx.rel_paths(&args.paths)?;
    let rows = ctx.db.files_under_any(&rels)?;
    let live = ctx.db.live_membership_map()?;
    for r in rows {
        if let Some(st) = args.state
            && r.state != st {
                continue;
            }
        let has = live.contains_key(&r.content_hash);
        if args.parity && !has || args.no_parity && has {
            continue;
        }
        if ctx.json {
            println!(
                "{}",
                serde_json::json!({"path": path_display(&r.path), "state": r.state.name(), "size": r.size,
                    "hash": format!("{}:{}", ctx.archive.config.algo, hex::encode(&r.content_hash)), "parity": has,
                    "last_verified_at": r.last_verified_at})
            );
        } else if args.long {
            println!(
                "{:<13} {:>10} {} {} {}",
                r.state,
                fmt_bytes(r.size),
                if has { "P" } else { "-" },
                hex::encode(&r.content_hash),
                path_display(&r.path)
            );
        } else {
            println!("{:<13} {:>10} {} {}", r.state, fmt_bytes(r.size), if has { "P" } else { "-" }, path_display(&r.path));
        }
    }
    Ok(())
}

pub fn show(ctx: &mut Ctx, path: &Path) -> Result<()> {
    let rel = ctx.rel(path)?;
    let Some(r) = ctx.db.get_file(&rel)? else {
        bail!("{} is not in the index", path_display(&rel));
    };
    let content = ctx.db.get_content(&r.content_hash)?;
    let mut resolver = Resolver::new(ctx.db.marks()?, ctx.archive.config.parity_default);
    let (mode, by) = resolver.explain_file(&rel);
    // Live parity membership (if any) and the geometry needed to judge it.
    let membership = ctx.db.memberships_of(&r.content_hash)?.into_iter().find(|m| !m.dead);
    let set_info = match &membership {
        Some(m) => ctx.db.get_parity_set(&m.set_id)?.map(|s| (m.clone(), s)),
        None => None,
    };
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "path": path_display(&rel), "state": r.state.name(), "size": r.size, "mtime_ns": r.mtime_ns,
                "hash": format!("{}:{}", content.as_ref().map(|c| c.algo.name()).unwrap_or("?"), hex::encode(&r.content_hash)),
                "added_at": r.added_at, "updated_at": r.updated_at, "last_verified_at": r.last_verified_at,
                "parity_mode": mode.name(), "parity_mode_from": path_display(&by),
                "has_parity": membership.is_some(),
                "parity_set": membership.as_ref().map(|m| hex::encode(&m.set_id)),
            })
        );
        return Ok(());
    }
    println!("path:          {}", path_display(&rel));
    println!("state:         {}", r.state);
    println!("size:          {} ({} bytes)", fmt_bytes(r.size), r.size);
    println!("mtime:         {}", fmt_time(r.mtime_ns / 1_000_000_000));
    if let Some(c) = &content {
        println!("hash:          {}:{}", c.algo, hex::encode(&r.content_hash));
        if c.algo == crate::hash::Algo::Fletcher4 {
            println!("  (zdb form):  {}", crate::hash::Digest::new(c.algo, r.content_hash.clone()).zfs_format());
        }
    }
    println!("added:         {}", fmt_time(r.added_at));
    println!("updated:       {}", fmt_time(r.updated_at));
    println!("last verified: {}", fmt_opt_time(r.last_verified_at));
    let dupes = ctx.db.files_by_content(&r.content_hash)?;
    if dupes.len() > 1 {
        println!("duplicates:    {}", dupes.iter().filter(|d| d.path != rel).map(|d| path_display(&d.path)).collect::<Vec<_>>().join(", "));
    }
    println!(
        "parity rule:   {} (from {})",
        mode.name(),
        if by.as_os_str().is_empty() {
            if resolver.marks().contains_key(Path::new("")) { "<root> mark".to_string() } else { "default".to_string() }
        } else {
            format!("mark on {}", path_display(&by))
        }
    );
    match set_info {
        Some((m, set)) => {
            let members = ctx.db.set_members(&set.id)?;
            let sc_path = mts::sidecar_path(&ctx.archive.parity_dir(), &set.id);
            println!(
                "parity:        set {} member {}/{} ({})",
                hex::encode(&set.id[..8.min(set.id.len())]),
                m.ord + 1,
                set.n_members,
                if sc_path.is_file() { sc_path.display().to_string() } else { "SIDECAR MISSING — run fsck".to_string() }
            );
            match setops::layout_from_rows(&set, &members) {
                Ok(layout) => {
                    let dead: u64 = members.iter().filter(|x| x.dead).map(|x| x.n_blocks).sum();
                    println!(
                        "  set layout:  block {} × {} blocks over {} member(s) ({} data), {} stripe(s), {} parity block(s) ({}), floor {}/stripe{}",
                        fmt_bytes(layout.block_size as u64),
                        layout.n_blocks(),
                        set.n_members,
                        fmt_bytes(set.data_bytes),
                        layout.n_stripes(),
                        layout.parity_blocks(),
                        fmt_bytes(layout.parity_bytes()),
                        layout.stripe_parity_blocks(0),
                        if dead > 0 { format!("; {dead} block(s) DEAD (margin reduced until rebuild)") } else { String::new() }
                    );
                    println!(
                        "  this file:   {} block(s); loss-protected: {}",
                        m.n_blocks,
                        if setops::loss_protected(&layout, &members, m.ord as usize) {
                            "yes (recoverable from the set even if the whole file is lost)"
                        } else {
                            "NO (too large for the set's margin; scattered damage is still repairable)"
                        }
                    );
                }
                Err(e) => println!("  set layout:  INCONSISTENT: {e:#}"),
            }
            if sc_path.is_file() {
                match mts::Reader::open(&sc_path) {
                    Ok(sc) => println!("  block table: {}", if sc.table_ok() { "ok" } else { "DAMAGED" }),
                    Err(e) => println!("  sidecar:     UNREADABLE: {e:#}"),
                }
            }
        }
        None => println!("parity:        no"),
    }
    let ev = ctx.db.events(Some(&rel), None, 20)?;
    if !ev.is_empty() {
        println!("history:");
        for e in ev.iter().rev() {
            println!("  {}  {:<10} {}", fmt_time(e.ts), e.kind, e.detail.as_deref().unwrap_or(""));
        }
    }
    Ok(())
}

pub fn history(ctx: &mut Ctx, args: &HistoryArgs) -> Result<()> {
    let rel = args.path.as_ref().map(|p| ctx.rel(p)).transpose()?;
    let since = args.since.as_deref().map(parse_duration).transpose()?.map(|d| now() - d.as_secs() as i64);
    let ev = ctx.db.events(rel.as_deref(), since, args.limit)?;
    for e in ev.iter().rev() {
        if ctx.json {
            println!("{}", serde_json::json!({"ts": e.ts, "kind": e.kind, "path": path_display(&e.path), "detail": e.detail}));
        } else {
            println!("{}  {:<10} {}  {}", fmt_time(e.ts), e.kind, path_display(&e.path), e.detail.as_deref().unwrap_or(""));
        }
    }
    if ev.is_empty() && !ctx.json {
        println!("no events");
    }
    Ok(())
}

pub fn config(ctx: &mut Ctx, args: &ConfigArgs) -> Result<()> {
    let cfg = &mut ctx.archive.config;
    let show = |k: &str, cfg: &crate::config::Config| -> Option<String> {
        Some(match k {
            "algo" => cfg.algo.to_string(),
            "block_size" => cfg.block_size.to_string(),
            "stripe_size" => cfg.stripe_size.to_string(),
            "parity" | "parity_ppm" => format!("{}%", cfg.parity_percent()),
            "parity_min_bytes" => cfg.parity_min_bytes.to_string(),
            "parity_default" => cfg.parity_default.name().to_string(),
            "exclude" => cfg.exclude.join(","),
            "jobs" => cfg.jobs.to_string(),
            _ => return None,
        })
    };
    let keys = ["algo", "block_size", "stripe_size", "parity", "parity_min_bytes", "parity_default", "exclude", "jobs"];
    match (&args.key, &args.value) {
        (None, _) => {
            for k in keys {
                println!("{k} = {}", show(k, cfg).unwrap());
            }
        }
        (Some(k), None) => match show(k, cfg) {
            Some(v) => println!("{v}"),
            None => bail!("unknown config key '{k}' (one of {})", keys.join(", ")),
        },
        (Some(k), Some(v)) => {
            match k.as_str() {
                "algo" => {
                    let a: crate::hash::Algo = v.parse()?;
                    if ctx.db.stats()?.files > 0 && a != cfg.algo {
                        bail!("cannot change the algorithm of a non-empty archive (existing hashes are {})", cfg.algo);
                    }
                    cfg.algo = a;
                }
                "block_size" => cfg.block_size = parse_size(v)? as u32,
                "stripe_size" => cfg.stripe_size = parse_size(v)?,
                "parity" | "parity_ppm" => cfg.parity_ppm = parse_parity(v)?,
                "parity_min_bytes" => cfg.parity_min_bytes = parse_size(v)?,
                "parity_default" => cfg.parity_default = ParityMode::parse(v)?,
                "exclude" => cfg.exclude = v.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect(),
                "jobs" => cfg.jobs = v.parse()?,
                _ => bail!("unknown config key '{k}'"),
            }
            cfg.validate()?;
            let p = ctx.archive.config_path();
            ctx.archive.config.save(&p)?;
            println!("{k} = {}", show(k, &ctx.archive.config).unwrap());
            if matches!(k.as_str(), "block_size" | "stripe_size" | "parity" | "parity_ppm" | "parity_min_bytes") {
                println!("note: applies to parity sets generated from now on; existing sets keep their layout");
            }
        }
    }
    let _ = State::Ok;
    Ok(())
}
