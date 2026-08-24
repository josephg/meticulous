use crate::cli::InitArgs;
use crate::config::{Archive, Config, DIR_NAME};
use crate::db::Db;
use crate::util::{parse_parity, parse_size};
use anyhow::{Context, Result, bail};
use std::path::Path;

pub fn run(args: &InitArgs, root_flag: Option<&Path>, quiet: bool) -> Result<()> {
    let dir = args
        .dir
        .clone()
        .or_else(|| root_flag.map(|p| p.to_path_buf()))
        .unwrap_or(std::env::current_dir()?);
    std::fs::create_dir_all(&dir)?;
    let root = std::fs::canonicalize(&dir)?;
    let csdir = root.join(DIR_NAME);
    if csdir.join(crate::config::CONFIG_FILE).exists() {
        bail!("{} is already a meticulous archive", root.display());
    }
    let block_size = parse_size(&args.block_size)?;
    if block_size > u32::MAX as u64 {
        bail!("block size too large");
    }
    let mut config = Config {
        algo: args.algo,
        block_size: block_size as u32,
        stripe_size: parse_size(&args.stripe_size)?,
        parity_ppm: parse_parity(&args.parity)?,
        parity_min_bytes: 0,
        parity_default: args.parity_default,
        exclude: args.exclude.clone(),
        jobs: args.jobs,
    };
    // On ZFS: align blocks with the dataset recordsize when it is larger than
    // the requested block size, and set the per-stripe parity floor to one
    // record so a single dead record is always within the repair margin
    // (per-set block sizes can shrink below the recordsize for small files).
    if let Some(rs) = crate::zfs::recordsize_for(&root) {
        if rs > config.block_size && rs % 64 == 0 && args.block_size == "64KiB" {
            config.block_size = rs;
            if !quiet {
                println!("note: {} is on ZFS with recordsize {}; using that as block size", root.display(), rs);
            }
        }
        config.parity_min_bytes = (rs as u64).min(config.stripe_size / 4);
        if !quiet {
            println!("note: minimum parity per stripe set to {} (one ZFS record)", crate::util::fmt_bytes(config.parity_min_bytes));
        }
    }
    config.validate()?;
    std::fs::create_dir_all(&csdir).with_context(|| format!("creating {}", csdir.display()))?;
    std::fs::create_dir_all(csdir.join(crate::config::PARITY_DIR))?;
    let archive = Archive { root: root.clone(), config };
    archive.config.save(&archive.config_path())?;
    let db = Db::create(&archive.db_path())?;
    db.finish()?;
    std::fs::write(csdir.join("FORMAT.md"), include_str!("../../FORMAT.md"))?;
    if !quiet {
        println!("initialised meticulous archive at {}", root.display());
        println!(
            "  algo={} block_size={} parity={}% parity_default={}",
            archive.config.algo,
            crate::util::fmt_bytes(archive.config.block_size as u64),
            archive.config.parity_percent(),
            archive.config.parity_default.name()
        );
        println!("next: `meticulous parity include <dir>` to choose what gets parity, then `meticulous scan`");
    }
    Ok(())
}
