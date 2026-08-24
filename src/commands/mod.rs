pub mod check;
pub mod fsck;
pub mod info;
pub mod init;
pub mod manifest;
pub mod parity;
pub mod rm;
pub mod scan;
pub mod setops;

use crate::cli::{Cli, Command};
use crate::config::Archive;
use crate::db::Db;
use crate::util::Assume;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Exit code when corruption / problems were found (vs 1 for usage/runtime errors).
pub const EXIT_PROBLEMS: i32 = 2;

pub struct Ctx {
    pub archive: Archive,
    pub db: Db,
    pub assume: Assume,
    pub quiet: bool,
    pub json: bool,
    /// Set by commands that found problems; becomes exit code 2.
    pub problems: bool,
}

impl Ctx {
    /// Convert CLI path args to archive-relative paths (must not be inside _meticulous/).
    pub fn rel_paths(&self, args: &[PathBuf]) -> Result<Vec<PathBuf>> {
        args.iter().map(|p| self.rel(p)).collect()
    }
    pub fn rel(&self, p: &Path) -> Result<PathBuf> {
        let rel = crate::util::to_relative(&self.archive.root, p)?;
        if rel.components().next().is_some_and(|c| c.as_os_str() == crate::config::DIR_NAME) {
            anyhow::bail!("{} is inside {}/ which is never indexed", rel.display(), crate::config::DIR_NAME);
        }
        Ok(rel)
    }
    /// Like `rel_paths`, but every path must exist on disk.
    pub fn rel_paths_existing(&self, args: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let rels = self.rel_paths(args)?;
        for r in &rels {
            if !self.archive.abs(r).exists() {
                anyhow::bail!("{} does not exist", crate::util::path_display(r));
            }
        }
        Ok(rels)
    }
    /// Report an EIO-style read failure with a ZFS-aware hint.
    pub fn read_error(&self, rel: &Path, msg: &str) {
        let hint = if crate::zfs::on_zfs(&self.archive.root) {
            "ZFS rejected a block of this file (checksum error it could not heal): the file is damaged ON DISK. See `zpool status -v`; restore it from a backup/snapshot, then re-run."
        } else {
            "the disk returned an I/O error while reading this file; it is likely damaged on disk."
        };
        eprintln!("READ ERROR: {}: {msg}\n  {hint}", crate::util::path_display(rel));
    }
    pub fn say(&self, msg: impl AsRef<str>) {
        if !self.quiet {
            println!("{}", msg.as_ref());
        }
    }
}

pub fn run(cli: Cli) -> Result<i32> {
    let assume = if cli.yes {
        Assume::Yes
    } else if cli.no {
        Assume::No
    } else {
        Assume::Ask
    };
    if let Command::Init(args) = &cli.cmd {
        init::run(args, cli.root.as_deref(), cli.quiet)?;
        return Ok(0);
    }
    let archive = Archive::discover(cli.root.as_deref())?;
    // One meticulous process at a time per archive (scan/check/fsck all write).
    let lock_file = std::fs::File::create(archive.lock_path())
        .with_context(|| format!("creating lock file {}", archive.lock_path().display()))?;
    let mut lock = fd_lock::RwLock::new(lock_file);
    if lock.try_write().is_err() {
        eprintln!("another meticulous process is running on this archive; waiting for it to finish...");
    }
    let _guard = lock.write().context("waiting for archive lock")?;
    // We hold the archive lock, so anything left in parity/tmp is from a dead run.
    if let Ok(rd) = std::fs::read_dir(archive.parity_dir().join("tmp")) {
        for e in rd.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
    let db = Db::open(&archive.db_path())?;
    if db.hash_ok() == Some(false) {
        eprintln!(
            "warning: {} does not match the hash meticulous last recorded for it (damaged, or modified externally). Read-only commands still work; run `meticulous fsck`.",
            archive.db_path().display()
        );
    }
    let mut ctx = Ctx { archive, db, assume, quiet: cli.quiet, json: cli.json, problems: false };
    let result = match cli.cmd {
        Command::Init(_) => unreachable!(),
        Command::Check(a) => check::check(&mut ctx, &a),
        Command::Scan(a) => scan::scan(&mut ctx, &a),
        Command::Accept(a) => scan::accept(&mut ctx, &a),
        Command::Repair(a) => check::repair(&mut ctx, &a),
        Command::Rm(a) => rm::rm(&mut ctx, &a),
        Command::Parity(a) => parity::run(&mut ctx, &a),
        Command::Status => info::status(&mut ctx),
        Command::Ls(a) => info::ls(&mut ctx, &a),
        Command::Show { path } => info::show(&mut ctx, &path),
        Command::History(a) => info::history(&mut ctx, &a),
        Command::Export(a) => manifest::export(&mut ctx, &a),
        Command::Import(a) => manifest::import(&mut ctx, &a),
        Command::Fsck(a) => fsck::run(&mut ctx, &a),
        Command::Config(a) => info::config(&mut ctx, &a),
    };
    let problems = ctx.problems;
    // Never leave a transaction open: on error, roll back whatever was not committed.
    ctx.db.rollback_open();
    let dirty = ctx.db.is_dirty();
    // Close cleanly; if the DB changed, refresh the manifests (from committed state) + hash file.
    let finish = (|| -> Result<()> {
        if dirty {
            manifest::write_sidecar_files(&ctx.archive, &ctx.db)?;
        }
        ctx.db.finish()
    })();
    result?;
    finish?;
    Ok(if problems { EXIT_PROBLEMS } else { 0 })
}
