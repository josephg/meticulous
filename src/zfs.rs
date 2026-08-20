//! Minimal ZFS awareness: detect the dataset (and recordsize) holding a path.
//!
//! ZFS verifies every block's checksum on read, so reading a file in full (which
//! `scan`/`check` do) is already a ZFS integrity check of that file: a block ZFS
//! cannot heal makes the read fail with EIO and the file appears in
//! `zpool status -v`. (ZFS per-record checksum import/compare was removed;
//! see git history / the plan if it is ever wanted again.)

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Dataset {
    pub name: String,
    pub mountpoint: PathBuf,
    pub recordsize: u32,
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// All mounted datasets (empty if zfs is unavailable).
pub fn datasets() -> Vec<Dataset> {
    let Some(out) = run("zfs", &["list", "-H", "-p", "-o", "name,mountpoint,recordsize", "-t", "filesystem"]) else {
        return vec![];
    };
    out.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 3 || !f[1].starts_with('/') {
                return None;
            }
            Some(Dataset { name: f[0].to_string(), mountpoint: PathBuf::from(f[1]), recordsize: f[2].parse().unwrap_or(131072) })
        })
        .collect()
}

/// Longest-mountpoint match.
pub fn dataset_for<'a>(ds: &'a [Dataset], abs: &Path) -> Option<&'a Dataset> {
    ds.iter().filter(|d| abs.starts_with(&d.mountpoint)).max_by_key(|d| d.mountpoint.as_os_str().len())
}

/// Recordsize of the dataset holding `path`, if on ZFS.
pub fn recordsize_for(path: &Path) -> Option<u32> {
    let ds = datasets();
    dataset_for(&ds, path).map(|d| d.recordsize)
}

/// Is `path` on a ZFS dataset?
pub fn on_zfs(path: &Path) -> bool {
    let ds = datasets();
    dataset_for(&ds, path).is_some()
}
