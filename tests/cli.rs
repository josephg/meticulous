//! End-to-end tests driving the binary against temporary archives.

use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};

fn bin(root: &Path) -> Command {
    let mut c = Command::cargo_bin("checksummer").unwrap();
    c.current_dir(root);
    c
}

fn pseudo(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761).wrapping_add(7);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

/// Flip bytes at the given offsets without touching mtime.
fn damage(path: &Path, offsets: &[u64]) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let meta = fs::metadata(path).unwrap();
    let mtime = meta.modified().unwrap();
    {
        let mut f = fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        for &o in offsets {
            f.seek(SeekFrom::Start(o)).unwrap();
            let mut b = [0u8; 1];
            f.read_exact(&mut b).unwrap();
            f.seek(SeekFrom::Start(o)).unwrap();
            f.write_all(&[b[0] ^ 0x5a]).unwrap();
        }
    }
    fs::File::options().write(true).open(path).unwrap().set_modified(mtime).unwrap();
}

fn truncate_keep_mtime(path: &Path, len: u64) {
    let mtime = fs::metadata(path).unwrap().modified().unwrap();
    let f = fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_len(len).unwrap();
    f.set_modified(mtime).unwrap();
}

struct Arch {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

fn setup() -> Arch {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("archive");
    fs::create_dir_all(root.join("foo/bar")).unwrap();
    fs::create_dir_all(root.join("foo/a/b")).unwrap();
    fs::create_dir_all(root.join("other")).unwrap();
    fs::write(root.join("foo/big.bin"), pseudo(3_000_000, 1)).unwrap();
    fs::write(root.join("foo/bar/zot.bin"), pseudo(200_000, 2)).unwrap();
    fs::write(root.join("foo/a/b/c.bin"), pseudo(150_000, 3)).unwrap();
    fs::write(root.join("other/small.txt"), b"hello world\n").unwrap();
    fs::write(root.join("other/empty"), b"").unwrap();
    bin(&root).args(["init", "."]).assert().success();
    bin(&root).args(["parity", "include", "foo"]).assert().success();
    bin(&root).args(["parity", "exclude", "foo/bar"]).assert().success();
    Arch { _tmp: tmp, root }
}

fn ls(root: &Path) -> String {
    let out = bin(root).args(["ls", "--json"]).output().unwrap();
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn scan_check_repair_cycle() {
    let a = setup();
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success().stdout(predicates::str::contains("5 added"));
    // parity inheritance: foo/* and foo/a/b/c yes; foo/bar/zot no; other no
    let l = ls(root);
    let line = |p: &str| l.lines().find(|x| x.contains(&format!("\"path\":\"{p}\""))).unwrap().to_string();
    assert!(line("foo/big.bin").contains("\"parity\":true"));
    assert!(line("foo/a/b/c.bin").contains("\"parity\":true"));
    assert!(line("foo/bar/zot.bin").contains("\"parity\":false"));
    assert!(line("other/small.txt").contains("\"parity\":false"));
    assert!(root.join(".checksummer/MANIFEST.txt").is_file());
    assert!(root.join(".checksummer/index.sqlite.bak").is_file());

    // clean check passes
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("5 ok"));

    // damage 3 blocks of big.bin (64 KiB blocks) and 1 of zot (no parity)
    damage(&root.join("foo/big.bin"), &[10, 65536 * 5 + 3, 65536 * 40]);
    damage(&root.join("foo/bar/zot.bin"), &[999]);
    bin(root)
        .arg("check")
        .assert()
        .code(2)
        .stdout(predicates::str::contains("CORRUPT: foo/big.bin"))
        .stdout(predicates::str::contains("CORRUPT: foo/bar/zot.bin"));
    bin(root).args(["repair", "foo"]).assert().code(2).stdout(predicates::str::contains("repaired: foo/big.bin"));
    assert_eq!(fs::read(root.join("foo/big.bin")).unwrap(), pseudo(3_000_000, 1));
    bin(root).args(["ls", "--state", "unrecoverable"]).assert().success().stdout(predicates::str::contains("foo/bar/zot.bin"));

    // truncation is repairable too
    truncate_keep_mtime(&root.join("foo/big.bin"), 2_999_000);
    bin(root).args(["check", "foo/big.bin", "--repair"]).assert().success().stdout(predicates::str::contains("1 repaired"));
    assert_eq!(fs::read(root.join("foo/big.bin")).unwrap(), pseudo(3_000_000, 1));

    // too much damage -> unrecoverable
    let offs: Vec<u64> = (0..8).map(|i| i * 65536 + 100).collect();
    damage(&root.join("foo/big.bin"), &offs);
    bin(root).args(["check", "foo"]).assert().code(2).stdout(predicates::str::contains("NOT repairable"));
    bin(root).args(["repair", "foo/big.bin"]).assert().code(2);
}

#[test]
fn scan_detects_modified_moved_removed() {
    let a = setup();
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();

    // legit edit (mtime changes)
    fs::write(root.join("other/small.txt"), b"hello world, edited\n").unwrap();
    let t = fs::metadata(root.join("other/small.txt")).unwrap().modified().unwrap() + std::time::Duration::from_secs(5);
    fs::File::options().write(true).open(root.join("other/small.txt")).unwrap().set_modified(t).unwrap();
    // move
    fs::rename(root.join("foo/a/b/c.bin"), root.join("other/c-moved.bin")).unwrap();
    // remove
    fs::remove_file(root.join("other/empty")).unwrap();

    // --no: keep removed as missing
    bin(root)
        .args(["scan", "--no"])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("modified: other/small.txt"))
        .stdout(predicates::str::contains("moved: foo/a/b/c.bin -> other/c-moved.bin"))
        .stdout(predicates::str::contains("other/empty"));
    bin(root).args(["ls", "--state", "missing"]).assert().success().stdout(predicates::str::contains("other/empty"));
    // --yes: drop it
    bin(root).args(["scan", "--yes"]).assert().success().stdout(predicates::str::contains("1 removed"));
    bin(root).args(["ls", "--state", "missing"]).assert().success().stdout(predicates::str::is_empty());
    // history has it all
    bin(root)
        .arg("history")
        .assert()
        .success()
        .stdout(predicates::str::contains("moved"))
        .stdout(predicates::str::contains("removed"))
        .stdout(predicates::str::contains("modified"));

    // bit rot with unchanged mtime found by scan when it re-reads (size change)
    truncate_keep_mtime(&root.join("foo/big.bin"), 2_000_000);
    bin(root).args(["scan", "-y"]).assert().code(2).stdout(predicates::str::contains("CORRUPT: foo/big.bin"));
}

#[test]
fn parity_sync_and_prune_and_fsck() {
    let a = setup();
    let root = &a.root;
    bin(root).args(["scan", "-y", "--no-parity"]).assert().success();
    bin(root).args(["parity", "list"]).assert().success().stdout(predicates::str::contains("2 files"));
    bin(root).args(["parity", "sync"]).assert().success().stdout(predicates::str::contains("2 generated"));
    bin(root).args(["parity", "exclude", "foo"]).assert().success();
    bin(root).args(["parity", "sync", "--prune"]).assert().success().stdout(predicates::str::contains("2 pruned"));
    bin(root).args(["parity", "unmark", "foo"]).assert().success();
    bin(root).args(["parity", "sync"]).assert().success().stdout(predicates::str::contains("0 generated"));
    bin(root).args(["fsck", "--deep"]).assert().success().stdout(predicates::str::contains("fsck: ok"));

    // damage a sidecar -> fsck --deep notices; --fix removes it; sync regenerates
    bin(root).args(["parity", "include", "foo"]).assert().success();
    bin(root).args(["parity", "sync"]).assert().success();
    let sc = walkdir::WalkDir::new(root.join(".checksummer/parity"))
        .into_iter()
        .flatten()
        .find(|e| e.file_type().is_file())
        .unwrap()
        .into_path();
    let len = fs::metadata(&sc).unwrap().len();
    damage(&sc, &[len - 3]);
    bin(root).args(["fsck", "--deep"]).assert().code(2).stdout(predicates::str::contains("damaged sidecar"));
    bin(root).args(["fsck", "--deep", "--fix"]).assert().success();
    bin(root).args(["parity", "sync"]).assert().success().stdout(predicates::str::contains("1 generated"));
    bin(root).args(["fsck", "--deep"]).assert().success();
}

#[test]
fn export_import_and_rebuild() {
    let a = setup();
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    let m = fs::read_to_string(root.join(".checksummer/MANIFEST.txt")).unwrap();
    assert_eq!(m.lines().count(), 5);
    // manifest line is "<64 hex>  <path>"
    let first = m.lines().next().unwrap();
    assert_eq!(first.split("  ").next().unwrap().len(), 64);

    // import our own manifest back: all match
    bin(root)
        .args(["import", ".checksummer/MANIFEST.txt", "--relative-to", "."])
        .assert()
        .success()
        .stdout(predicates::str::contains("5 match, 0 MISMATCH"));

    // md5 list with one wrong entry
    use md5::Digest as _;
    let md5 = format!(
        "{}  other/small.txt\n{}  foo/big.bin\n",
        hex::encode(md5::Md5::digest(b"hello world\n")),
        hex::encode(md5::Md5::digest(b"wrong"))
    );
    fs::write(root.join("legacy.md5"), md5).unwrap();
    bin(root)
        .args(["import", "legacy.md5"])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("1 match, 1 MISMATCH"));

    // rebuild the db from the manifest
    let marks_before = fs::read_to_string(root.join(".checksummer/PARITY_MARKS.txt")).unwrap();
    fs::remove_file(root.join("legacy.md5")).unwrap();
    bin(root).args(["fsck", "--rebuild-db"]).assert().success();
    bin(root).args(["scan", "-y"]).assert().success().stdout(predicates::str::contains("5 unchanged"));
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("5 ok"));
    let marks_after = fs::read_to_string(root.join(".checksummer/PARITY_MARKS.txt")).unwrap();
    assert_eq!(marks_before, marks_after);
    bin(root).arg("status").assert().success().stdout(predicates::str::contains("5 ok"));
}

#[test]
fn paths_relative_to_root_from_subdir() {
    let a = setup();
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    // run from a subdirectory with a cwd-relative path
    bin(&root.join("foo"))
        .args(["show", "big.bin"])
        .assert()
        .success()
        .stdout(predicates::str::contains("path:          foo/big.bin"));
    bin(&root.join("foo/a")).args(["check", "b"]).assert().success().stdout(predicates::str::contains("1 ok"));
}
