//! Regression tests for the findings in REDTEAM.md.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

fn bin(root: &Path) -> Command {
    let mut c = Command::cargo_bin("meticulous").unwrap();
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

fn flip(path: &Path, offsets: &[u64], keep_mtime: bool) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mtime = fs::metadata(path).unwrap().modified().unwrap();
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
    let f = fs::File::options().write(true).open(path).unwrap();
    if keep_mtime {
        f.set_modified(mtime).unwrap();
    } else {
        f.set_modified(mtime + Duration::from_secs(7)).unwrap();
    }
}

fn bump_mtime(path: &Path) {
    let f = fs::File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() + Duration::from_secs(5)).unwrap();
}

fn state_of(root: &Path, rel: &str) -> String {
    let out = bin(root).args(["ls", "--json"]).output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    let line = s.lines().find(|l| l.contains(&format!("\"path\":\"{rel}\""))).unwrap_or_else(|| panic!("{rel} not in ls: {s}"));
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    v["state"].as_str().unwrap().to_string()
}

fn sidecars(root: &Path) -> usize {
    walkdir::WalkDir::new(root.join("_meticulous/parity"))
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "mtp"))
        .count()
}

struct Arch {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

/// Small-block archive so stripes/blocks are easy to reason about:
/// block 64, stripe 4096 (64 blocks), 5% -> 4 parity blocks per full stripe.
fn setup(parity_default: &str) -> Arch {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("archive");
    fs::create_dir_all(root.join("d/sub")).unwrap();
    fs::write(root.join("d/f"), pseudo(100_000, 11)).unwrap(); // 1563 blocks, 25 stripes
    fs::write(root.join("d/sub/g"), pseudo(20_000, 12)).unwrap();
    fs::write(root.join("d/plain"), b"no parity here\n").unwrap();
    bin(&root)
        .args(["init", ".", "--block-size", "64", "--stripe-size", "4096", "--parity-default", parity_default])
        .assert()
        .success();
    Arch { _tmp: tmp, root }
}

// C1 / H1
#[test]
fn repair_refuses_edited_files_and_keeps_healthy_state() {
    let a = setup("include");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    // edit d/f (mtime changes) -> check says modified; repair must refuse and not touch bytes
    flip(&root.join("d/f"), &[10, 11, 12, 13], false);
    let edited = fs::read(root.join("d/f")).unwrap();
    bin(root).args(["check", "d/f"]).assert().code(2).stdout(predicates::str::contains("modified"));
    bin(root).args(["repair", "d/f"]).assert().code(2).stderr(predicates::str::contains("refusing to repair"));
    assert_eq!(fs::read(root.join("d/f")).unwrap(), edited);
    // H1: repair on a healthy parity-less file leaves it ok
    let a2 = setup("exclude");
    let root2 = &a2.root;
    bin(root2).args(["scan", "-y"]).assert().success();
    bin(root2).args(["repair", "d/plain"]).assert().code(2);
    assert_eq!(state_of(root2, "d/plain"), "ok");
}

// C6: timestamp reset + a little corruption is suspected corruption, not an edit
#[test]
fn mtime_reset_with_few_bad_blocks_is_not_accepted() {
    let a = setup("include");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    let original = fs::read(root.join("d/f")).unwrap();
    let n_sidecars = sidecars(root);
    // "cp without -p" style: bytes flipped in 2 blocks AND mtime changed
    flip(&root.join("d/f"), &[100, 5000], false);
    // plus a pure touch on g (content identical)
    bump_mtime(&root.join("d/sub/g"));
    bin(root)
        .args(["scan", "-y"])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("SUSPECTED CORRUPTION: d/f"))
        .stdout(predicates::str::contains("modified: d/sub/g (content unchanged)"));
    assert_eq!(state_of(root, "d/f"), "corrupt");
    assert_eq!(state_of(root, "d/sub/g"), "ok");
    assert_eq!(sidecars(root), n_sidecars, "old parity must be kept");
    // repair restores the recorded content (scan recorded the new mtime for us)
    bin(root).args(["repair", "d/f"]).assert().success().stdout(predicates::str::contains("repaired: d/f"));
    assert_eq!(fs::read(root.join("d/f")).unwrap(), original);
    // a real edit (most blocks differ) is accepted
    fs::write(root.join("d/f"), pseudo(100_000, 99)).unwrap();
    bump_mtime(&root.join("d/f"));
    bin(root).args(["scan", "-y"]).assert().success().stdout(predicates::str::contains("modified: d/f"));
    assert_eq!(state_of(root, "d/f"), "ok");
}

// C4: unreadable directory / nonexistent path must not delete rows or sidecars
#[test]
fn unreadable_dir_is_not_a_removal() {
    let a = setup("include");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    let n = sidecars(root);
    fs::set_permissions(root.join("d/sub"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = bin(root).args(["scan", "-y"]).assert().code(2);
    out.stdout(predicates::str::contains("could not be read")).stdout(predicates::str::contains("removed").not());
    fs::set_permissions(root.join("d/sub"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(state_of(root, "d/sub/g"), "ok");
    assert_eq!(sidecars(root), n);
    // nonexistent PATH is an error, not an empty scan
    bin(root).args(["scan", "-y", "nope"]).assert().code(1).stderr(predicates::str::contains("does not exist"));
    // removing a file keeps its sidecar on disk (orphan) until fsck --fix
    fs::remove_file(root.join("d/sub/g")).unwrap();
    bin(root).args(["scan", "-y"]).assert().success().stdout(predicates::str::contains("1 removed"));
    assert_eq!(sidecars(root), n);
    bin(root).args(["fsck"]).assert().code(2).stdout(predicates::str::contains("orphan sidecar"));
    bin(root).args(["fsck", "--fix"]).assert().success();
    assert_eq!(sidecars(root), n - 1);
}

// C5: fsck --fix must keep partially damaged parity when the file itself is damaged
#[test]
fn fsck_fix_keeps_parity_needed_for_repair() {
    let a = setup("include");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    let original = fs::read(root.join("d/f")).unwrap();
    // damage the file in stripe 0 (block 3) and the sidecar in stripe 10
    flip(&root.join("d/f"), &[3 * 64 + 1], true);
    let h = hex::encode(blake3::hash(&original).as_bytes());
    let sc = root.join(format!("_meticulous/parity/{}/{}/{h}.mtp", &h[0..2], &h[2..4]));
    assert!(sc.is_file());
    // stripe area begins after header (40+2*32) + table (1563*32+32); stripe = 4*64 parity + 32 hash.
    let stripe10 = 104 + 1563 * 32 + 32 + 10 * (4 * 64 + 32) + 5;
    flip(&sc, &[stripe10], true);
    bin(root).args(["fsck", "--deep", "--fix"]).assert().code(2).stdout(predicates::str::contains("KEPT"));
    assert!(sc.exists());
    bin(root).args(["repair", "d/f"]).assert().success().stdout(predicates::str::contains("repaired: d/f"));
    assert_eq!(fs::read(root.join("d/f")).unwrap(), original);
    // now the file is intact: --fix may drop the damaged sidecar and sync regenerates it
    bin(root).args(["fsck", "--deep", "--fix"]).assert().success().stdout(predicates::str::contains("removed (file(s) intact)"));
    bin(root).args(["parity", "sync"]).assert().success().stdout(predicates::str::contains("1 generated"));
    bin(root).args(["fsck", "--deep"]).assert().success();
}

// C3 / M4 / M5 / M11: rebuild keeps metadata, handles odd names, verifies its source
#[test]
fn rebuild_db_preserves_metadata_and_odd_names() {
    let a = setup("include");
    let root = &a.root;
    fs::write(root.join("d/a\\nb"), b"backslash-n in name\n").unwrap();
    fs::write(root.join("d/real\nnewline"), b"newline in name\n").unwrap();
    use std::os::unix::ffi::OsStrExt;
    let latin1 = std::ffi::OsStr::from_bytes(b"d/caf\xe9.txt");
    fs::write(root.join(latin1), b"non utf8 name\n").unwrap();
    bin(root).args(["scan", "-y"]).assert().success();
    // edit g after the scan: rebuild must NOT make it look corrupt
    fs::write(root.join("d/sub/g"), pseudo(20_000, 5)).unwrap();
    bump_mtime(&root.join("d/sub/g"));
    bin(root).args(["fsck", "--rebuild-db"]).assert().success().stdout(predicates::str::contains("hash: ok"));
    bin(root).args(["check", "d/sub/g"]).assert().code(2).stdout(predicates::str::contains("modified: d/sub/g"));
    bin(root).args(["repair", "d/sub/g"]).assert().code(2).stderr(predicates::str::contains("refusing"));
    // names round-trip: nothing missing, scan finds nothing new
    bin(root).args(["ls", "--state", "missing"]).assert().success().stdout(predicates::str::is_empty());
    bin(root).args(["scan", "-y"]).assert().code(0).stdout(predicates::str::contains("0 added").or(predicates::str::contains("added").not()));
    // MANIFEST.txt is verifiable by sha256sum-style tools: line count matches files
    let m = fs::read(root.join("_meticulous/MANIFEST.txt")).unwrap();
    assert_eq!(m.split(|&b| b == b'\n').filter(|l| !l.is_empty()).count(), 6);
}

// H3: a damaged/modified index is detected and never overwritten or copied over .bak
#[test]
fn damaged_db_is_not_written_or_backed_up() {
    let a = setup("exclude");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    let db = root.join("_meticulous/index.sqlite");
    let good = fs::read(&db).unwrap();
    let bak_before = fs::read(root.join("_meticulous/index.sqlite.bak")).unwrap();
    // corrupt a byte deep in the file
    flip(&db, &[4096 + 100], true);
    bin(root).args(["parity", "include", "d"]).assert().code(1).stderr(predicates::str::contains("refusing to write"));
    assert_eq!(fs::read(root.join("_meticulous/index.sqlite.bak")).unwrap(), bak_before);
    bin(root).arg("fsck").assert().code(2).stdout(predicates::str::contains("database file hash: MISMATCH"));
    // restore and carry on
    fs::write(&db, good).unwrap();
    bin(root).args(["parity", "include", "d"]).assert().success();
}

// H2: parity sync skips modified files instead of calling them corrupt
#[test]
fn parity_sync_skips_modified() {
    let a = setup("exclude");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    fs::write(root.join("d/f"), pseudo(100_000, 3)).unwrap();
    bump_mtime(&root.join("d/f"));
    bin(root).args(["parity", "include", "d"]).assert().success();
    bin(root).args(["parity", "sync"]).assert().code(2).stdout(predicates::str::contains("skipped (changed since last scan"));
    assert_eq!(state_of(root, "d/f"), "ok");
}

// H4 / H5 / M2 / M6: symlinks counted, _meticulous rejected, repair temps ignored, exclude semantics
#[test]
fn walk_rules() {
    let a = setup("exclude");
    let root = &a.root;
    std::os::unix::fs::symlink("f", root.join("d/link")).unwrap();
    fs::write(root.join("d/x.mtrepair.123"), b"leftover").unwrap();
    fs::create_dir_all(root.join("d/sub/cache")).unwrap();
    fs::write(root.join("d/sub/cache/c"), b"cached").unwrap();
    fs::write(root.join("d/t.tmp"), b"tmp").unwrap();
    bin(root).args(["config", "exclude", "cache,*.tmp"]).assert().success();
    bin(root)
        .args(["scan", "-y"])
        .assert()
        .success()
        .stdout(predicates::str::contains("1 symlinks skipped"))
        .stdout(predicates::str::contains("mtrepair").not())
        .stdout(predicates::str::contains("cache/c").not())
        .stdout(predicates::str::contains("t.tmp").not());
    bin(root).args(["scan", "_meticulous/parity"]).assert().code(1).stderr(predicates::str::contains("never indexed"));
    bin(root).args(["ls", "_meticulous"]).assert().code(1);
}

// H7: import never indexes a mismatching file as ok
#[test]
fn import_mismatch_not_indexed() {
    let a = setup("exclude");
    let root = &a.root;
    fs::write(root.join("list.md5"), "00000000000000000000000000000000  d/plain\n").unwrap();
    bin(root).args(["import", "list.md5"]).assert().code(2).stdout(predicates::str::contains("left unindexed"));
    bin(root).args(["ls"]).assert().success().stdout(predicates::str::contains("d/plain").not());
}

// M1: dry-run writes nothing even in a read-only directory; grown file message
#[test]
fn dry_run_and_grown_file() {
    let a = setup("include");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    flip(&root.join("d/f"), &[70], true);
    fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o555)).unwrap();
    bin(root).args(["repair", "d/f", "--dry-run"]).assert().success().stdout(predicates::str::contains("would repair: d/f"));
    fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o755)).unwrap();
    bin(root).args(["repair", "d/f"]).assert().success();
    // append with preserved mtime
    {
        use std::io::Write;
        let mtime = fs::metadata(root.join("d/f")).unwrap().modified().unwrap();
        let mut f = fs::OpenOptions::new().append(true).open(root.join("d/f")).unwrap();
        f.write_all(b"junk").unwrap();
        f.set_modified(mtime).unwrap();
    }
    bin(root).args(["check", "d/f", "--repair"]).assert().success().stdout(predicates::str::contains("4 extra bytes appended"));
    assert_eq!(fs::read(root.join("d/f")).unwrap(), pseudo(100_000, 11));
}

// M7: config validation of block/stripe sizes
#[test]
fn config_validation() {
    let a = setup("exclude");
    let root = &a.root;
    bin(root).args(["config", "block_size", "128MiB"]).assert().code(1);
    bin(root).args(["config", "block_size", "1MiB"]).assert().code(1).stderr(predicates::str::contains("stripe_size"));
    bin(root).args(["config", "stripe_size", "64MiB"]).assert().success();
    bin(root).args(["config", "block_size", "1MiB"]).assert().success();
}

// check scheduling flags
#[test]
fn check_older_than_and_budget() {
    let a = setup("exclude");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    bin(root).args(["check", "--older-than", "1h"]).assert().success().stdout(predicates::str::contains("nothing to check"));
    bin(root).args(["check", "--budget", "1"]).assert().success().stdout(predicates::str::contains("checking 1 files"));
}

// Interrupted session: marker present + stale hash must be accepted and resumed, not refused.
#[test]
fn interrupted_session_resumes() {
    let a = setup("exclude");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    // Emulate: a later session committed work (DB changed) and died before refreshing the hash.
    fs::write(root.join("d/new.bin"), b"new file").unwrap();
    fs::write(root.join("_meticulous/index.sqlite.inprogress"), "123").unwrap();
    let sha = root.join("_meticulous/index.sqlite.sha256");
    let stale = fs::read_to_string(&sha).unwrap().replace('0', "1").replace('a', "b");
    fs::write(&sha, stale).unwrap();
    bin(root)
        .args(["scan", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains("previous meticulous run was interrupted"))
        .stdout(predicates::str::contains("1 added"));
    assert!(!root.join("_meticulous/index.sqlite.inprogress").exists());
    // and now everything is consistent again
    bin(root).arg("fsck").assert().success().stdout(predicates::str::contains("database file hash: ok"));
    // a genuinely foreign modification (no marker) is still refused
    fs::write(&sha, "deadbeef  index.sqlite\n").unwrap();
    bin(root).args(["parity", "include", "d"]).assert().code(1).stderr(predicates::str::contains("refusing to write"));
}

// accept: explicit override for suspected corruption / flagged files
#[test]
fn accept_records_current_content() {
    let a = setup("include");
    let root = &a.root;
    bin(root).args(["scan", "-y"]).assert().success();
    flip(&root.join("d/f"), &[100, 5000], false);
    bin(root).args(["scan", "-y"]).assert().code(2).stdout(predicates::str::contains("SUSPECTED CORRUPTION"));
    let edited = fs::read(root.join("d/f")).unwrap();
    bin(root).args(["accept", "d/f"]).assert().success().stdout(predicates::str::contains("accepted: d/f"));
    assert_eq!(state_of(root, "d/f"), "ok");
    bin(root).args(["check", "d/f"]).assert().success().stdout(predicates::str::contains("1 ok"));
    assert_eq!(fs::read(root.join("d/f")).unwrap(), edited);
    bin(root).args(["history", "d/f"]).assert().success().stdout(predicates::str::contains("accepted"));
}

// a visible ZFS snapshot dir at the root is never indexed
#[test]
fn zfs_snapshot_dir_skipped() {
    let a = setup("exclude");
    let root = &a.root;
    fs::create_dir_all(root.join(".zfs/snapshot/daily/d")).unwrap();
    fs::write(root.join(".zfs/snapshot/daily/d/f"), b"snapshot copy").unwrap();
    bin(root).args(["scan", "-y"]).assert().success().stdout(predicates::str::contains(".zfs").not());
}
