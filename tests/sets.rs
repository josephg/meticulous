//! Integration tests for the parity-set scenarios in the design plan:
//! whole-file restore, `rm` (rebuild-then-delete), rebuild eligibility,
//! mass-rename convergence, underfull merging, orphan sweeping, rebuild-db.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

fn flip_keep_mtime(path: &Path, offsets: &[u64]) {
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
    fs::File::options().write(true).open(path).unwrap().set_modified(mtime).unwrap();
}

fn sidecars(root: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = walkdir::WalkDir::new(root.join("_meticulous/parity"))
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "mts"))
        .map(|e| e.into_path())
        .collect();
    v.sort();
    v
}

struct Arch {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

/// `n` 1000-byte files under data/, 64-byte blocks, 32 KiB packing target,
/// 5% parity, everything covered. The underfull boost (5% of 32 KiB) makes
/// any single 1000-byte file recoverable after total loss.
fn setup(n: usize) -> Arch {
    setup_with(n, "5%")
}

fn setup_with(n: usize, parity: &str) -> Arch {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("archive");
    fs::create_dir_all(root.join("data")).unwrap();
    for i in 0..n {
        fs::write(root.join(format!("data/f{i:02}")), pseudo(1000, i as u32 + 1)).unwrap();
    }
    bin(&root)
        .args(["init", ".", "--block-size", "64", "--stripe-size", "32KiB", "--parity-default", "include", "--parity", parity])
        .assert()
        .success();
    // On a ZFS-backed /tmp (e.g. FreeBSD), init auto-sets parity_min_bytes to
    // the recordsize, which would change the margins these tests reason about.
    bin(&root).args(["config", "parity_min_bytes", "0"]).assert().success();
    bin(&root).args(["scan", "-y"]).assert().success();
    Arch { _tmp: tmp, root }
}

// Scenario 9: a wholly-lost small file is restored from siblings + parity.
#[test]
fn deleted_small_file_is_restored() {
    let a = setup(10);
    let root = &a.root;
    let original = fs::read(root.join("data/f03")).unwrap();
    let mtime = fs::metadata(root.join("data/f03")).unwrap().modified().unwrap();
    fs::remove_file(root.join("data/f03")).unwrap();
    // check points at the restore
    bin(root)
        .args(["check", "data/f03"])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("restorable from its parity set"));
    bin(root)
        .args(["repair", "data/f03"])
        .assert()
        .success()
        .stdout(predicates::str::contains("restored: data/f03"));
    assert_eq!(fs::read(root.join("data/f03")).unwrap(), original);
    assert_eq!(fs::metadata(root.join("data/f03")).unwrap().modified().unwrap(), mtime);
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("10 ok"));
    bin(root).args(["fsck", "--deep"]).assert().success();
}

// Scenario 11 at CLI level: two files damaged in the same stripe heal each other.
#[test]
fn two_damaged_files_heal_together() {
    let a = setup(10);
    let root = &a.root;
    let (o2, o7) = (fs::read(root.join("data/f02")).unwrap(), fs::read(root.join("data/f07")).unwrap());
    flip_keep_mtime(&root.join("data/f02"), &[100]);
    flip_keep_mtime(&root.join("data/f07"), &[500]);
    bin(root)
        .args(["check", "--repair"])
        .assert()
        .success()
        .stdout(predicates::str::contains("repaired: data/f02"))
        .stdout(predicates::str::contains("repaired: data/f07"));
    assert_eq!(fs::read(root.join("data/f02")).unwrap(), o2);
    assert_eq!(fs::read(root.join("data/f07")).unwrap(), o7);
}

// Scenario 4: `rm` rebuilds the set first, then deletes; no degraded window,
// no orphans, and the deleted file is really gone from the index.
#[test]
fn rm_rebuilds_then_deletes() {
    let a = setup(10);
    let root = &a.root;
    let before = sidecars(root);
    assert_eq!(before.len(), 1);
    bin(root)
        .args(["rm", "data/f05", "-y"])
        .assert()
        .success()
        .stdout(predicates::str::contains("deleted: data/f05"))
        .stdout(predicates::str::contains("1 parity set(s) will be rebuilt"));
    assert!(!root.join("data/f05").exists());
    let after = sidecars(root);
    assert_eq!(after.len(), 1);
    assert_ne!(before, after, "the set must have been re-encoded without the deleted member");
    // no degraded sets, nothing restorable, fsck clean
    bin(root).arg("status").assert().success().stdout(predicates::str::contains("DEGRADED").not());
    bin(root).args(["ls", "--json"]).assert().success().stdout(predicates::str::contains("\"path\":\"data/f05\"").not());
    bin(root).args(["fsck", "--deep"]).assert().success();
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("9 ok"));
}

// Scenario / footgun 10: a set holding a corrupt member refuses rm (and scan
// keeps it) until the member is repaired or accepted; --force overrides.
#[test]
fn rm_refuses_while_sibling_awaits_repair() {
    let a = setup(10);
    let root = &a.root;
    let o1 = fs::read(root.join("data/f01")).unwrap();
    flip_keep_mtime(&root.join("data/f01"), &[100]);
    // check marks it corrupt (scan's fast path can't see same-mtime damage)
    bin(root).args(["check", "data/f01"]).assert().code(2).stdout(predicates::str::contains("CORRUPT: data/f01"));
    // scan must NOT dissolve the set (it is the repair source) …
    bin(root).args(["scan", "-y"]).assert().success();
    assert_eq!(sidecars(root).len(), 1);
    // … and rm of a sibling must refuse without --force
    bin(root)
        .args(["rm", "data/f02", "-y"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("refusing to delete"));
    assert!(root.join("data/f02").exists());
    // repair the member; after that rm goes through
    bin(root).args(["repair", "data/f01"]).assert().success();
    assert_eq!(fs::read(root.join("data/f01")).unwrap(), o1);
    bin(root).args(["rm", "data/f02", "-y"]).assert().success();
    assert!(!root.join("data/f02").exists());
    bin(root).args(["fsck", "--deep"]).assert().success();
}

// Scenario 3: editing one file rebuilds exactly its set; other sets are untouched.
#[test]
fn edit_rebuilds_only_the_affected_set() {
    let a = setup(66); // 66 KB of files -> two sets at the 32 KiB target
    let root = &a.root;
    let before = sidecars(root);
    assert!(before.len() >= 2, "expected multiple sets, got {}", before.len());
    // Edit one early file (new content, mtime bumped).
    fs::write(root.join("data/f00"), pseudo(1000, 999)).unwrap();
    let t = std::time::SystemTime::now() + Duration::from_secs(5);
    fs::File::options().write(true).open(root.join("data/f00")).unwrap().set_modified(t).unwrap();
    bin(root)
        .args(["scan", "-y"])
        .assert()
        .success()
        .stdout(predicates::str::contains("modified: data/f00"))
        .stdout(predicates::str::contains("set(s) encoded"));
    let after = sidecars(root);
    // The untouched set(s) survive by identity; the edited one was replaced.
    let kept: Vec<_> = before.iter().filter(|p| after.contains(p)).collect();
    assert!(!kept.is_empty(), "unrelated sets must not be rebuilt");
    assert!(after.iter().any(|p| !before.contains(p)), "the affected set must be re-encoded");
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("66 ok"));
    bin(root).args(["fsck", "--deep"]).assert().success();
}

// Scenario 6: a mass rename converges without duplicate parity and reports moves.
#[test]
fn mass_rename_converges() {
    let a = setup(20);
    let root = &a.root;
    let n_before = sidecars(root).len();
    fs::rename(root.join("data"), root.join("moved")).unwrap();
    bin(root)
        .args(["scan", "-y"])
        .assert()
        .success()
        .stdout(predicates::str::contains("moved: data/f00 -> moved/f00"));
    // Old sets keep covering the contents; redundant new sets are dropped.
    assert_eq!(sidecars(root).len(), n_before, "no duplicate parity may survive");
    bin(root).arg("status").assert().success().stdout(predicates::str::contains("DEGRADED").not());
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("20 ok"));
    bin(root).args(["fsck", "--deep"]).assert().success();
}

// Scenario 2: incremental additions merge the underfull tail set.
#[test]
fn underfull_sets_merge_on_growth() {
    let a = setup(10); // 10 KB: well under half the 32 KiB target
    let root = &a.root;
    assert_eq!(sidecars(root).len(), 1);
    for i in 10..20 {
        fs::write(root.join(format!("data/f{i:02}")), pseudo(1000, i as u32 + 1)).unwrap();
    }
    bin(root).args(["scan", "-y"]).assert().success();
    // Old tail set dissolved and merged with the new files into one set.
    assert_eq!(sidecars(root).len(), 1, "underfull sets must merge");
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("20 ok"));
}

// Scenario 15: a superseded sidecar left behind (crash between DB commit and
// unlink) is swept by the next parity phase.
#[test]
fn orphan_sidecar_is_swept() {
    let a = setup(10);
    let root = &a.root;
    let sc = sidecars(root)[0].clone();
    // Fake a stale sidecar with a plausible name (valid hex id, not in the DB).
    let stale = sc.with_file_name(format!("{}.mts", "ab".repeat(32)));
    fs::copy(&sc, &stale).unwrap();
    bin(root).args(["parity", "sync"]).assert().success();
    assert!(!stale.exists(), "orphan sidecar must be removed by the sweep");
    assert!(sc.exists());
}

// Scenario: fsck --rebuild-db reconstructs sets/memberships from sidecars,
// including restorability of a missing file.
#[test]
fn rebuild_db_restores_set_knowledge() {
    let a = setup(10);
    let root = &a.root;
    let original = fs::read(root.join("data/f04")).unwrap();
    // Lose a file, keep it in the index (scan --no).
    fs::remove_file(root.join("data/f04")).unwrap();
    bin(root).args(["scan", "--no"]).assert().code(2);
    // Nuke and rebuild the index.
    bin(root).args(["fsck", "--rebuild-db"]).assert().success().stdout(predicates::str::contains("1 parity set(s)"));
    // The missing file is still known and still restorable.
    bin(root)
        .args(["repair", "data/f04"])
        .assert()
        .success()
        .stdout(predicates::str::contains("restored: data/f04"));
    assert_eq!(fs::read(root.join("data/f04")).unwrap(), original);
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("10 ok"));
}

// Scenario 14: a sidecar left behind by a crash after the rename but before
// the DB commit is ADOPTED (recorded without re-reading the data). Simulated
// via fsck --fix on a missing sidecar (which drops the set rows — itself the
// missing-sidecar fix path under test) and putting the sidecar back.
#[test]
fn valid_orphan_sidecar_is_adopted() {
    let a = setup(10);
    let root = &a.root;
    let sc = sidecars(root)[0].clone();
    let stash = root.join("stash.mts");
    fs::copy(&sc, &stash).unwrap();
    fs::remove_file(&sc).unwrap();
    bin(root)
        .args(["fsck", "--fix"])
        .assert()
        .success()
        .stdout(predicates::str::contains("missing sidecar"))
        .stdout(predicates::str::contains("removed the set from the index"));
    // Crash-state reached: sidecar exists on disk, DB knows nothing about it.
    fs::rename(&stash, &sc).unwrap();
    bin(root)
        .args(["parity", "sync"])
        .assert()
        .success()
        .stdout(predicates::str::contains("1 adopted"));
    assert_eq!(sidecars(root), vec![sc]);
    bin(root).args(["fsck", "--deep"]).assert().success().stdout(predicates::str::contains("fsck: ok"));
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("10 ok"));
}

// fsck --fix on a missing sidecar without a copy to put back: the set rows go
// away and the next scan re-encodes the members from scratch.
#[test]
fn missing_sidecar_reencoded_by_next_scan() {
    let a = setup(10);
    let root = &a.root;
    fs::remove_file(&sidecars(root)[0]).unwrap();
    bin(root).args(["fsck", "--fix"]).assert().success().stdout(predicates::str::contains("removed the set from the index"));
    bin(root)
        .args(["scan", "-y"])
        .assert()
        .success()
        .stdout(predicates::str::contains("1 set(s) encoded"));
    assert_eq!(sidecars(root).len(), 1);
    bin(root).args(["fsck", "--deep"]).assert().success();
}

// rm --force on a held set: deletion goes through, the set stays degraded but
// keeps being the repair source for its damaged member.
#[test]
fn rm_force_leaves_degraded_but_repairable() {
    let a = setup(10);
    let root = &a.root;
    let o1 = fs::read(root.join("data/f01")).unwrap();
    flip_keep_mtime(&root.join("data/f01"), &[100]);
    bin(root).args(["check", "data/f01"]).assert().code(2);
    bin(root)
        .args(["rm", "data/f02", "-y", "--force"])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("deleted: data/f02"))
        .stdout(predicates::str::contains("left degraded (--force)"));
    assert!(!root.join("data/f02").exists());
    bin(root).arg("status").assert().code(2).stdout(predicates::str::contains("DEGRADED"));
    // The damaged member is still repairable from the kept set (f02's blocks
    // count as dead erasures, well within the boosted margin).
    bin(root).args(["repair", "data/f01"]).assert().success().stdout(predicates::str::contains("repaired: data/f01"));
    assert_eq!(fs::read(root.join("data/f01")).unwrap(), o1);
    // With the member healed, the next scan rebuilds and clears the degradation.
    bin(root).args(["scan", "-y"]).assert().success();
    bin(root).arg("status").assert().success().stdout(predicates::str::contains("DEGRADED").not());
    bin(root).args(["fsck", "--deep"]).assert().success();
}

// rm of a whole directory, and rm of one of two duplicate files (the content
// stays referenced, so no set is rebuilt for the duplicate).
#[test]
fn rm_directory_and_duplicate_handling() {
    let a = setup(6);
    let root = &a.root;
    fs::create_dir_all(root.join("data/sub")).unwrap();
    fs::write(root.join("data/sub/x"), pseudo(1000, 91)).unwrap();
    fs::write(root.join("data/sub/y"), pseudo(1000, 92)).unwrap();
    // Two duplicates of the same content.
    fs::write(root.join("data/dupA"), pseudo(1000, 93)).unwrap();
    fs::write(root.join("data/dupB"), pseudo(1000, 93)).unwrap();
    bin(root).args(["scan", "-y"]).assert().success();
    // Deleting one duplicate does not touch any set (content still referenced).
    bin(root)
        .args(["rm", "data/dupA", "-y"])
        .assert()
        .success()
        .stdout(predicates::str::contains("will be rebuilt").not());
    // The surviving duplicate is still protected: damage it, repair it.
    let dup = fs::read(root.join("data/dupB")).unwrap();
    flip_keep_mtime(&root.join("data/dupB"), &[10]);
    bin(root).args(["check", "--repair", "data/dupB"]).assert().success();
    assert_eq!(fs::read(root.join("data/dupB")).unwrap(), dup);
    // rm a whole directory.
    bin(root)
        .args(["rm", "data/sub", "-y"])
        .assert()
        .success()
        .stdout(predicates::str::contains("deleted: data/sub/x"))
        .stdout(predicates::str::contains("deleted: data/sub/y"));
    assert!(!root.join("data/sub/x").exists());
    bin(root).arg("check").assert().success();
    bin(root).args(["fsck", "--deep"]).assert().success();
    bin(root).arg("status").assert().success().stdout(predicates::str::contains("DEGRADED").not());
}

// Footgun 10: a degraded set whose damaged member blocks dissolution is
// reported ("kept: waiting on") every scan until the member is repaired.
#[test]
fn held_set_reported_until_member_repaired() {
    let a = setup(10);
    let root = &a.root;
    let o1 = fs::read(root.join("data/f01")).unwrap();
    // Damage f01 (same mtime -> corrupt via check), and edit f02 (different
    // size so scan accepts it plainly) to make the set degraded.
    flip_keep_mtime(&root.join("data/f01"), &[100]);
    bin(root).args(["check", "data/f01"]).assert().code(2).stdout(predicates::str::contains("CORRUPT"));
    fs::write(root.join("data/f02"), pseudo(1234, 77)).unwrap();
    let t = std::time::SystemTime::now() + Duration::from_secs(5);
    fs::File::options().write(true).open(root.join("data/f02")).unwrap().set_modified(t).unwrap();
    bin(root)
        .args(["scan", "-y"])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("modified: data/f02"))
        .stdout(predicates::str::contains("kept: waiting on"))
        .stdout(predicates::str::contains("data/f01 (corrupt)"));
    // Still held on the next scan, still degraded in status.
    bin(root).args(["scan", "-y"]).assert().code(2).stdout(predicates::str::contains("kept: waiting on"));
    bin(root).arg("status").assert().code(2).stdout(predicates::str::contains("DEGRADED"));
    // Repair unblocks; the next scan rebuilds and everything settles.
    bin(root).args(["repair", "data/f01"]).assert().success();
    assert_eq!(fs::read(root.join("data/f01")).unwrap(), o1);
    bin(root).args(["scan", "-y"]).assert().success().stdout(predicates::str::contains("kept: waiting on").not());
    bin(root).arg("status").assert().success().stdout(predicates::str::contains("DEGRADED").not());
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("10 ok"));
}

// Dead members consume margin: with low parity, an edited sibling's dead
// blocks push later damage over the limit — check estimates it, repair fails
// cleanly and names the cause.
#[test]
fn dead_members_shrink_margin_beyond_repair() {
    // 1% parity: boost = ceil(32 KiB * 1% / 64B) = 6 blocks per (single)
    // stripe; one dead 16-block member alone exceeds it.
    let a = setup_with(10, "1%");
    let root = &a.root;
    // Edit f02 (accepted -> old content dead), skipping the parity phase so
    // the degraded set is NOT rebuilt.
    fs::write(root.join("data/f02"), pseudo(1000, 55)).unwrap();
    let t = std::time::SystemTime::now() + Duration::from_secs(5);
    fs::File::options().write(true).open(root.join("data/f02")).unwrap().set_modified(t).unwrap();
    bin(root).args(["scan", "-y", "--no-parity"]).assert().success();
    // Now damage f03: 1 bad block + 16 dead blocks > 6 parity blocks.
    flip_keep_mtime(&root.join("data/f03"), &[100]);
    bin(root)
        .args(["check", "data/f03"])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("likely NOT repairable"));
    bin(root)
        .args(["repair", "data/f03"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("count against the margin"))
        .stderr(predicates::str::contains("cannot repair data/f03"));
    // A full scan rebuilds what it can; f03 stays damaged and holds its set.
    bin(root).args(["scan", "-y"]).assert().code(2).stdout(predicates::str::contains("kept: waiting on"));
}

// Empty files are hashed and tracked but never set members; every command
// copes with them.
#[test]
fn empty_files_are_never_members() {
    let a = setup(4);
    let root = &a.root;
    fs::write(root.join("data/empty"), b"").unwrap();
    bin(root).args(["scan", "-y"]).assert().success().stdout(predicates::str::contains("added: data/empty"));
    // Tracked and ok, but no parity membership.
    let out = bin(root).args(["ls", "--json"]).output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    let line = s.lines().find(|l| l.contains("\"path\":\"data/empty\"")).expect("empty file must be indexed");
    assert!(line.contains("\"parity\":false"), "empty files are never set members: {line}");
    bin(root).arg("check").assert().success().stdout(predicates::str::contains("5 ok"));
    bin(root).args(["repair", "data/empty"]).assert().success().stdout(predicates::str::contains("nothing recorded against it"));
    bin(root).args(["rm", "data/empty", "-y"]).assert().success();
    assert!(!root.join("data/empty").exists());
    bin(root).args(["fsck", "--deep"]).assert().success();
}

// Review gap #7: prune drops parity for contents that lost coverage, but a
// covered Missing file's content stays live — it must remain restorable.
#[test]
fn prune_keeps_covered_missing_restorable() {
    let a = setup(4);
    let root = &a.root;
    fs::create_dir_all(root.join("other")).unwrap();
    // Small enough that their dead blocks after pruning leave room in the
    // margin to restore a whole 16-block data file.
    for i in 0..3 {
        fs::write(root.join(format!("other/g{i}")), pseudo(100, 60 + i)).unwrap();
    }
    bin(root).args(["scan", "-y"]).assert().success();
    // Lose a covered file but keep it in the index.
    let original = fs::read(root.join("data/f01")).unwrap();
    fs::remove_file(root.join("data/f01")).unwrap();
    bin(root).args(["scan", "--no"]).assert().code(2);
    // Drop coverage for other/ and prune.
    bin(root).args(["parity", "exclude", "other"]).assert().success();
    bin(root)
        .args(["parity", "sync", "--prune"])
        .assert()
        .success()
        .stdout(predicates::str::contains("pruned parity for 3 content item(s)"));
    // other/* lost protection; the missing covered file did not.
    let out = bin(root).args(["ls", "--json"]).output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    let g0 = s.lines().find(|l| l.contains("\"path\":\"other/g0\"")).unwrap();
    assert!(g0.contains("\"parity\":false"), "pruned content must show no parity: {g0}");
    bin(root)
        .args(["repair", "data/f01"])
        .assert()
        .success()
        .stdout(predicates::str::contains("restored: data/f01"));
    assert_eq!(fs::read(root.join("data/f01")).unwrap(), original);
}

// Scenarios 13/16 at scale: kill a scan outright (SIGKILL — harsher than
// Ctrl-C) partway through; the next scan converges with no manual cleanup.
#[test]
fn killed_scan_converges_on_rerun() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("archive");
    fs::create_dir_all(&root).unwrap();
    for d in 0..30 {
        fs::create_dir_all(root.join(format!("t/d{d:02}"))).unwrap();
        for f in 0..100 {
            fs::write(root.join(format!("t/d{d:02}/f{f:02}")), pseudo(4000, (d * 100 + f) as u32)).unwrap();
        }
    }
    bin(&root)
        .args(["init", ".", "--block-size", "64", "--stripe-size", "64KiB", "--parity-default", "include"])
        .assert()
        .success();
    // Kill a scan mid-flight (whether it dies during hashing, parity encoding
    // or DB writes varies; convergence must not depend on where).
    let exe = env!("CARGO_BIN_EXE_meticulous");
    let mut child = std::process::Command::new(exe)
        .args(["scan", "-y", "-q"])
        .current_dir(&root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let _ = child.kill();
    let _ = child.wait();
    // Rerun: finishes the job (or redoes it), leaves everything consistent.
    bin(&root).args(["scan", "-y"]).assert().success();
    bin(&root).args(["fsck", "--deep"]).assert().success().stdout(predicates::str::contains("fsck: ok"));
    bin(&root).arg("check").assert().success().stdout(predicates::str::contains("3000 ok"));
    assert_eq!(fs::read_dir(root.join("_meticulous/parity/tmp")).map(|d| d.count()).unwrap_or(0), 0);
}

// show reports membership + loss protection; status counts sets.
#[test]
fn show_and_status_report_sets() {
    let a = setup(10);
    let root = &a.root;
    bin(root)
        .args(["show", "data/f00"])
        .assert()
        .success()
        .stdout(predicates::str::contains("parity:        set "))
        .stdout(predicates::str::contains("loss-protected: yes"));
    bin(root).arg("status").assert().success().stdout(predicates::str::contains("in 1 set(s)"));
    bin(root).args(["parity", "list"]).assert().success().stdout(predicates::str::contains("sets: 1"));
}
