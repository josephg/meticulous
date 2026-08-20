# checksummer red-team report

Scope: every file under `src/` and `tests/`, `README.md`, `FORMAT.md`, read in full; release binary built and exercised against throw-away archives under the scratchpad (`redteam/e*`). No source files were modified. `cargo test` passes (23 unit + 5 e2e) before and after.

Severity legend: **CRITICAL** = can lose/overwrite user data, record a wrong hash as truth, or destroy repair capability · **HIGH** = wrong results/state, missed corruption, crashes · **MEDIUM** = robustness/UX · **LOW** = nits/perf.

Each finding: location, what is wrong, how it was confirmed (command + output excerpt, or "by reading"), suggested fix.

---

## CRITICAL

### C1. `repair` silently reverts intentional edits (state `modified`) — user data overwritten
`src/commands/check.rs:249-278` (`repair`), `check.rs:217-247` (`do_repair`), `src/parity.rs:216-304` (`repair_file`).

`repair PATH` takes every file under PATH in state corrupt/unrecoverable **plus any explicitly named file regardless of state** (`check.rs:252-256`). `do_repair` never compares the on-disk size/mtime with the DB row; it just rebuilds to the recorded content hash. So a file the user edited since the last scan (mtime changed, `check` correctly says `modified`) is silently rewritten to its old content, and the edit is gone (no `.corrupt` copy unless `--keep-corrupt`).

Confirmed (E2c): 100 KB file with parity, scanned; then 4 bytes changed + mtime bumped (a legit edit):
```
$ checksummer check d/f
modified: d/f (size/mtime changed; run `checksummer scan` to accept)
$ checksummer repair d/f
repaired: d/f (1 block(s) rebuilt)        # exit 0
$ dd if=d/f bs=1 skip=10 count=4 | xxd -p
e5ee084f                                   # the "EDIT" bytes are gone
```
The same happens via the directory form when a file was in state `corrupt` and the user then replaced it with a new version (E2b shows the attempt; it only failed there because the replacement differed in every block — a small edit would be reverted as in E2c). It also happens after `fsck --rebuild-db` (see C3).

Fix: in `do_repair` (or `repair_file`) refuse when `mtime_ns(meta) != row.mtime_ns || meta.len() != row.size` unless `--force`; default `keep_corrupt=true` for anything the user did not explicitly mark corrupt; print the recorded vs. on-disk mtime in the refusal message.

### C2. `scan` records a stale hash with the *new* mtime when a file is written while it is being hashed → false CORRUPT later, and `--repair` would revert the user's write
`src/commands/scan.rs:198-202` + `scan.rs:218-258`.

The worker hashes the file, then `on_done` re-stats and stores the **post-hash** `size/mtime/inode` together with the hash of whatever bytes were read. If the file is modified during hashing, the DB ends up with (old-content hash, new mtime). `check` then sees mtime equal → hash mismatch → **CORRUPT/unrecoverable** (false positive); if parity was generated, `check --repair` rebuilds the *old* content over the user's new data and passes its own self-check (the sidecar hash is the old content's).

Confirmed (E3): 1.4 GiB file; a writer overwrites its first bytes 0.3 s into the scan:
```
$ checksummer scan -y -q        # scan complete: 1 added
recorded: <hash of all-zero file> ; actual file now: d60636d5…
$ checksummer check
CORRUPT: d/big (no parity available)
```
Fix: use the pre-hash `Entry{size,mtime_ns}` for the row, re-stat after hashing and if either differs, do **not** record — re-queue once or report "changed while scanning" and leave the row alone. (The parity path already bails on size change via `encode_inner`, but still records the post-hash mtime.)

### C3. `fsck --rebuild-db` stamps every file with its *current* mtime next to the manifest's (possibly stale) hash → edits since the last scan become "CORRUPT" and `check --repair` reverts them
`src/commands/fsck.rs:353-378`.

The manifest has no mtime/size. `rebuild` records `mtime_ns = current mtime`, `size = current size`, `state = Ok`. Any file edited after the manifest was written now looks like bit rot (mtime matches, hash doesn't).

Confirmed (E25):
```
$ checksummer fsck --rebuild-db
$ checksummer check --repair
CORRUPT: d/f — 1 bad block(s) (repairable)
repaired: d/f (1 block(s) rebuilt)     # user's edit gone
```
Fix: store size+mtime in the manifest (or a parallel `MANIFEST.json`) and use them in rebuild; failing that, rebuild with `mtime_ns = 0`/`state = Modified`-like marker so `check` reports "modified" and `scan` must be run to accept (and still refuse repair per C1).

### C4. Anything that makes a subtree unreadable + `scan -y` (or answering "y") deletes its index rows **and** its parity sidecars
`src/commands/scan.rs:57-62` (walk errors are only warnings), `scan.rs:307-349` (removed logic), `scan.rs:353-357` (`prune_orphan_content` → `remove_file(sidecar)`).

A directory that is EACCES, an unmounted mount point, a renamed directory, or a nonexistent PATH argument yields a walkdir error (just `eprintln!`) and every known file under it is treated as *removed*. With `-y` (which README recommends for non-interactive use) the rows are deleted and, because the content rows become orphans, the **sidecars are deleted from disk**. The files still exist; when the directory comes back, parity must be regenerated from the (hopefully still intact) file — if the file has rotted meanwhile, the repair capability is gone for good.

Confirmed (E4):
```
$ chmod 000 d/sub; checksummer scan -y
warning: IO error for operation on …/d/sub: Permission denied (os error 13)
1 file(s) in the index no longer exist on disk:  d/sub/f
scan complete: 1 removed, 0 unchanged
sidecars after: 0          # was 1; d/sub/f still exists on disk
```
and (Ed) `mv photos pictures; checksummer scan photos -y` → row + sidecar gone, "moved" not detected (pictures was outside the scanned PATH).

Fix: (a) treat a walk error under a directory as "unknown", never "removed": remember failed directory prefixes and exclude known rows under them from the removed set (and bail/return exit 2); (b) never delete sidecars in the same run that removed the rows — keep sidecars for content that still exists on disk or defer pruning to `parity sync --prune`/`fsck --fix`; (c) if the PATH root does not exist, error out instead of walking an empty tree.

### C5. `fsck --fix` deletes a *partially* damaged sidecar without checking that the file is intact → a repairable file becomes unrepairable
`src/commands/fsck.rs:303-315`.

The README (§Parity details) promises "damage to a sidecar only loses the damaged stripe's parity". But when any sidecar was flagged damaged, `--fix` reopens **every** sidecar, runs `deep_check`, and deletes any with any problem, then clears `has_parity`. If the file itself has a bad block in a different (intact) stripe, the still-good parity is thrown away, and the subsequent `parity sync` cannot regenerate it because the file is corrupt.

Confirmed (E6): block-64/stripe-4096 archive, file bad in stripe 0, sidecar damaged in stripe 4:
```
$ checksummer check d          → CORRUPT: d/f — 1 bad block(s) (repairable)
$ checksummer fsck --deep --fix → damaged sidecar …: stripe 4: … (hash mismatch)   (sidecar removed)
$ checksummer repair d         → cannot repair d/f: no usable parity … No such file or directory
$ checksummer parity sync      → CORRUPT: d/f (cannot generate parity for damaged content)
```
Fix: before deleting a damaged sidecar, run `check_blocks` on each referencing file; if any file is not `ok`, try `repair_file` with the usable stripes first and keep the sidecar otherwise. Also, the fix loop runs `deep_check` on *all* sidecars (full parity read) even without `--deep`, and `.unwrap_or(true)` deletes on any open error — make deletion explicit per reported sidecar.

### C6. Corruption accompanied by an mtime change is accepted as an "edit", the bad hash becomes truth and the good parity is deleted
`src/commands/scan.rs:157-163, 244-274, 353-357`.

Design assumption "mtime changed ⇒ intentional edit" fails for the very common archive operations `cp`/`rsync` without `-p`/`-t`, restores from backups that do not preserve timestamps, and filesystems/tools that touch files. `scan` then re-hashes every file, records whatever is on disk as `ok`, generates parity for the *corrupt* content, and `prune_orphan_content` deletes the sidecar of the good content — even though the old sidecar's block table would have shown "1 bad block out of 1563", which is unambiguously rot, not an edit.

Confirmed (Ei): three files with parity; `touch` all three (mtime reset), flip one byte in f2:
```
$ checksummer scan -y
modified: d/f3 (content unchanged) / modified: d/f2 / modified: d/f1 (content unchanged)
scan complete: 3 modified, 3 parity generated
$ checksummer ls   → all three "ok … P"; check → 3 ok    # f2's old sidecar is gone
```
Fix: for a mtime-changed file whose content has parity, run `check_blocks` against the old sidecar first; if `bad_blocks.len() <= parity` (and especially if size is unchanged) report it as *suspected corruption* and ask (or require `--accept-corruption`) before accepting; never prune sidecars of content replaced in the same run without confirmation. Also do not re-encode parity for `Tag::Modified` files whose content hash is unchanged (they are re-encoded and the tmp sidecar discarded — wasted work, `scan.rs:161`).

---

## HIGH

### H1. `repair FILE` on a healthy file without parity flips its state to `unrecoverable`
`src/commands/check.rs:270-276`. Any `do_repair` error (including "no sidecar") sets `Unrecoverable` for explicitly named files, even when the file is fine.
Confirmed (E1): `repair d/f` on an ok, parity-less file → `cannot repair d/f: no usable parity…` and `ls` shows `unrecoverable`. Fix: only downgrade state when the pre-check actually showed damage (`bc.ok()==false`), and never for missing-sidecar errors.

### H2. `parity sync` marks legitimately modified files `corrupt`
`src/commands/parity.rs:149-157`. `sync` compares the fresh hash with `row.content_hash` without looking at size/mtime. A file edited since the last scan (same size) is reported `CORRUPT … cannot generate parity`, state `corrupt` (not even `unrecoverable`), and the just-written sidecar for the real content is discarded; for size changes it fails with "file grew while reading" (layout built from `row.size`).
Confirmed (E12b): `parity sync` → `CORRUPT: d/f`, `ls` → `corrupt`; `check d/f` then says `modified`. Fix: in `parity_jobs_for_rows` stat the file and skip/flag rows whose size/mtime differ from the DB (report as modified, exit 2); use the on-disk size for the layout.

### H3. `.bak` is not the "previous good copy" the README/FORMAT claim; a damaged DB is copied over it by the next writing command, and a hash MISMATCH is silently "healed"
`src/db.rs:544-567` (`finish` → `protect_db_file` copies the *just-written* DB), `src/commands/mod.rs:65-91` (no check of the `.sha256` before opening/writing).
After every dirty command `.bak == index.sqlite`. If `index.sqlite` rots in a way SQLite does not detect, the next `parity include`/`scan` writes the rotten data back, copies it to `.bak`, and rewrites `.sha256` so `status`/`fsck` say "ok".
Confirmed (E7): bytes 96..99 of the DB altered → `status: file hash MISMATCH`; `parity include d`; `status: file hash ok`, `.bak` replaced. Fix: verify the recorded sha256 in `Db::open` (or at least before the first write) and refuse/require `--ignore-db-hash`; rotate `.bak` *before* writing (copy current → `.bak` only if its hash matches the recorded one), or keep N generations.

### H4. Silent skips: symlinks (files and directories) are never indexed, with no warning or count
`src/commands/scan.rs:54,78`. `follow_links(false)` + `is_file()` drops every symlink. For an archive where sub-trees live on other disks via symlinks, everything under them is silently unprotected.
Confirmed (E11): `real/x` indexed; `d/link -> ../real` and `d/flink -> ../real/x` produce no output at all. Fix: count and report skipped symlinks in the summary; offer `--follow-symlinks` (with loop protection) or at least index symlinked regular files.

### H5. `scan <path inside .checksummer>` indexes the parity store / manifest / DB as archive files
`src/commands/scan.rs:64-67` only prunes when the walk *starts above* `.checksummer`; `util::to_relative` accepts `.checksummer/...`.
Confirmed (E5): `scan -y .checksummer/parity` → `ok 744 B - .checksummer/parity/27/c8/….csp`. Those files then appear as "removed" on a later full scan. Fix: reject rel paths whose first component is `.checksummer` in `Ctx::rel_paths`/`walk`, and filter them from `known`.

### H6. `--no-accept-changes` state / `check` message for damaged block table; has_sidecar ⇒ `corrupt` even when nothing can repair it
`src/worker.rs:515-521` falls back to a plain hash when the block table is damaged; `src/commands/check.rs:134-139` then labels the file `corrupt` (because `has_sidecar`) while printing "(no parity available)", logs "(no parity)", and does not queue it for repair. Confirmed (E13): `CORRUPT: d/f (no parity available)`, `ls` → `corrupt … P`. `repair` afterwards fails ("block table is damaged") and flips to unrecoverable. Fix: return a distinct `Done::HashedNoTable` / carry a flag so state is `unrecoverable` and the message says "sidecar damaged; run fsck".

### H7. `import` indexes MISMATCHing, never-before-seen files as `ok` with their current (possibly rotten) hash and generates parity for that content
`src/commands/manifest.rs:239-273, 292-331`. The list says X, the file hashes to Y → "MISMATCH" printed, then the row is inserted as `ok` with Y (`last_verified_at = now`) and, if covered, parity is generated for Y. For the stated purpose ("use import with your old md5/sha1 lists" to find damage that predates ZFS) this blesses the damaged copy.
Confirmed (E24): `MISMATCH: d/f (md5 differs from list)` … `ok 15 B - d/f`. Fix: index mismatching files with state `unrecoverable` (or `modified`), no parity, and an event recording the listed digest; let `scan`/`--accept` bless them explicitly.

### H8. `scan`/`parity sync`/`import` transactions are left open on error; MANIFEST/marks are then written from uncommitted state, which is rolled back at close
`src/commands/scan.rs:189-304` (`begin` … `worker::run(...)?` … `commit`), same pattern in `check.rs:102-181`, `parity.rs:121-164`, `manifest.rs:171-279,284-336`; `src/commands/mod.rs:83-91` runs `write_sidecar_files` on the same connection **before** `finish()` closes (= rollback).
By reading: if `on_done` returns `Err` (any rusqlite error, disk full, FK violation), the `?` propagates with the transaction open; `dirty` is already true, so `MANIFEST.txt`/`PARITY_MARKS.txt` are rewritten from the *uncommitted* view, then `conn.close()` rolls back → manifest and DB disagree (manifest lists files the DB does not have). Fix: RAII transaction (`rusqlite::Transaction`) or an explicit `rollback()` on the error path, and write sidecar files only after a successful commit.

### H9. `worker::run` keeps draining after the first `on_done` error but silently drops all later results
`src/worker.rs:582-592`. After `first_err` is set, completed jobs (already hashed, sidecars already renamed into the parity dir) are discarded without any message; combined with H8 this also leaves orphan sidecars. By reading. Fix: on first error, stop dispatching (drop `rx` / use a cancellation flag) and report how many results were discarded; or keep calling `on_done` for bookkeeping.

---

## MEDIUM

### M1. `repair --dry-run` writes the whole repaired file to disk
`src/parity.rs:224-227, 288-291`. The temp file is created/written/synced even for dry-run (help text: "without writing anything"). Confirmed (E14): on a read-only directory `repair --dry-run d/f` fails with `creating …/d/f.csrepair.<pid>: Permission denied`. Fix: for dry-run, decode into memory/hash only.

### M2. Repair temp files and `--keep-corrupt` copies live inside the archive and get indexed
`src/parity.rs:306-325` (`<name>.csrepair.<pid>`, `<name>.corrupt`). A crash mid-repair leaves `x.csrepair.NNN`; `--keep-corrupt` leaves `x.corrupt`; the next `scan` indexes them as new files and (if covered) generates parity for corrupt content. Confirmed (E15): `ok 97.7 KiB P d/f.corrupt`. Fix: always exclude `*.csrepair.*` in `walk`; put kept copies under `.checksummer/quarantine/<path>` (or exclude `*.corrupt` by default and say so).

### M3. Repair breaks hard links and drops ownership
`src/parity.rs:292-302`: `rename(tmp, path)` replaces the inode; other hard links keep the damaged bytes (each link is repaired separately, doubling space); `set_permissions` copies mode but not uid/gid (matters when run as root). Confirmed (E26): after repair `d/a links=1`, `d/b links=1`. Fix: if `nlink > 1`, write in place (`pwrite` only the bad blocks, after backing up) or warn; `fchown` when root.

### M4. Manifest escape round-trip is wrong for names containing a literal backslash followed by `n` (and the same parser bug is in `import`)
`src/commands/manifest.rs:46,110`, `src/commands/fsck.rs:414`: unescaping does `replace("\\n","\n")` *then* `replace("\\\\","\\")` — `a\nb` (literal backslash-n) is written as `a\\nb` and read back as `a<newline>b`. Confirmed (E9): after `fsck --rebuild-db`, `ls` shows `d/a\` + newline + `b` as *missing*, and a scan re-adds/"moves" the real file. Fix: single left-to-right unescape pass (as coreutils does).

### M5. Non-UTF-8 file names are written lossily to MANIFEST and break rebuild / external verification
`src/commands/manifest.rs:44` uses `path_display` (U+FFFD). Confirmed (E10): rebuild → `missing d/caf�.txt`, later scan re-adds the real file and reports a bogus "moved". Fix: write raw bytes (`w.write_all(path_bytes)`), which is what `sha256sum -c` expects anyway; or escape non-UTF8 bytes.

### M6. Exclude glob semantics are surprising and undocumented
`src/config.rs:850-856` (globset defaults: `*` crosses `/`, no implicit `**/`). Confirmed (E23): `--exclude cache` excludes only top-level `cache/`, not `a/cache/`; `*.tmp` excludes at any depth. Document, or build with `literal_separator(true)` + auto-prefix `**/` for patterns without `/`.

### M7. `parity_blocks_for`/Layout ignore the configured stripe size when the block size is large (memory blow-up), and `Layout::choose` silently clamps config values
`src/csp.rs:65-67`: `bps = max(cfg_stripe/bs, 64)` ⇒ with `block_size=16MiB` (ZFS recordsize-aligned configs, or `init --block-size 64MiB`) a stripe is 1–4 GiB per worker regardless of `--stripe-size`; `config set block_size 128MiB` is accepted by `validate()` but clamped to 64 MiB in `choose`. By reading. Fix: validate `block_size*64 <= stripe_size` and `block_size <= MAX_BLOCK_SIZE` in `Config::validate`; drop the `.max(64)` when it would exceed the configured stripe.

### M8. `status`/`fsck` "ok" after concurrent writers; cross-process tmp/`fsck --fix` races
`src/worker.rs:499-511` temp sidecars are per-pid/job (`parity/tmp/<pid>-<job>.csp`, plus `csp::Writer`'s `….csp.tmp`, `csp.rs:222`) — unique, fine — but `fsck --fix` deletes anything under `parity/tmp` or `*.tmp` (`fsck.rs:284-291`), so a concurrent `scan`/`parity sync` loses its in-progress sidecars (rename fails, counted as error; by reading). `protect_db_file` copies the DB while another process may be mid-transaction. Two concurrent scans "work" (E21) only because rusqlite's default 5 s busy timeout; both hash everything twice and log duplicate events. Fix: a lock file in `.checksummer/` (flock) taken by every writing command.

### M9. `check` marks files MISSING on any stat error (EACCES, EIO on the directory)
`src/commands/check.rs:61-71`. Confirmed (E30): `chmod 000 d; check` → `MISSING: d/f`, state `missing`. A later `scan -y` would delete it (C4). Fix: distinguish `NotFound` from other errors; report the latter as errors without changing state.

### M10. Stale states / wrong state names
- `scan` Recheck mismatch always sets `corrupt` even when the content has no parity (`scan.rs:293`) — should be `unrecoverable`.
- `parity sync` failure sets `corrupt` without parity (`parity.rs:154`).
- `repair` on explicit files sets `unrecoverable` on any error (H1).
- `check` after a successful `--repair` exits 0 even though corruption was found (E18) — arguably fine, but `status`/history are the only trace; document.

### M11. `fsck --rebuild-db` trusts an unverified MANIFEST and loses history
`fsck.rs:343-380`: no hash of MANIFEST.txt exists (`.sha256` only covers the DB), so a rotten hex digit becomes a wrong "truth" that can never be repaired (sidecar hash mismatch ⇒ "no usable parity"). Events are not preserved. Fix: add MANIFEST.txt to `index.sqlite.sha256` (or a `MANIFEST.txt.sha256`), verify before rebuild, and keep the old `event` table when the broken DB is still readable.

### M12. `Reader::open` loads the entire block hash table; `Header::stripe_offset` is O(n) per call
`csp.rs:313-330, 164-170`. A 1 TiB file with 64 KiB blocks has a 512 MiB table, loaded per open (×4 workers in `check`, and sequentially for every sidecar in `fsck`); `deep_check`/`repair_file` call `stripe_offset` per stripe ⇒ O(stripes²) (only relevant for tiny block sizes). Fix: memory-map the sidecar (memmap2 is already a dependency) and precompute a stripe offset prefix array.

### M13. SIGPIPE → panic
`main.rs` does not reset SIGPIPE; `checksummer check | head -1` panics with `failed printing to stdout: Broken pipe` (seen in E2c/E12b). Fix: `libc::signal(SIGPIPE, SIG_DFL)` or handle `ErrorKind::BrokenPipe`.

### M14. `scan` prompt default and `-y` semantics
`util::confirm` returns `default=false` when stdin is not a TTY (safe), but `-y` is the documented non-interactive answer and — given C4/Ed — it is a foot-gun. Suggest `--remove-missing` as an explicit flag instead of overloading `-y`.

---

## LOW

- `hash.rs`: fletcher4 matches ZFS `fletcher_4_native` (4×u64 over LE u32 words, zero-padded tail); tests cover split updates. Note ZFS computes it over *compressed on-disk records*, so equality with `zdb` only holds for uncompressed, single-record files — README says this. `Digest::parse`/`Algo::from_str` fine. `Algo::id` stable.
- `parity.rs`: layout math, last-block zero padding, truncation, multi-stripe and size boundaries verified by experiment (E16: sizes 1…12289 with block 64/stripe 4096, last byte flipped, all repaired byte-exact; `fsck --deep` ok). Empty files get a 0-stripe sidecar and check/repair handle them (Ee). reed-solomon-simd constraints (`min(pow2(orig),pow2(rec)) + max(orig,rec) <= 65536`, shard bytes even) are satisfied by `Layout` (orig ≤ 32768, rec ≤ orig, block multiple of 64).
- `check_blocks`: a file that *grew* with unchanged mtime is reported as 1 bad block (the last) and "repaired" by truncation (E29) — correct w.r.t. the index but the message ("1 block rebuilt") is misleading; say "truncated N extra bytes".
- `parse_parity("0")` still yields one parity block per stripe (`Layout::parity_blocks_for` clamps to ≥1) — document or treat 0 % as "no parity".
- `db.rs`: `upsert_file` preserves `added_at` (good) but `last_insert_rowid()` is stale on the UPDATE path; `id` in `FileRow` is ignored by upsert (fine). `State::parse`/`row_to_content` silently map unknown values to `Ok`/`Blake3`. No `busy_timeout` is set explicitly (relies on rusqlite default). `dir_bounds` verified for `foo`/`foobar`/root. Per-row `conn.execute` re-prepares SQL (use `prepare_cached`) — matters at 10⁶ files.
- `Db::finish` copies the whole DB and `write_sidecar_files` rewrites the full manifest on *every* dirty command (`parity include` included) — O(archive) per command.
- `worker.rs`: a panic in a worker aborts the process (rayon `spawn` without panic handler) — sidecars already renamed stay as orphans; acceptable but document. `is_eio` treats `InvalidData` as a read error.
- `scan.rs`: `known`/`seen`/`jobs` all in memory (≈ few hundred MB at 10⁶ files); duplicate new files are each encoded (N× work for N copies); `Tag::Modified` with identical content re-encodes parity and throws it away.
- `fsck.rs:284`: `d.ends_with("tmp")` matches any directory named `tmp` (only `parity/tmp` exists today, fine) — compare against `parity_dir.join("tmp")` explicitly.
- `parity list`/`sync --prune`: O(files) plus one `files_by_content` query per stale hash — fine.
- `info.rs::config`: `exclude` is comma-separated so globs containing `,` cannot be set; `algo` change is blocked on non-empty archive (good) but nothing stops `block_size` > 64 MiB (M7).
- `util::to_relative`: a nonexistent `../x` argument normalises to `x` (the `root.join(arg)` candidate survives `strip_prefix`); harmless but odd.
- `cli.rs` help: `repair --dry-run` says "without writing anything" (M1); `FsckArgs.fix` says "remove orphan sidecars" but also deletes damaged ones (C5); README says `.bak` is the "previous good copy" (H3).
- Nested archives (a sub-directory with its own `.checksummer`) are indexed including their DB; only the root's `.checksummer` is skipped.
- `history PATH` uses `dir_bounds` prefix semantics (correct for dirs and exact files); `show` on a moved file says "not in the index" (expected).

---

## Missing tests (concrete)

Data safety / repair
1. `repair FILE` on a file with state `modified` (mtime changed) must **refuse** and leave bytes untouched (C1).
2. `repair FILE` on a healthy parity-less file must leave state `ok` (H1).
3. Scan race: modify a file while it is being hashed (large file + background writer, as in E3) → the DB must not contain (old hash, new mtime); expect the file to be re-queued or reported, and a following `check` must not say CORRUPT.
4. `fsck --rebuild-db` after an edit → `check` must report `modified`, not `corrupt`, and `--repair` must not touch the file (C3).
5. Walk error (chmod 000 / unmounted dir / nonexistent PATH) + `scan -y` must not delete rows or sidecars (C4/Ed); assert sidecar count unchanged.
6. Partially damaged sidecar + corrupt file: `fsck --fix` must not delete the sidecar; `repair` must still succeed using the intact stripes (C5).
7. mtime-reset + single-byte corruption: `scan` must flag suspected corruption and not prune the old sidecar (C6).
8. `parity sync` on a modified file must not mark it corrupt (H2); with size change it must not error with "file grew".
9. `--keep-corrupt`/crash leftovers (`*.csrepair.*`, `*.corrupt`) must not be indexed (M2).
10. Hard-linked pair: repair keeps them linked or warns (M3).
11. `repair --dry-run` on a read-only directory must succeed and write nothing (M1).
12. Concurrency: two `scan`s / `scan` + `fsck --fix` at once — no lost sidecars, no duplicate events (M8).
13. DB hash mismatch at startup must refuse to write / must not overwrite `.bak` (H3).

Parity engine (unit)
14. Property/fuzz test over sizes 0…3·stripe±1 and block sizes {64,128,4096,65536}, random bad-block sets up to `p` per stripe, plus truncation inside the last stripe and inside earlier stripes; assert byte-exact repair (E16 only covers last-byte damage by hand).
15. File *larger* than recorded (append with preserved mtime): `check_blocks` result, repair output size, and message (E29).
16. Damaged block table (`table_ok=false`): `check` state/message and that `repair` gives a clear "sidecar damaged" error (H6).
17. `Layout::choose` with large block sizes: assert `stripe_bytes() <= cfg_stripe_bytes` or that `Config::validate` rejects (M7).
18. `Header::decode` rejects `parity_ppm > 1e6` / `blocks_per_stripe > 32768` in a crafted header.
19. `fsck --fix` running concurrently with `parity sync` must not delete the other process's `parity/tmp` files (lock file, M8).

Scan / manifest / import
20. Non-UTF8 name and `a\nb` (literal backslash-n) round-trip through MANIFEST → rebuild → `ls` identical (M4/M5); `b3sum -c MANIFEST.txt` passes for them.
21. `scan .checksummer/parity` (and `check`/`ls` with such paths) is rejected (H5).
22. Symlinked dir/file: summary reports N symlinks skipped (H4).
23. Exclude semantics: `cache` vs `**/cache`, `*.tmp` at depth (M6) — pin whatever is decided.
24. `import` MISMATCH on a new file: state after import is not `ok`, no parity generated (H7); BSD-style `MD5 (f) = hex` lines are counted as unparsed (currently they are, but untested).
25. Error inside `on_done` (inject via a read-only `.checksummer` or a mock) → transaction rolled back, manifest not rewritten from uncommitted state (H8), later results reported (H9).

Existing-test weaknesses
- `scan_check_repair_cycle` asserts only substrings of stdout (`"5 ok"`, `"repaired: foo/big.bin"`); it does check file bytes after repair (good) but never inspects `ls --json` state transitions for `corrupt → ok`, the event log, or exit code after `check --repair` (currently 0 — decide and assert).
- `parity_sync_and_prune_and_fsck` damages the *last 3 bytes* of a sidecar (the last stripe hash) — it does not exercise a damaged block table, a damaged header, or a damaged stripe while the file is also damaged (C5).
- `export_import_and_rebuild` rebuilds right after a scan, so C3/M4/M5 cannot show up; add an edit between scan and rebuild, and a non-UTF8/backslash name.
- No test exercises `--older-than`/`--budget`, `--no-accept-changes` → later `scan` acceptance, `history PATH` filtering, `config set` validation, `ls --parity/--no-parity`, `status --json`, or `-j` > 1 with many files (channel/ordering).


---

# Disposition (2026-08-20)

All CRITICAL and HIGH findings were fixed, plus the MEDIUM ones that affect
data safety/correctness; each fix has a regression test in `tests/redteam.rs`.

| id | status | how |
|---|---|---|
| C1 | fixed | `do_repair` refuses when the on-disk mtime differs from the index; `repair` no longer downgrades state on such refusals |
| C2 | fixed | `scan` records the metadata seen *before* hashing and re-stats after; if size/mtime moved the result is discarded ("changed while scanning") |
| C3 | fixed | new `MANIFEST.tsv` (hash,size,mtime_ns,state,path) written alongside `MANIFEST.txt`; `--rebuild-db` uses it (and verifies its recorded sha256); falling back to `MANIFEST.txt` records mtime 0 so `check` reports *modified*, never corrupt |
| C4 | fixed | walk errors produce "unreliable" prefixes that are excluded from the removed set; nonexistent PATH is an error; sidecars are never deleted by `scan` (orphans are left for `fsck --fix`) |
| C5 | fixed | `fsck --fix` deletes a damaged sidecar only if every file using it hashes correctly; otherwise it is KEPT and reported |
| C6 | fixed | mtime-changed + same size + old content has parity → `scan` block-checks against the old sidecar: identical → metadata update only; few bad blocks (≤ parity) → SUSPECTED CORRUPTION, hash kept, mtime recorded so `repair` works; many → accepted as an edit (no parity re-encode for unchanged content) |
| H1 | fixed | state only downgraded when the pre-check showed real damage |
| H2 | fixed | `parity sync` stats first; modified files are skipped with a message (exit 2) |
| H3 | fixed | `.bak` is copied *before* the first write of a session and only if the DB matches its recorded hash; a mismatching DB refuses writes (read-only commands warn) — `fsck --fix`/`--rebuild-db` are the escape hatches |
| H4 | fixed | symlinks counted and reported in the scan summary (still not followed) |
| H5 | fixed | paths inside `.checksummer/` are rejected by every command |
| H6 | fixed | `Done::HashedNoTable` → state `unrecoverable` with a "sidecar damaged, run fsck" message |
| H7 | fixed | `import` leaves mismatching not-yet-indexed files unindexed (and discards any sidecar it produced) |
| H8 | fixed | `commands::run` rolls back any open transaction before writing manifests/closing |
| H9 | fixed | discarded results after the first error are counted and reported |
| M1 | fixed | dry-run decodes into a sink, writes nothing |
| M2 | fixed | `*.csrepair.*` ignored by the walk; `--keep-corrupt` moves originals to `.checksummer/quarantine/` |
| M3 | partial | hard links: warning printed; in-place repair not implemented |
| M4/M5 | fixed | single-pass coreutils escaping over raw path bytes; manifest written as bytes |
| M6 | fixed | gitignore-like exclude semantics (documented) |
| M7 | fixed | `Config::validate` requires `stripe_size >= 64 × block_size` and `block_size <= 64 MiB`; `Layout::choose` never exceeds the configured stripe |
| M8 | fixed | `flock` on `.checksummer/lock` for every command |
| M9 | fixed | only `NotFound` marks a file missing; other stat errors are reported |
| M10 | fixed | corrupt-without-parity → `unrecoverable` everywhere |
| M11 | fixed | `index.sqlite.sha256` now covers MANIFEST.txt/.tsv/PARITY_MARKS; rebuild verifies its source |
| M12 | open | sidecar table is still loaded eagerly (fine up to ~100 GB files at 64 KiB blocks); stripe offsets are now O(1) |
| M13 | fixed | SIGPIPE reset to default |
| M14 | unchanged | `-y` stays the documented non-interactive answer; removed files now keep their parity, so a wrong "yes" is recoverable |
| LOW | partially | grown-file message, header validation, `prepare_cached`/perf items left as is |

Not done (deliberately): PAR2, following symlinks, in-place hard-link repair,
preserving uid/gid on repair when run as root (mode and mtime are preserved).
