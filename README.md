# checksummer

Keep a long-lived archive (backups, photos, music…) safe from bit rot:
checksummer maintains an index of per-file checksums **inside the archive**
(`<archive>/.checksummer/`), verifies files on demand, and — for the
directories you choose — stores **Reed–Solomon parity** so a bounded amount of
damage in each file can be *repaired*, not just detected.

* Hashes: `blake3` (default), `sha256`, `sha512-256`, `fletcher4` — the last
  three are the algorithms ZFS can use, and `fletcher4` reproduces ZFS's native
  checksum exactly. Every stored digest is tagged with its algorithm.
* Parity: per file, a configurable percentage (default 5 %) of Reed–Solomon
  parity in a small documented sidecar format (see `FORMAT.md`). Any `k` bad
  or missing blocks per stripe are rebuildable, where `k` = number of parity
  blocks in that stripe. Which blocks are bad is known from per-block hashes.
* Index: SQLite (`index.sqlite`) plus a plaintext `MANIFEST.txt` that
  `b3sum -c` / `sha256sum -c` can verify without checksummer, a
  `MANIFEST.tsv` (hash, size, mtime, state per file), a `.bak` copy of the
  database taken *before* each writing command, and an `index.sqlite.sha256`
  covering all of them. A database that no longer matches its recorded hash
  is never written to (or copied over `.bak`); the index can be rebuilt from
  the manifests if it is ever lost.

## Quick start

```sh
cargo install --path .            # or cargo build --release

cd /archive
checksummer init                  # creates .checksummer/ (blake3, 64 KiB blocks, 5 % parity)
checksummer parity include photos # subtrees of 'photos' get parity...
checksummer parity exclude photos/2005/raw   # ...except this one (nearest mark wins)
checksummer scan                  # hash everything, generate parity where covered
checksummer check                 # later: re-read and verify everything
checksummer check --repair        # verify and repair what parity allows
```

All paths printed/accepted are relative to the archive root (the directory
holding `.checksummer/`); you can run commands from any subdirectory.

## Commands

| command | what it does |
|---|---|
| `init [DIR] [--algo] [--block-size] [--parity 5%] [--stripe-size] [--parity-default include\|exclude] [--exclude GLOB]` | create an archive |
| `scan [PATHS] [--no-accept-changes] [--no-parity] [-j N]` | find added/removed/modified files. New files are hashed (+parity if covered) automatically. Files whose size/mtime changed are re-hashed and accepted as edits. Removed files are listed and you are asked whether to drop them from the index (`-y`/`-n` to answer non-interactively). Renames are detected by content. |
| `check [PATHS] [--older-than 30d] [--budget 200GiB] [--repair] [-j N]` (alias `verify`) | re-read files and compare to the recorded hashes. Exit code 2 if anything is wrong. `--older-than/--budget` let you scrub incrementally, least-recently-verified first. |
| `accept PATHS` | record the current on-disk content of the named files (or every flagged file under a directory) as the truth — the override for *SUSPECTED CORRUPTION* / `modified` / `corrupt` when you know the content is right |
| `repair PATHS [--keep-corrupt] [--dry-run]` | rebuild corrupt files from parity (writes a temp file, verifies the whole-file hash, then atomically replaces the original) |
| `parity include\|exclude\|unmark DIRS`, `parity list`, `parity sync [--prune]` | choose which subtrees store parity; generate missing parity / delete parity no longer wanted |
| `status`, `ls [--state S] [--parity] [-l]`, `show PATH`, `history [PATH] [--since 7d]` | inspect |
| `export [--format sum\|json] [-o FILE]` | plaintext manifest |
| `import FILE [--algo md5\|sha1\|…] [--relative-to DIR] [--trust]` | verify files against an old `md5sum`/`sha1sum`/`sha256sum`/`b3sum` list and index any files not yet known |
| `fsck [--deep] [--fix] [--rebuild-db]` | check SQLite integrity, the database's own hash, every parity sidecar; rebuild the index from `MANIFEST.txt` |
| `config [KEY [VALUE]]` | show/change settings |

Global flags: `--root DIR`, `-q`, `--json`, `-y`, `-n`. Only one checksummer
runs per archive at a time (`.checksummer/lock`). A visible `.zfs` snapshot
directory at the root is never walked.

Exclude patterns (`init --exclude`, `config exclude a,b`) follow gitignore-like
rules: `cache` or `*.tmp` match a name at any depth; `photos/raw` is anchored
at the root; `*` never crosses `/`. Symlinks are never followed (the summary
counts them).

## How corruption is told apart from edits

* mtime unchanged but content (or size) differs → **bit rot**: state `corrupt`
  (`unrecoverable` if there is no/insufficient parity). The stored hash is never
  overwritten by a corrupt reading.
* mtime changed → probably an edit. `check` reports it as `modified` without
  accepting; `scan` accepts it — **except** when the old content has parity,
  the size is unchanged and only a few blocks differ (few enough for parity to
  fix): that pattern is a timestamp reset plus bit rot (`cp` without `-p`,
  restores without timestamps…), so `scan` reports *SUSPECTED CORRUPTION*,
  keeps the recorded hash, and `repair` restores the recorded content.
* `repair` refuses to touch a file whose mtime differs from the index (it may
  be a deliberate newer version); `scan` first, or `accept` it.
* Interrupting a long `scan`/`check` (Ctrl-C, reboot) is safe: committed
  progress is kept and the next run continues; files are only recorded once
  fully hashed.
* A file that changes *while* it is being hashed is not recorded ("changed
  while scanning"); re-run `scan`.
* Files whose directory could not be read (permissions, unmounted disk) are
  left alone — never treated as removed. Removing files from the index keeps
  their parity on disk until `fsck --fix` deletes the orphans.
* Repairs write a temp file, verify the whole-file hash, then atomically
  replace the original; `--keep-corrupt` moves the damaged original to
  `.checksummer/quarantine/<path>`; `--dry-run` writes nothing.

## Parity details

* Files are split into blocks (default 64 KiB; smaller for small files) and
  stripes (default 128 MiB of data). Each stripe gets `ceil(5 % × blocks)`
  (min 1) parity blocks. A single flipped bit costs one block of parity, so
  e.g. a 1 GiB file can survive ~100 scattered bad blocks per stripe.
* Parity is keyed by content hash, so duplicates share it and renames keep it.
* Sidecars are self-describing and section-hashed: damage to a sidecar only
  loses the damaged stripe's parity; `fsck --deep` finds it and
  `fsck --fix && parity sync` regenerates it from the intact file.
* Memory per worker ≈ stripe size + parity; set `--stripe-size`/`-j` for
  small machines.

## ZFS

ZFS verifies every block's checksum on every read, so `scan`/`check` (which
read every byte) are also a ZFS integrity check of each file: a block ZFS
cannot heal makes the read fail with `EIO`, which checksummer reports as
`READ ERROR` with a pointer to `zpool status -v` (and marks the file
`unrecoverable` rather than recording a hash). Before the first scan it is worth
running `zpool status -v` (and optionally a `zpool scrub`). Note ZFS can only
vouch for data since it was written to ZFS — damage that happened on older
disks is invisible to it; use `import` with your old md5/sha1 lists for that.

ZFS's own checksums are per record, computed over the *compressed* on-disk
bytes, `fletcher4` by default, and its blake3/skein/edonr are salted per pool.
checksummer can hash with `--algo fletcher4|sha256|sha512-256` (ZFS's
reproducible algorithms; `fletcher4` is not cryptographic) and `init` on a ZFS
dataset defaults the block size to the recordsize, but record-by-record
comparison against zdb is deliberately not implemented for now.

## Exit codes

`0` ok · `1` error · `2` problems found (corrupt/missing/modified files,
mismatches, damaged parity).
