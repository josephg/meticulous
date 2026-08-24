# meticulous on-disk formats

Everything meticulous stores lives in `<archive>/_meticulous/`:

| file | purpose |
|---|---|
| `config.toml` | algorithm, block/stripe size, parity %, minimum parity, default parity mode, excludes |
| `index.sqlite` | the index (tables `file`, `content`, `parity_set`, `parity_member`, `event`, `parity_mark`, `meta`) |
| `index.sqlite.bak`, `index.sqlite.sha256` | previous good copy of the index + sha256sum-format hashes of both |
| `MANIFEST.txt` | `"<hex>  <path>"` for every indexed file — `b3sum -c` / `sha256sum -c` compatible (run from the archive root) |
| `PARITY_MARKS.txt` | `mode<TAB>dir` lines; lets `fsck --rebuild-db` restore marks |
| `parity/ab/cd/<hex>.mts` | parity-set sidecar for the set whose id is `<hex>` |
| `FORMAT.md` | this document |

Paths are always relative to the archive root, stored as raw bytes.

## Parity sets

Parity is shared across files, PAR2-style. A **parity set** is an ordered list
of members `(content hash, size)`. Each member contributes
`ceil(size / B)` blocks (its last block zero-padded to B; padding is never
stored). The members' blocks concatenated form the set's global block
sequence, which is cut into stripes of at most S blocks — member boundaries
are ignored. Each stripe is an independent Reed–Solomon code over GF(2^16) as
implemented by the `reed-solomon-simd` crate (Leopard-RS, O(n log n),
FFT-based; shard index = block index within the stripe for data, 0.. for
parity). Because damage is *located* by the per-block hash table, damaged or
missing blocks are erasures: up to `p_i` of them per stripe can be rebuilt —
whether they are scattered bit flips, dead filesystem records, or every block
of a member whose file was lost entirely. A wholly-lost small file is
reconstructed from its surviving siblings plus the parity.

Per-stripe parity count:

```
p_i = clamp(max(ceil(d_i * ppm / 1e6), min_parity), 1, d_i)
```

where `d_i` is the stripe's data-block count and `min_parity` is a header
field fixed when the set is created, combining two floors:

- **one filesystem record** (`parity_min_bytes`, set to the ZFS recordsize at
  init): a single dead record is always within the repair margin;
- **the underfull boost**: `ppm` of a FULL packing target's bytes
  (`parity_ppm * stripe_size`), so a set smaller than the target carries the
  same absolute margin a full set would. A tiny set ends up fully duplicated —
  cheap precisely because it is tiny; a full set pays exactly `ppm`.

The set id is `H(header bytes 16..40 || member table)` — it commits to both
the geometry and the member list, so identical sets get identical ids
(idempotent re-encoding, rename-proof) and a sidecar can never be *wrong* for
its id, only unreferenced.

## `.mts` parity-set sidecar (version 2)

All integers little-endian. `dl` = digest length of the algorithm (32 for
blake3/sha256/sha512-256/fletcher4).

```
off     len   field
0       8     magic "MTPARSET"
8       4     version = 2 (u32)
12      1     algo id: 1=blake3 2=sha256 3=sha512-256 4=fletcher4 5=md5 6=sha1
13      1     dl
14      2     reserved (0)
16      4     block size B (u32, multiple of 64)
20      4     blocks per stripe S (u32, <= 32768)
24      4     parity parts-per-million ppm (u32)
28      4     minimum parity blocks per stripe (u32)
32      4     number of members (u32, 1..=32768)
36      4     reserved (0)
40      dl    set id = H(bytes 16..40 || member table)
40+dl   dl    header hash = H(bytes 0 .. 40+dl)
----- member table -----
        n_members * (dl + 8)   content hash + size (u64 LE) per member,
                               in order (integrity: covered by the set id)
----- block hash table -----
        n*dl  H(block i) for i in 0..n over the global block sequence
              (a member's last block is zero-padded to B before hashing)
        dl    table hash = H(table bytes)
----- stripes, i = 0 .. ceil(n / S) -----
        p_i*B parity shards for stripe i
        dl    H(those parity bytes)
```

Every section is independently hashed, so partial sidecar damage degrades
gracefully: a damaged stripe's parity only loses that stripe. The member
table makes sidecars self-describing — `fsck --rebuild-db` reconstructs the
`parity_set`/`parity_member` tables from the sidecars alone (a member whose
content no longer has an indexed file is recorded as dead).

### Per-set block size

The block size adapts per set: `B = clamp(round64(total_bytes / T), 64,
config block_size)` where `T = stripe_size / config block_size` is the target
block count of a full set. Sets of small files get proportionally small
blocks, so per-file padding stays bounded (~B/2 per member) and total parity
overhead stays ≈ ppm. A single file at or above `stripe_size` gets a solo,
multi-stripe set at the configured block size.

### Lifecycle

Sets are sealed. When a member's content is modified or its last file leaves
the index, the membership is marked **dead** in the database: its blocks are
permanent erasures that consume margin until the set is rebuilt. `scan` (and
`parity sync`) automatically dissolve degraded and underfull sets and repack
their live members — but only when every live member is intact on disk; a set
holding the only repair source for a damaged member is kept until that member
is repaired, accepted, or removed. `meticulous rm` deletes files in the safe
order: rebuild the affected sets without them first, then delete.

Crash safety: sidecars are written under `parity/tmp/`, renamed into place,
recorded in one DB transaction, and superseded sidecars are unlinked last.
Every intermediate state converges: temp files are swept at startup, a valid
orphan sidecar is adopted (or removed) by the next parity phase, and set ids
are content-derived so re-runs are idempotent.

## ZFS notes

ZFS checksums are per record (block pointer), cover the *compressed* on-disk
bytes, and `checksum=on` means fletcher4. `zdb -ddddd <dataset> <inode>` shows
them as `cksum=a:b:c:d`. meticulous's `fletcher4` reproduces ZFS's native
(little-endian word) algorithm. ZFS's blake3/skein/edonr are salted per pool
and cannot be reproduced outside the pool.

When ZFS detects an unhealable checksum error it returns EIO for the whole
record; meticulous reads around the bad record, treats its blocks as erasures
and rebuilds them from the parity set. A small file whose only record died is
rebuilt entirely from its set siblings. `parity_min_bytes` (default: the
recordsize) guarantees at least one record's worth of parity per stripe.
