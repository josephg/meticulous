# checksummer on-disk formats

Everything checksummer stores lives in `<archive>/.checksummer/`:

| file | purpose |
|---|---|
| `config.toml` | algorithm, block/stripe size, parity %, default parity mode, excludes |
| `index.sqlite` | the index (tables `file`, `content`, `event`, `parity_mark`, `zfs_record`, `meta`) |
| `index.sqlite.bak`, `index.sqlite.sha256` | previous good copy of the index + sha256sum-format hashes of both |
| `MANIFEST.txt` | `"<hex>  <path>"` for every indexed file — `b3sum -c` / `sha256sum -c` compatible (run from the archive root) |
| `PARITY_MARKS.txt` | `mode<TAB>dir` lines; lets `fsck --rebuild-db` restore marks |
| `parity/ab/cd/<hex>.csp` | parity sidecar for the content whose hash is `<hex>` |
| `FORMAT.md` | this document |

Paths are always relative to the archive root, stored as raw bytes.

## `.csp` parity sidecar (version 1)

All integers little-endian. `dl` = digest length of the algorithm (32 for
blake3/sha256/sha512-256/fletcher4).

```
off     len   field
0       8     magic "CSPARITY"
8       4     version = 1 (u32)
12      1     algo id: 1=blake3 2=sha256 3=sha512-256 4=fletcher4 5=md5 6=sha1
13      1     dl
14      2     reserved (0)
16      8     file size (u64)
24      4     block size B (u32, multiple of 64)
28      4     blocks per stripe S (u32)
32      4     parity parts-per-million ppm (u32)
36      4     reserved (0)
40      dl    whole-file hash
40+dl   dl    header hash = H(bytes 0 .. 40+dl)
----- block hash table -----
        n*dl  H(block i) for i in 0..n, n = ceil(file_size / B); the last block is
              zero-padded to B bytes before hashing
        dl    table hash = H(table bytes)
----- stripes, i = 0 .. ceil(n / S) -----
        p_i*B parity shards for stripe i
        dl    H(those parity bytes)
```

Stripe `i` covers data blocks `[i*S, min((i+1)*S, n))`; it has
`d_i` data blocks and `p_i = clamp(ceil(d_i * ppm / 1e6), 1, d_i)` parity blocks.
Each stripe is an independent Reed–Solomon code over GF(2^16) as implemented
by the `reed-solomon-simd` crate (Leopard-RS, O(n log n) FFT-based; shard
index = block index within the stripe for data, 0.. for parity). Up to `p_i`
damaged or missing blocks per stripe can be rebuilt. Which blocks are damaged
is determined by the block hash table; blocks beyond the current end of a
truncated file count as missing.

Small files use a smaller block size (the layout aims for >= 64 blocks), so the
minimum one parity block per stripe stays proportionate.

## ZFS notes

ZFS checksums are per record (block pointer), cover the *compressed* on-disk
bytes, and `checksum=on` means fletcher4. `zdb -ddddd <dataset> <inode>` shows
them as `cksum=a:b:c:d`. checksummer's `fletcher4` reproduces ZFS's native
(little-endian word) algorithm. ZFS's blake3/skein/edonr are salted per pool
and cannot be reproduced outside the pool.
