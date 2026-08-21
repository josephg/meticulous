//! Single-pass file processing: whole-file hash, per-block hashes and
//! Reed–Solomon parity generation; plus block verification and repair.

use crate::mtp::{Header, Layout, Reader, Writer};
use crate::hash::Algo;
use anyhow::{Context, Result, bail, ensure};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const READ_CHUNK: usize = 1 << 20;

/// Read `buf.len()` bytes or until EOF; returns bytes read.
fn read_full(f: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(r) => n += r,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Hash a whole file (no parity, no blocks). Returns (hash, bytes read).
pub fn hash_file(path: &Path, algo: Algo) -> Result<(Vec<u8>, u64)> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut h = algo.hasher();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut total = 0u64;
    loop {
        let n = read_full(&mut f, &mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
        if n < buf.len() {
            break;
        }
    }
    Ok((h.finish(), total))
}

pub struct Encoded {
    pub file_hash: Vec<u8>,
    pub bytes_read: u64,
}

/// Read the file once, computing the whole-file hash, every block hash and
/// the parity for each stripe, writing the sidecar to `sidecar_path`.
/// `expected_size` must match what the layout was built from; if the file
/// changes size underneath us we bail (the caller rescans).
pub fn encode_file(path: &Path, algo: Algo, layout: Layout, sidecar_path: &Path) -> Result<Encoded> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let header = Header { algo, layout, file_hash: vec![0u8; algo.digest_len()] };
    let mut w = Writer::create(sidecar_path, header)?;
    let res = encode_inner(&mut f, algo, layout, &mut w);
    match res {
        Ok(enc) => {
            w.finish(&enc.file_hash)?;
            Ok(enc)
        }
        Err(e) => {
            w.abort();
            Err(e)
        }
    }
}

fn encode_inner(f: &mut File, algo: Algo, layout: Layout, w: &mut Writer) -> Result<Encoded> {
    let bs = layout.block_size as usize;
    let stripe_cap = (layout.blocks_per_stripe as u64).min(layout.n_blocks().max(1)) as usize * bs;
    let mut buf = vec![0u8; stripe_cap];
    let mut file_hasher = algo.hasher();
    let mut block_hasher = algo.hasher();
    let mut total = 0u64;
    let mut encoder: Option<ReedSolomonEncoder> = None;

    for stripe in 0..layout.n_stripes() {
        let n_data = layout.stripe_data_blocks(stripe) as usize;
        let n_par = layout.stripe_parity_blocks(stripe) as usize;
        let want = ((layout.file_size - total) as usize).min(n_data * bs);
        let got = read_full(f, &mut buf[..want])?;
        if got != want {
            bail!("file shrank while reading ({} bytes read, expected {})", total + got as u64, layout.file_size);
        }
        // zero pad the tail block
        buf[want..n_data * bs].fill(0);
        total += want as u64;
        file_hasher.update(&buf[..want]);

        let enc = match encoder.as_mut() {
            Some(e) => {
                e.reset(n_data, n_par, bs)?;
                e
            }
            None => encoder.insert(ReedSolomonEncoder::new(n_data, n_par, bs)?),
        };
        for b in 0..n_data {
            let shard = &buf[b * bs..(b + 1) * bs];
            block_hasher.update(shard);
            w.push_block_hash(&block_hasher.finish_reset());
            enc.add_original_shard(shard)?;
        }
        let result = enc.encode()?;
        w.write_stripe(result.recovery_iter())?;
    }
    // Ensure the file did not grow.
    let mut probe = [0u8; 1];
    if read_full(f, &mut probe)? != 0 {
        bail!("file grew while reading");
    }
    Ok(Encoded { file_hash: file_hasher.finish(), bytes_read: total })
}

/// Random-access byte source. Abstracted so tests can inject EIO on chosen
/// blocks; `File` is the real one.
pub trait BlockSource {
    /// Read up to `buf.len()` bytes at `off`; short reads only at EOF.
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> std::io::Result<usize>;
}

impl BlockSource for File {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::os::unix::fs::FileExt;
        let mut n = 0;
        while n < buf.len() {
            match FileExt::read_at(self, &mut buf[n..], off + n as u64) {
                Ok(0) => break,
                Ok(r) => n += r,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(n)
    }
}

fn is_io_data_error(e: &std::io::Error) -> bool {
    // EIO: the filesystem (e.g. ZFS) refused to return a block whose checksum failed.
    e.raw_os_error() == Some(5) || e.kind() == std::io::ErrorKind::InvalidData
}

/// Read `[off, off+len)` in block-sized pieces, tolerating EIO per block.
/// Returns bytes read (contiguous-valid length up to EOF) and the indices
/// (relative to `off / bs`) of blocks that could not be read; those bytes are
/// left zeroed. Non-EIO errors propagate.
fn read_region_tolerant(src: &mut dyn BlockSource, off: u64, buf: &mut [u8], bs: usize) -> std::io::Result<(usize, Vec<usize>)> {
    match src.read_at(off, buf) {
        Ok(n) => Ok((n, vec![])),
        Err(e) if is_io_data_error(&e) => {
            // Retry block by block so one bad record only loses its own blocks.
            let mut unreadable = Vec::new();
            let mut total = 0usize;
            let mut eof = false;
            let mut i = 0usize;
            while i * bs < buf.len() && !eof {
                let s = i * bs;
                let e = (s + bs).min(buf.len());
                match src.read_at(off + s as u64, &mut buf[s..e]) {
                    Ok(n) => {
                        total = s + n;
                        if n < e - s {
                            eof = true;
                        }
                    }
                    Err(e2) if is_io_data_error(&e2) => {
                        buf[s..e].fill(0);
                        unreadable.push(i);
                        total = e;
                    }
                    Err(e2) => return Err(e2),
                }
                i += 1;
            }
            Ok((total, unreadable))
        }
        Err(e) => Err(e),
    }
}

/// Result of verifying a file against its sidecar.
#[derive(Debug, Default)]
pub struct BlockCheck {
    pub file_hash: Vec<u8>,
    pub actual_size: u64,
    pub n_blocks: u64,
    /// Indices of blocks whose content hash does not match (includes blocks
    /// missing because the file is shorter than recorded).
    pub bad_blocks: Vec<u64>,
    /// Subset of `bad_blocks` the filesystem refused to read at all (EIO —
    /// on ZFS: a record whose checksum failed and could not be healed).
    pub unreadable_blocks: Vec<u64>,
    /// Stripes that have more bad blocks than parity blocks.
    pub unrecoverable_stripes: Vec<u64>,
    /// Bytes present on disk beyond the recorded file size.
    pub extra_bytes: u64,
}

impl BlockCheck {
    pub fn ok(&self, expected_hash: &[u8]) -> bool {
        self.bad_blocks.is_empty() && self.file_hash == expected_hash
    }
    pub fn repairable(&self) -> bool {
        self.unrecoverable_stripes.is_empty()
    }
}

/// Hash every block and the whole file, compare blocks with the sidecar table.
pub fn check_blocks(path: &Path, sc: &Reader) -> Result<BlockCheck> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    check_blocks_from(&mut f, sc)
}

pub fn check_blocks_from(src: &mut dyn BlockSource, sc: &Reader) -> Result<BlockCheck> {
    ensure!(sc.table_ok(), "sidecar block table is damaged; per-block check impossible");
    let layout = *sc.layout();
    let algo = sc.algo();
    let bs = layout.block_size as usize;
    let mut buf = vec![0u8; bs.max(READ_CHUNK / bs * bs)];
    let mut file_hasher = algo.hasher();
    let mut block_hasher = algo.hasher();
    let mut out = BlockCheck { n_blocks: layout.n_blocks(), ..Default::default() };
    let mut block = 0u64;
    let n_blocks = layout.n_blocks();
    let mut bad_per_stripe: std::collections::BTreeMap<u64, u32> = Default::default();
    let mut pos = 0u64;

    loop {
        let (n, unreadable) = read_region_tolerant(src, pos, &mut buf, bs)?;
        if n == 0 {
            break;
        }
        pos += n as u64;
        out.actual_size += n as u64;
        file_hasher.update(&buf[..n]);
        let first_block_in_chunk = block;
        let mut off = 0;
        while off < n {
            let end = (off + bs).min(n);
            let idx_in_chunk = (block - first_block_in_chunk) as usize;
            let this_unreadable = unreadable.contains(&idx_in_chunk);
            if block < n_blocks {
                let (bstart, bend) = layout.block_range(block);
                let expect_len = (bend - bstart) as usize;
                let ok = if this_unreadable {
                    out.unreadable_blocks.push(block);
                    false
                } else if end - off == expect_len {
                    block_hasher.update(&buf[off..end]);
                    if expect_len < bs {
                        let pad = vec![0u8; bs - expect_len];
                        block_hasher.update(&pad);
                    }
                    block_hasher.finish_reset() == sc.block_hash(block)
                } else {
                    false
                };
                if !ok {
                    out.bad_blocks.push(block);
                    *bad_per_stripe.entry(layout.stripe_of_block(block)).or_default() += 1;
                }
            }
            block += 1;
            off = end;
        }
        if n < buf.len() {
            break;
        }
    }
    // Blocks we never saw (file truncated).
    while block < n_blocks {
        out.bad_blocks.push(block);
        *bad_per_stripe.entry(layout.stripe_of_block(block)).or_default() += 1;
        block += 1;
    }
    out.file_hash = if out.unreadable_blocks.is_empty() { file_hasher.finish() } else { Vec::new() };
    out.extra_bytes = out.actual_size.saturating_sub(layout.file_size);
    for (stripe, bad) in bad_per_stripe {
        if bad > layout.stripe_parity_blocks(stripe) {
            out.unrecoverable_stripes.push(stripe);
        }
    }
    Ok(out)
}

#[derive(Debug)]
pub struct RepairOutcome {
    pub blocks_repaired: usize,
}

/// Rebuild `path` from its good blocks + sidecar parity. Writes the repaired
/// file to a temp file next to the original, verifies its whole-file hash
/// against the sidecar, then atomically renames it over the original
/// (optionally keeping the damaged original as `<name>.corrupt`).
/// `keep_corrupt`: where to move the damaged original (outside the scanned
/// tree, e.g. `_meticulous/quarantine/...`) instead of deleting it.
pub fn repair_file(path: &Path, sc: &mut Reader, check: &BlockCheck, keep_corrupt: Option<&Path>, dry_run: bool) -> Result<RepairOutcome> {
    let mut src_file = File::open(path)?;
    repair_file_from(&mut src_file, path, sc, check, keep_corrupt, dry_run)
}

pub fn repair_file_from(src: &mut dyn BlockSource, path: &Path, sc: &mut Reader, check: &BlockCheck, keep_corrupt: Option<&Path>, dry_run: bool) -> Result<RepairOutcome> {
    ensure!(check.repairable(), "stripes {:?} have more damaged blocks than parity blocks", check.unrecoverable_stripes);
    let layout = *sc.layout();
    let algo = sc.algo();
    let bs = layout.block_size as usize;
    let expected_hash = sc.header.file_hash.clone();

    let tmp_path = temp_sibling(path, ".mtrepair");
    // In dry-run mode nothing is written to disk: decode into a sink and only hash.
    let mut out: BufWriter<Box<dyn Write>> = if dry_run {
        BufWriter::new(Box::new(std::io::sink()))
    } else {
        let tmp_file = File::create(&tmp_path).with_context(|| format!("creating {}", tmp_path.display()))?;
        BufWriter::with_capacity(1 << 20, Box::new(tmp_file))
    };
    let mut out_hasher = algo.hasher();
    let mut stripe_buf = vec![0u8; layout.stripe_bytes().min(layout.n_blocks().max(1) * bs as u64) as usize];
    let mut bad_iter = check.bad_blocks.iter().copied().peekable();
    let mut repaired = 0usize;

    for stripe in 0..layout.n_stripes() {
        let n_data = layout.stripe_data_blocks(stripe) as usize;
        let n_par = layout.stripe_parity_blocks(stripe) as usize;
        let first = layout.first_block_of_stripe(stripe);
        let start = first * bs as u64;
        // Read whatever the file has for this stripe (may be short; EIO blocks are zeroed and treated as bad).
        let want = n_data * bs;
        let (got, unreadable) = read_region_tolerant(src, start, &mut stripe_buf[..want], bs)?;
        stripe_buf[got..want].fill(0);

        let mut bad_here = Vec::new();
        while let Some(&b) = bad_iter.peek() {
            if b < first + n_data as u64 {
                bad_here.push((b - first) as usize);
                bad_iter.next();
            } else {
                break;
            }
        }
        for u in unreadable {
            if u < n_data && !bad_here.contains(&u) {
                bad_here.push(u);
            }
        }
        bad_here.sort_unstable();
        ensure!(bad_here.len() <= n_par, "stripe {stripe}: {} damaged/unreadable blocks exceed {} parity blocks", bad_here.len(), n_par);
        if !bad_here.is_empty() {
            let parity = sc.read_stripe(stripe)?;
            let mut dec = ReedSolomonDecoder::new(n_data, n_par, bs)?;
            for b in 0..n_data {
                if !bad_here.contains(&b) {
                    dec.add_original_shard(b, &stripe_buf[b * bs..(b + 1) * bs])?;
                }
            }
            for (i, p) in parity.iter().enumerate() {
                dec.add_recovery_shard(i, p)?;
            }
            let res = dec.decode()?;
            for &b in &bad_here {
                let restored = res
                    .restored_original(b)
                    .with_context(|| format!("decoder did not restore block {}", first + b as u64))?;
                stripe_buf[b * bs..(b + 1) * bs].copy_from_slice(restored);
                repaired += 1;
            }
        }
        // Write the stripe's real bytes (trim padding on the last block).
        let stripe_end = ((first + n_data as u64) * bs as u64).min(layout.file_size);
        let real = (stripe_end - start) as usize;
        out.write_all(&stripe_buf[..real])?;
        out_hasher.update(&stripe_buf[..real]);
    }
    out.flush()?;
    let got_hash = out_hasher.finish();
    if got_hash != expected_hash {
        drop(out);
        if !dry_run {
            let _ = std::fs::remove_file(&tmp_path);
        }
        bail!("repaired data does not match the recorded file hash; repair aborted (is the sidecar for this exact file?)");
    }
    drop(out);
    if dry_run {
        return Ok(RepairOutcome { blocks_repaired: repaired });
    }
    {
        let f = File::open(&tmp_path)?;
        f.sync_all()?;
    }
    // Preserve permissions / mtime so the DB fast path stays valid.
    let meta = std::fs::metadata(path)?;
    if std::os::unix::fs::MetadataExt::nlink(&meta) > 1 {
        eprintln!(
            "warning: {} has {} hard links; the repaired copy replaces only this name (other links keep the damaged bytes)",
            path.display(),
            std::os::unix::fs::MetadataExt::nlink(&meta)
        );
    }
    let _ = std::fs::set_permissions(&tmp_path, meta.permissions());
    if let Ok(mtime) = meta.modified() {
        let _ = File::options().write(true).open(&tmp_path).and_then(|f| f.set_modified(mtime));
    }
    if let Some(q) = keep_corrupt {
        if let Some(parent) = q.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(path, q).with_context(|| format!("keeping damaged copy as {}", q.display()))?;
    }
    std::fs::rename(&tmp_path, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(RepairOutcome { blocks_repaired: repaired })
}

fn temp_sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(suffix);
    name.push(format!(".{}", std::process::id()));
    path.with_file_name(name)
}


/// Convenience: open a sidecar and verify that it belongs to `expected_hash`.
pub fn open_sidecar(sidecar: &Path, expected_hash: &[u8]) -> Result<Reader> {
    let r = Reader::open(sidecar)?;
    ensure!(r.header.file_hash == expected_hash, "sidecar file hash does not match the database record");
    Ok(r)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    fn mk(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    fn pseudo(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 24) as u8
            })
            .collect()
    }

    fn encode_then_damage(size: usize, block: u32, stripe: u64, ppm: u32, damage: &[u64], truncate_to: Option<u64>) -> (bool, bool) {
        let dir = tempfile::tempdir().unwrap();
        let data = pseudo(size, size as u32);
        let file = mk(dir.path(), "f.bin", &data);
        let layout = Layout::choose(size as u64, block, stripe, ppm);
        let sc_path = dir.path().join("f.mtp");
        let enc = encode_file(&file, Algo::Blake3, layout, &sc_path).unwrap();
        assert_eq!(enc.file_hash, Algo::Blake3.hash(&data));
        assert_eq!(enc.bytes_read, size as u64);
        let mut sc = Reader::open(&sc_path).unwrap();
        assert!(sc.table_ok());
        assert!(sc.deep_check().unwrap().is_empty());
        // clean check
        let c = check_blocks(&file, &sc).unwrap();
        assert!(c.ok(&enc.file_hash), "clean file should verify: {c:?}");

        // damage
        {
            let mut f = File::options().write(true).open(&file).unwrap();
            for &b in damage {
                let (s, e) = layout.block_range(b);
                f.seek(SeekFrom::Start(s)).unwrap();
                let mut byte = [0u8; 1];
                let _ = f.read(&mut byte);
                f.seek(SeekFrom::Start(s)).unwrap();
                f.write_all(&[byte[0] ^ 0xA5]).unwrap();
                let _ = e;
            }
            if let Some(t) = truncate_to {
                f.set_len(t).unwrap();
            }
        }
        let c = check_blocks(&file, &sc).unwrap();
        if damage.is_empty() && truncate_to.is_none() {
            return (true, true);
        }
        assert!(!c.ok(&enc.file_hash));
        let repairable = c.repairable();
        if repairable {
            // dry run first: must not touch anything
            let before = std::fs::read(&file).unwrap();
            let r0 = repair_file(&file, &mut sc, &c, None, true).unwrap();
            assert!(r0.blocks_repaired > 0);
            assert_eq!(std::fs::read(&file).unwrap(), before);
            assert!(!dir.path().join("f.bin.mtrepair").exists());
            let q = dir.path().join("q/f.bin.corrupt");
            let r = repair_file(&file, &mut sc, &c, Some(&q), false).unwrap();
            assert!(r.blocks_repaired > 0);
            assert_eq!(std::fs::read(&file).unwrap(), data);
            assert!(q.exists());
            let c2 = check_blocks(&file, &sc).unwrap();
            assert!(c2.ok(&enc.file_hash));
        } else {
            assert!(repair_file(&file, &mut sc, &c, None, false).is_err());
        }
        (true, repairable)
    }

    #[test]
    fn roundtrip_tiny_file_one_bad_block() {
        assert_eq!(encode_then_damage(100, 65536, 128 << 20, 50_000, &[1], None), (true, true));
    }

    #[test]
    fn roundtrip_multi_stripe() {
        // block 64, stripe = 64 blocks (4096 B), 5% -> 4 parity / stripe. 20000 B => 313 blocks, 5 stripes.
        assert_eq!(encode_then_damage(20_000, 64, 4096, 50_000, &[0, 3, 70, 200, 312], None), (true, true));
    }

    #[test]
    fn too_much_damage_in_one_stripe() {
        assert_eq!(encode_then_damage(20_000, 64, 4096, 50_000, &[0, 1, 2, 3, 4], None), (true, false));
    }

    #[test]
    fn truncated_file_is_repairable_within_parity() {
        // last stripe: 313-256=57 blocks, parity 3. Truncate away last 2 blocks.
        assert_eq!(encode_then_damage(20_000, 64, 4096, 50_000, &[], Some(20_000 - 64 - 32)), (true, true));
    }

    /// A file whose filesystem refuses to read some blocks (EIO), like ZFS
    /// does for records that fail their checksum.
    struct EioSource {
        file: File,
        bad_blocks: Vec<u64>,
        bs: u64,
    }
    impl BlockSource for EioSource {
        fn read_at(&mut self, off: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let first = off / self.bs;
            let last = (off + buf.len() as u64).div_ceil(self.bs);
            if self.bad_blocks.iter().any(|&b| b >= first && b < last) {
                return Err(std::io::Error::from_raw_os_error(5));
            }
            BlockSource::read_at(&mut self.file, off, buf)
        }
    }

    #[test]
    fn eio_blocks_are_erasures_and_repairable() {
        let dir = tempfile::tempdir().unwrap();
        let data = pseudo(20_000, 21);
        let file = mk(dir.path(), "f", &data);
        let layout = Layout::choose(20_000, 64, 4096, 50_000); // 64 blocks/stripe, 4 parity
        let sc_path = dir.path().join("f.mtp");
        let enc = encode_file(&file, Algo::Blake3, layout, &sc_path).unwrap();
        let mut sc = Reader::open(&sc_path).unwrap();
        // ZFS-style: a 128-byte "record" (2 blocks) unreadable in stripe 0, one block in stripe 3
        let mut src = EioSource { file: File::open(&file).unwrap(), bad_blocks: vec![10, 11, 200], bs: 64 };
        let c = check_blocks_from(&mut src, &sc).unwrap();
        assert_eq!(c.unreadable_blocks, vec![10, 11, 200]);
        assert_eq!(c.bad_blocks, vec![10, 11, 200]);
        assert!(c.repairable());
        assert!(!c.ok(&enc.file_hash));
        let r = repair_file_from(&mut src, &file, &mut sc, &c, None, false).unwrap();
        assert_eq!(r.blocks_repaired, 3);
        assert_eq!(std::fs::read(&file).unwrap(), data);
        // too many unreadable blocks in one stripe -> unrecoverable
        let mut src = EioSource { file: File::open(&file).unwrap(), bad_blocks: vec![1, 2, 3, 4, 5], bs: 64 };
        let c = check_blocks_from(&mut src, &sc).unwrap();
        assert!(!c.repairable());
    }

    #[test]
    fn empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = mk(dir.path(), "e", b"");
        let layout = Layout::choose(0, 65536, 128 << 20, 50_000);
        let sc_path = dir.path().join("e.mtp");
        let enc = encode_file(&file, Algo::Sha256, layout, &sc_path).unwrap();
        assert_eq!(enc.file_hash, Algo::Sha256.hash(b""));
        let sc = Reader::open(&sc_path).unwrap();
        let c = check_blocks(&file, &sc).unwrap();
        assert!(c.ok(&enc.file_hash));
    }

    #[test]
    fn damaged_sidecar_stripe_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let data = pseudo(20_000, 9);
        let file = mk(dir.path(), "f", &data);
        let layout = Layout::choose(20_000, 64, 4096, 50_000);
        let sc_path = dir.path().join("f.mtp");
        encode_file(&file, Algo::Blake3, layout, &sc_path).unwrap();
        let mut sc = Reader::open(&sc_path).unwrap();
        let off = sc.header.stripe_offset(2) + 5;
        {
            let mut f = File::options().write(true).open(&sc_path).unwrap();
            f.seek(SeekFrom::Start(off)).unwrap();
            f.write_all(&[0xFF]).unwrap();
        }
        let mut sc2 = Reader::open(&sc_path).unwrap();
        let probs = sc2.deep_check().unwrap();
        assert_eq!(probs.len(), 1, "{probs:?}");
        assert!(sc2.read_stripe(1).is_ok());
        assert!(sc2.read_stripe(2).is_err());
        let _ = &mut sc;
    }
}
