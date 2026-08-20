//! The `.csp` parity sidecar format ("checksummer parity"). See FORMAT.md.
//!
//! All integers little-endian. `dl` = digest length of `algo`.
//!
//! ```text
//! off  len  field
//! 0    8    magic  "CSPARITY"
//! 8    4    version (u32) = 1
//! 12   1    algo id (see hash::Algo::id)
//! 13   1    digest length dl
//! 14   2    reserved (0)
//! 16   8    file size (u64)
//! 24   4    block size (u32, multiple of 64)
//! 28   4    blocks per stripe (u32)
//! 32   4    parity parts-per-million (u32)
//! 36   4    reserved (0)
//! 40   dl   whole-file hash
//! 40+dl dl  header hash = H(bytes 0 .. 40+dl)
//! ---- block hash table ----
//!      n_blocks*dl   hash of every data block (last block zero-padded to block size)
//!      dl            table hash = H(table)
//! ---- stripes, in order ----
//!      p_i*block_size  parity shards for stripe i (p_i = parity_blocks(n_data_i))
//!      dl              H(those parity bytes)
//! ```
//! Everything needed to decode is derivable from the header, so any single
//! damaged section only loses that section: a damaged stripe's parity still
//! leaves every other stripe repairable.

use crate::hash::Algo;
use anyhow::{Context, Result, bail, ensure};
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 8] = b"CSPARITY";
pub const VERSION: u32 = 1;
pub const FIXED_HEADER_LEN: usize = 40;
/// reed-solomon-simd limit we stay under per stripe.
pub const MAX_DATA_BLOCKS_PER_STRIPE: u64 = 32768;
pub const MIN_BLOCK_SIZE: u32 = 64;
pub const MAX_BLOCK_SIZE: u32 = 64 * 1024 * 1024;

/// Geometry of one file's blocks/stripes/parity. Fully determined by the
/// header fields, so it can be recomputed from any sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub file_size: u64,
    pub block_size: u32,
    pub blocks_per_stripe: u32,
    pub parity_ppm: u32,
}

impl Layout {
    /// Pick a layout for a file. Small files get a smaller block size so the
    /// mandatory single parity block is not absurdly large relative to the file.
    /// The stripe never exceeds `cfg_stripe_bytes` (which Config::validate
    /// guarantees is >= 64 blocks) so memory per worker stays bounded.
    pub fn choose(file_size: u64, cfg_block_size: u32, cfg_stripe_bytes: u64, parity_ppm: u32) -> Layout {
        let cfg_block_size = cfg_block_size.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE).next_multiple_of(64);
        let mut block_size = cfg_block_size as u64;
        // Aim for >= 64 blocks for small files.
        if file_size < block_size * 64 {
            block_size = file_size.div_ceil(64).next_multiple_of(64).max(MIN_BLOCK_SIZE as u64);
        }
        let block_size = block_size.min(cfg_block_size as u64) as u32;
        let bps = (cfg_stripe_bytes.max(block_size as u64) / block_size as u64).clamp(1, MAX_DATA_BLOCKS_PER_STRIPE);
        Layout {
            file_size,
            block_size,
            blocks_per_stripe: bps as u32,
            parity_ppm: parity_ppm.min(1_000_000),
        }
    }

    pub fn n_blocks(&self) -> u64 {
        self.file_size.div_ceil(self.block_size as u64)
    }
    pub fn n_stripes(&self) -> u64 {
        self.n_blocks().div_ceil(self.blocks_per_stripe as u64)
    }
    pub fn stripe_data_blocks(&self, stripe: u64) -> u32 {
        let start = stripe * self.blocks_per_stripe as u64;
        (self.n_blocks() - start).min(self.blocks_per_stripe as u64) as u32
    }
    pub fn parity_blocks_for(&self, n_data: u32) -> u32 {
        if n_data == 0 {
            return 0;
        }
        let p = (n_data as u64 * self.parity_ppm as u64).div_ceil(1_000_000);
        p.clamp(1, n_data as u64) as u32
    }
    pub fn stripe_parity_blocks(&self, stripe: u64) -> u32 {
        self.parity_blocks_for(self.stripe_data_blocks(stripe))
    }
    pub fn first_block_of_stripe(&self, stripe: u64) -> u64 {
        stripe * self.blocks_per_stripe as u64
    }
    pub fn stripe_of_block(&self, block: u64) -> u64 {
        block / self.blocks_per_stripe as u64
    }
    pub fn stripe_bytes(&self) -> u64 {
        self.blocks_per_stripe as u64 * self.block_size as u64
    }
    /// Total parity bytes (excluding hashes/headers).
    pub fn parity_bytes(&self) -> u64 {
        (0..self.n_stripes())
            .map(|s| self.stripe_parity_blocks(s) as u64 * self.block_size as u64)
            .sum()
    }
    /// Total parity blocks across the file.
    pub fn parity_blocks(&self) -> u64 {
        (0..self.n_stripes()).map(|s| self.stripe_parity_blocks(s) as u64).sum()
    }
    /// Byte range of a block within the file (clamped to file size).
    pub fn block_range(&self, block: u64) -> (u64, u64) {
        let start = block * self.block_size as u64;
        let end = (start + self.block_size as u64).min(self.file_size);
        (start, end)
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub algo: Algo,
    pub layout: Layout,
    pub file_hash: Vec<u8>,
}

impl Header {
    fn encode(&self) -> Vec<u8> {
        let dl = self.algo.digest_len();
        let mut b = Vec::with_capacity(FIXED_HEADER_LEN + 2 * dl);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&VERSION.to_le_bytes());
        b.push(self.algo.id());
        b.push(dl as u8);
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&self.layout.file_size.to_le_bytes());
        b.extend_from_slice(&self.layout.block_size.to_le_bytes());
        b.extend_from_slice(&self.layout.blocks_per_stripe.to_le_bytes());
        b.extend_from_slice(&self.layout.parity_ppm.to_le_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        debug_assert_eq!(b.len(), FIXED_HEADER_LEN);
        b.extend_from_slice(&self.file_hash);
        let hh = self.algo.hash(&b);
        b.extend_from_slice(&hh);
        b
    }

    pub fn total_len(&self) -> u64 {
        (FIXED_HEADER_LEN + 2 * self.algo.digest_len()) as u64
    }
    pub fn table_offset(&self) -> u64 {
        self.total_len()
    }
    pub fn table_len(&self) -> u64 {
        self.layout.n_blocks() * self.algo.digest_len() as u64 + self.algo.digest_len() as u64
    }
    pub fn stripes_offset(&self) -> u64 {
        self.table_offset() + self.table_len()
    }
    /// Offset of stripe `i`'s parity within the sidecar. All stripes but the
    /// last have the same length, so this is O(1).
    pub fn stripe_offset(&self, stripe: u64) -> u64 {
        let n = self.layout.n_stripes();
        if stripe == 0 || n == 0 {
            return self.stripes_offset();
        }
        let full = self.stripe_len(0);
        if stripe < n {
            self.stripes_offset() + full * stripe
        } else {
            // one past the last stripe = end of file
            self.stripes_offset() + full * (n - 1) + self.stripe_len(n - 1)
        }
    }
    pub fn stripe_len(&self, stripe: u64) -> u64 {
        self.layout.stripe_parity_blocks(stripe) as u64 * self.layout.block_size as u64
            + self.algo.digest_len() as u64
    }
    pub fn expected_file_len(&self) -> u64 {
        self.stripe_offset(self.layout.n_stripes())
    }

    fn decode(buf: &[u8]) -> Result<Header> {
        ensure!(buf.len() >= FIXED_HEADER_LEN, "sidecar too short for header");
        ensure!(&buf[0..8] == MAGIC, "bad sidecar magic");
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        ensure!(version == VERSION, "unsupported sidecar version {version}");
        let algo = Algo::from_id(buf[12]).with_context(|| format!("unknown algo id {}", buf[12]))?;
        let dl = buf[13] as usize;
        ensure!(dl == algo.digest_len(), "digest length mismatch in sidecar header");
        let file_size = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let block_size = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let blocks_per_stripe = u32::from_le_bytes(buf[28..32].try_into().unwrap());
        let parity_ppm = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        ensure!(block_size >= MIN_BLOCK_SIZE && block_size % 64 == 0 && block_size <= MAX_BLOCK_SIZE, "bad block size in sidecar");
        ensure!(blocks_per_stripe >= 1 && blocks_per_stripe as u64 <= MAX_DATA_BLOCKS_PER_STRIPE, "bad blocks-per-stripe in sidecar");
        ensure!(parity_ppm <= 1_000_000, "bad parity ppm in sidecar");
        ensure!(buf.len() >= FIXED_HEADER_LEN + 2 * dl, "sidecar too short for header hashes");
        let file_hash = buf[FIXED_HEADER_LEN..FIXED_HEADER_LEN + dl].to_vec();
        let stored = &buf[FIXED_HEADER_LEN + dl..FIXED_HEADER_LEN + 2 * dl];
        let computed = algo.hash(&buf[..FIXED_HEADER_LEN + dl]);
        ensure!(stored == computed.as_slice(), "sidecar header hash mismatch (sidecar damaged)");
        Ok(Header {
            algo,
            layout: Layout { file_size, block_size, blocks_per_stripe, parity_ppm },
            file_hash,
        })
    }
}

/// Incremental writer: header first, block table reserved, stripes appended,
/// table filled in at the end. Writes to `<path>.tmp` and renames on finish.
pub struct Writer {
    path: PathBuf,
    tmp: PathBuf,
    out: BufWriter<File>,
    header: Header,
    block_hashes: Vec<u8>,
    stripes_written: u64,
}

impl Writer {
    pub fn create(path: &Path, header: Header) -> Result<Writer> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("csp.tmp");
        let f = File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        let mut out = BufWriter::with_capacity(1 << 20, f);
        out.write_all(&header.encode())?;
        // Reserve block hash table + table hash.
        let zeros = vec![0u8; 1 << 16];
        let mut remaining = header.table_len();
        while remaining > 0 {
            let n = remaining.min(zeros.len() as u64) as usize;
            out.write_all(&zeros[..n])?;
            remaining -= n as u64;
        }
        Ok(Writer {
            path: path.to_path_buf(),
            tmp,
            out,
            block_hashes: Vec::with_capacity((header.layout.n_blocks() as usize) * header.algo.digest_len()),
            header,
            stripes_written: 0,
        })
    }

    pub fn push_block_hash(&mut self, h: &[u8]) {
        debug_assert_eq!(h.len(), self.header.algo.digest_len());
        self.block_hashes.extend_from_slice(h);
    }

    /// Append parity shards for the next stripe.
    pub fn write_stripe<'a>(&mut self, shards: impl Iterator<Item = &'a [u8]>) -> Result<()> {
        let mut h = self.header.algo.hasher();
        let mut n = 0u32;
        for s in shards {
            ensure!(s.len() == self.header.layout.block_size as usize, "parity shard size mismatch");
            self.out.write_all(s)?;
            h.update(s);
            n += 1;
        }
        ensure!(
            n == self.header.layout.stripe_parity_blocks(self.stripes_written),
            "wrong number of parity shards for stripe {}",
            self.stripes_written
        );
        self.out.write_all(&h.finish())?;
        self.stripes_written += 1;
        Ok(())
    }

    /// Set the final whole-file hash (known only after reading everything),
    /// fill in the table, fsync and rename into place.
    pub fn finish(mut self, file_hash: &[u8]) -> Result<()> {
        ensure!(
            self.stripes_written == self.header.layout.n_stripes(),
            "sidecar: wrote {} stripes, layout has {}",
            self.stripes_written,
            self.header.layout.n_stripes()
        );
        ensure!(
            self.block_hashes.len() as u64 == self.header.layout.n_blocks() * self.header.algo.digest_len() as u64,
            "sidecar: block hash count mismatch"
        );
        self.header.file_hash = file_hash.to_vec();
        self.out.flush()?;
        let f = self.out.get_mut();
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&self.header.encode())?;
        f.seek(SeekFrom::Start(self.header.table_offset()))?;
        f.write_all(&self.block_hashes)?;
        f.write_all(&self.header.algo.hash(&self.block_hashes))?;
        f.sync_all()?;
        drop(self.out);
        std::fs::rename(&self.tmp, &self.path)
            .with_context(|| format!("renaming {} -> {}", self.tmp.display(), self.path.display()))?;
        Ok(())
    }

    pub fn abort(self) {
        drop(self.out);
        let _ = std::fs::remove_file(&self.tmp);
    }
}

/// Read-side view of a sidecar.
pub struct Reader {
    file: File,
    pub header: Header,
    block_hashes: Vec<u8>,
    /// None until `table_ok()` is evaluated.
    table_ok: bool,
}

impl Reader {
    pub fn open(path: &Path) -> Result<Reader> {
        let mut file = File::open(path).with_context(|| format!("opening sidecar {}", path.display()))?;
        let mut hdr = vec![0u8; FIXED_HEADER_LEN + 2 * 32];
        let n = read_up_to(&mut file, &mut hdr)?;
        hdr.truncate(n);
        let header = Header::decode(&hdr).with_context(|| format!("sidecar {}", path.display()))?;
        let dl = header.algo.digest_len();
        let table_bytes = header.layout.n_blocks() * dl as u64;
        ensure!(table_bytes < (1u64 << 34), "sidecar block table implausibly large");
        file.seek(SeekFrom::Start(header.table_offset()))?;
        let mut block_hashes = vec![0u8; table_bytes as usize];
        let mut stored = vec![0u8; dl];
        let table_ok = match (file.read_exact(&mut block_hashes), file.read_exact(&mut stored)) {
            (Ok(()), Ok(())) => header.algo.hash(&block_hashes) == stored,
            _ => false,
        };
        Ok(Reader { file, header, block_hashes, table_ok })
    }

    pub fn layout(&self) -> &Layout {
        &self.header.layout
    }
    pub fn algo(&self) -> Algo {
        self.header.algo
    }
    /// Whether the block hash table is intact. If not, per-block verification
    /// and repair are impossible (the whole-file hash is still usable).
    pub fn table_ok(&self) -> bool {
        self.table_ok
    }
    pub fn block_hash(&self, block: u64) -> &[u8] {
        let dl = self.header.algo.digest_len();
        let i = block as usize * dl;
        &self.block_hashes[i..i + dl]
    }

    /// Read and verify the parity shards of one stripe.
    pub fn read_stripe(&mut self, stripe: u64) -> Result<Vec<Vec<u8>>> {
        let layout = self.header.layout;
        let p = layout.stripe_parity_blocks(stripe) as usize;
        let bs = layout.block_size as usize;
        let dl = self.header.algo.digest_len();
        self.file.seek(SeekFrom::Start(self.header.stripe_offset(stripe)))?;
        let mut buf = vec![0u8; p * bs + dl];
        self.file
            .read_exact(&mut buf)
            .with_context(|| format!("sidecar truncated: cannot read stripe {stripe}"))?;
        let computed = self.header.algo.hash(&buf[..p * bs]);
        if computed != buf[p * bs..] {
            bail!("parity for stripe {stripe} is damaged (hash mismatch)");
        }
        buf.truncate(p * bs);
        Ok(buf.chunks_exact(bs).map(|c| c.to_vec()).collect())
    }

    /// Deep check: every section hash. Returns list of problems (empty = ok).
    pub fn deep_check(&mut self) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        if !self.table_ok {
            problems.push("block hash table damaged".into());
        }
        let len = self.file.metadata()?.len();
        let expected = self.header.expected_file_len();
        if len != expected {
            problems.push(format!("sidecar length {len}, expected {expected}"));
        }
        for s in 0..self.header.layout.n_stripes() {
            if let Err(e) = self.read_stripe(s) {
                problems.push(format!("stripe {s}: {e}"));
            }
        }
        Ok(problems)
    }
}

fn read_up_to(f: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let r = f.read(&mut buf[n..])?;
        if r == 0 {
            break;
        }
        n += r;
    }
    Ok(n)
}

/// Path of the sidecar for a given content hash under the parity directory.
pub fn sidecar_path(parity_dir: &Path, content_hash: &[u8]) -> PathBuf {
    let h = hex::encode(content_hash);
    parity_dir.join(&h[0..2]).join(&h[2..4]).join(format!("{h}.csp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_small_files() {
        let l = Layout::choose(100, 65536, 128 << 20, 50_000);
        assert_eq!(l.block_size, 64);
        assert_eq!(l.n_blocks(), 2);
        assert_eq!(l.n_stripes(), 1);
        assert_eq!(l.stripe_parity_blocks(0), 1);
        let l = Layout::choose(0, 65536, 128 << 20, 50_000);
        assert_eq!(l.n_blocks(), 0);
        assert_eq!(l.n_stripes(), 0);
        assert_eq!(l.parity_bytes(), 0);
    }

    #[test]
    fn layout_big_files() {
        let l = Layout::choose(10 << 30, 65536, 128 << 20, 50_000);
        assert_eq!(l.block_size, 65536);
        assert_eq!(l.blocks_per_stripe, 2048);
        assert_eq!(l.n_stripes(), 80);
        assert_eq!(l.stripe_parity_blocks(0), 103); // ceil(2048*0.05)
        // Odd tail
        let l = Layout::choose((128 << 20) + 1, 65536, 128 << 20, 50_000);
        assert_eq!(l.n_stripes(), 2);
        assert_eq!(l.stripe_data_blocks(1), 1);
        assert_eq!(l.stripe_parity_blocks(1), 1);
        assert_eq!(l.block_range(2048), (128 << 20, (128 << 20) + 1));
    }

    #[test]
    fn layout_blocks_per_stripe_capped() {
        let l = Layout::choose(1 << 40, 64, 128 << 20, 10_000);
        assert!(l.blocks_per_stripe as u64 <= MAX_DATA_BLOCKS_PER_STRIPE);
        // stripe never exceeds configured bytes even with huge blocks
        let l = Layout::choose(1 << 40, 16 << 20, 128 << 20, 50_000);
        assert!(l.stripe_bytes() <= 128 << 20);
        assert_eq!(l.blocks_per_stripe, 8);
    }

    #[test]
    fn stripe_offsets_consistent() {
        let h = Header {
            algo: Algo::Blake3,
            layout: Layout { file_size: 20_000, block_size: 64, blocks_per_stripe: 64, parity_ppm: 50_000 },
            file_hash: vec![0u8; 32],
        };
        let mut off = h.stripes_offset();
        for s in 0..h.layout.n_stripes() {
            assert_eq!(h.stripe_offset(s), off);
            off += h.stripe_len(s);
        }
        assert_eq!(h.expected_file_len(), off);
    }

    #[test]
    fn header_roundtrip() {
        let h = Header {
            algo: Algo::Blake3,
            layout: Layout { file_size: 12345, block_size: 64, blocks_per_stripe: 64, parity_ppm: 50_000 },
            file_hash: vec![7u8; 32],
        };
        let enc = h.encode();
        let dec = Header::decode(&enc).unwrap();
        assert_eq!(dec.layout, h.layout);
        assert_eq!(dec.file_hash, h.file_hash);
        let mut bad = enc.clone();
        bad[20] ^= 1;
        assert!(Header::decode(&bad).is_err());
    }
}
