//! The `.mts` parity-set sidecar format ("meticulous parity set"). See FORMAT.md.
//!
//! A parity set is an ordered list of members (content hash, size). Each
//! member contributes ceil(size / B) blocks (last block zero-padded); the
//! members' blocks concatenated form the set's global block sequence, which is
//! cut into stripes of <= S blocks. Each stripe is an independent Reed-Solomon
//! code whose data shards may come from many files.
//!
//! All integers little-endian. `dl` = digest length of `algo`.
//!
//! ```text
//! off  len  field
//! 0    8    magic  "MTPARSET"
//! 8    4    version (u32) = 2
//! 12   1    algo id (see hash::Algo::id)
//! 13   1    digest length dl
//! 14   2    reserved (0)
//! 16   4    block size B (u32, multiple of 64)
//! 20   4    blocks per stripe S (u32)
//! 24   4    parity parts-per-million (u32)
//! 28   4    minimum parity blocks per stripe (u32)
//! 32   4    number of members (u32)
//! 36   4    reserved (0)
//! 40   dl   set id = H(bytes 16..40 || member table)
//! 40+dl dl  header hash = H(bytes 0 .. 40+dl)
//! ---- member table ----
//!      n_members * (dl + 8)   content hash + size (u64) per member, in order
//!                             (integrity: covered by the set id above)
//! ---- block hash table ----
//!      n_blocks*dl   hash of every data block in global order (a member's
//!                    last block is zero-padded to B before hashing)
//!      dl            table hash = H(table)
//! ---- stripes, in order ----
//!      p_i*B  parity shards for stripe i (p_i = parity_blocks(stripe))
//!      dl     H(those parity bytes)
//! ```
//!
//! Per-stripe parity count: `p_i = clamp(max(ceil(d_i*ppm/1e6), min_parity), 1, d_i)`.
//! `min_parity` (a header field, fixed when the set is created) encodes both
//! floors: one filesystem record (so a dead ZFS record is always within the
//! margin) and ppm of a FULL packing target's bytes — so an underfull set
//! carries the same absolute margin a full set would, and small files in
//! small sets stay recoverable after whole-file loss.
//!
//! Everything needed to decode is derivable from the header + member table, so
//! any single damaged section only loses that section, and `fsck --rebuild-db`
//! can reconstruct the set/membership tables from sidecars alone.

use crate::hash::Algo;
use anyhow::{Context, Result, bail, ensure};
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 8] = b"MTPARSET";
pub const VERSION: u32 = 2;
pub const FIXED_HEADER_LEN: usize = 40;
/// reed-solomon-simd limit we stay under per stripe.
pub const MAX_DATA_BLOCKS_PER_STRIPE: u64 = 32768;
pub const MIN_BLOCK_SIZE: u32 = 64;
pub const MAX_BLOCK_SIZE: u32 = 64 * 1024 * 1024;
/// Cap on members per set: bounds the member table (32768 × (dl+8) ≈ 1.3 MB)
/// and packing pathologies. Tiny-file swarms need a high cap so their sets
/// can still approach the byte target.
pub const MAX_MEMBERS: u32 = 32768;

/// Geometry of one parity set: block/stripe/parity parameters plus the member
/// sizes (which fix every member's block range). Fully determined by the
/// header + member table, so it can be recomputed from any sidecar — or from
/// the database's parity_set/parity_member rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetLayout {
    pub block_size: u32,
    pub blocks_per_stripe: u32,
    pub parity_ppm: u32,
    pub min_parity_blocks: u32,
    member_sizes: Vec<u64>,
    /// firsts[m] = first global block of member m; firsts[n_members] = n_blocks.
    firsts: Vec<u64>,
}

impl SetLayout {
    pub fn new(
        block_size: u32,
        blocks_per_stripe: u32,
        parity_ppm: u32,
        min_parity_blocks: u32,
        member_sizes: Vec<u64>,
    ) -> Result<SetLayout> {
        ensure!(
            block_size >= MIN_BLOCK_SIZE && block_size.is_multiple_of(64) && block_size <= MAX_BLOCK_SIZE,
            "bad block size {block_size}"
        );
        ensure!(
            blocks_per_stripe >= 1 && blocks_per_stripe as u64 <= MAX_DATA_BLOCKS_PER_STRIPE,
            "bad blocks-per-stripe {blocks_per_stripe}"
        );
        ensure!(parity_ppm <= 1_000_000, "bad parity ppm {parity_ppm}");
        ensure!(member_sizes.len() as u64 <= MAX_MEMBERS as u64, "too many members ({})", member_sizes.len());
        ensure!(member_sizes.iter().all(|&s| s > 0), "zero-size member (empty contents are never set members)");
        let mut firsts = Vec::with_capacity(member_sizes.len() + 1);
        let mut acc = 0u64;
        for &s in &member_sizes {
            firsts.push(acc);
            acc += s.div_ceil(block_size as u64);
        }
        firsts.push(acc);
        Ok(SetLayout { block_size, blocks_per_stripe, parity_ppm, min_parity_blocks, member_sizes, firsts })
    }

    /// Choose the geometry for a set of member sizes given the archive config.
    /// The per-set block size shrinks below the configured one for small-file
    /// sets — aiming for ~`stripe_size / cfg_block_size` blocks in a full set,
    /// but never above the average member size, so tiny files don't each pay
    /// a whole oversized block of padding (padding is charged in parity).
    pub fn choose(
        member_sizes: Vec<u64>,
        cfg_block_size: u32,
        cfg_stripe_bytes: u64,
        parity_ppm: u32,
        parity_min_bytes: u64,
    ) -> Result<SetLayout> {
        let cfg_block = cfg_block_size.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE).next_multiple_of(64) as u64;
        let total: u64 = member_sizes.iter().sum();
        // Target block count of a full set.
        let t = (cfg_stripe_bytes.max(cfg_block) / cfg_block).max(1);
        let avg = (total / member_sizes.len().max(1) as u64).max(1);
        let block_size =
            total.div_ceil(t).min(avg).next_multiple_of(64).clamp(MIN_BLOCK_SIZE as u64, cfg_block) as u32;
        let bps = (cfg_stripe_bytes.max(block_size as u64) / block_size as u64).clamp(1, MAX_DATA_BLOCKS_PER_STRIPE) as u32;
        let ppm = parity_ppm.min(1_000_000) as u64;
        let n_blocks: u64 = member_sizes.iter().map(|s| s.div_ceil(block_size as u64)).sum();
        let n_stripes = n_blocks.div_ceil(bps as u64).max(1);
        // Minimum parity per stripe, folded into one header field:
        // - one filesystem record (e.g. ZFS recordsize), capped so a
        //   misconfigured value cannot dominate a stripe; and
        // - the "underfull boost": ppm of a FULL packing target's bytes,
        //   spread over the set's stripes, so a set smaller than the target
        //   still carries a full set's absolute margin (clamped to the data at
        //   use — a tiny set ends up fully duplicated, which is cheap
        //   precisely because it is tiny) while a big set stays at ~ppm.
        let record_floor = parity_min_bytes.div_ceil(block_size as u64).min(bps as u64 / 4);
        let boost = (cfg_stripe_bytes * ppm / 1_000_000).div_ceil(block_size as u64).div_ceil(n_stripes);
        let min = record_floor.max(boost).min(MAX_DATA_BLOCKS_PER_STRIPE) as u32;
        SetLayout::new(block_size, bps, ppm as u32, min, member_sizes)
    }

    pub fn n_members(&self) -> usize {
        self.member_sizes.len()
    }
    pub fn member_size(&self, m: usize) -> u64 {
        self.member_sizes[m]
    }
    pub fn member_first_block(&self, m: usize) -> u64 {
        self.firsts[m]
    }
    pub fn member_blocks(&self, m: usize) -> u64 {
        self.firsts[m + 1] - self.firsts[m]
    }
    /// Which member owns global block `g`.
    pub fn member_of_block(&self, g: u64) -> usize {
        debug_assert!(g < self.n_blocks());
        match self.firsts.binary_search(&g) {
            Ok(mut i) => {
                // firsts can repeat only if a member had 0 blocks, which new() forbids.
                while i + 1 < self.firsts.len() && self.firsts[i + 1] == g {
                    i += 1;
                }
                i
            }
            Err(i) => i - 1,
        }
    }
    /// Byte range of a member's block within the member's file (clamped to its size).
    pub fn member_block_range(&self, m: usize, member_block: u64) -> (u64, u64) {
        let start = member_block * self.block_size as u64;
        let end = (start + self.block_size as u64).min(self.member_sizes[m]);
        (start, end)
    }

    pub fn total_data_bytes(&self) -> u64 {
        self.member_sizes.iter().sum()
    }
    pub fn n_blocks(&self) -> u64 {
        *self.firsts.last().unwrap()
    }
    pub fn n_stripes(&self) -> u64 {
        self.n_blocks().div_ceil(self.blocks_per_stripe as u64)
    }
    pub fn stripe_data_blocks(&self, stripe: u64) -> u32 {
        let start = stripe * self.blocks_per_stripe as u64;
        (self.n_blocks() - start).min(self.blocks_per_stripe as u64) as u32
    }
    /// Parity blocks for a stripe with `n_data` data blocks. The
    /// `min_parity_blocks` floor (one filesystem record + the underfull
    /// boost, see `choose`) keeps short stripes from being under-protected.
    pub fn parity_blocks_for(&self, n_data: u32) -> u32 {
        if n_data == 0 {
            return 0;
        }
        let p = (n_data as u64 * self.parity_ppm as u64).div_ceil(1_000_000);
        p.max(self.min_parity_blocks as u64).clamp(1, n_data as u64) as u32
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
    /// Total parity bytes (excluding hashes/headers).
    pub fn parity_bytes(&self) -> u64 {
        (0..self.n_stripes()).map(|s| self.stripe_parity_blocks(s) as u64 * self.block_size as u64).sum()
    }
    pub fn parity_blocks(&self) -> u64 {
        (0..self.n_stripes()).map(|s| self.stripe_parity_blocks(s) as u64).sum()
    }
}

/// The 24 layout bytes (header offsets 16..40) that, with the member table,
/// form the set id preimage.
fn layout_bytes(l: &SetLayout) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0..4].copy_from_slice(&l.block_size.to_le_bytes());
    b[4..8].copy_from_slice(&l.blocks_per_stripe.to_le_bytes());
    b[8..12].copy_from_slice(&l.parity_ppm.to_le_bytes());
    b[12..16].copy_from_slice(&l.min_parity_blocks.to_le_bytes());
    b[16..20].copy_from_slice(&(l.n_members() as u32).to_le_bytes());
    b
}

fn member_table_bytes(algo: Algo, l: &SetLayout, member_hashes: &[Vec<u8>]) -> Vec<u8> {
    let dl = algo.digest_len();
    let mut t = Vec::with_capacity(l.n_members() * (dl + 8));
    for (m, h) in member_hashes.iter().enumerate() {
        debug_assert_eq!(h.len(), dl);
        t.extend_from_slice(h);
        t.extend_from_slice(&l.member_size(m).to_le_bytes());
    }
    t
}

/// The set id: H(layout bytes || member table). Deterministic from geometry +
/// (content hash, size) of every member, so identical sets get identical ids.
pub fn compute_set_id(algo: Algo, layout: &SetLayout, member_hashes: &[Vec<u8>]) -> Vec<u8> {
    let mut h = algo.hasher();
    h.update(&layout_bytes(layout));
    h.update(&member_table_bytes(algo, layout, member_hashes));
    h.finish()
}

#[derive(Debug, Clone)]
pub struct Header {
    pub algo: Algo,
    pub layout: SetLayout,
    pub set_id: Vec<u8>,
}

impl Header {
    fn encode_fixed(&self) -> Vec<u8> {
        let dl = self.algo.digest_len();
        let mut b = Vec::with_capacity(FIXED_HEADER_LEN + 2 * dl);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&VERSION.to_le_bytes());
        b.push(self.algo.id());
        b.push(dl as u8);
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&layout_bytes(&self.layout));
        debug_assert_eq!(b.len(), FIXED_HEADER_LEN);
        b.extend_from_slice(&self.set_id);
        let hh = self.algo.hash(&b);
        b.extend_from_slice(&hh);
        b
    }

    pub fn header_len(&self) -> u64 {
        (FIXED_HEADER_LEN + 2 * self.algo.digest_len()) as u64
    }
    pub fn member_table_offset(&self) -> u64 {
        self.header_len()
    }
    pub fn member_table_len(&self) -> u64 {
        self.layout.n_members() as u64 * (self.algo.digest_len() as u64 + 8)
    }
    pub fn table_offset(&self) -> u64 {
        self.member_table_offset() + self.member_table_len()
    }
    pub fn table_len(&self) -> u64 {
        (self.layout.n_blocks() + 1) * self.algo.digest_len() as u64
    }
    pub fn stripes_offset(&self) -> u64 {
        self.table_offset() + self.table_len()
    }
    /// Offset of stripe `i`'s parity within the sidecar. All stripes but the
    /// last have the same parity count, so this is O(1).
    pub fn stripe_offset(&self, stripe: u64) -> u64 {
        let n = self.layout.n_stripes();
        if stripe == 0 || n == 0 {
            return self.stripes_offset();
        }
        let full = self.stripe_len(0);
        if stripe < n {
            self.stripes_offset() + full * stripe
        } else {
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
}

/// Decode the fixed part of a header. The member sizes are not yet known at
/// this point, so the returned pieces are used to read the member table next.
struct FixedHeader {
    algo: Algo,
    block_size: u32,
    blocks_per_stripe: u32,
    parity_ppm: u32,
    min_parity_blocks: u32,
    n_members: u32,
    set_id: Vec<u8>,
}

fn decode_fixed(buf: &[u8]) -> Result<FixedHeader> {
    ensure!(buf.len() >= FIXED_HEADER_LEN, "sidecar too short for header");
    ensure!(&buf[0..8] == MAGIC, "bad sidecar magic");
    let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    ensure!(version == VERSION, "unsupported sidecar version {version}");
    let algo = Algo::from_id(buf[12]).with_context(|| format!("unknown algo id {}", buf[12]))?;
    let dl = buf[13] as usize;
    ensure!(dl == algo.digest_len(), "digest length mismatch in sidecar header");
    let block_size = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let blocks_per_stripe = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    let parity_ppm = u32::from_le_bytes(buf[24..28].try_into().unwrap());
    let min_parity_blocks = u32::from_le_bytes(buf[28..32].try_into().unwrap());
    let n_members = u32::from_le_bytes(buf[32..36].try_into().unwrap());
    ensure!(
        block_size >= MIN_BLOCK_SIZE && block_size % 64 == 0 && block_size <= MAX_BLOCK_SIZE,
        "bad block size in sidecar"
    );
    ensure!(blocks_per_stripe >= 1 && blocks_per_stripe as u64 <= MAX_DATA_BLOCKS_PER_STRIPE, "bad blocks-per-stripe in sidecar");
    ensure!(parity_ppm <= 1_000_000, "bad parity ppm in sidecar");
    ensure!((1..=MAX_MEMBERS).contains(&n_members), "bad member count in sidecar");
    ensure!(buf.len() >= FIXED_HEADER_LEN + 2 * dl, "sidecar too short for header hashes");
    let set_id = buf[FIXED_HEADER_LEN..FIXED_HEADER_LEN + dl].to_vec();
    let stored = &buf[FIXED_HEADER_LEN + dl..FIXED_HEADER_LEN + 2 * dl];
    let computed = algo.hash(&buf[..FIXED_HEADER_LEN + dl]);
    ensure!(stored == computed.as_slice(), "sidecar header hash mismatch (sidecar damaged)");
    Ok(FixedHeader { algo, block_size, blocks_per_stripe, parity_ppm, min_parity_blocks, n_members, set_id })
}

/// Incremental writer: zeroed header + member/block tables reserved up front,
/// parity stripes appended, everything backfilled in `finish` (member hashes —
/// and therefore the set id — are only known after reading every member).
/// The caller writes to a temp path and renames to `sidecar_path(dir, set_id)`.
pub struct Writer {
    path: PathBuf,
    out: BufWriter<File>,
    algo: Algo,
    layout: SetLayout,
    block_hashes: Vec<u8>,
    stripes_written: u64,
}

impl Writer {
    pub fn create(path: &Path, algo: Algo, layout: SetLayout) -> Result<Writer> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
        let mut out = BufWriter::with_capacity(1 << 20, f);
        let header = Header { algo, layout: layout.clone(), set_id: vec![0u8; algo.digest_len()] };
        // Reserve header + member table + block hash table.
        let reserve = header.stripes_offset();
        let zeros = vec![0u8; 1 << 16];
        let mut remaining = reserve;
        while remaining > 0 {
            let n = remaining.min(zeros.len() as u64) as usize;
            out.write_all(&zeros[..n])?;
            remaining -= n as u64;
        }
        Ok(Writer {
            path: path.to_path_buf(),
            out,
            algo,
            block_hashes: Vec::with_capacity(layout.n_blocks() as usize * algo.digest_len()),
            layout,
            stripes_written: 0,
        })
    }

    pub fn push_block_hash(&mut self, h: &[u8]) {
        debug_assert_eq!(h.len(), self.algo.digest_len());
        self.block_hashes.extend_from_slice(h);
    }

    /// Append parity shards for the next stripe.
    pub fn write_stripe<'a>(&mut self, shards: impl Iterator<Item = &'a [u8]>) -> Result<()> {
        let mut h = self.algo.hasher();
        let mut n = 0u32;
        for s in shards {
            ensure!(s.len() == self.layout.block_size as usize, "parity shard size mismatch");
            self.out.write_all(s)?;
            h.update(s);
            n += 1;
        }
        ensure!(
            n == self.layout.stripe_parity_blocks(self.stripes_written),
            "wrong number of parity shards for stripe {}",
            self.stripes_written
        );
        self.out.write_all(&h.finish())?;
        self.stripes_written += 1;
        Ok(())
    }

    /// Backfill the header, member table and block hash table now that every
    /// member's content hash is known. Returns the set id; the file stays at
    /// its (temp) path — the caller renames it to `sidecar_path(dir, id)`.
    pub fn finish(mut self, member_hashes: &[Vec<u8>]) -> Result<Vec<u8>> {
        ensure!(member_hashes.len() == self.layout.n_members(), "member hash count mismatch");
        ensure!(
            self.stripes_written == self.layout.n_stripes(),
            "sidecar: wrote {} stripes, layout has {}",
            self.stripes_written,
            self.layout.n_stripes()
        );
        ensure!(
            self.block_hashes.len() as u64 == self.layout.n_blocks() * self.algo.digest_len() as u64,
            "sidecar: block hash count mismatch"
        );
        let set_id = compute_set_id(self.algo, &self.layout, member_hashes);
        let header = Header { algo: self.algo, layout: self.layout.clone(), set_id: set_id.clone() };
        self.out.flush()?;
        let f = self.out.get_mut();
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&header.encode_fixed())?;
        f.write_all(&member_table_bytes(self.algo, &self.layout, member_hashes))?;
        f.write_all(&self.block_hashes)?;
        f.write_all(&self.algo.hash(&self.block_hashes))?;
        // No fsync: sidecars are regenerable and every section is hashed, so a
        // torn write after a crash is detected; per-set fsync would dominate
        // scan time for many small sets.
        drop(self.out);
        Ok(set_id)
    }

    pub fn abort(self) {
        let path = self.path.clone();
        drop(self.out);
        let _ = std::fs::remove_file(&path);
    }
}

/// Read-side view of a set sidecar.
pub struct Reader {
    file: File,
    pub header: Header,
    member_hashes: Vec<Vec<u8>>,
    block_hashes: Vec<u8>,
    table_ok: bool,
}

impl Reader {
    pub fn open(path: &Path) -> Result<Reader> {
        let mut file = File::open(path).with_context(|| format!("opening sidecar {}", path.display()))?;
        let mut hdr = vec![0u8; FIXED_HEADER_LEN + 2 * 32];
        let n = read_up_to(&mut file, &mut hdr)?;
        hdr.truncate(n);
        let fixed = decode_fixed(&hdr).with_context(|| format!("sidecar {}", path.display()))?;
        let dl = fixed.algo.digest_len();
        // Member table (verified against the set id in the header).
        let mt_off = (FIXED_HEADER_LEN + 2 * dl) as u64;
        let mt_len = fixed.n_members as usize * (dl + 8);
        file.seek(SeekFrom::Start(mt_off))?;
        let mut mt = vec![0u8; mt_len];
        file.read_exact(&mut mt).with_context(|| format!("sidecar {}: truncated member table", path.display()))?;
        let mut member_hashes = Vec::with_capacity(fixed.n_members as usize);
        let mut member_sizes = Vec::with_capacity(fixed.n_members as usize);
        for m in 0..fixed.n_members as usize {
            let e = &mt[m * (dl + 8)..(m + 1) * (dl + 8)];
            member_hashes.push(e[..dl].to_vec());
            member_sizes.push(u64::from_le_bytes(e[dl..].try_into().unwrap()));
        }
        let layout = SetLayout::new(
            fixed.block_size,
            fixed.blocks_per_stripe,
            fixed.parity_ppm,
            fixed.min_parity_blocks,
            member_sizes,
        )
        .with_context(|| format!("sidecar {}", path.display()))?;
        {
            let mut h = fixed.algo.hasher();
            h.update(&layout_bytes(&layout));
            h.update(&mt);
            ensure!(h.finish() == fixed.set_id, "sidecar {}: member table does not match the set id (damaged)", path.display());
        }
        let header = Header { algo: fixed.algo, layout, set_id: fixed.set_id };
        let table_bytes = header.layout.n_blocks() * dl as u64;
        ensure!(table_bytes < (1u64 << 34), "sidecar block table implausibly large");
        file.seek(SeekFrom::Start(header.table_offset()))?;
        let mut block_hashes = vec![0u8; table_bytes as usize];
        let mut stored = vec![0u8; dl];
        let table_ok = match (file.read_exact(&mut block_hashes), file.read_exact(&mut stored)) {
            (Ok(()), Ok(())) => header.algo.hash(&block_hashes) == stored,
            _ => false,
        };
        Ok(Reader { file, header, member_hashes, block_hashes, table_ok })
    }

    pub fn layout(&self) -> &SetLayout {
        &self.header.layout
    }
    pub fn algo(&self) -> Algo {
        self.header.algo
    }
    pub fn set_id(&self) -> &[u8] {
        &self.header.set_id
    }
    pub fn member_hash(&self, m: usize) -> &[u8] {
        &self.member_hashes[m]
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn find_member(&self, content_hash: &[u8]) -> Option<usize> {
        self.member_hashes.iter().position(|h| h == content_hash)
    }
    /// Whether the block hash table is intact. If not, per-block verification
    /// and repair are impossible.
    pub fn table_ok(&self) -> bool {
        self.table_ok
    }
    pub fn block_hash(&self, global_block: u64) -> &[u8] {
        let dl = self.header.algo.digest_len();
        let i = global_block as usize * dl;
        &self.block_hashes[i..i + dl]
    }

    /// Read and verify the parity shards of one stripe.
    pub fn read_stripe(&mut self, stripe: u64) -> Result<Vec<Vec<u8>>> {
        let p = self.header.layout.stripe_parity_blocks(stripe) as usize;
        let bs = self.header.layout.block_size as usize;
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

/// Path of the sidecar for a given set id under the parity directory.
pub fn sidecar_path(parity_dir: &Path, set_id: &[u8]) -> PathBuf {
    let h = hex::encode(set_id);
    parity_dir.join(&h[0..2]).join(&h[2..4]).join(format!("{h}.mts"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(sizes: &[u64]) -> SetLayout {
        SetLayout::choose(sizes.to_vec(), 65536, 128 << 20, 50_000, 0).unwrap()
    }

    #[test]
    fn layout_small_file_set_shrinks_blocks() {
        // 100 files of 1000 bytes: total 100 KB, target 2048 blocks -> 64-byte blocks.
        let sizes = vec![1000u64; 100];
        let lay = l(&sizes);
        assert_eq!(lay.block_size, 64);
        assert_eq!(lay.n_members(), 100);
        assert_eq!(lay.member_blocks(0), 16); // ceil(1000/64)
        assert_eq!(lay.n_blocks(), 1600);
        // One stripe; the underfull boost (5% of 128 MiB in 64-byte blocks)
        // far exceeds the data, so this tiny set is fully duplicated.
        assert_eq!(lay.n_stripes(), 1);
        assert_eq!(lay.stripe_parity_blocks(0), 1600);
        // A whole member (16 blocks) is far below the margin.
        assert!(lay.member_blocks(0) <= lay.stripe_parity_blocks(0) as u64);
    }

    #[test]
    fn layout_solo_big_file_matches_config_block() {
        let lay = l(&[10u64 << 30]);
        assert_eq!(lay.block_size, 65536);
        assert_eq!(lay.blocks_per_stripe, 2048);
        assert_eq!(lay.n_stripes(), 80);
        assert_eq!(lay.stripe_parity_blocks(0), 103); // ceil(2048*0.05)
        // Short last stripe still gets the (per-stripe share of the) boost.
        let lay = l(&[(128u64 << 20) + 65536]);
        assert_eq!(lay.min_parity_blocks, 52); // ceil(5% of 128 MiB / 64K) spread over 2 stripes
        assert_eq!(lay.n_stripes(), 2);
        assert_eq!(lay.stripe_data_blocks(1), 1);
        assert_eq!(lay.stripe_parity_blocks(1), 1); // clamp(103, 1, 1)
        let lay = l(&[(128u64 << 20) + 200 * 65536]);
        assert_eq!(lay.stripe_data_blocks(1), 200);
        assert_eq!(lay.stripe_parity_blocks(1), 52); // per-stripe boost share, d_i = 200 > 52
    }

    #[test]
    fn underfull_set_gets_boosted_parity() {
        // 10 files of 64 KiB in one tiny set: the boost floor (5% of the
        // 128 MiB packing target) exceeds the data, so parity = d_i and every
        // member is recoverable after total loss.
        let lay = l(&[65536u64; 10]);
        let d0 = lay.stripe_data_blocks(0);
        let boost = ((128u64 << 20) * 50_000 / 1_000_000).div_ceil(lay.block_size as u64);
        assert_eq!(lay.stripe_parity_blocks(0) as u64, boost.min(d0 as u64));
        for m in 0..lay.n_members() {
            assert!(lay.member_blocks(m) <= lay.stripe_parity_blocks(0) as u64, "member {m} not loss-protected");
        }
        // A near-full set pays ~ppm of the packing target, not more: 96 MiB
        // of members => parity bytes stay ~5% of 128 MiB (+ rounding).
        let lay = l(&[1u64 << 20; 96]);
        assert!(
            lay.parity_bytes() <= (128u64 << 20) / 20 + lay.block_size as u64 * lay.n_stripes(),
            "parity {} too large",
            lay.parity_bytes()
        );
    }

    #[test]
    fn min_parity_blocks_floor_and_cap() {
        // parity_min_bytes = 1 MiB with 64 KiB blocks -> 16-block record floor
        // (the 0.1%-of-128MiB underfull boost is only ceil(134218/65536) = 3).
        let lay = SetLayout::choose(vec![256u64 << 20], 65536, 128 << 20, 1_000, 1 << 20).unwrap();
        assert_eq!(lay.min_parity_blocks, 16);
        // ppm term would be ceil(2048*0.001) = 3; the record floor wins.
        assert_eq!(lay.stripe_parity_blocks(0), 16);
        // The record floor is capped at a quarter of the stripe.
        let lay = SetLayout::choose(vec![1u64 << 30], 65536, 128 << 20, 1_000, 1 << 30).unwrap();
        assert!(lay.min_parity_blocks <= lay.blocks_per_stripe / 4);
    }

    #[test]
    fn member_block_math() {
        let lay = SetLayout::new(64, 64, 50_000, 0, vec![100, 64, 129]).unwrap();
        assert_eq!(lay.member_first_block(0), 0);
        assert_eq!(lay.member_blocks(0), 2);
        assert_eq!(lay.member_first_block(1), 2);
        assert_eq!(lay.member_blocks(1), 1);
        assert_eq!(lay.member_first_block(2), 3);
        assert_eq!(lay.member_blocks(2), 3);
        assert_eq!(lay.n_blocks(), 6);
        assert_eq!(lay.member_of_block(0), 0);
        assert_eq!(lay.member_of_block(1), 0);
        assert_eq!(lay.member_of_block(2), 1);
        assert_eq!(lay.member_of_block(3), 2);
        assert_eq!(lay.member_of_block(5), 2);
        assert_eq!(lay.member_block_range(0, 1), (64, 100));
        assert_eq!(lay.member_block_range(2, 2), (128, 129));
    }

    #[test]
    fn stripe_offsets_consistent() {
        let lay = SetLayout::new(64, 64, 50_000, 0, vec![10_000, 5_000, 5_000]).unwrap();
        let h = Header { algo: Algo::Blake3, layout: lay, set_id: vec![0u8; 32] };
        let mut off = h.stripes_offset();
        for s in 0..h.layout.n_stripes() {
            assert_eq!(h.stripe_offset(s), off);
            off += h.stripe_len(s);
        }
        assert_eq!(h.expected_file_len(), off);
    }

    #[test]
    fn set_id_depends_on_layout_and_members() {
        let lay1 = SetLayout::new(64, 64, 50_000, 0, vec![100, 200]).unwrap();
        let lay2 = SetLayout::new(64, 64, 60_000, 0, vec![100, 200]).unwrap();
        let h = vec![vec![1u8; 32], vec![2u8; 32]];
        let id1 = compute_set_id(Algo::Blake3, &lay1, &h);
        let id2 = compute_set_id(Algo::Blake3, &lay2, &h);
        assert_ne!(id1, id2, "layout change must change the set id");
        let h2 = vec![vec![1u8; 32], vec![3u8; 32]];
        assert_ne!(id1, compute_set_id(Algo::Blake3, &lay1, &h2));
        let lay3 = SetLayout::new(64, 64, 50_000, 0, vec![100, 201]).unwrap();
        assert_ne!(id1, compute_set_id(Algo::Blake3, &lay3, &h));
        assert_eq!(id1, compute_set_id(Algo::Blake3, &lay1, &h));
    }

    #[test]
    fn writer_reader_roundtrip_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let lay = SetLayout::new(64, 64, 50_000, 0, vec![100, 64]).unwrap();
        let algo = Algo::Blake3;
        let path = dir.path().join("t.mts");
        let mut w = Writer::create(&path, algo, lay.clone()).unwrap();
        // 3 blocks total, 1 stripe with p = clamp(max(ceil(3*0.05)=1, 0), 1, 3) = 1.
        assert_eq!(lay.stripe_parity_blocks(0), 1);
        for i in 0..lay.n_blocks() {
            w.push_block_hash(&algo.hash(&[i as u8]));
        }
        let shards: Vec<Vec<u8>> = (0..1).map(|i| vec![i as u8; 64]).collect();
        w.write_stripe(shards.iter().map(|s| s.as_slice())).unwrap();
        let hashes = vec![vec![7u8; 32], vec![9u8; 32]];
        let id = w.finish(&hashes).unwrap();
        assert_eq!(id, compute_set_id(algo, &lay, &hashes));

        let mut r = Reader::open(&path).unwrap();
        assert!(r.table_ok());
        assert_eq!(r.set_id(), id.as_slice());
        assert_eq!(r.member_hash(1), &[9u8; 32]);
        assert_eq!(r.find_member(&[7u8; 32]), Some(0));
        assert_eq!(r.layout().member_size(0), 100);
        assert_eq!(r.layout().member_size(1), 64);
        assert_eq!(r.read_stripe(0).unwrap(), shards);
        assert!(r.deep_check().unwrap().is_empty());

        // Tamper with the member table: open must fail (set id mismatch).
        let hlen = FIXED_HEADER_LEN + 2 * 32;
        {
            use std::os::unix::fs::FileExt;
            let f = std::fs::File::options().write(true).open(&path).unwrap();
            f.write_at(&[0xFF], hlen as u64 + 3).unwrap();
        }
        assert!(Reader::open(&path).is_err());
    }
}
