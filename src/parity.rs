//! Reed–Solomon parity over sets of files: single-pass set encoding (whole
//! member hashes + per-block hashes + parity), per-member verification, and
//! set-wide repair (including restoring a wholly-lost member from its
//! siblings + parity).

use crate::hash::Algo;
use crate::mts::{Reader, SetLayout, Writer};
use anyhow::{Context, Result, bail, ensure};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::collections::HashMap;
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

pub fn is_io_data_error(e: &std::io::Error) -> bool {
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

// ---------------------------------------------------------------------------
// Set encoding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EncodeMember {
    pub abs: PathBuf,
    pub size: u64,
    /// For rebuilds of known content: bail out of this member if the bytes
    /// hash to something else (the file changed / rotted since it was indexed).
    pub expected_hash: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct EncodedSet {
    pub set_id: Vec<u8>,
    pub member_hashes: Vec<Vec<u8>>,
    pub bytes_read: u64,
}

/// A member could not be read as expected; the caller drops it and re-encodes
/// the set from the remaining members.
#[derive(Debug)]
pub enum EncodeSetError {
    Member { index: usize, msg: String, eio: bool },
    Other(anyhow::Error),
}

impl From<anyhow::Error> for EncodeSetError {
    fn from(e: anyhow::Error) -> Self {
        EncodeSetError::Other(e)
    }
}
impl std::fmt::Display for EncodeSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeSetError::Member { index, msg, .. } => write!(f, "member {index}: {msg}"),
            EncodeSetError::Other(e) => write!(f, "{e:#}"),
        }
    }
}

/// Read every member once, in order, computing each member's content hash,
/// every (padded) block hash, and the Reed–Solomon parity of every stripe.
/// The sidecar is written to `tmp_path`; on success the set id is returned and
/// the caller renames the file to `mts::sidecar_path(dir, id)`.
pub fn encode_set(members: &[EncodeMember], algo: Algo, layout: &SetLayout, tmp_path: &Path) -> Result<EncodedSet, EncodeSetError> {
    ensure_members_match(members, layout)?;
    let w = Writer::create(tmp_path, algo, layout.clone()).map_err(EncodeSetError::Other)?;
    encode_inner(members, algo, layout, w)
}

fn ensure_members_match(members: &[EncodeMember], layout: &SetLayout) -> Result<(), EncodeSetError> {
    if members.len() != layout.n_members() {
        return Err(EncodeSetError::Other(anyhow::anyhow!("member count does not match layout")));
    }
    for (i, m) in members.iter().enumerate() {
        if m.size != layout.member_size(i) {
            return Err(EncodeSetError::Other(anyhow::anyhow!("member {i} size does not match layout")));
        }
    }
    Ok(())
}

fn member_err(index: usize, msg: impl Into<String>, eio: bool, w: Writer) -> EncodeSetError {
    w.abort();
    EncodeSetError::Member { index, msg: msg.into(), eio }
}

fn encode_inner(members: &[EncodeMember], algo: Algo, layout: &SetLayout, mut w: Writer) -> Result<EncodedSet, EncodeSetError> {
    let bs = layout.block_size as usize;
    let mut block_buf = vec![0u8; bs];
    let mut member_hashes: Vec<Vec<u8>> = Vec::with_capacity(members.len());
    let mut block_hasher = algo.hasher();
    let mut total = 0u64;
    let mut encoder: Option<ReedSolomonEncoder> = None;
    // Sequential per-member state.
    let mut cur: Option<(usize, File, Box<dyn crate::hash::Hasher>)> = None;

    let n_stripes = layout.n_stripes();
    let mut g = 0u64; // global block index
    for stripe in 0..n_stripes {
        let n_data = layout.stripe_data_blocks(stripe) as usize;
        let n_par = layout.stripe_parity_blocks(stripe) as usize;
        let enc = match encoder.as_mut() {
            Some(e) => {
                e.reset(n_data, n_par, bs).map_err(|e| EncodeSetError::Other(e.into()))?;
                e
            }
            None => encoder.insert(ReedSolomonEncoder::new(n_data, n_par, bs).map_err(|e| EncodeSetError::Other(e.into()))?),
        };
        for _ in 0..n_data {
            let m = layout.member_of_block(g);
            let mb = g - layout.member_first_block(m);
            // Open the next member when we cross into it.
            if cur.as_ref().map(|c| c.0) != Some(m) {
                debug_assert_eq!(mb, 0);
                let f = match File::open(&members[m].abs) {
                    Ok(f) => f,
                    Err(e) => return Err(member_err(m, format!("opening {}: {e}", members[m].abs.display()), is_io_data_error(&e), w)),
                };
                match f.metadata() {
                    Ok(meta) if meta.len() == members[m].size => {}
                    Ok(meta) => {
                        return Err(member_err(m, format!("size changed ({} on disk, {} expected)", meta.len(), members[m].size), false, w));
                    }
                    Err(e) => return Err(member_err(m, format!("stat: {e}"), false, w)),
                }
                cur = Some((m, f, algo.hasher()));
            }
            let (start, end) = layout.member_block_range(m, mb);
            let want = (end - start) as usize;
            let (_, file, mh) = cur.as_mut().unwrap();
            let got = match BlockSource::read_at(file, start, &mut block_buf[..want]) {
                Ok(n) => n,
                Err(e) => return Err(member_err(m, format!("read at {start}: {e}"), is_io_data_error(&e), w)),
            };
            if got != want {
                return Err(member_err(m, "file shrank while reading", false, w));
            }
            block_buf[want..].fill(0);
            mh.update(&block_buf[..want]);
            total += want as u64;
            block_hasher.update(&block_buf);
            w.push_block_hash(&block_hasher.finish_reset());
            enc.add_original_shard(&block_buf).map_err(|e| EncodeSetError::Other(e.into()))?;
            // Member finished with this block?
            if mb + 1 == layout.member_blocks(m) {
                let (_, mut file, mh) = cur.take().unwrap();
                // Ensure the file did not grow.
                let mut probe = [0u8; 1];
                match BlockSource::read_at(&mut file, members[m].size, &mut probe) {
                    Ok(0) => {}
                    Ok(_) => return Err(member_err(m, "file grew while reading", false, w)),
                    Err(e) if is_io_data_error(&e) => {} // EOF region unreadable: treat as not grown
                    Err(e) => return Err(member_err(m, format!("read: {e}"), false, w)),
                }
                let h = mh.finish();
                if let Some(want) = &members[m].expected_hash
                    && h != *want
                {
                    return Err(member_err(m, "content does not match the indexed hash (changed or rotted since last scan)", false, w));
                }
                member_hashes.push(h);
            }
            g += 1;
        }
        let result = enc.encode().map_err(|e| EncodeSetError::Other(e.into()))?;
        w.write_stripe(result.recovery_iter()).map_err(EncodeSetError::Other)?;
    }
    debug_assert_eq!(member_hashes.len(), members.len());
    let set_id = w.finish(&member_hashes).map_err(EncodeSetError::Other)?;
    Ok(EncodedSet { set_id, member_hashes, bytes_read: total })
}

// ---------------------------------------------------------------------------
// Per-member verification
// ---------------------------------------------------------------------------

/// Result of verifying one member's file against the set's block-hash table.
/// Block indices are member-relative. Whether damage is repairable is NOT
/// decidable from one member alone (it depends on the other members of each
/// stripe); use the DB-side margin estimate or `repair_set` for that.
#[derive(Debug, Default)]
pub struct BlockCheck {
    /// Whole-member content hash (empty when any block was unreadable).
    pub file_hash: Vec<u8>,
    pub actual_size: u64,
    pub n_blocks: u64,
    /// Member-relative indices of blocks whose hash does not match (includes
    /// blocks missing because the file is shorter than recorded).
    pub bad_blocks: Vec<u64>,
    /// Subset of `bad_blocks` the filesystem refused to read at all (EIO —
    /// on ZFS: a record whose checksum failed and could not be healed).
    pub unreadable_blocks: Vec<u64>,
    /// Bytes present on disk beyond the recorded size.
    pub extra_bytes: u64,
}

impl BlockCheck {
    pub fn ok(&self, expected_hash: &[u8]) -> bool {
        self.bad_blocks.is_empty() && self.file_hash == expected_hash
    }
}

/// Hash every block of member `ord`'s file and compare with the sidecar table.
pub fn check_member(path: &Path, sc: &Reader, ord: usize) -> Result<BlockCheck> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    check_member_from(&mut f, sc, ord)
}

pub fn check_member_from(src: &mut dyn BlockSource, sc: &Reader, ord: usize) -> Result<BlockCheck> {
    ensure!(sc.table_ok(), "sidecar block table is damaged; per-block check impossible");
    let layout = sc.layout().clone();
    let algo = sc.algo();
    let bs = layout.block_size as usize;
    let size = layout.member_size(ord);
    let first = layout.member_first_block(ord);
    let n_blocks = layout.member_blocks(ord);
    let mut buf = vec![0u8; bs.max(READ_CHUNK / bs * bs)];
    let mut file_hasher = algo.hasher();
    let mut block_hasher = algo.hasher();
    let mut out = BlockCheck { n_blocks, ..Default::default() };
    let mut block = 0u64; // member-relative
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
                let (bstart, bend) = layout.member_block_range(ord, block);
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
                    block_hasher.finish_reset() == sc.block_hash(first + block)
                } else {
                    false
                };
                if !ok {
                    out.bad_blocks.push(block);
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
        block += 1;
    }
    out.file_hash = if out.unreadable_blocks.is_empty() { file_hasher.finish() } else { Vec::new() };
    out.extra_bytes = out.actual_size.saturating_sub(size);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Set repair
// ---------------------------------------------------------------------------

/// How one member of a set participates in a repair.
#[derive(Debug, Clone, Default)]
pub struct MemberCtx {
    /// A file to read this member's bytes from, if a trustworthy one exists
    /// (its size+mtime match the index; every block is hash-verified anyway).
    /// None = pure erasure: the content is missing / edited / superseded.
    pub source: Option<PathBuf>,
    /// Where to write a repaired/restored copy if this member turns out
    /// damaged (usually = source; for a missing file, its recorded path).
    /// None = never write this member (report only).
    pub write_to: Option<PathBuf>,
    /// Move the damaged original here instead of overwriting it.
    pub keep_corrupt: Option<PathBuf>,
    /// mtime to stamp on a restored-from-nothing member (source == None).
    pub restore_mtime_ns: Option<i64>,
}

#[derive(Debug)]
pub enum MemberOutcome {
    /// Read fully and every block verified.
    Intact,
    /// No source and no write target (dead/absent member): contributed nothing.
    NoSource,
    /// Damaged but the caller did not ask for it to be written.
    DamagedNotWritable { bad_blocks: u64 },
    Repaired { blocks: usize },
    WouldRepair { blocks: usize },
    /// Rebuilt entirely (source was None but write_to was set).
    Restored { bytes: u64 },
    WouldRestore { bytes: u64 },
    Failed { msg: String },
}

#[derive(Debug)]
pub struct SetRepairOutcome {
    /// One outcome per member (same order as the sidecar's member table).
    pub members: Vec<MemberOutcome>,
    /// Stripes where erasures exceeded parity: (stripe, erasures, parity).
    pub unrecoverable_stripes: Vec<(u64, usize, usize)>,
}

/// Repair a set: read every available member block (hash-verified), treat
/// mismatching/unreadable/absent blocks as erasures, decode each stripe that
/// needs it, and rewrite/restore every damaged member that has a write target.
/// Every written file is verified against its recorded content hash before it
/// replaces anything.
pub fn repair_set(sc: &mut Reader, members: &[MemberCtx], dry_run: bool) -> Result<SetRepairOutcome> {
    // Open sources, remembering their on-disk length (a source longer than
    // the recorded size has junk appended: its blocks may all verify, but it
    // still needs a rewrite that truncates it).
    let mut sources: Vec<Option<(Box<dyn BlockSource>, u64)>> = Vec::with_capacity(members.len());
    for m in members.iter() {
        let f = m.source.as_ref().and_then(|p| File::open(p).ok());
        sources.push(f.and_then(|f| {
            let len = f.metadata().ok()?.len();
            Some((Box::new(f) as Box<dyn BlockSource>, len))
        }));
    }
    repair_set_from(sc, members, sources, dry_run)
}

/// Like `repair_set`, but with the block sources supplied by the caller —
/// the tests inject EIO-returning sources here. Pass 2 (`write_member`)
/// still re-reads good blocks from `MemberCtx::source` paths; the final
/// whole-content hash check guards that read either way.
fn repair_set_from(
    sc: &mut Reader,
    members: &[MemberCtx],
    mut files: Vec<Option<(Box<dyn BlockSource>, u64)>>,
    dry_run: bool,
) -> Result<SetRepairOutcome> {
    ensure!(sc.table_ok(), "sidecar block table is damaged; repair impossible");
    let layout = sc.layout().clone();
    ensure!(members.len() == layout.n_members(), "member context count does not match the set");
    ensure!(files.len() == members.len(), "source count does not match the set");
    let algo = sc.algo();
    let bs = layout.block_size as usize;

    let mut oversize = vec![false; members.len()];
    for (i, f) in files.iter().enumerate() {
        if let Some((_, len)) = f
            && *len > layout.member_size(i)
        {
            oversize[i] = true;
        }
    }

    let mut bad_per_member = vec![0u64; members.len()];
    let mut restored: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut unrecoverable: Vec<(u64, usize, usize)> = Vec::new();
    let mut member_unrecoverable = vec![false; members.len()];

    let stripe_cap = (layout.blocks_per_stripe as u64).min(layout.n_blocks().max(1)) as usize * bs;
    let mut stripe_buf = vec![0u8; stripe_cap];
    let mut block_hasher = algo.hasher();

    for stripe in 0..layout.n_stripes() {
        let n_data = layout.stripe_data_blocks(stripe) as usize;
        let n_par = layout.stripe_parity_blocks(stripe) as usize;
        let first_g = layout.first_block_of_stripe(stripe);
        let mut erased: Vec<usize> = Vec::new(); // indices within the stripe
        let mut touched_members: Vec<usize> = Vec::new();
        for i in 0..n_data {
            let g = first_g + i as u64;
            let m = layout.member_of_block(g);
            let mb = g - layout.member_first_block(m);
            let dst = &mut stripe_buf[i * bs..(i + 1) * bs];
            let ok = match files[m].as_mut() {
                None => false,
                Some((f, _)) => {
                    let (start, end) = layout.member_block_range(m, mb);
                    let want = (end - start) as usize;
                    match read_region_tolerant(f.as_mut(), start, &mut dst[..want], bs) {
                        Err(e) => return Err(e).with_context(|| format!("reading member {m}")),
                        Ok((got, unreadable)) if unreadable.is_empty() && got == want => {
                            dst[want..].fill(0);
                            block_hasher.update(dst);
                            block_hasher.finish_reset() == sc.block_hash(g)
                        }
                        Ok(_) => false,
                    }
                }
            };
            if !ok {
                dst.fill(0);
                erased.push(i);
                if members[m].source.is_some() {
                    bad_per_member[m] += 1;
                }
                if !touched_members.contains(&m) {
                    touched_members.push(m);
                }
            }
        }
        if erased.is_empty() {
            continue;
        }
        if erased.len() > n_par {
            unrecoverable.push((stripe, erased.len(), n_par));
            for &m in &touched_members {
                member_unrecoverable[m] = true;
            }
            // A member with NO source spans this stripe: unrecoverable too.
            for i in &erased {
                let m = layout.member_of_block(first_g + *i as u64);
                member_unrecoverable[m] = true;
            }
            continue;
        }
        let parity = sc.read_stripe(stripe)?;
        let mut dec = ReedSolomonDecoder::new(n_data, n_par, bs)?;
        for i in 0..n_data {
            if !erased.contains(&i) {
                dec.add_original_shard(i, &stripe_buf[i * bs..(i + 1) * bs])?;
            }
        }
        for (i, p) in parity.iter().enumerate() {
            dec.add_recovery_shard(i, p)?;
        }
        let res = dec.decode()?;
        for &i in &erased {
            let g = first_g + i as u64;
            let m = layout.member_of_block(g);
            if members[m].write_to.is_some() {
                let bytes = res
                    .restored_original(i)
                    .with_context(|| format!("decoder did not restore block {g}"))?
                    .to_vec();
                restored.insert(g, bytes);
            }
        }
    }
    drop(stripe_buf);

    // Second pass: rewrite every damaged member that has a write target.
    let mut outcomes: Vec<MemberOutcome> = Vec::with_capacity(members.len());
    for (m, ctx) in members.iter().enumerate() {
        let damaged = bad_per_member[m] > 0 || oversize[m] || (ctx.source.is_none() && ctx.write_to.is_some());
        let outcome = if !damaged {
            if ctx.source.is_some() {
                MemberOutcome::Intact
            } else {
                MemberOutcome::NoSource
            }
        } else if ctx.write_to.is_none() {
            MemberOutcome::DamagedNotWritable { bad_blocks: bad_per_member[m] }
        } else if member_unrecoverable[m] {
            MemberOutcome::Failed {
                msg: "a stripe of this member has more damaged/missing blocks than parity".into(),
            }
        } else {
            match write_member(sc, &layout, algo, m, ctx, &restored, dry_run) {
                Ok(o) => o,
                Err(e) => MemberOutcome::Failed { msg: format!("{e:#}") },
            }
        };
        outcomes.push(outcome);
    }
    Ok(SetRepairOutcome { members: outcomes, unrecoverable_stripes: unrecoverable })
}

fn write_member(
    sc: &Reader,
    layout: &SetLayout,
    algo: Algo,
    m: usize,
    ctx: &MemberCtx,
    restored: &HashMap<u64, Vec<u8>>,
    dry_run: bool,
) -> Result<MemberOutcome> {
    let target = ctx.write_to.as_ref().unwrap();
    let is_restore = ctx.source.is_none();
    let bs = layout.block_size as usize;
    let first = layout.member_first_block(m);
    let n_blocks = layout.member_blocks(m);
    let size = layout.member_size(m);
    let expected_hash = sc.member_hash(m);

    let tmp_path = temp_sibling(target, ".mtrepair");
    let mut out: BufWriter<Box<dyn Write>> = if dry_run {
        BufWriter::new(Box::new(std::io::sink()))
    } else {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_file = File::create(&tmp_path).with_context(|| format!("creating {}", tmp_path.display()))?;
        BufWriter::with_capacity(1 << 20, Box::new(tmp_file))
    };
    let cleanup = |tmp: &Path| {
        if !dry_run {
            let _ = std::fs::remove_file(tmp);
        }
    };
    let mut src = ctx.source.as_ref().map(File::open).transpose().unwrap_or(None);
    let mut hasher = algo.hasher();
    let mut buf = vec![0u8; bs];
    let mut blocks_from_parity = 0usize;
    for mb in 0..n_blocks {
        let g = first + mb;
        let (start, end) = layout.member_block_range(m, mb);
        let want = (end - start) as usize;
        let data: &[u8] = if let Some(r) = restored.get(&g) {
            blocks_from_parity += 1;
            &r[..want]
        } else {
            let Some(f) = src.as_mut() else {
                cleanup(&tmp_path);
                bail!("block {g} was neither readable nor restored");
            };
            match read_region_tolerant(f, start, &mut buf[..want], bs) {
                Ok((got, unreadable)) if got == want && unreadable.is_empty() => &buf[..want],
                _ => {
                    cleanup(&tmp_path);
                    bail!("block {g} became unreadable between passes; re-run repair");
                }
            }
        };
        out.write_all(data)?;
        hasher.update(data);
    }
    out.flush()?;
    let got_hash = hasher.finish();
    if got_hash != expected_hash {
        drop(out);
        cleanup(&tmp_path);
        bail!("repaired data does not match the recorded content hash; not written");
    }
    drop(out);
    if dry_run {
        return Ok(if is_restore {
            MemberOutcome::WouldRestore { bytes: size }
        } else {
            MemberOutcome::WouldRepair { blocks: blocks_from_parity }
        });
    }
    {
        let f = File::open(&tmp_path)?;
        f.sync_all()?;
    }
    if is_restore {
        if let Some(mt) = ctx.restore_mtime_ns {
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(mt.max(0) as u64);
            let _ = File::options().write(true).open(&tmp_path).and_then(|f| f.set_modified(t));
        }
        std::fs::rename(&tmp_path, target).with_context(|| format!("restoring {}", target.display()))?;
        return Ok(MemberOutcome::Restored { bytes: size });
    }
    // Preserve permissions / mtime so the DB fast path stays valid.
    let meta = std::fs::metadata(target)?;
    if std::os::unix::fs::MetadataExt::nlink(&meta) > 1 {
        eprintln!(
            "warning: {} has {} hard links; the repaired copy replaces only this name (other links keep the damaged bytes)",
            target.display(),
            std::os::unix::fs::MetadataExt::nlink(&meta)
        );
    }
    let _ = std::fs::set_permissions(&tmp_path, meta.permissions());
    if let Ok(mtime) = meta.modified() {
        let _ = File::options().write(true).open(&tmp_path).and_then(|f| f.set_modified(mtime));
    }
    if let Some(q) = &ctx.keep_corrupt {
        if let Some(parent) = q.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(target, q).with_context(|| format!("keeping damaged copy as {}", q.display()))?;
    }
    std::fs::rename(&tmp_path, target).with_context(|| format!("replacing {}", target.display()))?;
    Ok(MemberOutcome::Repaired { blocks: blocks_from_parity })
}

fn temp_sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(suffix);
    name.push(format!(".{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

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

    struct TestSet {
        dir: tempfile::TempDir,
        paths: Vec<PathBuf>,
        datas: Vec<Vec<u8>>,
        layout: SetLayout,
        sc_path: PathBuf,
        enc: EncodedSet,
    }

    /// Build a set of `sizes.len()` files with a 64-byte block size.
    fn build_set(sizes: &[usize], ppm: u32) -> TestSet {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        let mut datas = Vec::new();
        for (i, &s) in sizes.iter().enumerate() {
            let d = pseudo(s, i as u32 + 1);
            let p = dir.path().join(format!("f{i}.bin"));
            std::fs::write(&p, &d).unwrap();
            paths.push(p);
            datas.push(d);
        }
        let layout = SetLayout::choose(sizes.iter().map(|&s| s as u64).collect(), 64, 4096, ppm, 0).unwrap();
        let members: Vec<EncodeMember> =
            paths.iter().zip(sizes).map(|(p, &s)| EncodeMember { abs: p.clone(), size: s as u64, expected_hash: None }).collect();
        let tmp = dir.path().join("t.mts");
        let enc = encode_set(&members, Algo::Blake3, &layout, &tmp).unwrap();
        let sc_path = dir.path().join(format!("{}.mts", hex::encode(&enc.set_id)));
        std::fs::rename(&tmp, &sc_path).unwrap();
        TestSet { dir, paths, datas, layout, sc_path, enc }
    }

    fn ctx_all(ts: &TestSet) -> Vec<MemberCtx> {
        ts.paths
            .iter()
            .map(|p| MemberCtx { source: Some(p.clone()), write_to: Some(p.clone()), ..Default::default() })
            .collect()
    }

    fn flip_byte(path: &Path, off: u64) {
        let mut f = File::options().read(true).write(true).open(path).unwrap();
        f.seek(SeekFrom::Start(off)).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        f.seek(SeekFrom::Start(off)).unwrap();
        f.write_all(&[b[0] ^ 0xA5]).unwrap();
    }

    #[test]
    fn encode_hashes_match_and_clean_check() {
        let ts = build_set(&[1000, 64, 129, 5000], 50_000);
        for (i, d) in ts.datas.iter().enumerate() {
            assert_eq!(ts.enc.member_hashes[i], Algo::Blake3.hash(d));
        }
        let sc = Reader::open(&ts.sc_path).unwrap();
        assert!(sc.table_ok());
        assert_eq!(sc.set_id(), ts.enc.set_id.as_slice());
        for i in 0..ts.paths.len() {
            let c = check_member(&ts.paths[i], &sc, i).unwrap();
            assert!(c.ok(&ts.enc.member_hashes[i]), "member {i}: {c:?}");
        }
        let _ = &ts.layout;
    }

    #[test]
    fn multi_member_damage_repairs_byte_exact() {
        let ts = build_set(&[1000, 300, 5000, 129], 50_000);
        // Damage two different members.
        flip_byte(&ts.paths[0], 10);
        flip_byte(&ts.paths[2], 3000);
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let c0 = check_member(&ts.paths[0], &sc, 0).unwrap();
        assert_eq!(c0.bad_blocks.len(), 1);
        // dry run first: nothing touched
        let out = repair_set(&mut sc, &ctx_all(&ts), true).unwrap();
        assert!(matches!(out.members[0], MemberOutcome::WouldRepair { blocks: 1 }));
        assert_ne!(std::fs::read(&ts.paths[0]).unwrap(), ts.datas[0]);
        // real repair: both members healed in one pass
        let out = repair_set(&mut sc, &ctx_all(&ts), false).unwrap();
        assert!(matches!(out.members[0], MemberOutcome::Repaired { blocks: 1 }), "{:?}", out.members[0]);
        assert!(matches!(out.members[2], MemberOutcome::Repaired { blocks: 1 }), "{:?}", out.members[2]);
        assert!(matches!(out.members[1], MemberOutcome::Intact));
        for i in 0..ts.paths.len() {
            assert_eq!(std::fs::read(&ts.paths[i]).unwrap(), ts.datas[i], "member {i}");
        }
    }

    #[test]
    fn whole_member_loss_is_restored_from_siblings() {
        // 20% parity: the 700-byte member (11 blocks) fits inside the margin
        // (ceil(64 * 0.2) = 13 parity blocks per stripe).
        let ts = build_set(&[500, 700, 900, 4000], 200_000);
        // Delete one small file entirely.
        std::fs::remove_file(&ts.paths[1]).unwrap();
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let mut ctxs = ctx_all(&ts);
        ctxs[1] = MemberCtx { source: None, write_to: Some(ts.paths[1].clone()), restore_mtime_ns: Some(123_000_000_000), ..Default::default() };
        let out = repair_set(&mut sc, &ctxs, false).unwrap();
        assert!(matches!(out.members[1], MemberOutcome::Restored { bytes: 700 }), "{:?}", out.members[1]);
        assert_eq!(std::fs::read(&ts.paths[1]).unwrap(), ts.datas[1]);
        let mt = std::fs::metadata(&ts.paths[1]).unwrap().modified().unwrap();
        assert_eq!(mt, std::time::UNIX_EPOCH + std::time::Duration::from_secs(123));
    }

    #[test]
    fn damage_beyond_margin_is_refused_cleanly() {
        // ppm tiny -> full-stripe floor = ceil(64 * 0.001) = 1, min 0 -> 1 parity block/stripe.
        let ts = build_set(&[1000, 1000], 1_000);
        assert_eq!(ts.layout.stripe_parity_blocks(0), 1);
        flip_byte(&ts.paths[0], 0);
        flip_byte(&ts.paths[0], 100);
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let out = repair_set(&mut sc, &ctx_all(&ts), false).unwrap();
        assert!(!out.unrecoverable_stripes.is_empty());
        assert!(matches!(out.members[0], MemberOutcome::Failed { .. }), "{:?}", out.members[0]);
        // The other member is untouched.
        assert_eq!(std::fs::read(&ts.paths[1]).unwrap(), ts.datas[1]);
    }

    #[test]
    fn modified_sibling_is_pure_erasure_and_not_written() {
        // The edited sibling erases all 16 of its blocks; +1 bad block in
        // member 0 needs p >= 17, so 30% (ceil(64 * 0.3) = 20) suffices.
        let ts = build_set(&[1000, 1000, 1000], 300_000);
        // Member 1 was "edited": no source, no write (caller's mtime rule).
        flip_byte(&ts.paths[0], 10);
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let mut ctxs = ctx_all(&ts);
        ctxs[1] = MemberCtx::default(); // no source, no write
        let edited = std::fs::read(&ts.paths[1]).unwrap();
        let out = repair_set(&mut sc, &ctxs, false).unwrap();
        assert!(matches!(out.members[0], MemberOutcome::Repaired { .. }), "{:?}", out.members[0]);
        assert!(matches!(out.members[1], MemberOutcome::NoSource));
        assert_eq!(std::fs::read(&ts.paths[0]).unwrap(), ts.datas[0]);
        assert_eq!(std::fs::read(&ts.paths[1]).unwrap(), edited, "edited sibling must not be touched");
    }

    #[test]
    fn sibling_damage_found_during_repair_is_fixed_too() {
        let ts = build_set(&[1000, 1000, 1000], 200_000);
        flip_byte(&ts.paths[0], 10);
        flip_byte(&ts.paths[1], 20); // caller only knows about member 0
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let out = repair_set(&mut sc, &ctx_all(&ts), false).unwrap();
        assert!(matches!(out.members[0], MemberOutcome::Repaired { .. }));
        assert!(matches!(out.members[1], MemberOutcome::Repaired { .. }), "{:?}", out.members[1]);
        assert_eq!(std::fs::read(&ts.paths[1]).unwrap(), ts.datas[1]);
    }

    #[test]
    fn truncated_member_is_repairable() {
        let ts = build_set(&[1000, 2000], 200_000);
        let f = File::options().write(true).open(&ts.paths[1]).unwrap();
        f.set_len(1900).unwrap();
        drop(f);
        let sc = Reader::open(&ts.sc_path).unwrap();
        let c = check_member(&ts.paths[1], &sc, 1).unwrap();
        assert!(!c.bad_blocks.is_empty());
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let out = repair_set(&mut sc, &ctx_all(&ts), false).unwrap();
        assert!(matches!(out.members[1], MemberOutcome::Repaired { .. }), "{:?}", out.members[1]);
        assert_eq!(std::fs::read(&ts.paths[1]).unwrap(), ts.datas[1]);
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

    /// A ZFS-style dead record (EIO on read) inside one member is treated as
    /// an erasure by repair_set and rebuilt byte-exact from the stripe.
    #[test]
    fn eio_blocks_are_erasures_in_repair() {
        let ts = build_set(&[2000, 2000, 2000], 200_000);
        let sources: Vec<Option<(Box<dyn BlockSource>, u64)>> = ts
            .paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let f = File::open(p).unwrap();
                let src: Box<dyn BlockSource> = if i == 0 {
                    // Member 0: a 128-byte "record" (blocks 3+4) is unreadable.
                    Box::new(EioSource { file: f, bad_blocks: vec![3, 4], bs: 64 })
                } else {
                    Box::new(f)
                };
                Some((src, 2000))
            })
            .collect();
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let out = repair_set_from(&mut sc, &ctx_all(&ts), sources, false).unwrap();
        assert!(matches!(out.members[0], MemberOutcome::Repaired { blocks: 2 }), "{:?}", out.members[0]);
        assert!(matches!(out.members[1], MemberOutcome::Intact));
        assert_eq!(std::fs::read(&ts.paths[0]).unwrap(), ts.datas[0]);
        // Too many unreadable blocks in the stripe -> clean failure.
        let sources: Vec<Option<(Box<dyn BlockSource>, u64)>> = ts
            .paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let f = File::open(p).unwrap();
                let src: Box<dyn BlockSource> = if i == 0 {
                    Box::new(EioSource { file: f, bad_blocks: (0..25).collect(), bs: 64 })
                } else {
                    Box::new(f)
                };
                Some((src, 2000))
            })
            .collect();
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let out = repair_set_from(&mut sc, &ctx_all(&ts), sources, false).unwrap();
        assert!(!out.unrecoverable_stripes.is_empty());
        assert!(matches!(out.members[0], MemberOutcome::Failed { .. }), "{:?}", out.members[0]);
        assert_eq!(std::fs::read(&ts.paths[1]).unwrap(), ts.datas[1], "intact sibling untouched");
    }

    #[test]
    fn eio_blocks_are_erasures_in_check() {
        let ts = build_set(&[2000, 2000], 200_000);
        let mut src = EioSource { file: File::open(&ts.paths[0]).unwrap(), bad_blocks: vec![3, 4], bs: 64 };
        let sc = Reader::open(&ts.sc_path).unwrap();
        let c = check_member_from(&mut src, &sc, 0).unwrap();
        assert_eq!(c.unreadable_blocks, vec![3, 4]);
        assert_eq!(c.bad_blocks, vec![3, 4]);
        assert!(c.file_hash.is_empty());
    }

    #[test]
    fn encode_member_hash_mismatch_is_member_error() {
        let dir = tempfile::tempdir().unwrap();
        let d0 = pseudo(500, 1);
        let d1 = pseudo(500, 2);
        let p0 = dir.path().join("a");
        let p1 = dir.path().join("b");
        std::fs::write(&p0, &d0).unwrap();
        std::fs::write(&p1, &d1).unwrap();
        let layout = SetLayout::choose(vec![500, 500], 64, 4096, 50_000, 0).unwrap();
        let members = vec![
            EncodeMember { abs: p0, size: 500, expected_hash: None },
            EncodeMember { abs: p1, size: 500, expected_hash: Some(vec![0u8; 32]) }, // wrong
        ];
        let tmp = dir.path().join("t.mts");
        match encode_set(&members, Algo::Blake3, &layout, &tmp) {
            Err(EncodeSetError::Member { index: 1, eio: false, .. }) => {}
            other => panic!("expected member error, got {other:?}"),
        }
        assert!(!tmp.exists(), "aborted encode must remove the temp sidecar");
    }

    #[test]
    fn encode_size_change_is_member_error() {
        let dir = tempfile::tempdir().unwrap();
        let p0 = dir.path().join("a");
        std::fs::write(&p0, pseudo(500, 1)).unwrap();
        let layout = SetLayout::choose(vec![600], 64, 4096, 50_000, 0).unwrap(); // wrong size on purpose
        let members = vec![EncodeMember { abs: p0, size: 600, expected_hash: None }];
        let tmp = dir.path().join("t.mts");
        match encode_set(&members, Algo::Blake3, &layout, &tmp) {
            Err(EncodeSetError::Member { index: 0, .. }) => {}
            other => panic!("expected member error, got {other:?}"),
        }
    }

    #[test]
    fn solo_big_file_multi_stripe_roundtrip() {
        // 20000 bytes, 64-byte blocks, stripe 4096 bytes => 313 blocks, 5 stripes.
        let ts = build_set(&[20_000], 50_000);
        assert!(ts.layout.n_stripes() >= 5);
        for &off in &[0u64, 200, 4500, 13_000, 19_999] {
            flip_byte(&ts.paths[0], off);
        }
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let out = repair_set(&mut sc, &ctx_all(&ts), false).unwrap();
        assert!(matches!(out.members[0], MemberOutcome::Repaired { .. }), "{:?}", out.members[0]);
        assert_eq!(std::fs::read(&ts.paths[0]).unwrap(), ts.datas[0]);
    }

    #[test]
    fn quarantine_keeps_damaged_copy() {
        let ts = build_set(&[1000, 1000], 200_000);
        flip_byte(&ts.paths[0], 10);
        let damaged = std::fs::read(&ts.paths[0]).unwrap();
        let q = ts.dir.path().join("quarantine/f0.bin");
        let mut sc = Reader::open(&ts.sc_path).unwrap();
        let mut ctxs = ctx_all(&ts);
        ctxs[0].keep_corrupt = Some(q.clone());
        let out = repair_set(&mut sc, &ctxs, false).unwrap();
        assert!(matches!(out.members[0], MemberOutcome::Repaired { .. }));
        assert_eq!(std::fs::read(&ts.paths[0]).unwrap(), ts.datas[0]);
        assert_eq!(std::fs::read(&q).unwrap(), damaged);
    }
}
