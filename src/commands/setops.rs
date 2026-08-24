//! The parity-phase engine shared by `scan`, `parity sync` and `rm`:
//! building the pool of contents that need (re)packing, packing them into
//! sets, encoding/adopting sidecars, dissolving superseded sets, converging
//! duplicate memberships, and sweeping orphan sidecars.

use super::Ctx;
use super::scan::mtime_ns;
use crate::db::{MemberRow, SetRow, State};
use crate::marks::Resolver;
use crate::mts::{self, SetLayout};
use crate::util::{fmt_bytes, now, path_display};
use crate::worker::{self, Done, Job, SetMember, Settings, Work};
use anyhow::{Result, ensure};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

/// Rebuild the exact sidecar geometry from database rows.
pub fn layout_from_rows(set: &SetRow, members: &[MemberRow]) -> Result<SetLayout> {
    let sizes: Vec<u64> = members.iter().map(|m| m.size).collect();
    ensure!(members.len() == set.n_members as usize, "set {} member rows are incomplete", hex::encode(&set.id));
    let l = SetLayout::new(set.block_size, set.blocks_per_stripe, set.parity_ppm, set.min_parity_blocks, sizes)?;
    ensure!(l.n_blocks() == set.n_blocks, "set {} geometry mismatch between rows and layout", hex::encode(&set.id));
    for (i, m) in members.iter().enumerate() {
        ensure!(m.ord as usize == i && l.member_first_block(i) == m.first_block, "set {} member rows are inconsistent", hex::encode(&set.id));
    }
    Ok(l)
}

/// Cross-check that a sidecar on disk describes the same set as the DB rows.
pub fn verify_sidecar_matches(set: &SetRow, members: &[MemberRow], r: &mts::Reader) -> Result<()> {
    ensure!(r.set_id() == set.id.as_slice(), "sidecar set id differs from the database");
    let h = &r.header;
    ensure!(
        h.layout.block_size == set.block_size
            && h.layout.blocks_per_stripe == set.blocks_per_stripe
            && h.layout.parity_ppm == set.parity_ppm
            && h.layout.min_parity_blocks == set.min_parity_blocks
            && h.layout.n_members() == set.n_members as usize,
        "sidecar geometry differs from the database"
    );
    for m in members {
        ensure!(r.member_hash(m.ord as usize) == m.content_hash.as_slice(), "sidecar member table differs from the database");
    }
    Ok(())
}

/// Dead (erased-forever) blocks per stripe, from the membership rows.
pub fn dead_blocks_per_stripe(layout: &SetLayout, members: &[MemberRow]) -> BTreeMap<u64, u64> {
    let mut out = BTreeMap::new();
    let bps = layout.blocks_per_stripe as u64;
    for m in members.iter().filter(|m| m.dead) {
        let (mut b, end) = (m.first_block, m.first_block + m.n_blocks);
        while b < end {
            let s = b / bps;
            let stripe_end = (s + 1) * bps;
            let n = end.min(stripe_end) - b;
            *out.entry(s).or_default() += n;
            b += n;
        }
    }
    out
}

/// Best-effort repairability estimate for damage in one live member, counting
/// only what the database knows (dead members); intact siblings are assumed
/// intact. `repair` makes the authoritative call.
pub fn estimated_margin_ok(set: &SetRow, members: &[MemberRow], ord: u32, bad_member_rel: &[u64]) -> Result<bool> {
    let layout = layout_from_rows(set, members)?;
    let dead = dead_blocks_per_stripe(&layout, members);
    let first = members[ord as usize].first_block;
    let mut bad_per_stripe: BTreeMap<u64, u64> = BTreeMap::new();
    for &b in bad_member_rel {
        *bad_per_stripe.entry(layout.stripe_of_block(first + b)).or_default() += 1;
    }
    for (s, bad) in bad_per_stripe {
        if bad + dead.get(&s).copied().unwrap_or(0) > layout.stripe_parity_blocks(s) as u64 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether a member could be rebuilt even if its file were lost entirely
/// (per stripe: its blocks + already-dead blocks fit within the parity count).
pub fn loss_protected(layout: &SetLayout, members: &[MemberRow], ord: usize) -> bool {
    let dead = dead_blocks_per_stripe(layout, members);
    let bps = layout.blocks_per_stripe as u64;
    let (mut b, end) = (layout.member_first_block(ord), layout.member_first_block(ord) + layout.member_blocks(ord));
    while b < end {
        let s = b / bps;
        let stripe_end = (s + 1) * bps;
        let n = end.min(stripe_end) - b;
        if n + dead.get(&s).copied().unwrap_or(0) > layout.stripe_parity_blocks(s) as u64 {
            return false;
        }
        b += n;
    }
    true
}

/// One content that needs a (new) parity set, with a file to read it from.
#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub hash: Vec<u8>,
    pub size: u64,
    pub rel: PathBuf,
    pub abs: PathBuf,
    pub mtime_ns: i64,
}

#[derive(Debug, Default)]
pub struct PhaseOutcome {
    pub built: u64,
    pub adopted: u64,
    pub dissolved: u64,
    pub encoded_bytes: u64,
    pub errors: u64,
    /// Sets kept because a member awaits repair/accept: (set id hex prefix, blockers).
    pub held: Vec<(String, Vec<String>)>,
    pub orphans_removed: u64,
    /// Files skipped because they changed since the last scan.
    pub skipped_modified: u64,
}

impl PhaseOutcome {
    pub fn had_problems(&self) -> bool {
        self.errors > 0 || !self.held.is_empty()
    }
    pub fn print(&self, quiet: bool) {
        let mut parts = Vec::new();
        if self.built > 0 {
            parts.push(format!("{} set(s) encoded ({})", self.built, fmt_bytes(self.encoded_bytes)));
        }
        if self.adopted > 0 {
            parts.push(format!("{} adopted", self.adopted));
        }
        if self.dissolved > 0 {
            parts.push(format!("{} dissolved", self.dissolved));
        }
        if self.orphans_removed > 0 {
            parts.push(format!("{} orphan sidecar(s) removed", self.orphans_removed));
        }
        if self.skipped_modified > 0 {
            parts.push(format!("{} skipped (modified)", self.skipped_modified));
        }
        if self.errors > 0 {
            parts.push(format!("{} errors", self.errors));
        }
        if !parts.is_empty() && (!quiet || self.errors > 0) {
            println!("parity: {}", parts.join(", "));
        }
        for (id, blockers) in &self.held {
            println!(
                "parity set {id} kept: waiting on {} — repair or `meticulous accept` them (or remove them from the index) so the set can be rebuilt",
                blockers.join(", ")
            );
        }
    }
}

/// Keep the best live membership per content, mark the rest dead, and delete
/// sets that end up with no live members at all. Called at the start of every
/// parity phase and again after new sets are committed.
pub fn converge_duplicates(ctx: &mut Ctx) -> Result<u64> {
    let dups = ctx.db.duplicate_live_memberships()?;
    if !dups.is_empty() {
        let mut dead_counts: HashMap<Vec<u8>, u64> = HashMap::new();
        for h in &dups {
            let ms: Vec<MemberRow> = ctx.db.memberships_of(h)?.into_iter().filter(|m| !m.dead).collect();
            // Keep the membership in the set with the fewest dead blocks
            // (tie: memberships_of orders oldest-first, keep the first).
            let mut best = 0usize;
            let mut best_dead = u64::MAX;
            for (i, m) in ms.iter().enumerate() {
                let dead = match dead_counts.get(&m.set_id) {
                    Some(&d) => d,
                    None => {
                        let d = ctx
                            .db
                            .set_members(&m.set_id)?
                            .iter()
                            .filter(|x| x.dead)
                            .map(|x| x.n_blocks)
                            .sum();
                        dead_counts.insert(m.set_id.clone(), d);
                        d
                    }
                };
                if dead < best_dead {
                    best_dead = dead;
                    best = i;
                }
            }
            for (i, m) in ms.iter().enumerate() {
                if i != best {
                    ctx.db.mark_member_dead(&m.set_id, m.ord)?;
                }
            }
        }
    }
    // Sets with no live members left carry nothing: drop them outright.
    let mut deleted = 0u64;
    for set in ctx.db.all_parity_sets()? {
        let members = ctx.db.set_members(&set.id)?;
        if members.iter().all(|m| m.dead) {
            ctx.db.delete_parity_set(&set.id)?;
            let _ = std::fs::remove_file(mts::sidecar_path(&ctx.archive.parity_dir(), &set.id));
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Can this set be dissolved (all live members re-readable from intact,
/// unmodified files)? Returns the pool entries for its live members, or the
/// list of blockers. Contents in `exclude` (about to be deleted by `rm`) are
/// left out of both the entries and the blockers.
pub fn dissolution_entries(
    ctx: &Ctx,
    set: &SetRow,
    exclude: &HashSet<Vec<u8>>,
) -> Result<std::result::Result<Vec<PoolEntry>, Vec<String>>> {
    let members = ctx.db.set_members(&set.id)?;
    let mut entries = Vec::new();
    let mut blockers = Vec::new();
    for m in members.iter().filter(|m| !m.dead && !exclude.contains(&m.content_hash)) {
        let mut found = None;
        let mut reason = "no intact file".to_string();
        for f in ctx.db.files_by_content(&m.content_hash)? {
            if f.state != State::Ok {
                reason = format!("{} ({})", path_display(&f.path), f.state);
                continue;
            }
            let abs = ctx.archive.abs(&f.path);
            match std::fs::metadata(&abs) {
                Ok(meta) if meta.len() == f.size && mtime_ns(&meta) == f.mtime_ns => {
                    found = Some(PoolEntry { hash: m.content_hash.clone(), size: m.size, rel: f.path.clone(), abs, mtime_ns: f.mtime_ns });
                    break;
                }
                _ => reason = format!("{} (changed on disk)", path_display(&f.path)),
            }
        }
        match found {
            Some(e) => entries.push(e),
            None => blockers.push(reason),
        }
    }
    Ok(if blockers.is_empty() { Ok(entries) } else { Err(blockers) })
}

/// Greedy path-ordered packing: close a group at the byte target or the member
/// cap; a single entry at or above the target gets a solo (multi-stripe) set.
pub fn pack_pool(mut pool: Vec<PoolEntry>, stripe_size: u64) -> Vec<Vec<PoolEntry>> {
    pool.sort_by(|a, b| a.rel.cmp(&b.rel));
    let mut groups: Vec<Vec<PoolEntry>> = Vec::new();
    let mut cur: Vec<PoolEntry> = Vec::new();
    let mut cur_bytes = 0u64;
    for e in pool {
        if e.size >= stripe_size {
            if !cur.is_empty() {
                groups.push(std::mem::take(&mut cur));
                cur_bytes = 0;
            }
            groups.push(vec![e]);
            continue;
        }
        cur_bytes += e.size;
        cur.push(e);
        if cur_bytes >= stripe_size || cur.len() >= mts::MAX_MEMBERS as usize {
            groups.push(std::mem::take(&mut cur));
            cur_bytes = 0;
        }
    }
    if !cur.is_empty() {
        groups.push(cur);
    }
    groups
}

fn set_row_from(layout: &SetLayout, algo: crate::hash::Algo, id: &[u8]) -> SetRow {
    SetRow {
        id: id.to_vec(),
        algo,
        block_size: layout.block_size,
        blocks_per_stripe: layout.blocks_per_stripe,
        parity_ppm: layout.parity_ppm,
        min_parity_blocks: layout.min_parity_blocks,
        n_members: layout.n_members() as u32,
        n_blocks: layout.n_blocks(),
        data_bytes: layout.total_data_bytes(),
        created_at: now(),
    }
}

fn member_rows_from(layout: &SetLayout, id: &[u8], hashes: &[Vec<u8>], dead: &[bool]) -> Vec<MemberRow> {
    (0..layout.n_members())
        .map(|i| MemberRow {
            set_id: id.to_vec(),
            ord: i as u32,
            content_hash: hashes[i].clone(),
            size: layout.member_size(i),
            first_block: layout.member_first_block(i),
            n_blocks: layout.member_blocks(i),
            dead: dead[i],
        })
        .collect()
}

/// Insert an encoded set into the DB. `dead[i]` marks members that changed
/// underneath the encoder (their file rows are NOT touched here).
pub fn insert_encoded_set(ctx: &mut Ctx, algo: crate::hash::Algo, layout: &SetLayout, set_id: &[u8], member_hashes: &[Vec<u8>], dead: &[bool]) -> Result<()> {
    let set = set_row_from(layout, algo, set_id);
    let members = member_rows_from(layout, set_id, member_hashes, dead);
    ctx.db.insert_parity_set(&set, &members)?;
    Ok(())
}

/// Delete every `.mts` under parity/ that no parity_set row references
/// (superseded sidecars left behind by an interrupted run).
pub fn orphan_sweep(ctx: &mut Ctx) -> Result<u64> {
    let parity_dir = ctx.archive.parity_dir();
    let tmp_dir = parity_dir.join("tmp");
    let known: HashSet<Vec<u8>> = ctx.db.all_parity_sets()?.into_iter().map(|s| s.id).collect();
    let mut removed = 0u64;
    for e in walkdir::WalkDir::new(&parity_dir).into_iter().flatten() {
        if !e.file_type().is_file() || e.path().starts_with(&tmp_dir) {
            continue;
        }
        if e.path().extension().is_none_or(|x| x != "mts") {
            continue;
        }
        let id = e
            .path()
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| hex::decode(s).ok());
        let keep = id.map(|i| known.contains(&i)).unwrap_or(false);
        if !keep {
            let _ = std::fs::remove_file(e.path());
            removed += 1;
        }
    }
    Ok(removed)
}

/// The full parity phase: converge duplicates, build the pool (uncovered
/// contents + eligible degraded/underfull sets), pack, encode or adopt,
/// dissolve superseded sets, converge again, sweep orphans.
pub fn parity_phase(ctx: &mut Ctx, settings: &Settings, resolver: &mut Resolver) -> Result<PhaseOutcome> {
    let mut out = PhaseOutcome::default();

    ctx.db.begin()?;
    converge_duplicates(ctx)?;

    // Pool part 1: covered, intact contents with no live membership.
    let live = ctx.db.live_membership_map()?;
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut pool: Vec<PoolEntry> = Vec::new();
    for row in ctx.db.files_under(std::path::Path::new(""))? {
        if row.state != State::Ok || !resolver.covers_file(&row.path) {
            continue;
        }
        if row.size == 0 || live.contains_key(&row.content_hash) || seen.contains(&row.content_hash) {
            continue;
        }
        let abs = ctx.archive.abs(&row.path);
        match std::fs::metadata(&abs) {
            Ok(m) if m.len() == row.size && mtime_ns(&m) == row.mtime_ns => {
                seen.insert(row.content_hash.clone());
                pool.push(PoolEntry { hash: row.content_hash.clone(), size: row.size, rel: row.path.clone(), abs, mtime_ns: row.mtime_ns });
            }
            Ok(_) => out.skipped_modified += 1,
            Err(_) => {}
        }
    }

    // Pool part 2: live members of eligible degraded sets.
    let no_exclude: HashSet<Vec<u8>> = HashSet::new();
    let mut dissolve: Vec<SetRow> = Vec::new();
    let mut dissolve_ids: HashSet<Vec<u8>> = HashSet::new();
    for set in ctx.db.degraded_sets()? {
        match dissolution_entries(ctx, &set, &no_exclude)? {
            Ok(entries) => {
                for e in entries {
                    if seen.insert(e.hash.clone()) {
                        pool.push(e);
                    }
                }
                dissolve_ids.insert(set.id.clone());
                dissolve.push(set);
            }
            Err(blockers) => out.held.push((hex::encode(&set.id[..std::cmp::min(8, set.id.len())]), blockers)),
        }
    }

    // Pool part 3: merge underfull sets — when new content arrived, or when
    // two or more of them could combine (each incremental scan leaves a tail
    // set; without this they would accumulate).
    let underfull: Vec<SetRow> = ctx
        .db
        .all_parity_sets()?
        .into_iter()
        .filter(|s| !dissolve_ids.contains(&s.id) && s.data_bytes * 2 < settings.stripe_size)
        .collect();
    if !pool.is_empty() || underfull.len() >= 2 {
        for set in underfull {
            if let Ok(entries) = dissolution_entries(ctx, &set, &no_exclude)? {
                for e in entries {
                    if seen.insert(e.hash.clone()) {
                        pool.push(e);
                    }
                }
                dissolve_ids.insert(set.id.clone());
                dissolve.push(set);
            }
        }
    }
    ctx.db.commit()?;

    if pool.is_empty() && dissolve.is_empty() {
        ctx.db.begin()?;
        out.orphans_removed = orphan_sweep(ctx)?;
        ctx.db.commit()?;
        return Ok(out);
    }

    encode_pool(ctx, settings, pool, &mut out)?;

    ctx.db.begin()?;
    finalize_dissolve(ctx, &dissolve, &mut out)?;
    converge_duplicates(ctx)?;
    out.orphans_removed = orphan_sweep(ctx)?;
    ctx.db.commit()?;
    Ok(out)
}

/// `rm`'s rebuild step: dissolve the given sets, repacking their live members
/// minus the contents in `exclude`. Callers verify eligibility first.
pub fn rebuild_excluding(
    ctx: &mut Ctx,
    settings: &Settings,
    sets: Vec<SetRow>,
    exclude: &HashSet<Vec<u8>>,
) -> Result<PhaseOutcome> {
    let mut out = PhaseOutcome::default();
    let mut pool: Vec<PoolEntry> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut dissolve: Vec<SetRow> = Vec::new();
    ctx.db.begin()?;
    for set in sets {
        match dissolution_entries(ctx, &set, exclude)? {
            Ok(entries) => {
                for e in entries {
                    if seen.insert(e.hash.clone()) {
                        pool.push(e);
                    }
                }
                dissolve.push(set);
            }
            Err(blockers) => out.held.push((hex::encode(&set.id[..std::cmp::min(8, set.id.len())]), blockers)),
        }
    }
    ctx.db.commit()?;
    encode_pool(ctx, settings, pool, &mut out)?;
    ctx.db.begin()?;
    // The excluded contents are about to be deleted: their memberships in the
    // dissolving sets must not block the dissolve check.
    for h in exclude {
        ctx.db.mark_members_dead(h)?;
    }
    finalize_dissolve(ctx, &dissolve, &mut out)?;
    converge_duplicates(ctx)?;
    out.orphans_removed = orphan_sweep(ctx)?;
    ctx.db.commit()?;
    Ok(out)
}

/// Pack a pool into groups and encode (or adopt) each group's sidecar,
/// recording the sets in the DB.
fn encode_pool(ctx: &mut Ctx, settings: &Settings, pool: Vec<PoolEntry>, out: &mut PhaseOutcome) -> Result<()> {
    if pool.is_empty() {
        return Ok(());
    }
    let groups = pack_pool(pool, settings.stripe_size);
    let mut jobs: Vec<Job<()>> = Vec::new();
    ctx.db.begin()?;
    for g in groups {
        let layout = settings.set_layout_for(g.iter().map(|e| e.size).collect())?;
        let hashes: Vec<Vec<u8>> = g.iter().map(|e| e.hash.clone()).collect();
        let id = mts::compute_set_id(settings.algo, &layout, &hashes);
        // Repacking produced a set that already exists (e.g. an underfull set
        // with nothing to merge into): nothing to do.
        if ctx.db.get_parity_set(&id)?.is_some() {
            continue;
        }
        let sc_path = mts::sidecar_path(&settings.parity_dir, &id);
        // Adopt a valid sidecar left by an interrupted run: verify every
        // section hash, then just record it — no data re-read.
        if sc_path.is_file()
            && let Ok(mut r) = mts::Reader::open(&sc_path)
            && r.set_id() == id.as_slice()
            && r.deep_check().map(|p| p.is_empty()).unwrap_or(false)
        {
            insert_encoded_set(ctx, settings.algo, &layout, &id, &hashes, &vec![false; g.len()])?;
            out.adopted += 1;
            continue;
        }
        let total: u64 = g.iter().map(|e| e.size).sum();
        let members: Vec<SetMember> = g
            .iter()
            .map(|e| SetMember { rel: e.rel.clone(), abs: e.abs.clone(), size: e.size, mtime_ns: e.mtime_ns, expected_hash: Some(e.hash.clone()) })
            .collect();
        jobs.push(Job { rel: g[0].rel.clone(), abs: g[0].abs.clone(), size: total, work: Work::EncodeSet { members }, tag: () });
    }
    ctx.db.commit()?;

    if !jobs.is_empty() {
        ctx.say(format!(
            "generating parity: {} set(s), {}",
            jobs.len(),
            fmt_bytes(jobs.iter().map(|j| j.size).sum())
        ));
    }
    ctx.db.begin()?;
    worker::run(jobs, settings, |_job, done| {
        match done {
            Done::SetEncoded(rep) => {
                for (m, msg, eio) in &rep.ejected {
                    if *eio {
                        ctx.read_error(&m.rel, msg);
                        ctx.db.set_state(&m.rel, State::Unrecoverable)?;
                        ctx.db.log_event(&m.rel, "read-error", Some(msg))?;
                    } else {
                        println!("skipped (changed or damaged while encoding parity): {}: {msg}", path_display(&m.rel));
                        ctx.db.log_event(&m.rel, "parity-skip", Some(msg))?;
                    }
                    out.errors += 1;
                }
                if rep.set_id.is_empty() {
                    return Ok(());
                }
                // Members that changed after their bytes were consumed are
                // sealed into the set but committed dead.
                let dead: Vec<bool> = rep
                    .members
                    .iter()
                    .map(|m| match std::fs::metadata(&m.abs) {
                        Ok(meta) => meta.len() != m.size || mtime_ns(&meta) != m.mtime_ns,
                        Err(_) => true,
                    })
                    .collect();
                insert_encoded_set(ctx, settings.algo, &rep.layout, &rep.set_id, &rep.member_hashes, &dead)?;
                out.built += 1;
                out.encoded_bytes += rep.bytes;
            }
            Done::Failed(m) | Done::ReadError(m) => {
                eprintln!("error: encoding parity set: {m}");
                out.errors += 1;
            }
            _ => unreachable!(),
        }
        Ok(())
    })?;
    ctx.db.commit()?;
    Ok(())
}

/// Delete superseded sets whose live members were all re-homed into another
/// set; sets with a member left behind are kept (retried next scan).
fn finalize_dissolve(ctx: &mut Ctx, dissolve: &[SetRow], out: &mut PhaseOutcome) -> Result<()> {
    for set in dissolve {
        let members = ctx.db.set_members(&set.id)?;
        let mut all_rehomed = true;
        for m in members.iter().filter(|m| !m.dead) {
            let rehomed = ctx
                .db
                .memberships_of(&m.content_hash)?
                .iter()
                .any(|x| !x.dead && x.set_id != set.id);
            if !rehomed {
                all_rehomed = false;
                break;
            }
        }
        if all_rehomed {
            ctx.db.delete_parity_set(&set.id)?;
            let _ = std::fs::remove_file(mts::sidecar_path(&ctx.archive.parity_dir(), &set.id));
            out.dissolved += 1;
        }
    }
    Ok(())
}
