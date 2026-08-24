//! SQLite index. Paths are archive-relative and stored as BLOBs (raw bytes).

use crate::config::ParityMode;
use crate::hash::Algo;
use crate::util::{now, path_bytes, path_from_bytes};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: i64 = 2;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS content (
    hash              BLOB PRIMARY KEY,
    algo              TEXT NOT NULL,
    size              INTEGER NOT NULL,
    created_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS parity_set (
    id                BLOB PRIMARY KEY,
    algo              TEXT NOT NULL,
    block_size        INTEGER NOT NULL,
    blocks_per_stripe INTEGER NOT NULL,
    parity_ppm        INTEGER NOT NULL,
    min_parity_blocks INTEGER NOT NULL,
    n_members         INTEGER NOT NULL,
    n_blocks          INTEGER NOT NULL,
    data_bytes        INTEGER NOT NULL,
    created_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS parity_member (
    set_id            BLOB NOT NULL REFERENCES parity_set(id),
    ord               INTEGER NOT NULL,
    content_hash      BLOB NOT NULL,
    size              INTEGER NOT NULL,
    first_block       INTEGER NOT NULL,
    n_blocks          INTEGER NOT NULL,
    dead              INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (set_id, ord)
);
CREATE INDEX IF NOT EXISTS parity_member_content ON parity_member(content_hash);
CREATE TABLE IF NOT EXISTS file (
    id               INTEGER PRIMARY KEY,
    path             BLOB NOT NULL UNIQUE,
    content_hash     BLOB NOT NULL REFERENCES content(hash),
    size             INTEGER NOT NULL,
    mtime_ns         INTEGER NOT NULL,
    inode            INTEGER,
    state            TEXT NOT NULL DEFAULT 'ok',
    added_at         INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    last_verified_at INTEGER
);
CREATE INDEX IF NOT EXISTS file_content ON file(content_hash);
CREATE INDEX IF NOT EXISTS file_state ON file(state);
CREATE INDEX IF NOT EXISTS file_verified ON file(last_verified_at);
CREATE TABLE IF NOT EXISTS event (
    id     INTEGER PRIMARY KEY,
    ts     INTEGER NOT NULL,
    path   BLOB NOT NULL,
    kind   TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS event_path ON event(path);
CREATE TABLE IF NOT EXISTS parity_mark (
    path       BLOB PRIMARY KEY,
    mode       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Content matches the recorded hash (as of last check).
    Ok,
    /// File changed on disk (size/mtime) and the change was not accepted.
    Modified,
    /// Content differs from the recorded hash although size/mtime are unchanged.
    Corrupt,
    /// Corrupt, and parity is insufficient/absent.
    Unrecoverable,
    /// File no longer exists on disk.
    Missing,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::Modified => "modified",
            State::Corrupt => "corrupt",
            State::Unrecoverable => "unrecoverable",
            State::Missing => "missing",
        }
    }
    pub fn parse(s: &str) -> State {
        match s {
            "modified" => State::Modified,
            "corrupt" => State::Corrupt,
            "unrecoverable" => State::Unrecoverable,
            "missing" => State::Missing,
            _ => State::Ok,
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone)]
pub struct FileRow {
    pub id: i64,
    pub path: PathBuf,
    pub content_hash: Vec<u8>,
    pub size: u64,
    pub mtime_ns: i64,
    pub inode: Option<u64>,
    pub state: State,
    pub added_at: i64,
    pub updated_at: i64,
    pub last_verified_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ContentRow {
    pub hash: Vec<u8>,
    pub algo: Algo,
    pub size: u64,
    pub created_at: i64,
}

/// One parity set (see mts.rs): geometry + summary. The member layout comes
/// from `parity_member` rows and reconstructs an `mts::SetLayout` exactly.
#[derive(Debug, Clone)]
pub struct SetRow {
    pub id: Vec<u8>,
    pub algo: Algo,
    pub block_size: u32,
    pub blocks_per_stripe: u32,
    pub parity_ppm: u32,
    pub min_parity_blocks: u32,
    pub n_members: u32,
    pub n_blocks: u64,
    pub data_bytes: u64,
    pub created_at: i64,
}

/// content hash -> (set id, ord) for contents with a live parity membership.
pub type LiveMembershipMap = HashMap<Vec<u8>, (Vec<u8>, u32)>;

#[derive(Debug, Clone)]
pub struct MemberRow {
    pub set_id: Vec<u8>,
    pub ord: u32,
    pub content_hash: Vec<u8>,
    pub size: u64,
    pub first_block: u64,
    pub n_blocks: u64,
    /// The content was modified/removed after the set was sealed: its blocks
    /// are permanent erasures in this set until the set is rebuilt.
    pub dead: bool,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub ts: i64,
    pub path: PathBuf,
    pub kind: String,
    pub detail: Option<String>,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Stats {
    pub files: u64,
    pub bytes: u64,
    pub by_state: Vec<(String, u64)>,
    pub distinct_content: u64,
    pub parity_sets: u64,
    pub parity_sets_degraded: u64,
    pub parity_covered_files: u64,
    pub parity_bytes_covered: u64,
    pub never_verified: u64,
    pub oldest_verified: Option<i64>,
    pub events: u64,
}

pub struct Db {
    conn: Connection,
    path: PathBuf,
    dirty: bool,
    /// Result of comparing the file with index.sqlite.sha256 at open time.
    hash_ok: Option<bool>,
    /// Whether the pre-write backup (.bak) has been taken this session.
    backed_up: bool,
    /// Set by `allow_write_despite_hash_mismatch` (fsck / explicit override).
    force: bool,
    /// A previous session was interrupted (marker file present at open).
    interrupted: bool,
}

fn marker_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("sqlite.inprogress")
}

const FILE_COLS: &str = "id, path, content_hash, size, mtime_ns, inode, state, added_at, updated_at, last_verified_at";

fn row_to_file(r: &rusqlite::Row) -> rusqlite::Result<FileRow> {
    Ok(FileRow {
        id: r.get(0)?,
        path: path_from_bytes(&r.get::<_, Vec<u8>>(1)?),
        content_hash: r.get(2)?,
        size: r.get::<_, i64>(3)? as u64,
        mtime_ns: r.get(4)?,
        inode: r.get::<_, Option<i64>>(5)?.map(|i| i as u64),
        state: State::parse(&r.get::<_, String>(6)?),
        added_at: r.get(7)?,
        updated_at: r.get(8)?,
        last_verified_at: r.get(9)?,
    })
}

fn row_to_content(r: &rusqlite::Row) -> rusqlite::Result<ContentRow> {
    let algo_s: String = r.get(1)?;
    Ok(ContentRow {
        hash: r.get(0)?,
        algo: algo_s.parse().unwrap_or(Algo::Blake3),
        size: r.get::<_, i64>(2)? as u64,
        created_at: r.get(3)?,
    })
}

const SET_COLS: &str = "id, algo, block_size, blocks_per_stripe, parity_ppm, min_parity_blocks, n_members, n_blocks, data_bytes, created_at";

fn row_to_set(r: &rusqlite::Row) -> rusqlite::Result<SetRow> {
    let algo_s: String = r.get(1)?;
    Ok(SetRow {
        id: r.get(0)?,
        algo: algo_s.parse().unwrap_or(Algo::Blake3),
        block_size: r.get::<_, i64>(2)? as u32,
        blocks_per_stripe: r.get::<_, i64>(3)? as u32,
        parity_ppm: r.get::<_, i64>(4)? as u32,
        min_parity_blocks: r.get::<_, i64>(5)? as u32,
        n_members: r.get::<_, i64>(6)? as u32,
        n_blocks: r.get::<_, i64>(7)? as u64,
        data_bytes: r.get::<_, i64>(8)? as u64,
        created_at: r.get(9)?,
    })
}

const MEMBER_COLS: &str = "set_id, ord, content_hash, size, first_block, n_blocks, dead";

fn row_to_member(r: &rusqlite::Row) -> rusqlite::Result<MemberRow> {
    Ok(MemberRow {
        set_id: r.get(0)?,
        ord: r.get::<_, i64>(1)? as u32,
        content_hash: r.get(2)?,
        size: r.get::<_, i64>(3)? as u64,
        first_block: r.get::<_, i64>(4)? as u64,
        n_blocks: r.get::<_, i64>(5)? as u64,
        dead: r.get::<_, i64>(6)? != 0,
    })
}

/// Upper bound for a BLOB prefix range query: `prefix` with a trailing '/'
/// -> same bytes with '/' replaced by '0' (the next byte). Returns None for root.
fn dir_bounds(dir: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
    let b = path_bytes(dir);
    if b.is_empty() {
        return None;
    }
    let mut lo = b.to_vec();
    lo.push(b'/');
    let mut hi = lo.clone();
    *hi.last_mut().unwrap() = b'/' + 1;
    Some((lo, hi))
}

impl Db {
    pub fn create(path: &Path) -> Result<Db> {
        if path.exists() {
            bail!("database {} already exists", path.display());
        }
        let mut db = Db::open_raw(path)?;
        db.conn.execute_batch(SCHEMA)?;
        db.set_meta("schema_version", &SCHEMA_VERSION.to_string())?;
        db.set_meta("created_at", &now().to_string())?;
        db.dirty = true;
        Ok(db)
    }

    pub fn open(path: &Path) -> Result<Db> {
        if !path.exists() {
            bail!("database {} not found", path.display());
        }
        let mut db = Db::open_raw(path)?;
        db.hash_ok = check_db_hash_file(path)?;
        db.interrupted = marker_path(path).exists();
        if db.hash_ok == Some(false) && db.interrupted {
            // The previous meticulous run was interrupted after committing some
            // work but before it could record the new hash. SQLite transactions are
            // atomic, so the file is consistent if it passes its own integrity check.
            if db.integrity_check()?.is_empty() {
                eprintln!("note: the previous meticulous run was interrupted; the index is intact and will be picked up where it left off");
                db.hash_ok = None;
            }
        }
        let v: Option<String> = db.get_meta("schema_version")?;
        match v.as_deref().map(|s| s.parse::<i64>()) {
            Some(Ok(SCHEMA_VERSION)) => {}
            Some(Ok(other)) => bail!(
                "database schema version {other} is not supported by this build (wants {SCHEMA_VERSION}). \
                 This archive predates the parity-set format: re-create it (`meticulous init` in a fresh copy and re-scan) \
                 or rebuild the index with `meticulous fsck --rebuild-db` after upgrading the manifests"
            ),
            _ => bail!("database {} has no schema version (damaged?); try `meticulous fsck`", path.display()),
        }
        // Apply any additive schema (CREATE IF NOT EXISTS is idempotent).
        db.conn.execute_batch(SCHEMA)?;
        Ok(db)
    }

    fn open_raw(path: &Path) -> Result<Db> {
        let conn = Connection::open(path).with_context(|| format!("opening database {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY; PRAGMA cache_size = -65536; PRAGMA busy_timeout = 30000;",
        )?;
        Ok(Db { conn, path: path.to_path_buf(), dirty: false, hash_ok: None, backed_up: false, force: false, interrupted: false })
    }

    /// Was the database file unchanged since meticulous last wrote it?
    /// None = no record yet.
    pub fn hash_ok(&self) -> Option<bool> {
        self.hash_ok
    }
    pub fn allow_write_despite_hash_mismatch(&mut self) {
        self.force = true;
    }

    /// Called before the first write of a session: refuse if the file does not
    /// match its recorded hash (it was damaged or modified outside meticulous),
    /// otherwise copy it to `.bak` so `.bak` is always the previous good copy.
    fn before_write(&mut self) -> Result<()> {
        if self.backed_up {
            return Ok(());
        }
        if self.hash_ok == Some(false) && !self.force {
            bail!(
                "refusing to write: {} does not match the hash meticulous recorded for it (damaged or edited externally). \
                 Run `meticulous fsck`; restore from {} if it is intact, or `fsck --rebuild-db`.",
                self.path.display(),
                self.path.with_extension("sqlite.bak").display()
            );
        }
        // Keep the backup from before the interrupted session rather than replacing
        // it with a half-finished (though consistent) index.
        if self.hash_ok != Some(false) && !self.interrupted && self.path.exists() && self.conn.is_autocommit() {
            let bak = self.path.with_extension("sqlite.bak");
            let tmp = self.path.with_extension("sqlite.bak.tmp");
            std::fs::copy(&self.path, &tmp).with_context(|| format!("backing up {}", self.path.display()))?;
            std::fs::rename(&tmp, &bak)?;
        }
        // Marker: "a session is writing"; removed only after the hash file is refreshed.
        std::fs::write(marker_path(&self.path), std::process::id().to_string())?;
        self.backed_up = true;
        Ok(())
    }

    /// Roll back an open transaction, if any (error paths).
    pub fn rollback_open(&mut self) {
        if !self.conn.is_autocommit() {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn begin(&mut self) -> Result<()> {
        self.before_write()?;
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }
    pub fn commit(&mut self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        self.dirty = true;
        Ok(())
    }

    // ---- meta ----
    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }
    pub fn set_meta(&mut self, key: &str, value: &str) -> Result<()> {
        self.before_write()?;
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        self.dirty = true;
        Ok(())
    }

    // ---- content ----
    pub fn get_content(&self, hash: &[u8]) -> Result<Option<ContentRow>> {
        Ok(self
            .conn
            .query_row("SELECT hash, algo, size, created_at FROM content WHERE hash = ?1", [hash], row_to_content)
            .optional()?)
    }

    pub fn upsert_content(&mut self, c: &ContentRow) -> Result<()> {
        self.before_write()?;
        self.conn.execute(
            "INSERT INTO content(hash, algo, size, created_at) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(hash) DO NOTHING",
            params![c.hash, c.algo.name(), c.size as i64, c.created_at],
        )?;
        self.dirty = true;
        Ok(())
    }

    /// Delete content rows no longer referenced by any file (their parity
    /// memberships are marked dead first). Returns hashes removed.
    pub fn prune_orphan_content(&mut self) -> Result<Vec<Vec<u8>>> {
        self.before_write()?;
        let mut st = self
            .conn
            .prepare("SELECT hash FROM content WHERE NOT EXISTS (SELECT 1 FROM file WHERE file.content_hash = content.hash)")?;
        let hashes: Vec<Vec<u8>> = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        drop(st);
        for h in &hashes {
            self.conn.execute("UPDATE parity_member SET dead = 1 WHERE content_hash = ?1", [h])?;
            self.conn.execute("DELETE FROM content WHERE hash = ?1", [h])?;
        }
        if !hashes.is_empty() {
            self.dirty = true;
        }
        Ok(hashes)
    }

    // ---- parity sets ----
    /// Insert a set with its members (idempotent: an existing row with the
    /// same id — same layout + members by construction — is left alone).
    pub fn insert_parity_set(&mut self, set: &SetRow, members: &[MemberRow]) -> Result<()> {
        self.before_write()?;
        self.conn.execute(
            "INSERT INTO parity_set(id, algo, block_size, blocks_per_stripe, parity_ppm, min_parity_blocks, n_members, n_blocks, data_bytes, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) ON CONFLICT(id) DO NOTHING",
            params![
                set.id,
                set.algo.name(),
                set.block_size as i64,
                set.blocks_per_stripe as i64,
                set.parity_ppm as i64,
                set.min_parity_blocks as i64,
                set.n_members as i64,
                set.n_blocks as i64,
                set.data_bytes as i64,
                set.created_at
            ],
        )?;
        for m in members {
            self.conn.execute(
                "INSERT INTO parity_member(set_id, ord, content_hash, size, first_block, n_blocks, dead)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(set_id, ord) DO UPDATE SET dead = MAX(parity_member.dead, excluded.dead)",
                params![set.id, m.ord as i64, m.content_hash, m.size as i64, m.first_block as i64, m.n_blocks as i64, m.dead as i64],
            )?;
        }
        self.dirty = true;
        Ok(())
    }

    /// Remove a set and its membership rows (the sidecar file is the caller's problem).
    pub fn delete_parity_set(&mut self, id: &[u8]) -> Result<()> {
        self.before_write()?;
        self.conn.execute("DELETE FROM parity_member WHERE set_id = ?1", [id])?;
        self.conn.execute("DELETE FROM parity_set WHERE id = ?1", [id])?;
        self.dirty = true;
        Ok(())
    }

    pub fn get_parity_set(&self, id: &[u8]) -> Result<Option<SetRow>> {
        Ok(self
            .conn
            .query_row(&format!("SELECT {SET_COLS} FROM parity_set WHERE id = ?1"), [id], row_to_set)
            .optional()?)
    }

    pub fn all_parity_sets(&self) -> Result<Vec<SetRow>> {
        let mut st = self.conn.prepare(&format!("SELECT {SET_COLS} FROM parity_set ORDER BY id"))?;
        let v = st.query_map([], row_to_set)?.collect::<rusqlite::Result<_>>()?;
        Ok(v)
    }

    /// All members of a set, ordered by ord (dead ones included: they still
    /// occupy their block ranges in the set's geometry).
    pub fn set_members(&self, id: &[u8]) -> Result<Vec<MemberRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {MEMBER_COLS} FROM parity_member WHERE set_id = ?1 ORDER BY ord"))?;
        let v = st.query_map([id], row_to_member)?.collect::<rusqlite::Result<_>>()?;
        Ok(v)
    }

    /// All memberships of a content (live and dead), oldest set first.
    pub fn memberships_of(&self, content_hash: &[u8]) -> Result<Vec<MemberRow>> {
        let mut st = self.conn.prepare(
            "SELECT m.set_id, m.ord, m.content_hash, m.size, m.first_block, m.n_blocks, m.dead
             FROM parity_member m JOIN parity_set s ON s.id = m.set_id
             WHERE m.content_hash = ?1 ORDER BY s.created_at, s.id",
        )?;
        let v = st.query_map([content_hash], row_to_member)?.collect::<rusqlite::Result<_>>()?;
        Ok(v)
    }

    /// content hash -> (set id, ord) for every content with a live membership
    /// (one arbitrary-but-stable membership per content).
    pub fn live_membership_map(&self) -> Result<LiveMembershipMap> {
        let mut st = self
            .conn
            .prepare("SELECT content_hash, set_id, ord FROM parity_member WHERE dead = 0 ORDER BY set_id, ord")?;
        let mut out = HashMap::new();
        for r in st.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, i64>(2)? as u32)))? {
            let (h, sid, ord) = r?;
            out.entry(h).or_insert((sid, ord));
        }
        Ok(out)
    }

    /// Mark one specific membership dead (duplicate-membership convergence).
    pub fn mark_member_dead(&mut self, set_id: &[u8], ord: u32) -> Result<()> {
        self.before_write()?;
        self.conn
            .execute("UPDATE parity_member SET dead = 1 WHERE set_id = ?1 AND ord = ?2", params![set_id, ord as i64])?;
        self.dirty = true;
        Ok(())
    }

    /// Mark every membership of this content dead. Returns how many changed.
    pub fn mark_members_dead(&mut self, content_hash: &[u8]) -> Result<usize> {
        self.before_write()?;
        let n = self
            .conn
            .execute("UPDATE parity_member SET dead = 1 WHERE content_hash = ?1 AND dead = 0", [content_hash])?;
        if n > 0 {
            self.dirty = true;
        }
        Ok(n)
    }

    /// The central dead-marking hook: call after anything that removes or
    /// supersedes a file→content association. If no file references the
    /// content any more, its memberships become erasures.
    pub fn mark_dead_if_unreferenced(&mut self, content_hash: &[u8]) -> Result<()> {
        let referenced: bool = self
            .conn
            .query_row("SELECT EXISTS(SELECT 1 FROM file WHERE content_hash = ?1)", [content_hash], |r| {
                r.get::<_, i64>(0).map(|v| v != 0)
            })?;
        if !referenced {
            self.mark_members_dead(content_hash)?;
        }
        Ok(())
    }

    /// Sets that currently contain at least one dead member.
    pub fn degraded_sets(&self) -> Result<Vec<SetRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {SET_COLS} FROM parity_set s WHERE EXISTS
             (SELECT 1 FROM parity_member m WHERE m.set_id = s.id AND m.dead = 1) ORDER BY s.id"
        ))?;
        let v = st.query_map([], row_to_set)?.collect::<rusqlite::Result<_>>()?;
        Ok(v)
    }

    /// Contents that hold more than one live membership (transient after a
    /// mass rename); each entry is (content_hash, memberships oldest-first).
    pub fn duplicate_live_memberships(&self) -> Result<Vec<Vec<u8>>> {
        let mut st = self
            .conn
            .prepare("SELECT content_hash FROM parity_member WHERE dead = 0 GROUP BY content_hash HAVING COUNT(*) > 1")?;
        let v = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(v)
    }

    // ---- files ----
    pub fn get_file(&self, path: &Path) -> Result<Option<FileRow>> {
        Ok(self
            .conn
            .query_row(&format!("SELECT {FILE_COLS} FROM file WHERE path = ?1"), [path_bytes(path)], row_to_file)
            .optional()?)
    }

    /// All files under `dir` ("" = everything), ordered by path.
    pub fn files_under(&self, dir: &Path) -> Result<Vec<FileRow>> {
        match dir_bounds(dir) {
            None => {
                let mut st = self.conn.prepare(&format!("SELECT {FILE_COLS} FROM file ORDER BY path"))?;
                let v = st.query_map([], row_to_file)?.collect::<rusqlite::Result<_>>()?;
                Ok(v)
            }
            Some((lo, hi)) => {
                let mut st = self.conn.prepare(&format!(
                    "SELECT {FILE_COLS} FROM file WHERE (path >= ?1 AND path < ?2) OR path = ?3 ORDER BY path"
                ))?;
                let v = st
                    .query_map(params![lo, hi, path_bytes(dir)], row_to_file)?
                    .collect::<rusqlite::Result<_>>()?;
                Ok(v)
            }
        }
    }

    /// Files under any of `dirs` (deduplicated), ordered by path.
    pub fn files_under_any(&self, dirs: &[PathBuf]) -> Result<Vec<FileRow>> {
        if dirs.is_empty() {
            return self.files_under(Path::new(""));
        }
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for d in dirs {
            for f in self.files_under(d)? {
                if seen.insert(f.id) {
                    out.push(f);
                }
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    pub fn files_by_content(&self, hash: &[u8]) -> Result<Vec<FileRow>> {
        let mut st = self.conn.prepare(&format!("SELECT {FILE_COLS} FROM file WHERE content_hash = ?1 ORDER BY path"))?;
        let v = st.query_map([hash], row_to_file)?.collect::<rusqlite::Result<_>>()?;
        Ok(v)
    }

    /// Insert or replace the record for `path`. If this supersedes a different
    /// content hash whose last reference this was, the old content's parity
    /// memberships are marked dead (they are erasures from now on).
    pub fn upsert_file(&mut self, f: &FileRow) -> Result<i64> {
        self.before_write()?;
        let old_hash: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT content_hash FROM file WHERE path = ?1", [path_bytes(&f.path)], |r| r.get(0))
            .optional()?;
        self.conn.execute(
            "INSERT INTO file(path, content_hash, size, mtime_ns, inode, state, added_at, updated_at, last_verified_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(path) DO UPDATE SET
               content_hash = excluded.content_hash, size = excluded.size, mtime_ns = excluded.mtime_ns,
               inode = excluded.inode, state = excluded.state, updated_at = excluded.updated_at,
               last_verified_at = excluded.last_verified_at",
            params![
                path_bytes(&f.path),
                f.content_hash,
                f.size as i64,
                f.mtime_ns,
                f.inode.map(|i| i as i64),
                f.state.name(),
                f.added_at,
                f.updated_at,
                f.last_verified_at
            ],
        )?;
        self.dirty = true;
        let id = self.conn.last_insert_rowid();
        if let Some(old) = old_hash
            && old != f.content_hash
        {
            self.mark_dead_if_unreferenced(&old)?;
        }
        Ok(id)
    }

    pub fn set_state(&mut self, path: &Path, state: State) -> Result<()> {
        self.before_write()?;
        self.conn.execute(
            "UPDATE file SET state = ?2, updated_at = ?3 WHERE path = ?1",
            params![path_bytes(path), state.name(), now()],
        )?;
        self.dirty = true;
        Ok(())
    }

    pub fn set_verified(&mut self, path: &Path, ts: i64, state: State) -> Result<()> {
        self.before_write()?;
        self.conn.execute(
            "UPDATE file SET last_verified_at = ?2, state = ?3 WHERE path = ?1",
            params![path_bytes(path), ts, state.name()],
        )?;
        self.dirty = true;
        Ok(())
    }

    /// Forget a file. If it was the last reference to its content, the
    /// content's parity memberships are marked dead.
    pub fn delete_file(&mut self, path: &Path) -> Result<bool> {
        self.before_write()?;
        let old_hash: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT content_hash FROM file WHERE path = ?1", [path_bytes(path)], |r| r.get(0))
            .optional()?;
        let n = self.conn.execute("DELETE FROM file WHERE path = ?1", [path_bytes(path)])?;
        if n > 0 {
            self.dirty = true;
            if let Some(old) = old_hash {
                self.mark_dead_if_unreferenced(&old)?;
            }
        }
        Ok(n > 0)
    }

    // ---- events ----
    pub fn log_event(&mut self, path: &Path, kind: &str, detail: Option<&str>) -> Result<()> {
        self.before_write()?;
        self.conn.execute(
            "INSERT INTO event(ts, path, kind, detail) VALUES(?1, ?2, ?3, ?4)",
            params![now(), path_bytes(path), kind, detail],
        )?;
        self.dirty = true;
        Ok(())
    }

    pub fn events(&self, path: Option<&Path>, since: Option<i64>, limit: usize) -> Result<Vec<Event>> {
        let mut sql = String::from("SELECT ts, path, kind, detail FROM event WHERE 1=1");
        let mut args: Vec<rusqlite::types::Value> = vec![];
        if let Some(p) = path
            && let Some((lo, hi)) = dir_bounds(p) {
                sql.push_str(" AND ((path >= ? AND path < ?) OR path = ?)");
                args.push(lo.into());
                args.push(hi.into());
                args.push(path_bytes(p).to_vec().into());
            }
        if let Some(s) = since {
            sql.push_str(" AND ts >= ?");
            args.push(s.into());
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        args.push((limit as i64).into());
        let mut st = self.conn.prepare(&sql)?;
        let v = st
            .query_map(rusqlite::params_from_iter(args), |r| {
                Ok(Event {
                    ts: r.get(0)?,
                    path: path_from_bytes(&r.get::<_, Vec<u8>>(1)?),
                    kind: r.get(2)?,
                    detail: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(v)
    }

    // ---- parity marks ----
    pub fn marks(&self) -> Result<HashMap<PathBuf, ParityMode>> {
        let mut st = self.conn.prepare("SELECT path, mode FROM parity_mark")?;
        let mut out = HashMap::new();
        for r in st.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)))? {
            let (p, m) = r?;
            out.insert(path_from_bytes(&p), ParityMode::parse(&m)?);
        }
        Ok(out)
    }
    pub fn set_mark(&mut self, dir: &Path, mode: ParityMode) -> Result<()> {
        self.before_write()?;
        self.conn.execute(
            "INSERT INTO parity_mark(path, mode, created_at) VALUES(?1, ?2, ?3) ON CONFLICT(path) DO UPDATE SET mode = excluded.mode, created_at = excluded.created_at",
            params![path_bytes(dir), mode.name(), now()],
        )?;
        self.dirty = true;
        Ok(())
    }
    pub fn remove_mark(&mut self, dir: &Path) -> Result<bool> {
        self.before_write()?;
        let n = self.conn.execute("DELETE FROM parity_mark WHERE path = ?1", [path_bytes(dir)])?;
        self.dirty = true;
        Ok(n > 0)
    }

    // ---- stats ----
    #[allow(clippy::field_reassign_with_default)]
    pub fn stats(&self) -> Result<Stats> {
        let mut s = Stats::default();
        s.files = self.conn.query_row("SELECT COUNT(*) FROM file", [], |r| r.get::<_, i64>(0))? as u64;
        s.bytes = self
            .conn
            .query_row("SELECT COALESCE(SUM(size),0) FROM file WHERE state != 'missing'", [], |r| r.get::<_, i64>(0))? as u64;
        let mut st = self.conn.prepare("SELECT state, COUNT(*) FROM file GROUP BY state ORDER BY state")?;
        s.by_state = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)))?
            .collect::<rusqlite::Result<_>>()?;
        s.distinct_content = self.conn.query_row("SELECT COUNT(*) FROM content", [], |r| r.get::<_, i64>(0))? as u64;
        s.parity_sets = self.conn.query_row("SELECT COUNT(*) FROM parity_set", [], |r| r.get::<_, i64>(0))? as u64;
        s.parity_sets_degraded = self.conn.query_row(
            "SELECT COUNT(*) FROM parity_set s WHERE EXISTS (SELECT 1 FROM parity_member m WHERE m.set_id = s.id AND m.dead = 1)",
            [],
            |r| r.get::<_, i64>(0),
        )? as u64;
        let (cf, cb) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size),0) FROM file WHERE state != 'missing'
             AND EXISTS (SELECT 1 FROM parity_member m WHERE m.content_hash = file.content_hash AND m.dead = 0)",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )?;
        s.parity_covered_files = cf as u64;
        s.parity_bytes_covered = cb as u64;
        s.never_verified = self
            .conn
            .query_row("SELECT COUNT(*) FROM file WHERE last_verified_at IS NULL AND state != 'missing'", [], |r| r.get::<_, i64>(0))?
            as u64;
        s.oldest_verified = self
            .conn
            .query_row("SELECT MIN(last_verified_at) FROM file WHERE state != 'missing'", [], |r| r.get(0))?;
        s.events = self.conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0))? as u64;
        Ok(s)
    }

    pub fn integrity_check(&self) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("PRAGMA integrity_check")?;
        let v: Vec<String> = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(v.into_iter().filter(|s| s != "ok").collect())
    }

    /// Close the connection, then (if anything was written) rotate the backup
    /// copy and write the sidecar hash file. Call at the end of every command.
    pub fn finish(self) -> Result<()> {
        let Db { conn, path, dirty, backed_up, interrupted, .. } = self;
        conn.close().map_err(|(_, e)| e)?;
        if dirty || backed_up || interrupted {
            write_db_hash_file(&path)?;
            let _ = std::fs::remove_file(marker_path(&path));
        }
        Ok(())
    }

    /// Close without touching backup/hash files (used while rebuilding into a temp file).
    pub fn finish_without_protect(self) -> Result<()> {
        self.conn.close().map_err(|(_, e)| e)?;
        Ok(())
    }
}

/// Write `index.sqlite.sha256` (sha256sum format) covering the database, its
/// backup and the plaintext manifests, so damage to any of them is detectable.
pub fn write_db_hash_file(db_path: &Path) -> Result<()> {
    let dir = db_path.parent().unwrap_or(Path::new("."));
    let bak = db_path.with_extension("sqlite.bak");
    let manifest = dir.join(crate::config::MANIFEST_FILE);
    let tsv = dir.join(crate::config::MANIFEST_TSV_FILE);
    let marks = dir.join(crate::commands::manifest::MARKS_FILE);
    let mut lines = String::new();
    for p in [db_path, &bak, &manifest, &tsv, &marks] {
        if p.is_file() {
            let (h, _) = crate::parity::hash_file(p, Algo::Sha256)?;
            lines.push_str(&format!(
                "{}  {}\n",
                hex::encode(h),
                p.file_name().unwrap().to_string_lossy()
            ));
        }
    }
    std::fs::write(db_path.with_extension("sqlite.sha256"), lines)?;
    Ok(())
}

/// Verify a file in `_meticulous/` against `index.sqlite.sha256`. Ok(None) if no record.
pub fn check_recorded_hash(db_path: &Path, file: &Path) -> Result<Option<bool>> {
    let p = db_path.with_extension("sqlite.sha256");
    if !p.is_file() {
        return Ok(None);
    }
    let want = std::fs::read_to_string(&p)?;
    let name = file.file_name().unwrap().to_string_lossy().into_owned();
    for line in want.lines() {
        if let Some((h, n)) = line.split_once("  ")
            && n == name
        {
            let (got, _) = crate::parity::hash_file(file, Algo::Sha256)?;
            return Ok(Some(hex::encode(got) == h));
        }
    }
    Ok(None)
}

/// Verify the db file against the recorded sha256. Ok(None) if no record.
pub fn check_db_hash_file(db_path: &Path) -> Result<Option<bool>> {
    check_recorded_hash(db_path, db_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_under_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::create(&dir.path().join("x.sqlite")).unwrap();
        let c = ContentRow { hash: vec![1; 32], algo: Algo::Blake3, size: 1, created_at: 0 };
        db.upsert_content(&c).unwrap();
        for p in ["foo/a", "foo/b/c", "foobar", "bar"] {
            db.upsert_file(&FileRow {
                id: 0,
                path: PathBuf::from(p),
                content_hash: vec![1; 32],
                size: 1,
                mtime_ns: 0,
                inode: None,
                state: State::Ok,
                added_at: 0,
                updated_at: 0,
                last_verified_at: None,
            })
            .unwrap();
        }
        let got: Vec<String> = db
            .files_under(Path::new("foo"))
            .unwrap()
            .iter()
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(got, vec!["foo/a", "foo/b/c"]);
        assert_eq!(db.files_under(Path::new("")).unwrap().len(), 4);
        assert_eq!(db.files_under(Path::new("foobar")).unwrap().len(), 1);
        assert_eq!(db.stats().unwrap().files, 4);
    }

    #[test]
    fn parity_set_crud_and_dead_marking() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::create(&dir.path().join("x.sqlite")).unwrap();
        let (h1, h2) = (vec![1u8; 32], vec![2u8; 32]);
        for h in [&h1, &h2] {
            db.upsert_content(&ContentRow { hash: h.clone(), algo: Algo::Blake3, size: 100, created_at: 0 }).unwrap();
        }
        let file = |p: &str, h: &Vec<u8>| FileRow {
            id: 0,
            path: PathBuf::from(p),
            content_hash: h.clone(),
            size: 100,
            mtime_ns: 0,
            inode: None,
            state: State::Ok,
            added_at: 0,
            updated_at: 0,
            last_verified_at: None,
        };
        let (fa, fb, fb2) = (file("a", &h1), file("b", &h2), file("b2", &h2));
        db.upsert_file(&fa).unwrap();
        db.upsert_file(&fb).unwrap();
        db.upsert_file(&fb2).unwrap();
        let set = SetRow {
            id: vec![9u8; 32],
            algo: Algo::Blake3,
            block_size: 64,
            blocks_per_stripe: 64,
            parity_ppm: 50_000,
            min_parity_blocks: 0,
            n_members: 2,
            n_blocks: 4,
            data_bytes: 200,
            created_at: 1,
        };
        let members = vec![
            MemberRow { set_id: set.id.clone(), ord: 0, content_hash: h1.clone(), size: 100, first_block: 0, n_blocks: 2, dead: false },
            MemberRow { set_id: set.id.clone(), ord: 1, content_hash: h2.clone(), size: 100, first_block: 2, n_blocks: 2, dead: false },
        ];
        db.insert_parity_set(&set, &members).unwrap();
        // Idempotent re-insert.
        db.insert_parity_set(&set, &members).unwrap();
        assert_eq!(db.all_parity_sets().unwrap().len(), 1);
        assert_eq!(db.set_members(&set.id).unwrap().len(), 2);
        assert_eq!(db.live_membership_map().unwrap().len(), 2);
        assert!(db.degraded_sets().unwrap().is_empty());

        // Deleting one of two files referencing h2 does not kill the membership...
        db.delete_file(Path::new("b")).unwrap();
        assert!(db.degraded_sets().unwrap().is_empty());
        // ...deleting the last one does.
        db.delete_file(Path::new("b2")).unwrap();
        assert_eq!(db.degraded_sets().unwrap().len(), 1);
        assert_eq!(db.live_membership_map().unwrap().len(), 1);
        // Superseding a's content marks h1 dead too.
        db.upsert_content(&ContentRow { hash: vec![3u8; 32], algo: Algo::Blake3, size: 100, created_at: 0 }).unwrap();
        db.upsert_file(&FileRow { content_hash: vec![3u8; 32], ..fa }).unwrap();
        assert!(db.live_membership_map().unwrap().is_empty());
        // Members (even dead) still enumerate; delete removes everything.
        assert_eq!(db.set_members(&set.id).unwrap().iter().filter(|m| m.dead).count(), 2);
        db.delete_parity_set(&set.id).unwrap();
        assert!(db.all_parity_sets().unwrap().is_empty());
        assert!(db.set_members(&set.id).unwrap().is_empty());
        let stats = db.stats().unwrap();
        assert_eq!(stats.parity_sets, 0);
    }
}
