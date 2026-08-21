//! SQLite index. Paths are archive-relative and stored as BLOBs (raw bytes).

use crate::config::ParityMode;
use crate::hash::Algo;
use crate::util::{now, path_bytes, path_from_bytes};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS content (
    hash              BLOB PRIMARY KEY,
    algo              TEXT NOT NULL,
    size              INTEGER NOT NULL,
    block_size        INTEGER,
    blocks_per_stripe INTEGER,
    parity_ppm        INTEGER,
    has_parity        INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
);
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
    pub block_size: Option<u32>,
    pub blocks_per_stripe: Option<u32>,
    pub parity_ppm: Option<u32>,
    pub has_parity: bool,
    pub created_at: i64,
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
    pub parity_contents: u64,
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
        block_size: r.get::<_, Option<i64>>(3)?.map(|v| v as u32),
        blocks_per_stripe: r.get::<_, Option<i64>>(4)?.map(|v| v as u32),
        parity_ppm: r.get::<_, Option<i64>>(5)?.map(|v| v as u32),
        has_parity: r.get::<_, i64>(6)? != 0,
        created_at: r.get(7)?,
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
            Some(Ok(other)) => bail!("database schema version {other} is not supported by this build ({SCHEMA_VERSION})"),
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
            .query_row(
                "SELECT hash, algo, size, block_size, blocks_per_stripe, parity_ppm, has_parity, created_at FROM content WHERE hash = ?1",
                [hash],
                row_to_content,
            )
            .optional()?)
    }

    pub fn upsert_content(&mut self, c: &ContentRow) -> Result<()> {
        self.before_write()?;
        self.conn.execute(
            "INSERT INTO content(hash, algo, size, block_size, blocks_per_stripe, parity_ppm, has_parity, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(hash) DO UPDATE SET
               block_size = COALESCE(excluded.block_size, content.block_size),
               blocks_per_stripe = COALESCE(excluded.blocks_per_stripe, content.blocks_per_stripe),
               parity_ppm = COALESCE(excluded.parity_ppm, content.parity_ppm),
               has_parity = MAX(content.has_parity, excluded.has_parity)",
            params![
                c.hash,
                c.algo.name(),
                c.size as i64,
                c.block_size.map(|v| v as i64),
                c.blocks_per_stripe.map(|v| v as i64),
                c.parity_ppm.map(|v| v as i64),
                c.has_parity as i64,
                c.created_at
            ],
        )?;
        self.dirty = true;
        Ok(())
    }

    pub fn set_has_parity(&mut self, hash: &[u8], has: bool) -> Result<()> {
        self.before_write()?;
        self.conn
            .execute("UPDATE content SET has_parity = ?2 WHERE hash = ?1", params![hash, has as i64])?;
        self.dirty = true;
        Ok(())
    }

    /// Delete content rows no longer referenced by any file. Returns hashes removed.
    pub fn prune_orphan_content(&mut self) -> Result<Vec<Vec<u8>>> {
        self.before_write()?;
        let mut st = self
            .conn
            .prepare("SELECT hash FROM content WHERE NOT EXISTS (SELECT 1 FROM file WHERE file.content_hash = content.hash)")?;
        let hashes: Vec<Vec<u8>> = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        drop(st);
        for h in &hashes {
            self.conn.execute("DELETE FROM content WHERE hash = ?1", [h])?;
        }
        if !hashes.is_empty() {
            self.dirty = true;
        }
        Ok(hashes)
    }

    pub fn all_parity_contents(&self) -> Result<Vec<ContentRow>> {
        let mut st = self.conn.prepare(
            "SELECT hash, algo, size, block_size, blocks_per_stripe, parity_ppm, has_parity, created_at FROM content WHERE has_parity = 1",
        )?;
        let v = st.query_map([], row_to_content)?.collect::<rusqlite::Result<_>>()?;
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

    /// Insert or replace the record for `path`.
    pub fn upsert_file(&mut self, f: &FileRow) -> Result<i64> {
        self.before_write()?;
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
        Ok(self.conn.last_insert_rowid())
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

    pub fn delete_file(&mut self, path: &Path) -> Result<bool> {
        self.before_write()?;
        let n = self.conn.execute("DELETE FROM file WHERE path = ?1", [path_bytes(path)])?;
        if n > 0 {
            self.dirty = true;
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
        s.parity_contents =
            self.conn.query_row("SELECT COUNT(*) FROM content WHERE has_parity = 1", [], |r| r.get::<_, i64>(0))? as u64;
        s.parity_bytes_covered = self.conn.query_row(
            "SELECT COALESCE(SUM(f.size),0) FROM file f JOIN content c ON c.hash = f.content_hash WHERE c.has_parity = 1 AND f.state != 'missing'",
            [],
            |r| r.get::<_, i64>(0),
        )? as u64;
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
        let c = ContentRow {
            hash: vec![1; 32],
            algo: Algo::Blake3,
            size: 1,
            block_size: None,
            blocks_per_stripe: None,
            parity_ppm: None,
            has_parity: false,
            created_at: 0,
        };
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
}
