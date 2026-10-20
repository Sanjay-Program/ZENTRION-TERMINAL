//! SQLite-backed block store.
//!
//! WAL mode, prepared statements, compressed output chunks and FTS5 search.
//! The audit log itself remains append-only JSONL; this database is an index
//! and content store that can be rebuilt, not the source of truth for audit.
//!
//! The database stores command output, which may contain secrets. The file is
//! created under the user data directory with restrictive permissions, and
//! sharing always redacts. Encryption-at-rest is a documented future option;
//! this module does not claim it.

use crate::model::{Block, BlockFilter, BlockSearchHit, BlockStatus, Session, StoreStats};
use crate::recorder::MAX_BLOCK_OUTPUT;
use crate::share::strip_ansi;
use chrono::{DateTime, TimeZone, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const SCHEMA_VERSION: i64 = 1;
const OUTPUT_CHUNK: usize = 64 * 1024;
const FTS_TEXT_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("block store error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("block store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid stored data: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub struct BlockStore {
    conn: Connection,
    path: PathBuf,
}

impl BlockStore {
    /// Open (or create) a store at `path`. Parent directories are created.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let mut store = Self {
            conn,
            path: path.to_path_buf(),
        };
        store.configure()?;
        store.migrate()?;
        store.secure_permissions();
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self {
            conn,
            path: PathBuf::from(":memory:"),
        };
        store.configure()?;
        store.migrate()?;
        Ok(store)
    }

    /// Default location: `<data>/blocks.db`.
    pub fn open_default() -> Result<Self> {
        let dir = z_core::config::user_data_dir()
            .ok_or_else(|| StoreError::Invalid("cannot determine data directory".into()))?;
        Self::open(&dir.join("blocks.db"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn configure(&mut self) -> Result<()> {
        self.conn.pragma_update(None, "journal_mode", "WAL")?;
        self.conn.pragma_update(None, "synchronous", "NORMAL")?;
        self.conn.pragma_update(None, "foreign_keys", "ON")?;
        self.conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(())
    }

    fn migrate(&mut self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                shell TEXT NOT NULL,
                cwd TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                closed_at INTEGER,
                status TEXT NOT NULL,
                workspace_id TEXT,
                agent_id TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS blocks (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                seq INTEGER NOT NULL,
                command TEXT NOT NULL,
                cwd TEXT NOT NULL,
                shell TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                exit_code INTEGER,
                status TEXT NOT NULL,
                duration_ms INTEGER,
                output_hash TEXT,
                output_bytes INTEGER,
                agent_id TEXT,
                policy_decision TEXT,
                approval_id TEXT,
                tags_json TEXT NOT NULL DEFAULT '[]',
                risk TEXT,
                parent_block_id TEXT
            );
            CREATE INDEX IF NOT EXISTS blocks_session_seq ON blocks(session_id, seq);
            CREATE INDEX IF NOT EXISTS blocks_started ON blocks(started_at DESC);
            CREATE INDEX IF NOT EXISTS blocks_status ON blocks(status);
            CREATE INDEX IF NOT EXISTS blocks_agent ON blocks(agent_id);
            CREATE TABLE IF NOT EXISTS block_output (
                block_id TEXT NOT NULL REFERENCES blocks(id) ON DELETE CASCADE,
                chunk_no INTEGER NOT NULL,
                encoding TEXT NOT NULL,
                data BLOB NOT NULL,
                PRIMARY KEY (block_id, chunk_no)
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS blocks_fts USING fts5(
                command, output_text, cwd, tags, tokenize='unicode61'
            );
            "#,
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )?;
        Ok(())
    }

    fn secure_permissions(&self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if self.path != Path::new(":memory:") {
                let _ =
                    std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------

    pub fn upsert_session(&self, session: &Session) -> Result<()> {
        let metadata = serde_json::to_string(&session.metadata)
            .map_err(|e| StoreError::Invalid(format!("session metadata: {e}")))?;
        self.conn.execute(
            r#"INSERT INTO sessions
               (id, title, shell, cwd, created_at, closed_at, status, workspace_id, agent_id, metadata_json)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
               ON CONFLICT(id) DO UPDATE SET
                 title=excluded.title, cwd=excluded.cwd, closed_at=excluded.closed_at,
                 status=excluded.status, workspace_id=excluded.workspace_id,
                 agent_id=excluded.agent_id, metadata_json=excluded.metadata_json"#,
            params![
                session.id,
                session.title,
                session.shell,
                session.cwd,
                session.created_at.timestamp_millis(),
                session.closed_at.map(|t| t.timestamp_millis()),
                session.status,
                session.workspace_id,
                session.agent_id,
                metadata,
            ],
        )?;
        Ok(())
    }

    pub fn get_session(&self, id: &str) -> Result<Option<Session>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM sessions WHERE id = ?1",
                params![id],
                session_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_sessions(&self, limit: usize) -> Result<Vec<Session>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?1")?;
        let rows = stmt
            .query_map(params![limit as i64], session_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ------------------------------------------------------------------
    // Blocks
    // ------------------------------------------------------------------

    /// Insert or replace a block and its output atomically enough for normal
    /// operation (each statement is idempotent; a crash can at worst leave a
    /// block without output, which `consistent` is designed to detect).
    pub fn insert(&self, block: &Block, output: &[u8]) -> Result<()> {
        let output = &output[..output.len().min(MAX_BLOCK_OUTPUT)];
        self.conn.execute("BEGIN IMMEDIATE", [])?;
        let result = self.insert_inner(block, output);
        match result {
            Ok(()) => {
                self.conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    fn insert_inner(&self, block: &Block, output: &[u8]) -> Result<()> {
        let tags = serde_json::to_string(&block.tags)
            .map_err(|e| StoreError::Invalid(format!("tags: {e}")))?;
        self.conn.execute(
            r#"INSERT INTO blocks
               (id, session_id, seq, command, cwd, shell, started_at, ended_at, exit_code,
                status, duration_ms, output_hash, output_bytes, agent_id, policy_decision,
                approval_id, tags_json, risk, parent_block_id)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)
               ON CONFLICT(id) DO UPDATE SET
                 command=excluded.command, cwd=excluded.cwd, ended_at=excluded.ended_at,
                 exit_code=excluded.exit_code, status=excluded.status,
                 duration_ms=excluded.duration_ms, output_hash=excluded.output_hash,
                 output_bytes=excluded.output_bytes, agent_id=excluded.agent_id,
                 policy_decision=excluded.policy_decision, approval_id=excluded.approval_id,
                 tags_json=excluded.tags_json, risk=excluded.risk,
                 parent_block_id=excluded.parent_block_id"#,
            params![
                block.id,
                block.session_id,
                block.seq as i64,
                block.command,
                block.cwd,
                block.shell,
                block.started_at.timestamp_millis(),
                block.ended_at.map(|t| t.timestamp_millis()),
                block.exit_code,
                block.status.as_str(),
                block.duration_ms.map(|v| v as i64),
                block.output_hash,
                block.output_bytes.map(|v| v as i64),
                block.agent_id,
                block.policy_decision,
                block.approval_id,
                tags,
                block.risk,
                block.parent_block_id,
            ],
        )?;

        let rowid: i64 = self.conn.query_row(
            "SELECT rowid FROM blocks WHERE id = ?1",
            params![block.id],
            |row| row.get(0),
        )?;

        // Replace output chunks.
        self.conn.execute(
            "DELETE FROM block_output WHERE block_id = ?1",
            params![block.id],
        )?;
        for (index, chunk) in output.chunks(OUTPUT_CHUNK).enumerate() {
            let compressed = compress(chunk)?;
            self.conn.execute(
                "INSERT INTO block_output(block_id, chunk_no, encoding, data) VALUES (?1,?2,'gzip',?3)",
                params![block.id, index as i64, compressed],
            )?;
        }

        // Rebuild the search row.
        let plain = strip_ansi(&String::from_utf8_lossy(output));
        let plain = if plain.len() > FTS_TEXT_LIMIT {
            &plain[..previous_char_boundary(&plain, FTS_TEXT_LIMIT)]
        } else {
            &plain
        };
        self.conn
            .execute("DELETE FROM blocks_fts WHERE rowid = ?1", params![rowid])?;
        self.conn.execute(
            "INSERT INTO blocks_fts(rowid, command, output_text, cwd, tags) VALUES (?1,?2,?3,?4,?5)",
            params![rowid, block.command, plain, block.cwd, tags],
        )?;
        Ok(())
    }

    /// Update only block metadata (used when a live block finishes).
    pub fn update(&self, block: &Block) -> Result<()> {
        let tags = serde_json::to_string(&block.tags)
            .map_err(|e| StoreError::Invalid(format!("tags: {e}")))?;
        self.conn.execute(
            r#"UPDATE blocks SET ended_at=?2, exit_code=?3, status=?4, duration_ms=?5,
                 output_hash=?6, output_bytes=?7, tags_json=?8, risk=?9
               WHERE id=?1"#,
            params![
                block.id,
                block.ended_at.map(|t| t.timestamp_millis()),
                block.exit_code,
                block.status.as_str(),
                block.duration_ms.map(|v| v as i64),
                block.output_hash,
                block.output_bytes.map(|v| v as i64),
                tags,
                block.risk,
            ],
        )?;
        if let Some(rowid) = self.block_rowid(&block.id)? {
            self.conn.execute(
                "UPDATE blocks_fts SET command=?2, cwd=?3, tags=?4 WHERE rowid=?1",
                params![rowid, block.command, block.cwd, tags],
            )?;
        }
        Ok(())
    }

    fn block_rowid(&self, id: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row("SELECT rowid FROM blocks WHERE id=?1", params![id], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn get(&self, id: &str) -> Result<Option<Block>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM blocks WHERE id = ?1",
                params![id],
                block_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub fn output(&self, id: &str) -> Result<Vec<u8>> {
        let mut stmt = self.conn.prepare(
            "SELECT encoding, data FROM block_output WHERE block_id=?1 ORDER BY chunk_no",
        )?;
        let chunks = stmt.query_map(params![id], |row| {
            let encoding: String = row.get(0)?;
            let data: Vec<u8> = row.get(1)?;
            Ok((encoding, data))
        })?;
        let mut out = Vec::new();
        for chunk in chunks {
            let (encoding, data) = chunk?;
            match encoding.as_str() {
                "gzip" => {
                    let mut decoder = GzDecoder::new(data.as_slice());
                    let mut buffer = Vec::new();
                    decoder.read_to_end(&mut buffer)?;
                    out.extend_from_slice(&buffer);
                }
                "none" => out.extend_from_slice(&data),
                other => {
                    return Err(StoreError::Invalid(format!(
                        "unknown output encoding {other}"
                    )))
                }
            }
        }
        Ok(out)
    }

    pub fn list(&self, filter: &BlockFilter) -> Result<Vec<Block>> {
        let mut sql = String::from("SELECT * FROM blocks WHERE 1=1");
        let mut values: Vec<Value> = Vec::new();
        if let Some(session) = &filter.session_id {
            sql.push_str(&format!(" AND session_id = ?{}", values.len() + 1));
            values.push(Value::Text(session.clone()));
        }
        if let Some(status) = filter.status {
            sql.push_str(&format!(" AND status = ?{}", values.len() + 1));
            values.push(Value::Text(status.as_str().to_string()));
        }
        if filter.exit_nonzero {
            sql.push_str(" AND exit_code IS NOT NULL AND exit_code <> 0");
        }
        if let Some(cwd) = &filter.cwd {
            sql.push_str(&format!(" AND cwd = ?{}", values.len() + 1));
            values.push(Value::Text(cwd.clone()));
        }
        if let Some(agent) = &filter.agent_id {
            sql.push_str(&format!(" AND agent_id = ?{}", values.len() + 1));
            values.push(Value::Text(agent.clone()));
        }
        if let Some(tag) = &filter.tag {
            sql.push_str(&format!(" AND tags_json LIKE ?{}", values.len() + 1));
            values.push(Value::Text(format!("%\"{}\"%", escape_like(tag))));
        }
        if let Some(since) = filter.since {
            sql.push_str(&format!(" AND started_at >= ?{}", values.len() + 1));
            values.push(Value::Integer(since.timestamp_millis()));
        }
        if let Some(until) = filter.until {
            sql.push_str(&format!(" AND started_at <= ?{}", values.len() + 1));
            values.push(Value::Integer(until.timestamp_millis()));
        }
        sql.push_str(" ORDER BY started_at DESC, seq DESC");
        sql.push_str(&format!(" LIMIT ?{}", values.len() + 1));
        values.push(Value::Integer(
            filter.limit.unwrap_or(100).min(10_000) as i64
        ));
        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET ?{}", values.len() + 1));
            values.push(Value::Integer(offset as i64));
        }

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(values.iter()), block_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Full-text search over command, output, cwd and tags.
    ///
    /// The user query is converted to a safe FTS5 expression; invalid queries
    /// fall back to a literal substring search rather than erroring the UI.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<BlockSearchHit>> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let limit = limit.clamp(1, 1000);
        if let Some(fts) = fts_query(query) {
            let mut stmt = self.conn.prepare(
                "SELECT b.*, snippet(blocks_fts, 1, '[', ']', '…', 12), bm25(blocks_fts)
                 FROM blocks_fts JOIN blocks b ON b.rowid = blocks_fts.rowid
                 WHERE blocks_fts MATCH ?1
                 ORDER BY bm25(blocks_fts) LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![fts, limit as i64], |row| {
                let block = block_from_row(row)?;
                let snippet: String = row.get(19)?;
                let rank: f64 = row.get(20)?;
                Ok(BlockSearchHit {
                    block,
                    snippet,
                    rank,
                })
            });
            if let Ok(rows) = rows {
                let collected: rusqlite::Result<Vec<_>> = rows.collect();
                if let Ok(hits) = collected {
                    return Ok(hits);
                }
            }
        }
        self.like_search(query, limit)
    }

    fn like_search(&self, query: &str, limit: usize) -> Result<Vec<BlockSearchHit>> {
        let pattern = format!("%{}%", escape_like(query));
        let mut stmt = self.conn.prepare(
            "SELECT * FROM blocks WHERE command LIKE ?1 ESCAPE '\\' OR cwd LIKE ?1 ESCAPE '\\'
             ORDER BY started_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![pattern, limit as i64], |row| {
                let block = block_from_row(row)?;
                Ok(BlockSearchHit {
                    snippet: block.command.clone(),
                    block,
                    rank: 0.0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn session_blocks(&self, session_id: &str) -> Result<Vec<Block>> {
        self.list(&BlockFilter {
            session_id: Some(session_id.to_string()),
            limit: Some(10_000),
            ..BlockFilter::default()
        })
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let sessions: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))?;
        let blocks: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))?;
        let output_bytes: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(output_bytes),0) FROM blocks",
            [],
            |row| row.get(0),
        )?;
        let oldest: Option<i64> =
            self.conn
                .query_row("SELECT MIN(started_at) FROM blocks", [], |row| row.get(0))?;
        let newest: Option<i64> =
            self.conn
                .query_row("SELECT MAX(started_at) FROM blocks", [], |row| row.get(0))?;
        Ok(StoreStats {
            sessions: sessions.max(0) as u64,
            blocks: blocks.max(0) as u64,
            output_bytes: output_bytes.max(0) as u64,
            oldest: oldest.and_then(millis),
            newest: newest.and_then(millis),
        })
    }

    /// Delete blocks older than `days`. Returns the number of blocks removed.
    pub fn delete_older_than(&self, days: u64) -> Result<usize> {
        let cutoff = Utc::now() - chrono::Duration::days(days.min(3650) as i64);
        let ids: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM blocks WHERE started_at < ?1")?;
            let rows = stmt.query_map(params![cutoff.timestamp_millis()], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<Vec<String>>>()?
        };
        if ids.is_empty() {
            return Ok(0);
        }
        self.conn.execute("BEGIN IMMEDIATE", [])?;
        for id in &ids {
            self.conn
                .execute("DELETE FROM block_output WHERE block_id=?1", params![id])?;
            if let Some(rowid) = self.block_rowid(id)? {
                self.conn
                    .execute("DELETE FROM blocks_fts WHERE rowid=?1", params![rowid])?;
            }
            self.conn
                .execute("DELETE FROM blocks WHERE id=?1", params![id])?;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(ids.len())
    }

    /// Verify that every block with output bytes has exactly the output that
    /// its stored hash describes.
    pub fn verify_outputs(&self, limit: usize) -> Result<Vec<String>> {
        use sha2::{Digest, Sha256};
        let mut stmt = self.conn.prepare(
            "SELECT id, output_hash, output_bytes FROM blocks
             WHERE output_hash IS NOT NULL ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut bad = Vec::new();
        for (id, hash, bytes) in rows {
            let output = match self.output(&id) {
                Ok(output) => output,
                // Undecodable output is tampering, not a reason to fail the
                // whole verification pass.
                Err(_) => {
                    bad.push(id);
                    continue;
                }
            };
            let len_ok = bytes.map(|b| b as usize == output.len()).unwrap_or(true);
            let hash_ok = hash
                .as_deref()
                .and_then(|h| h.strip_prefix("sha256:"))
                .map(|expected| {
                    let mut hasher = Sha256::new();
                    hasher.update(&output);
                    format!("{:x}", hasher.finalize()) == expected
                })
                .unwrap_or(true);
            if !len_ok || !hash_ok {
                bad.push(id);
            }
        }
        Ok(bad)
    }

    /// Export blocks and output as a portable JSON document.
    pub fn export_json(&self, filter: &BlockFilter) -> Result<String> {
        use base64::Engine;
        let blocks = self.list(filter)?;
        let mut entries = Vec::with_capacity(blocks.len());
        for block in &blocks {
            let output = self.output(&block.id)?;
            entries.push(serde_json::json!({
                "block": block,
                "output_base64": base64::engine::general_purpose::STANDARD.encode(output),
            }));
        }
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "version": 1,
            "exported_at": Utc::now().to_rfc3339(),
            "blocks": entries,
        }))
        .map_err(|e| StoreError::Invalid(e.to_string()))?)
    }

    /// Import a document produced by [`export_json`]. Returns block count.
    pub fn import_json(&self, json: &str) -> Result<usize> {
        use base64::Engine;
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| StoreError::Invalid(e.to_string()))?;
        let version = value.get("version").and_then(|v| v.as_i64()).unwrap_or(0);
        if version != 1 {
            return Err(StoreError::Invalid(format!(
                "unsupported export version {version}"
            )));
        }
        let blocks = value
            .get("blocks")
            .and_then(|v| v.as_array())
            .ok_or_else(|| StoreError::Invalid("missing blocks array".into()))?;
        let mut count = 0;
        for entry in blocks {
            let block: Block =
                serde_json::from_value(entry.get("block").cloned().unwrap_or_default())
                    .map_err(|e| StoreError::Invalid(format!("invalid block: {e}")))?;
            let output = entry
                .get("output_base64")
                .and_then(|v| v.as_str())
                .map(|encoded| base64::engine::general_purpose::STANDARD.decode(encoded))
                .transpose()
                .map_err(|e| StoreError::Invalid(format!("invalid output: {e}")))?
                .unwrap_or_default();
            self.insert(&block, &output)?;
            count += 1;
        }
        Ok(count)
    }
}

fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn previous_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn escape_like(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Convert user input into a conservative FTS5 expression: every token is
/// quoted and prefix-matched. Returns `None` for input with no usable tokens.
fn fts_query(input: &str) -> Option<String> {
    let tokens: Vec<String> = input
        .split_whitespace()
        .map(|token| {
            token
                .chars()
                .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':'))
                .collect::<String>()
        })
        .filter(|token| !token.is_empty())
        .take(16)
        .collect();
    if tokens.is_empty() {
        return None;
    }
    Some(
        tokens
            .iter()
            .map(|token| format!("\"{}\"*", token.replace('"', "")))
            .collect::<Vec<_>>()
            .join(" AND "),
    )
}

fn millis(value: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_millis_opt(value).single()
}

fn block_from_row(row: &Row<'_>) -> rusqlite::Result<Block> {
    let status: String = row.get("status")?;
    let tags_json: String = row.get("tags_json")?;
    let started: i64 = row.get("started_at")?;
    let ended: Option<i64> = row.get("ended_at")?;
    let output_bytes: Option<i64> = row.get("output_bytes")?;
    let duration_ms: Option<i64> = row.get("duration_ms")?;
    Ok(Block {
        id: row.get("id")?,
        session_id: row.get("session_id")?,
        seq: row.get::<_, i64>("seq")?.max(0) as u64,
        command: row.get("command")?,
        cwd: row.get("cwd")?,
        shell: row.get("shell")?,
        started_at: millis(started).unwrap_or_else(Utc::now),
        ended_at: ended.and_then(millis),
        exit_code: row.get("exit_code")?,
        status: BlockStatus::parse(&status).unwrap_or(BlockStatus::Cancelled),
        duration_ms: duration_ms.map(|v| v.max(0) as u64),
        output_hash: row.get("output_hash")?,
        output_bytes: output_bytes.map(|v| v.max(0) as u64),
        agent_id: row.get("agent_id")?,
        policy_decision: row.get("policy_decision")?,
        approval_id: row.get("approval_id")?,
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
        risk: row.get("risk")?,
        parent_block_id: row.get("parent_block_id")?,
    })
}

fn session_from_row(row: &Row<'_>) -> rusqlite::Result<Session> {
    let created: i64 = row.get("created_at")?;
    let closed: Option<i64> = row.get("closed_at")?;
    let metadata_json: String = row.get("metadata_json")?;
    Ok(Session {
        id: row.get("id")?,
        title: row.get("title")?,
        shell: row.get("shell")?,
        cwd: row.get("cwd")?,
        created_at: millis(created).unwrap_or_else(Utc::now),
        closed_at: closed.and_then(millis),
        status: row.get("status")?,
        workspace_id: row.get("workspace_id")?,
        agent_id: row.get("agent_id")?,
        metadata: serde_json::from_str(&metadata_json).unwrap_or(serde_json::Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn session(id: &str) -> Session {
        Session {
            id: id.to_string(),
            title: "test".into(),
            shell: "bash".into(),
            cwd: "/repo".into(),
            created_at: Utc::now(),
            closed_at: None,
            status: "open".into(),
            workspace_id: None,
            agent_id: None,
            metadata: serde_json::json!({}),
        }
    }

    fn block(id: &str, command: &str, status: BlockStatus, exit: Option<i32>) -> Block {
        Block {
            id: id.to_string(),
            session_id: "s1".into(),
            seq: 1,
            command: command.into(),
            cwd: "/repo".into(),
            shell: "bash".into(),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            exit_code: exit,
            status,
            duration_ms: Some(10),
            output_hash: None,
            output_bytes: None,
            agent_id: None,
            policy_decision: None,
            approval_id: None,
            tags: vec![],
            risk: None,
            parent_block_id: None,
        }
    }

    fn store() -> BlockStore {
        let store = BlockStore::open_in_memory().unwrap();
        store.upsert_session(&session("s1")).unwrap();
        store
    }

    #[test]
    fn insert_get_and_output_round_trip() {
        let store = store();
        let output = b"hello \x1b[31mworld\x1b[0m\n";
        let block = block("b1", "echo hello", BlockStatus::Ok, Some(0));
        store.insert(&block, output).unwrap();
        let loaded = store.get("b1").unwrap().unwrap();
        assert_eq!(loaded.command, "echo hello");
        assert_eq!(loaded.status, BlockStatus::Ok);
        assert_eq!(store.output("b1").unwrap(), output);
    }

    #[test]
    fn large_output_is_chunked_and_lossless() {
        let store = store();
        let output = vec![b'x'; OUTPUT_CHUNK * 2 + 17];
        store
            .insert(&block("b1", "big", BlockStatus::Ok, Some(0)), &output)
            .unwrap();
        assert_eq!(store.output("b1").unwrap(), output);
        let chunks: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM block_output WHERE block_id='b1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(chunks, 3);
    }

    #[test]
    fn search_finds_command_and_output() {
        let store = store();
        store
            .insert(
                &block("b1", "cargo test", BlockStatus::Failed, Some(101)),
                b"test result: FAILED. 3 passed; 1 failed\n",
            )
            .unwrap();
        store
            .insert(
                &block("b2", "git status", BlockStatus::Ok, Some(0)),
                b"nothing to commit\n",
            )
            .unwrap();
        let hits = store.search("failed", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].block.id, "b1");
        let hits = store.search("cargo", 10).unwrap();
        assert_eq!(hits[0].block.id, "b1");
    }

    #[test]
    fn search_with_punctuation_is_safe() {
        let store = store();
        store
            .insert(&block("b1", "echo a", BlockStatus::Ok, Some(0)), b"x")
            .unwrap();
        // These would be FTS5 syntax errors without sanitisation.
        for query in ["\"", "(", "a OR", "foo*", "-", "c++"] {
            let _ = store.search(query, 10).unwrap();
        }
    }

    #[test]
    fn filters_work() {
        let store = store();
        let mut failed = block("b1", "false", BlockStatus::Failed, Some(1));
        failed.cwd = "/other".into();
        failed.tags = vec!["ci".into()];
        store.insert(&failed, b"").unwrap();
        store
            .insert(&block("b2", "true", BlockStatus::Ok, Some(0)), b"")
            .unwrap();
        let hits = store
            .list(&BlockFilter {
                exit_nonzero: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        let hits = store
            .list(&BlockFilter {
                cwd: Some("/other".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        let hits = store
            .list(&BlockFilter {
                tag: Some("ci".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn verify_outputs_detects_tampering() {
        let store = store();
        store
            .insert(
                &block("b1", "echo hi", BlockStatus::Ok, Some(0)),
                b"hello\n",
            )
            .unwrap();
        // Insert a correct hash by computing it the same way the recorder does.
        let output = b"hello\n";
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(output);
        let hash = format!("sha256:{:x}", hasher.finalize());
        let mut b = block("b1", "echo hi", BlockStatus::Ok, Some(0));
        b.output_hash = Some(hash);
        b.output_bytes = Some(output.len() as u64);
        store.insert(&b, output).unwrap();
        assert!(store.verify_outputs(10).unwrap().is_empty());
        store
            .conn
            .execute(
                "UPDATE block_output SET data=?1 WHERE block_id='b1'",
                params![b"tampered".to_vec()],
            )
            .unwrap();
        assert_eq!(store.verify_outputs(10).unwrap(), vec!["b1"]);
    }

    #[test]
    fn export_import_round_trip() {
        let store = store();
        store
            .insert(
                &block("b1", "echo hi", BlockStatus::Ok, Some(0)),
                b"hello\n",
            )
            .unwrap();
        let exported = store.export_json(&BlockFilter::default()).unwrap();
        let other = BlockStore::open_in_memory().unwrap();
        other.upsert_session(&session("s1")).unwrap();
        assert_eq!(other.import_json(&exported).unwrap(), 1);
        assert_eq!(other.output("b1").unwrap(), b"hello\n");
    }

    #[test]
    fn retention_deletes_old_blocks() {
        let store = store();
        let mut old = block("old", "old", BlockStatus::Ok, Some(0));
        old.started_at = Utc::now() - Duration::days(60);
        store.insert(&old, b"old").unwrap();
        store
            .insert(&block("new", "new", BlockStatus::Ok, Some(0)), b"new")
            .unwrap();
        assert_eq!(store.delete_older_than(30).unwrap(), 1);
        assert!(store.get("old").unwrap().is_none());
        assert!(store.get("new").unwrap().is_some());
    }

    #[test]
    fn stats_are_consistent() {
        let store = store();
        store
            .insert(&block("b1", "a", BlockStatus::Ok, Some(0)), b"12345")
            .unwrap();
        let stats = store.stats().unwrap();
        assert_eq!(stats.blocks, 1);
        assert_eq!(stats.sessions, 1);
    }
}
