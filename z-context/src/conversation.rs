//! Persistent conversation store with SQLite, FTS5 semantic indexing,
//! sliding-window compaction, and mandatory secret/PII redaction.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConversationTurn {
    pub id: String,
    pub session_id: String,
    pub block_id: Option<String>,
    pub role: String,
    pub content: String,
    pub redacted_content: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactedContext {
    pub recent_turns: Vec<ConversationTurn>,
    pub retrieved_context: Vec<String>,
    pub summary: Option<String>,
    pub total_turns_in_session: usize,
}

#[derive(Clone)]
pub struct ConversationStore {
    conn: Arc<Mutex<Connection>>,
    db_path: Option<PathBuf>,
}

impl ConversationStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create dir for conversation db: {parent:?}"))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open conversation database at {path:?}"))?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: Some(path.to_path_buf()),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .context("failed to open in-memory conversation database")?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: None,
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_default() -> Result<Self> {
        let path = match z_core::config::user_data_dir() {
            Some(d) => d.join("copilot_conversations.db"),
            None => PathBuf::from(".zentrion/copilot_conversations.db"),
        };
        Self::open(&path)
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS conversation_turns (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                block_id TEXT,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                redacted_content TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_conv_session_time 
                ON conversation_turns(session_id, created_at);

            CREATE VIRTUAL TABLE IF NOT EXISTS conversation_fts USING fts5(
                content,
                redacted_content,
                content='conversation_turns',
                content_rowid='rowid'
            );

            CREATE TRIGGER IF NOT EXISTS conversation_ai AFTER INSERT ON conversation_turns BEGIN
                INSERT INTO conversation_fts(rowid, content, redacted_content)
                VALUES (new.rowid, new.content, new.redacted_content);
            END;

            CREATE TRIGGER IF NOT EXISTS conversation_ad AFTER DELETE ON conversation_turns BEGIN
                INSERT INTO conversation_fts(conversation_fts, rowid, content, redacted_content)
                VALUES ('delete', old.rowid, old.content, old.redacted_content);
            END;
            "#,
        )
        .context("failed to initialize conversation store schema")?;
        Ok(())
    }

    pub fn record_turn(
        &self,
        session_id: &str,
        block_id: Option<&str>,
        role: &str,
        content: &str,
    ) -> Result<ConversationTurn> {
        let id = Uuid::new_v4().to_string();
        let (redacted, _) = z_blocks::share::redact(content);
        let created_at = chrono::Utc::now().timestamp_millis();

        let turn = ConversationTurn {
            id: id.clone(),
            session_id: session_id.to_string(),
            block_id: block_id.map(ToString::to_string),
            role: role.to_string(),
            content: content.to_string(),
            redacted_content: redacted.clone(),
            created_at,
        };

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO conversation_turns (id, session_id, block_id, role, content, redacted_content, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![turn.id, turn.session_id, turn.block_id, turn.role, turn.content, turn.redacted_content, turn.created_at],
        )?;

        Ok(turn)
    }

    pub fn get_history(&self, session_id: &str, limit: usize) -> Result<Vec<ConversationTurn>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, block_id, role, content, redacted_content, created_at
             FROM conversation_turns
             WHERE session_id = ?1
             ORDER BY created_at ASC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![session_id, limit as i64], |row| {
            Ok(ConversationTurn {
                id: row.get(0)?,
                session_id: row.get(1)?,
                block_id: row.get(2)?,
                role: row.get(3)?,
                content: row.get(4)?,
                redacted_content: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn search_history(
        &self,
        session_id: Option<&str>,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ConversationTurn>> {
        let safe_query = query
            .replace('"', "\"\"")
            .split_whitespace()
            .map(|w| format!("\"{w}\""))
            .collect::<Vec<_>>()
            .join(" ");

        if safe_query.is_empty() {
            return Ok(Vec::new());
        }

        let conn = self.conn.lock().unwrap();
        let sql = match session_id {
            Some(_) => {
                "SELECT t.id, t.session_id, t.block_id, t.role, t.content, t.redacted_content, t.created_at
                 FROM conversation_turns t
                 JOIN conversation_fts ON conversation_fts.rowid = t.rowid
                 WHERE conversation_fts MATCH ?1 AND t.session_id = ?2
                 ORDER BY t.created_at DESC
                 LIMIT ?3"
            }
            None => {
                "SELECT t.id, t.session_id, t.block_id, t.role, t.content, t.redacted_content, t.created_at
                 FROM conversation_turns t
                 JOIN conversation_fts ON conversation_fts.rowid = t.rowid
                 WHERE conversation_fts MATCH ?1
                 ORDER BY t.created_at DESC
                 LIMIT ?2"
            }
        };

        let mut stmt = conn.prepare(sql)?;
        let mut out = Vec::new();
        if let Some(sid) = session_id {
            let rows = stmt.query_map(params![safe_query, sid, limit as i64], |row| {
                Ok(ConversationTurn {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    block_id: row.get(2)?,
                    role: row.get(3)?,
                    content: row.get(4)?,
                    redacted_content: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?;
            for r in rows {
                out.push(r?);
            }
        } else {
            let rows = stmt.query_map(params![safe_query, limit as i64], |row| {
                Ok(ConversationTurn {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    block_id: row.get(2)?,
                    role: row.get(3)?,
                    content: row.get(4)?,
                    redacted_content: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?;
            for r in rows {
                out.push(r?);
            }
        }

        Ok(out)
    }

    pub fn compact_session(
        &self,
        session_id: &str,
        recent_window_size: usize,
        query: Option<&str>,
    ) -> Result<CompactedContext> {
        let all_turns = self.get_history(session_id, 1000)?;
        let total_turns = all_turns.len();

        if total_turns <= recent_window_size {
            return Ok(CompactedContext {
                recent_turns: all_turns,
                retrieved_context: Vec::new(),
                summary: None,
                total_turns_in_session: total_turns,
            });
        }

        let split_idx = total_turns.saturating_sub(recent_window_size);
        let older_turns = &all_turns[..split_idx];
        let recent_turns = all_turns[split_idx..].to_vec();

        // Retrieve relevant older snippets using FTS5 if a query is specified
        let mut retrieved = Vec::new();
        if let Some(q) = query {
            let search_hits = self.search_history(Some(session_id), q, 5)?;
            for hit in search_hits {
                if hit.created_at < recent_turns.first().map(|r| r.created_at).unwrap_or(i64::MAX) {
                    retrieved.push(format!("[Past {}: {}]", hit.role, hit.redacted_content));
                }
            }
        }

        // Generate semantic summary of older turns
        let mut summary_lines = Vec::new();
        summary_lines.push(format!("Prior conversation history summary ({split_idx} turns):"));
        for turn in older_turns.iter().step_by((older_turns.len() / 5).max(1)).take(5) {
            let snippet = turn.redacted_content.lines().next().unwrap_or("");
            summary_lines.push(format!("- {}: {snippet}", turn.role));
        }

        Ok(CompactedContext {
            recent_turns,
            retrieved_context: retrieved,
            summary: Some(summary_lines.join("\n")),
            total_turns_in_session: total_turns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_turn_and_redaction() {
        let store = ConversationStore::open_in_memory().unwrap();
        let turn = store
            .record_turn(
                "sess-1",
                Some("block-42"),
                "user",
                "My AWS key is AKIAIOSFODNN7EXAMPLE and secret is password123",
            )
            .unwrap();

        assert_eq!(turn.session_id, "sess-1");
        assert_eq!(turn.block_id.as_deref(), Some("block-42"));
        assert!(turn.redacted_content.contains("[REDACTED:aws_access_key]"));
        assert!(!turn.redacted_content.contains("AKIAIOSFODNN7EXAMPLE"));

        let history = store.get_history("sess-1", 10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, turn.id);
    }

    #[test]
    fn test_search_and_compaction() {
        let store = ConversationStore::open_in_memory().unwrap();
        for i in 1..=20 {
            store
                .record_turn(
                    "sess-compact",
                    None,
                    if i % 2 == 1 { "user" } else { "assistant" },
                    &format!("Message number {i} discussing kubernetes cluster setup"),
                )
                .unwrap();
        }

        let hits = store
            .search_history(Some("sess-compact"), "kubernetes", 5)
            .unwrap();
        assert!(!hits.is_empty());

        let compacted = store
            .compact_session("sess-compact", 8, Some("kubernetes"))
            .unwrap();
        assert_eq!(compacted.recent_turns.len(), 8);
        assert_eq!(compacted.total_turns_in_session, 20);
        assert!(compacted.summary.is_some());
    }
}
