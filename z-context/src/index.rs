//! Incremental repository index in SQLite (WAL + FTS5).
//!
//! Files are indexed by hash, not just mtime. Ignored paths are never read, and
//! secret-shaped files are excluded at the walk stage so they cannot leak into
//! a context pack or a search snippet. Symbol extraction is lexer-level (see
//! [`crate::symbols`]) and labelled approximate.

use crate::symbols::{extract_symbols, language_for, Symbol};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

const CONTENT_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexOptions {
    pub max_file_bytes: u64,
    pub max_files: usize,
    pub ignore: Vec<String>,
    pub follow_symlinks: bool,
    /// Use `git ls-files` when the root is a repository; this honours
    /// `.gitignore` without reimplementing it.
    pub use_git: bool,
    pub include_hidden: bool,
}

impl Default for IndexOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: 512 * 1024,
            max_files: 100_000,
            ignore: vec![
                ".git".into(),
                "target".into(),
                "node_modules".into(),
                ".venv".into(),
                "venv".into(),
                "dist".into(),
                "build".into(),
                ".next".into(),
                "__pycache__".into(),
                ".idea".into(),
                ".vscode".into(),
                "*.pem".into(),
                "*.key".into(),
                "*.p12".into(),
                "*.pfx".into(),
                ".env".into(),
                ".env.*".into(),
                "id_rsa*".into(),
                "id_ed25519*".into(),
                "credentials*".into(),
                "*.lock".into(),
            ],
            follow_symlinks: false,
            use_git: true,
            include_hidden: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndexStats {
    pub root: String,
    pub indexed: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub removed: usize,
    pub skipped: usize,
    pub symbols: usize,
    pub bytes: u64,
    pub duration_ms: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub language: String,
    pub hash: String,
    pub size: u64,
    pub mtime: Option<i64>,
    pub symbols: Vec<Symbol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub path: String,
    pub language: String,
    pub score: f64,
    pub line: usize,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStatus {
    pub root: Option<String>,
    pub path: String,
    pub files: u64,
    pub symbols: u64,
    pub bytes: u64,
    pub indexed_at: Option<i64>,
    pub stale: bool,
}

pub struct RepoIndex {
    conn: Connection,
    path: PathBuf,
}

impl RepoIndex {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| e.to_string())?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| e.to_string())?;
        let mut index = Self {
            conn,
            path: path.to_path_buf(),
        };
        index.migrate()?;
        Ok(index)
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        let mut index = Self {
            conn,
            path: PathBuf::from(":memory:"),
        };
        index.migrate()?;
        Ok(index)
    }

    pub fn open_default() -> Result<Self, String> {
        let dir = z_core::config::user_data_dir()
            .ok_or_else(|| "cannot determine user data directory".to_string())?;
        Self::open(&dir.join("context").join("index.db"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn migrate(&mut self) -> Result<(), String> {
        self.conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY,
                    path TEXT NOT NULL UNIQUE,
                    language TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mtime INTEGER,
                    content BLOB NOT NULL,
                    symbols_json TEXT NOT NULL,
                    indexed_at INTEGER NOT NULL
                );
                CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
                    path, symbols, content, tokenize='unicode61'
                );
                "#,
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn indexed_root(&self) -> Option<String> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key='root'", [], |row| {
                row.get(0)
            })
            .optional()
            .ok()
            .flatten()
    }

    fn indexed_at(&self) -> Option<i64> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key='indexed_at'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .and_then(|value| value.parse().ok())
    }

    /// Index (or re-index) a repository root. Returns counters.
    pub fn index_dir(&mut self, root: &Path, options: &IndexOptions) -> Result<IndexStats, String> {
        self.index_dir_with_progress(root, options, |_, _| {})
    }

    pub fn index_dir_with_progress<F>(
        &mut self,
        root: &Path,
        options: &IndexOptions,
        mut progress: F,
    ) -> Result<IndexStats, String>
    where
        F: FnMut(usize, &str),
    {
        let started = Instant::now();
        let canonical = root
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", root.display()))?;
        if !canonical.is_dir() {
            return Err(format!("{} is not a directory", canonical.display()));
        }
        let root_string = canonical.display().to_string();
        if let Some(previous) = self.indexed_root() {
            if previous != root_string {
                // One index per root: never mix repositories.
                self.conn
                    .execute_batch("DELETE FROM files_fts; DELETE FROM files; DELETE FROM meta;")
                    .map_err(|e| e.to_string())?;
            }
        }
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('root',?1)",
                params![root_string],
            )
            .map_err(|e| e.to_string())?;

        let files = collect_files(&canonical, options);
        let mut stats = IndexStats {
            root: root_string,
            ..Default::default()
        };
        let existing: std::collections::HashMap<String, (i64, String, i64)> = self
            .conn
            .prepare("SELECT path, id, hash, size FROM files")
            .map_err(|e| e.to_string())?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|row| row.ok())
            .map(|(path, id, hash, size)| (path, (id, hash, size)))
            .collect();
        let mut seen = std::collections::HashSet::new();
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        let mut total_bytes = 0u64;
        for (index, (relative, absolute)) in files.iter().enumerate() {
            if index >= options.max_files {
                stats.errors.push(format!(
                    "stopped at {} files (max_files={})",
                    options.max_files, options.max_files
                ));
                break;
            }
            if index % 100 == 0 {
                progress(index, relative);
            }
            let metadata = match std::fs::metadata(absolute) {
                Ok(metadata) => metadata,
                Err(error) => {
                    stats.skipped += 1;
                    stats.errors.push(format!("{relative}: {error}"));
                    continue;
                }
            };
            if metadata.len() > options.max_file_bytes {
                stats.skipped += 1;
                continue;
            }
            let mtime = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis() as i64);
            let content = match std::fs::read(absolute) {
                Ok(content) => content,
                Err(error) => {
                    stats.skipped += 1;
                    stats.errors.push(format!("{relative}: {error}"));
                    continue;
                }
            };
            if content.iter().take(8192).any(|byte| *byte == 0) {
                stats.skipped += 1;
                continue;
            }
            let text = match String::from_utf8(content) {
                Ok(text) => text,
                Err(_) => {
                    stats.skipped += 1;
                    continue;
                }
            };
            if text.len() > CONTENT_LIMIT {
                stats.skipped += 1;
                continue;
            }
            let hash = sha256_hex(text.as_bytes());
            let size = text.len() as i64;
            seen.insert(relative.clone());
            total_bytes += text.len() as u64;
            if let Some((_id, existing_hash, existing_size)) = existing.get(relative) {
                if existing_hash == &hash && *existing_size == size {
                    stats.unchanged += 1;
                    continue;
                }
            }
            let language = language_for(relative);
            let symbols = extract_symbols(relative, &text);
            stats.symbols += symbols.len();
            let symbols_json = serde_json::to_string(&symbols).map_err(|e| e.to_string())?;
            let compressed = gzip(text.as_bytes())?;
            tx.execute(
                "INSERT OR REPLACE INTO files(path,language,hash,size,mtime,content,symbols_json,indexed_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    relative,
                    language,
                    hash,
                    size,
                    mtime,
                    compressed,
                    symbols_json,
                    chrono::Utc::now().timestamp_millis()
                ],
            )
            .map_err(|e| e.to_string())?;
            let id: i64 = tx
                .query_row(
                    "SELECT id FROM files WHERE path=?1",
                    params![relative],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            tx.execute("DELETE FROM files_fts WHERE rowid=?1", params![id])
                .map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO files_fts(rowid,path,symbols,content) VALUES(?1,?2,?3,?4)",
                params![id, relative, symbols_json, text],
            )
            .map_err(|e| e.to_string())?;
            if existing.contains_key(relative) {
                stats.updated += 1;
            } else {
                stats.indexed += 1;
            }
        }
        // Remove files that disappeared.
        let stale: Vec<String> = existing
            .keys()
            .filter(|path| !seen.contains(*path))
            .cloned()
            .collect();
        for path in &stale {
            if let Some((id, _, _)) = existing.get(path) {
                tx.execute("DELETE FROM files_fts WHERE rowid=?1", params![id])
                    .map_err(|e| e.to_string())?;
                tx.execute("DELETE FROM files WHERE id=?1", params![id])
                    .map_err(|e| e.to_string())?;
                stats.removed += 1;
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('indexed_at',?1)",
            params![chrono::Utc::now().timestamp_millis().to_string()],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        stats.bytes = total_bytes;
        stats.duration_ms = started.elapsed().as_millis() as u64;
        Ok(stats)
    }

    pub fn status(&mut self) -> Result<IndexStatus, String> {
        let files: u64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        let bytes: u64 = self
            .conn
            .query_row("SELECT COALESCE(SUM(size),0) FROM files", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|value| value as u64)
            .map_err(|e| e.to_string())?;
        let symbols: u64 = self
            .conn
            .query_row(
                "SELECT COALESCE(SUM(json_array_length(symbols_json)),0) FROM files",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|value| value as u64)
            .unwrap_or(0);
        Ok(IndexStatus {
            root: self.indexed_root(),
            path: self.path.display().to_string(),
            files,
            symbols,
            bytes,
            indexed_at: self.indexed_at(),
            stale: self.is_stale(),
        })
    }

    /// Cheap freshness check against mtimes of indexed files.
    pub fn is_stale(&self) -> bool {
        let Some(root) = self.indexed_root() else {
            return true;
        };
        let root = PathBuf::from(root);
        let mut stmt = match self.conn.prepare("SELECT path, mtime, size FROM files") {
            Ok(stmt) => stmt,
            Err(_) => return true,
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        });
        let Ok(rows) = rows else {
            return true;
        };
        for row in rows.flatten() {
            let (path, mtime, size) = row;
            let absolute = root.join(&path);
            let Ok(metadata) = std::fs::metadata(&absolute) else {
                return true;
            };
            if metadata.len() as i64 != size {
                return true;
            }
            if let (Some(mtime), Ok(modified)) = (mtime, metadata.modified()) {
                if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                    if duration.as_millis() as i64 != mtime {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>, String> {
        let Some(expression) = fts_expression(query) else {
            return Ok(Vec::new());
        };
        let limit = limit.clamp(1, 1000);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT f.path, f.language, bm25(files_fts), f.content
                 FROM files_fts JOIN files f ON f.id = files_fts.rowid
                 WHERE files_fts MATCH ?1
                 ORDER BY bm25(files_fts), f.path LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![expression, limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, f64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let terms: Vec<String> = query
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|term| !term.is_empty())
            .map(|term| term.to_ascii_lowercase())
            .collect();
        let mut hits = Vec::new();
        for row in rows.flatten() {
            let (path, language, rank, compressed) = row;
            let Ok(content) = gunzip(&compressed) else {
                continue;
            };
            let (line, snippet) = best_line(&content, &terms);
            hits.push(SearchHit {
                path,
                language,
                score: -rank,
                line,
                snippet,
            });
        }
        Ok(hits)
    }

    pub fn file_entry(&self, path: &str) -> Result<Option<FileEntry>, String> {
        let row = self
            .conn
            .query_row(
                "SELECT path,language,hash,size,mtime,symbols_json FROM files WHERE path=?1",
                params![path],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;
        Ok(row.map(
            |(path, language, hash, size, mtime, symbols_json)| FileEntry {
                path,
                language,
                hash,
                size: size as u64,
                mtime,
                symbols: serde_json::from_str(&symbols_json).unwrap_or_default(),
            },
        ))
    }

    pub fn file_content(&self, path: &str) -> Result<Option<String>, String> {
        let compressed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT content FROM files WHERE path=?1",
                params![path],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        compressed.map(|bytes| gunzip(&bytes)).transpose()
    }

    pub fn file_lines(&self, path: &str) -> Result<Option<Vec<String>>, String> {
        Ok(self
            .file_content(path)?
            .map(|content| content.lines().map(str::to_string).collect()))
    }

    pub fn all_paths(&self) -> Result<Vec<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT path FROM files ORDER BY path")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    pub fn clear(&mut self) -> Result<(), String> {
        self.conn
            .execute_batch("DELETE FROM files_fts; DELETE FROM files; DELETE FROM meta;")
            .map_err(|e| e.to_string())
    }
}

fn collect_files(root: &Path, options: &IndexOptions) -> Vec<(String, PathBuf)> {
    let mut files = Vec::new();
    if options.use_git && root.join(".git").exists() {
        if let Some(git_files) = git_ls_files(root) {
            for relative in git_files {
                if relative.starts_with("../") || relative.contains("/../") {
                    continue;
                }
                if is_ignored(&relative, options) {
                    continue;
                }
                let absolute = root.join(&relative);
                let metadata = match std::fs::symlink_metadata(&absolute) {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };
                if metadata.file_type().is_symlink() && !options.follow_symlinks {
                    continue;
                }
                if !absolute.is_file() {
                    continue;
                }
                files.push((relative, absolute));
            }
            files.sort_by(|a, b| a.0.cmp(&b.0));
            return files;
        }
    }
    for entry in WalkDir::new(root)
        .follow_links(options.follow_symlinks)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            if entry.file_type().is_dir() {
                if !options.include_hidden && name.starts_with('.') && name != ".github" {
                    return false;
                }
                !is_ignored_dir(&name, options)
            } else {
                true
            }
        })
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = match entry.path().strip_prefix(root) {
            Ok(relative) => relative.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if is_ignored(&relative, options) {
            continue;
        }
        files.push((relative, entry.path().to_path_buf()));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn git_ls_files(root: &Path) -> Option<Vec<String>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(
        text.split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn is_ignored_dir(name: &str, options: &IndexOptions) -> bool {
    options.ignore.iter().any(|pattern| {
        !pattern.contains('*') && !pattern.contains('.') && pattern.eq_ignore_ascii_case(name)
    })
}

/// Ignore matching: component names, prefixes and a small `*` glob.
pub fn is_ignored(relative: &str, options: &IndexOptions) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    let lower = name.to_ascii_lowercase();
    if !options.include_hidden
        && relative.split('/').any(|part| {
            part.starts_with('.') && part != ".github" && !relative.starts_with(".github/")
        })
    {
        return true;
    }
    // Never index credential-shaped files even if the user removed the default.
    if lower == ".env"
        || lower.starts_with(".env.")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
        || lower.starts_with("id_rsa")
        || lower.starts_with("id_ed25519")
        || lower.contains("credentials")
    {
        return true;
    }
    options.ignore.iter().any(|pattern| {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            lower.ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            lower.starts_with(&prefix.to_ascii_lowercase())
        } else {
            relative == pattern
                || relative.starts_with(&format!("{pattern}/"))
                || relative.split('/').any(|part| part == pattern)
        }
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).map_err(|e| e.to_string())?;
    encoder.finish().map_err(|e| e.to_string())
}

fn gunzip(bytes: &[u8]) -> Result<String, String> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = String::new();
    decoder
        .read_to_string(&mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Convert free text into a safe FTS5 AND expression.
pub fn fts_expression(query: &str) -> Option<String> {
    let terms: Vec<String> = query
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|term| !term.is_empty() && term.len() <= 64)
        .map(|term| format!("\"{}\"", term.replace('"', "")))
        .collect();
    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" AND "))
    }
}

fn best_line(content: &str, terms: &[String]) -> (usize, String) {
    for (index, line) in content.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        if terms.iter().any(|term| lower.contains(term)) {
            return (index + 1, snippet_for(line));
        }
    }
    (1, snippet_for(content.lines().next().unwrap_or("")))
}

fn snippet_for(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.chars().count() <= 240 {
        return trimmed.to_string();
    }
    let mut out: String = trimmed.chars().take(240).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn repo(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-context-{}-{}-{}",
            name,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let mut file = std::fs::File::create(dir.join("src/lib.rs")).unwrap();
        file.write_all(
            b"pub fn payment_total(amount: u64) -> u64 {\n    amount * 2\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn totals() {}\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("README.md"),
            "# Payments API\n\nHandles payment totals.\n",
        )
        .unwrap();
        std::fs::write(
            dir.join(".env"),
            "OPENAI_API_KEY=sk-should-never-be-indexed\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("src/secret.pem"),
            "-----BEGIN PRIVATE KEY-----\nxx\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn indexes_symbols_and_excludes_secrets() {
        let dir = repo("index");
        let mut index = RepoIndex::open_in_memory().unwrap();
        let options = IndexOptions {
            use_git: false,
            ..Default::default()
        };
        let stats = index.index_dir(&dir, &options).unwrap();
        assert!(stats.indexed >= 2);
        assert!(!index
            .all_paths()
            .unwrap()
            .iter()
            .any(|p| p.contains(".env")));
        assert!(!index
            .all_paths()
            .unwrap()
            .iter()
            .any(|p| p.ends_with(".pem")));
        let entry = index.file_entry("src/lib.rs").unwrap().unwrap();
        assert_eq!(entry.language, "rust");
        assert!(entry.symbols.iter().any(|s| s.name == "payment_total"));
        assert!(index.file_content("src/lib.rs").unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn incremental_reindex_only_updates_changed_files() {
        let dir = repo("incremental");
        let mut index = RepoIndex::open_in_memory().unwrap();
        let options = IndexOptions {
            use_git: false,
            ..Default::default()
        };
        index.index_dir(&dir, &options).unwrap();
        let second = index.index_dir(&dir, &options).unwrap();
        assert_eq!(second.updated, 0);
        assert!(second.unchanged >= 2);
        std::fs::write(
            dir.join("README.md"),
            "# Payments API\n\nHandles payment totals and refunds.\n",
        )
        .unwrap();
        // Make sure the mtime differs even on coarse filesystems.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let third = index.index_dir(&dir, &options).unwrap();
        assert!(third.updated >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_returns_lines_and_handles_punctuation() {
        let dir = repo("search");
        let mut index = RepoIndex::open_in_memory().unwrap();
        index
            .index_dir(
                &dir,
                &IndexOptions {
                    use_git: false,
                    ..Default::default()
                },
            )
            .unwrap();
        let hits = index.search("payment_total", 10).unwrap();
        assert!(hits.iter().any(|hit| hit.path == "src/lib.rs"));
        assert!(index.search("\"unbalanced", 10).unwrap().is_empty());
        assert!(!index.search("payment totals", 10).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn index_switching_roots_does_not_mix_repositories() {
        let first = repo("root-a");
        let second = repo("root-b");
        let mut index = RepoIndex::open_in_memory().unwrap();
        let options = IndexOptions {
            use_git: false,
            ..Default::default()
        };
        index.index_dir(&first, &options).unwrap();
        index.index_dir(&second, &options).unwrap();
        let status = index.status().unwrap();
        assert_eq!(
            status.root.as_deref().map(|r| r.to_string()),
            Some(second.canonicalize().unwrap().display().to_string())
        );
        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
    }

    #[test]
    fn fts_expression_is_safe() {
        assert_eq!(
            fts_expression("cargo test").as_deref(),
            Some("\"cargo\" AND \"test\"")
        );
        assert!(fts_expression("!!!").is_none());
        assert!(fts_expression("\"quoted\"").unwrap().contains("quoted"));
    }
}
