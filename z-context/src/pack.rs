//! Deterministic context packing.
//!
//! Given a query and a token budget, the packer retrieves candidates from the
//! index, ranks them (pins, FTS rank, proximity), expands to line windows,
//! redacts credential-shaped strings, and stops at the budget. The same index
//! and query always produce the same pack.
//!
//! Only indexed content can be pinned or packed. Ignored files (secrets,
//! credentials) are not in the index and therefore cannot be sent, even if a
//! caller asks for them.

use crate::index::RepoIndex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextQuery {
    pub query: String,
    pub budget_tokens: usize,
    pub max_items: usize,
    /// File paths (relative to the indexed root) pinned ahead of search hits.
    pub pins: Vec<String>,
    pub include_git: bool,
    pub window_lines: usize,
}

impl ContextQuery {
    pub fn new(query: impl Into<String>, budget_tokens: usize) -> Self {
        Self {
            query: query.into(),
            budget_tokens: budget_tokens.max(256),
            max_items: 12,
            pins: Vec::new(),
            include_git: true,
            window_lines: 40,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextItem {
    pub kind: String,
    pub path: Option<String>,
    pub language: Option<String>,
    pub start_line: Option<usize>,
    pub end_line: Option<usize>,
    pub content: String,
    pub tokens: usize,
    pub why: String,
    pub score: f64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedactionCount {
    pub kind: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextPack {
    pub query: String,
    pub budget_tokens: usize,
    pub used_tokens: usize,
    pub items: Vec<ContextItem>,
    pub citations: Vec<String>,
    pub redactions: Vec<RedactionCount>,
    pub warnings: Vec<String>,
    pub truncated: bool,
}

impl ContextPack {
    /// Render the pack for a model prompt. Line numbers are included so a
    /// citation can be checked.
    pub fn render(&self) -> String {
        let mut out = format!(
            "Context pack for: {}\nBudget: {} tokens, used: {} tokens\n\n",
            self.query, self.budget_tokens, self.used_tokens
        );
        for item in &self.items {
            let location = match (&item.path, item.start_line, item.end_line) {
                (Some(path), Some(start), Some(end)) => format!("{path}:{start}-{end}"),
                (Some(path), _, _) => path.clone(),
                _ => "git".into(),
            };
            out.push_str(&format!(
                "--- {location} [{}] ({}) ---\n",
                item.kind, item.why
            ));
            if let (Some(start), Some(path)) = (item.start_line, &item.path) {
                for (offset, line) in item.content.lines().enumerate() {
                    out.push_str(&format!("{path}:{}: {line}\n", start + offset));
                }
            } else {
                out.push_str(&item.content);
                if !item.content.ends_with('\n') {
                    out.push('\n');
                }
            }
            out.push('\n');
        }
        if !self.redactions.is_empty() {
            out.push_str("Redactions applied before packing:\n");
            for redaction in &self.redactions {
                out.push_str(&format!("- {}: {}\n", redaction.kind, redaction.count));
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackError(pub String);

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PackError {}

/// Estimate tokens without a tokenizer. Deliberately conservative for code.
pub fn estimate_tokens(text: &str) -> usize {
    let chars = text.chars().count();
    chars.div_ceil(4) + 1
}

pub fn build_context(index: &RepoIndex, query: &ContextQuery) -> Result<ContextPack, PackError> {
    let root = index
        .indexed_root()
        .ok_or_else(|| PackError("repository is not indexed; run `z context index`".into()))?;
    let mut warnings = Vec::new();
    let mut items: Vec<ContextItem> = Vec::new();
    let mut citations: Vec<String> = Vec::new();
    let mut redactions: Vec<RedactionCount> = Vec::new();

    // Pins first: explicit user intent beats ranking.
    let mut pinned_paths: Vec<String> = Vec::new();
    for pin in &query.pins {
        let normalized = normalize_pin(pin, &root);
        let Some(normalized) = normalized else {
            warnings.push(format!("pin `{pin}` is outside the indexed root; ignored"));
            continue;
        };
        if index.file_entry(&normalized).map_err(PackError)?.is_none() {
            warnings.push(format!(
                "pin `{pin}` is not indexed (ignored, binary or secret-shaped); not sent"
            ));
            continue;
        }
        if !pinned_paths.contains(&normalized) {
            pinned_paths.push(normalized);
        }
    }

    let mut candidates: Vec<Candidate> = pinned_paths
        .iter()
        .map(|path| Candidate {
            path: path.clone(),
            score: 1_000.0,
            why: "pinned".into(),
        })
        .collect();

    if !query.query.trim().is_empty() {
        let hits = index
            .search(&query.query, query.max_items.saturating_mul(3).max(8))
            .map_err(PackError)?;
        for hit in hits {
            if candidates.iter().any(|c| c.path == hit.path) {
                continue;
            }
            candidates.push(Candidate {
                path: hit.path,
                score: hit.score,
                why: format!("search match at line {}", hit.line),
            });
        }
    }
    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.path.cmp(&b.path))
    });
    candidates.truncate(query.max_items.max(1) * 2);

    let mut used = estimate_tokens(&query.query) + 32;
    let budget = query.budget_tokens;

    if query.include_git {
        if let Some(summary) = git_summary(&root) {
            let (content, redactions_found) = redact_text(&summary);
            merge_redactions(&mut redactions, &redactions_found);
            let tokens = estimate_tokens(&content);
            if used + tokens <= budget / 3 {
                used += tokens;
                items.push(ContextItem {
                    kind: "git".into(),
                    path: None,
                    language: None,
                    start_line: None,
                    end_line: None,
                    content,
                    tokens,
                    why: "repository state".into(),
                    score: 0.0,
                    truncated: false,
                });
            } else {
                warnings.push("git summary skipped: budget".into());
            }
        }
    }

    for candidate in candidates {
        if items.len() >= query.max_items.max(1) {
            break;
        }
        let Some(lines) = index.file_lines(&candidate.path).map_err(PackError)? else {
            continue;
        };
        let (start, end, mut content) = window(
            &lines,
            &query.query,
            query.window_lines,
            budget.saturating_sub(used),
        );
        let (redacted, found) = redact_text(&content);
        merge_redactions(&mut redactions, &found);
        content = redacted;
        let tokens = estimate_tokens(&content);
        let mut truncated = false;
        let content = if used + tokens > budget {
            if used + 32 >= budget {
                break;
            }
            let mut cut = content.clone();
            let allowed_chars = (budget - used).saturating_sub(8) * 4;
            if allowed_chars < 64 {
                break;
            }
            let mut end_at = allowed_chars.min(cut.chars().count());
            while end_at > 0 && !cut.is_char_boundary(end_at) {
                end_at -= 1;
            }
            cut = cut.chars().take(end_at).collect();
            truncated = true;
            warnings.push(format!(
                "{} truncated to fit the token budget",
                candidate.path
            ));
            cut
        } else {
            content
        };
        let tokens = estimate_tokens(&content);
        if tokens == 0 {
            continue;
        }
        used += tokens;
        citations.push(format!("{}:{}-{}", candidate.path, start, end));
        items.push(ContextItem {
            kind: if candidate.why == "pinned" {
                "pin".into()
            } else {
                "file".into()
            },
            path: Some(candidate.path.clone()),
            language: None,
            start_line: Some(start),
            end_line: Some(end),
            content,
            tokens,
            why: candidate.why,
            score: candidate.score,
            truncated,
        });
        if used >= budget {
            break;
        }
    }

    let truncated = items.iter().any(|item| item.truncated);
    if items.is_empty() {
        warnings.push("no context items matched; nothing will be sent".into());
    }
    redactions.sort_by(|a, b| a.kind.cmp(&b.kind));
    Ok(ContextPack {
        query: query.query.clone(),
        budget_tokens: budget,
        used_tokens: used,
        items,
        citations,
        redactions,
        warnings,
        truncated,
    })
}

struct Candidate {
    path: String,
    score: f64,
    why: String,
}

fn normalize_pin(pin: &str, root: &str) -> Option<String> {
    let root_path = std::path::Path::new(root);
    let path = std::path::Path::new(pin);
    let relative = if path.is_absolute() {
        path.strip_prefix(root_path).ok()?.to_path_buf()
    } else {
        path.to_path_buf()
    };
    if relative
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return None;
    }
    Some(relative.to_string_lossy().replace('\\', "/"))
}

/// Choose a line window around the first query match.
fn window(
    lines: &[String],
    query: &str,
    window_lines: usize,
    _remaining: usize,
) -> (usize, usize, String) {
    let terms: Vec<String> = query
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|term| !term.is_empty())
        .map(|term| term.to_ascii_lowercase())
        .collect();
    let mut anchor = 0usize;
    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if terms.iter().any(|term| lower.contains(term)) {
            anchor = index;
            break;
        }
    }
    let window_lines = window_lines.max(5);
    let half = window_lines / 2;
    let start = anchor.saturating_sub(half);
    let end = (start + window_lines).min(lines.len());
    let content = lines[start..end].join("\n");
    (start + 1, end, content)
}

fn redact_text(text: &str) -> (String, Vec<z_blocks::Redaction>) {
    z_blocks::redact(text)
}

fn merge_redactions(into: &mut Vec<RedactionCount>, found: &[z_blocks::Redaction]) {
    for redaction in found {
        if let Some(existing) = into.iter_mut().find(|r| r.kind == redaction.kind) {
            existing.count += redaction.count;
        } else {
            into.push(RedactionCount {
                kind: redaction.kind.clone(),
                count: redaction.count,
            });
        }
    }
}

/// Read-only git summary. Never fetches, never prompts, never runs a shell.
pub fn git_summary(root: &str) -> Option<String> {
    if !std::path::Path::new(root).join(".git").exists() {
        return None;
    }
    let run = |args: &[&str]| -> Option<String> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if text.len() > 16 * 1024 {
            let mut end = 16 * 1024;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            Some(text[..end].to_string())
        } else {
            Some(text)
        }
    };
    let branch = run(&["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let status = run(&["status", "--short"]).unwrap_or_default();
    let log = run(&["log", "-5", "--oneline"]).unwrap_or_default();
    let diffstat = run(&["diff", "--stat"]).unwrap_or_default();
    let mut out = format!("branch: {branch}\n");
    if !status.is_empty() {
        out.push_str(&format!("status:\n{status}\n"));
    }
    if !diffstat.is_empty() {
        out.push_str(&format!("working diff:\n{diffstat}\n"));
    }
    if !log.is_empty() {
        out.push_str(&format!("recent commits:\n{log}\n"));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::IndexOptions;
    use std::io::Write;

    fn indexed_repo(name: &str) -> (RepoIndex, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-pack-{}-{}-{}",
            name,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub fn payment_total(amount: u64) -> u64 {\n    // total payment\n    amount * 2\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("src/auth.rs"),
            "const TOKEN: &str = \"sk-abcdefghijklmnopqrstuvwxyz123456\";\npub fn login() {}\n",
        )
        .unwrap();
        std::fs::write(dir.join(".env"), "OPENAI_API_KEY=sk-never-index-this-key\n").unwrap();
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
        (index, dir)
    }

    #[test]
    fn pack_is_deterministic_and_within_budget() {
        let (index, dir) = indexed_repo("deterministic");
        let query = ContextQuery {
            include_git: false,
            budget_tokens: 200,
            ..ContextQuery::new("payment total", 200)
        };
        let first = build_context(&index, &query).unwrap();
        let second = build_context(&index, &query).unwrap();
        assert_eq!(first, second);
        assert!(first.used_tokens <= first.budget_tokens, "{first:?}");
        assert!(first
            .items
            .iter()
            .any(|item| item.path.as_deref() == Some("src/lib.rs")));
        assert!(first.citations.iter().any(|c| c.starts_with("src/lib.rs:")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secrets_are_redacted_or_never_indexed() {
        let (index, dir) = indexed_repo("secrets");
        let mut query = ContextQuery::new("token", 2_000);
        query.include_git = false;
        query.pins = vec![".env".into(), "src/auth.rs".into()];
        let pack = build_context(&index, &query).unwrap();
        assert!(pack.warnings.iter().any(|warning| warning.contains(".env")));
        let rendered = pack.render();
        assert!(!rendered.contains("sk-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(pack.redactions.iter().any(|r| r.kind == "openai_key"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_traversal_pins_are_rejected() {
        let (index, dir) = indexed_repo("traversal");
        let mut query = ContextQuery::new("payment", 500);
        query.include_git = false;
        query.pins = vec!["../../etc/passwd".into()];
        let pack = build_context(&index, &query).unwrap();
        assert!(pack
            .warnings
            .iter()
            .any(|warning| warning.contains("outside the indexed root")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_query_with_no_pins_reports_nothing_sent() {
        let (index, dir) = indexed_repo("empty");
        let mut query = ContextQuery::new("", 500);
        query.include_git = false;
        let pack = build_context(&index, &query).unwrap();
        assert!(pack.items.is_empty());
        assert!(pack
            .warnings
            .iter()
            .any(|warning| warning.contains("nothing will be sent")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_estimate_is_conservative() {
        assert!(estimate_tokens("fn main() {}") >= 3);
        assert_eq!(estimate_tokens(""), 1);
    }

    #[test]
    fn git_summary_is_read_only_and_absent_outside_repos() {
        assert!(git_summary("/definitely/not/a/repo").is_none());
    }

    #[test]
    fn render_contains_citations_and_line_numbers() {
        let (index, dir) = indexed_repo("render");
        let mut query = ContextQuery::new("payment_total", 1_000);
        query.include_git = false;
        let pack = build_context(&index, &query).unwrap();
        let rendered = pack.render();
        assert!(rendered.contains("src/lib.rs:"));
        assert!(rendered.contains("payment_total"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[allow(dead_code)]
    fn write_file(path: &std::path::Path, text: &str) {
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }
}
