//! Block sharing with mandatory redaction.
//!
//! Sharing is a data-egress path: it must strip ANSI, drop environment
//! values (they are never stored), redact credential-shaped strings, and cap
//! the payload. There is no "share raw" API.

use crate::model::Block;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareOptions {
    pub redact: bool,
    pub max_output_bytes: usize,
    pub include_metadata: bool,
    pub title: Option<String>,
}

impl Default for ShareOptions {
    fn default() -> Self {
        Self {
            redact: true,
            max_output_bytes: 256 * 1024,
            include_metadata: true,
            title: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redaction {
    pub kind: String,
    pub count: usize,
}

struct Pattern {
    kind: &'static str,
    regex: Regex,
    replacement: &'static str,
}

fn patterns() -> &'static Vec<Pattern> {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let mut p = Vec::new();
        let mut add = |kind: &'static str, pattern: &str, replacement: &'static str| {
            if let Ok(regex) = Regex::new(pattern) {
                p.push(Pattern {
                    kind,
                    regex,
                    replacement,
                });
            }
        };
        add(
            "aws_access_key",
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            "[REDACTED:aws_access_key]",
        );
        add(
            "github_token",
            r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b",
            "[REDACTED:github_token]",
        );
        add(
            "openai_key",
            r"\bsk-[A-Za-z0-9_\-]{20,}\b",
            "[REDACTED:api_key]",
        );
        add(
            "anthropic_key",
            r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
            "[REDACTED:api_key]",
        );
        add(
            "slack_token",
            r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
            "[REDACTED:slack_token]",
        );
        add(
            "jwt",
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
            "[REDACTED:jwt]",
        );
        add(
            "private_key",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            "[REDACTED:private_key]",
        );
        add(
            "authorization",
            r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=\-]{8,}",
            "$1[REDACTED:token]",
        );
        add(
            "assigned_secret",
            r#"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*)([^\s'"]{4,})"#,
            "$1[REDACTED:secret]",
        );
        p
    })
}

/// Redact credential-shaped strings. Returns the redacted text and counts.
pub fn redact(text: &str) -> (String, Vec<Redaction>) {
    let mut out = text.to_string();
    let mut report: Vec<Redaction> = Vec::new();
    for pattern in patterns() {
        let count = pattern.regex.find_iter(&out).count();
        if count == 0 {
            continue;
        }
        out = pattern
            .regex
            .replace_all(&out, pattern.replacement)
            .to_string();
        if let Some(existing) = report.iter_mut().find(|r| r.kind == pattern.kind) {
            existing.count += count;
        } else {
            report.push(Redaction {
                kind: pattern.kind.to_string(),
                count,
            });
        }
    }
    report.sort_by(|a, b| a.kind.cmp(&b.kind));
    (out, report)
}

/// Strip ANSI CSI/OSC/DCS sequences and C0 control bytes (except newline/tab).
pub fn strip_ansi(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            0x1b if i + 1 < bytes.len() => match bytes[i + 1] {
                b'[' => {
                    i += 2;
                    while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                        i += 1;
                    }
                    i += 1;
                }
                b']' => {
                    i += 2;
                    while i < bytes.len() {
                        if bytes[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                b'P' | b'^' | b'_' => {
                    i += 2;
                    while i < bytes.len() {
                        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                _ => {
                    i += 2;
                }
            },
            b'\n' | b'\t' | b'\r' => {
                out.push(bytes[i] as char);
                i += 1;
            }
            b if b < 0x20 || b == 0x7f => {
                i += 1;
            }
            _ => {
                // Copy a whole UTF-8 scalar.
                let width = utf8_width(bytes[i]);
                let end = (i + width).min(bytes.len());
                out.push_str(&String::from_utf8_lossy(&bytes[i..end]));
                i = end;
            }
        }
    }
    out
}

fn utf8_width(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

fn truncate_output(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}\n… [truncated]", &text[..end]), true)
}

/// Render a block as shareable Markdown. Output is always redacted unless the
/// caller explicitly passes `redact: false`, and even then secrets that match
/// the mandatory patterns are replaced (there is no unredacted export path).
pub fn block_to_markdown(
    block: &Block,
    output: &[u8],
    options: &ShareOptions,
) -> (String, Vec<Redaction>) {
    let plain = strip_ansi(&String::from_utf8_lossy(output));
    let (text, truncated) = truncate_output(&plain, options.max_output_bytes);
    let (text, redactions) = if options.redact {
        redact(&text)
    } else {
        // Even with redaction disabled, credential-shaped secrets are
        // removed: sharing must never be a secret-egress path.
        redact(&text)
    };

    let mut md = String::new();
    let title = options
        .title
        .clone()
        .unwrap_or_else(|| block.command.clone());
    md.push_str(&format!("# {}\n\n", title.replace('\n', " ")));
    if options.include_metadata {
        md.push_str("| field | value |\n|---|---|\n");
        md.push_str(&format!(
            "| command | `{}` |\n",
            block.command.replace('`', "'")
        ));
        md.push_str(&format!("| cwd | `{}` |\n", block.cwd.replace('`', "'")));
        md.push_str(&format!("| shell | `{}` |\n", block.shell));
        md.push_str(&format!("| status | {} |\n", block.status));
        if let Some(code) = block.exit_code {
            md.push_str(&format!("| exit code | {code} |\n"));
        }
        if let Some(ms) = block.duration_ms {
            md.push_str(&format!("| duration | {ms} ms |\n"));
        }
        md.push_str(&format!(
            "| started | {} |\n",
            block.started_at.to_rfc3339()
        ));
        if let Some(hash) = &block.output_hash {
            md.push_str(&format!("| output sha256 | `{hash}` |\n"));
        }
        if let Some(agent) = &block.agent_id {
            md.push_str(&format!("| agent | `{agent}` |\n"));
        }
        if let Some(risk) = &block.risk {
            md.push_str(&format!("| risk | {risk} |\n"));
        }
        md.push('\n');
    }
    md.push_str("```console\n");
    md.push_str(text.trim_end());
    md.push_str("\n```\n");
    if truncated {
        md.push_str("\n> Output truncated for sharing.\n");
    }
    if !redactions.is_empty() {
        let total: usize = redactions.iter().map(|r| r.count).sum();
        md.push_str(&format!("\n> {total} secret(s) redacted.\n"));
    }
    (md, redactions)
}

/// Escape minimal HTML and preserve output in a `<pre>` block.
pub fn block_to_html(block: &Block, output: &[u8]) -> String {
    let (markdown, _) = block_to_markdown(block, output, &ShareOptions::default());
    let escaped = markdown
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!("<article class=\"zentrion-block\"><pre>{escaped}</pre></article>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::BlockStatus;
    use chrono::Utc;

    fn block() -> Block {
        Block {
            id: "b1".into(),
            session_id: "s1".into(),
            seq: 1,
            command: "curl -H 'Authorization: Bearer abcdefghijklmnop' https://x".into(),
            cwd: "/repo".into(),
            shell: "bash".into(),
            started_at: Utc::now(),
            ended_at: None,
            exit_code: Some(0),
            status: BlockStatus::Ok,
            duration_ms: Some(12),
            output_hash: Some("sha256:abc".into()),
            output_bytes: Some(10),
            agent_id: None,
            policy_decision: None,
            approval_id: None,
            tags: vec![],
            risk: None,
            parent_block_id: None,
        }
    }

    #[test]
    fn ansi_is_stripped() {
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m\n"), "red\n");
        assert_eq!(strip_ansi("\x1b]0;title\x07ok"), "ok");
    }

    #[test]
    fn secrets_are_redacted_in_share_output() {
        let output = b"token=supersecret123\nAKIAABCDEFGHIJKLMNOP\n";
        let (md, report) = block_to_markdown(&block(), output, &ShareOptions::default());
        assert!(!md.contains("supersecret123"));
        assert!(!md.contains("AKIAABCDEFGHIJKLMNOP"));
        assert!(!report.is_empty());
    }

    #[test]
    fn output_is_truncated() {
        let output = b"x".repeat(10_000);
        let options = ShareOptions {
            max_output_bytes: 100,
            ..ShareOptions::default()
        };
        let (md, _) = block_to_markdown(&block(), &output, &options);
        assert!(md.contains("truncated"));
        assert!(md.len() < 2000);
    }

    #[test]
    fn normal_text_is_not_mangled() {
        let (redacted, report) = redact("cargo test passed in 42ms");
        assert_eq!(redacted, "cargo test passed in 42ms");
        assert!(report.is_empty());
    }
}
