//! Hyperlink and file-reference detection.
//!
//! Detection is not activation. Every link is surfaced with its exact target
//! so the UI can ask the user; nothing is opened automatically and schemes
//! must be on an explicit allowlist.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Url,
    Email,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedLink {
    pub kind: LinkKind,
    /// The exact text shown to the user.
    pub text: String,
    /// Where activation would go. For files this is the path; `line`/`col`
    /// carry the position separately.
    pub target: String,
    pub line: Option<u32>,
    pub col: Option<u32>,
    /// Byte offset in the source line.
    pub start: usize,
    pub end: usize,
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:https?://|mailto:)[^\s<>"'`)\]]+"#).expect("valid url regex")
    })
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
            .expect("valid email regex")
    })
}

fn file_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // path/to/file.ext[:line[:col]] — requires a separator and an
        // extension or an explicit :line suffix so ordinary words do not match.
        Regex::new(
            r"(?x)
            (?P<path>
                (?:\.{0,2}/)?(?:[\w@+\-]+/)+[\w@+\-]+\.[A-Za-z0-9]{1,8}
              | [\w@+\-]+\.[A-Za-z0-9]{1,8}
            )
            (?::(?P<line>\d+))?
            (?::(?P<col>\d+))?
            ",
        )
        .expect("valid file regex")
    })
}

/// True when `uri` has a scheme explicitly allowed by policy.
///
/// Scheme comparison is ASCII case-insensitive and exact. A missing scheme is
/// never safe for a hyperlink.
pub fn is_safe_scheme(uri: &str, allowed: &[String]) -> bool {
    let Some((scheme, rest)) = uri.split_once(':') else {
        return false;
    };
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return false;
    }
    if !allowed
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(scheme))
    {
        return false;
    }
    // A scheme alone is not a URI. Hierarchical schemes need an authority
    // ("//"), while mailto needs a non-empty address. This rejects lookalikes
    // such as "https:/x" or "https:javascript".
    match scheme.to_ascii_lowercase().as_str() {
        "mailto" => !rest.trim().is_empty(),
        _ => rest.starts_with("//") && rest.len() > 2,
    }
}

/// Detect URLs, email addresses and `path:line[:col]` references in a line.
///
/// Overlapping matches are resolved in favour of the earliest, longest match
/// (URLs win over the email/path inside them). Results are ordered by start
/// offset and are deterministic.
pub fn detect_links(line: &str) -> Vec<DetectedLink> {
    let mut found: Vec<DetectedLink> = Vec::new();

    for m in url_re().find_iter(line) {
        let text = trim_trailing(m.as_str()).to_string();
        if text.is_empty() {
            continue;
        }
        let kind = if text.to_ascii_lowercase().starts_with("mailto:") {
            LinkKind::Email
        } else {
            LinkKind::Url
        };
        let end = m.start() + text.len();
        found.push(DetectedLink {
            kind,
            target: text.clone(),
            text,
            line: None,
            col: None,
            start: m.start(),
            end,
        });
    }

    for m in email_re().find_iter(line) {
        if overlaps(&found, m.start(), m.end()) {
            continue;
        }
        found.push(DetectedLink {
            kind: LinkKind::Email,
            text: m.as_str().to_string(),
            target: format!("mailto:{}", m.as_str()),
            line: None,
            col: None,
            start: m.start(),
            end: m.end(),
        });
    }

    for caps in file_re().captures_iter(line) {
        let Some(path) = caps.name("path") else {
            continue;
        };
        // Reject things that are really URLs or version numbers.
        if path.as_str().contains("://") || overlaps(&found, path.start(), path.end()) {
            continue;
        }
        let line_no = caps
            .name("line")
            .and_then(|m| m.as_str().parse::<u32>().ok());
        let col_no = caps
            .name("col")
            .and_then(|m| m.as_str().parse::<u32>().ok());
        let end = caps
            .name("col")
            .or_else(|| caps.name("line"))
            .map(|m| m.end())
            .unwrap_or(path.end());
        found.push(DetectedLink {
            kind: LinkKind::File,
            text: line[path.start()..end].to_string(),
            target: path.as_str().to_string(),
            line: line_no,
            col: col_no,
            start: path.start(),
            end,
        });
    }

    found.sort_by_key(|link| (link.start, std::cmp::Reverse(link.end)));
    found
}

fn trim_trailing(text: &str) -> &str {
    text.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '>'])
}

fn overlaps(links: &[DetectedLink], start: usize, end: usize) -> bool {
    links
        .iter()
        .any(|link| start < link.end && end > link.start)
}

/// Return the detected link containing byte `col`, if any.
pub fn link_at(line: &str, col: usize) -> Option<DetectedLink> {
    detect_links(line)
        .into_iter()
        .find(|link| col >= link.start && col < link.end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_https_url() {
        let links = detect_links("see https://example.com/a?b=1, then");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].target, "https://example.com/a?b=1");
        assert_eq!(links[0].kind, LinkKind::Url);
    }

    #[test]
    fn detects_file_line_col() {
        let links = detect_links("error at src/main.rs:42:7: expected");
        let file = links
            .iter()
            .find(|l| l.kind == LinkKind::File)
            .expect("file link");
        assert_eq!(file.target, "src/main.rs");
        assert_eq!(file.line, Some(42));
        assert_eq!(file.col, Some(7));
    }

    #[test]
    fn detects_email_without_duplicating_in_url() {
        let links = detect_links("mail me@example.com or see https://x.test/a@b");
        assert_eq!(
            links.iter().filter(|l| l.kind == LinkKind::Email).count(),
            1
        );
        assert!(links.iter().any(|l| l.kind == LinkKind::Url));
    }

    #[test]
    fn scheme_allowlist_is_exact() {
        let allowed = vec!["https".to_string()];
        assert!(is_safe_scheme("https://x", &allowed));
        assert!(is_safe_scheme("HTTPS://x", &allowed));
        assert!(!is_safe_scheme("http://x", &allowed));
        assert!(!is_safe_scheme("javascript:alert(1)", &allowed));
        assert!(!is_safe_scheme("httpsx://x", &allowed));
        assert!(!is_safe_scheme("//example.com", &allowed));
        assert!(!is_safe_scheme("https:/x", &allowed));
    }

    #[test]
    fn no_match_for_plain_sentence() {
        assert!(detect_links("this is just a sentence with no links").is_empty());
    }
}
