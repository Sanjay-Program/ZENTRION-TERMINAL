//! Heuristic credential detection.
//!
//! These patterns intentionally cover common provider formats. They are a
//! first-pass filter, not a replacement for a dedicated secret scanner: every
//! hit should be reviewed before rotation.

use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"sk-proj-[A-Za-z0-9_-]{32,}",
        r"sk-[A-Za-z0-9]{32,}",
        r"gh[pousr]_[A-Za-z0-9]{20,}",
        r"xox[baprs]-[0-9A-Za-z-]{10,}",
        r"AIza[0-9A-Za-z_-]{35}",
        concat!(
            "-----",
            "BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE",
            " KEY-----"
        ),
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        r#"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*["'][^"'\s]{12,}["']"#,
    ]
    .iter()
    .map(|pattern| Regex::new(pattern).expect("built-in secret pattern must compile"))
    .collect()
});

/// Return every matching credential-like string in `content`.
///
/// Obvious documentation placeholders are ignored so a first-run scan of a
/// repository does not drown in AWS/OpenAI example keys.
pub fn scan_for_secrets(content: &str) -> Vec<String> {
    let mut hits: Vec<String> = Vec::new();
    for regex in PATTERNS.iter() {
        for found in regex.find_iter(content) {
            let value = found.as_str();
            if is_placeholder(value) {
                continue;
            }
            let value = value.to_string();
            if !hits.contains(&value) {
                hits.push(value);
            }
        }
    }
    hits
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("example")
        || lower.contains("abcdefghijklmnop")
        || lower.contains("abcdefghijklmnopqrstuvwxyz")
        || lower.contains("0123456789")
        || lower.contains("dummy")
        || lower.contains("placeholder")
        || lower.contains("correct-horse")
        || lower.contains("super_secret")
        || lower.contains("test_key")
        || lower.contains("sentinel")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_known_provider_formats() {
        let key = concat!("AKIA", "7QZ2", "M4X9", "PLK3", "RT8V");
        let token = concat!("ghp_", "R7tY2mK9pL4xQ8wZ1nB6vC3dF5gH0jS2aE9u");
        let text = format!("{key}\n{token}\npassword = \"Tr0ub4dor&3-real-looking\"");
        let hits = scan_for_secrets(&text);
        assert!(hits.iter().any(|h| h.starts_with("AKIA")));
        assert!(hits.iter().any(|h| h.starts_with("ghp_")));
        assert!(hits.iter().any(|h| h.contains("password")));
    }

    #[test]
    fn ignores_documentation_placeholders() {
        let aws = concat!("AKIA", "IOSFODNN7EXAMPLE");
        let github = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz0123");
        let text = format!("{aws}\n{github}");
        assert!(scan_for_secrets(&text).is_empty());
    }

    #[test]
    fn ignores_ordinary_text() {
        assert!(scan_for_secrets("let total = 42;\nfn main() {}").is_empty());
    }

    #[test]
    fn deduplicates_identical_matches() {
        let key = concat!("AKIA", "7QZ2", "M4X9", "PLK3", "RT8V");
        let text = format!("{key} {key}");
        assert_eq!(scan_for_secrets(&text).len(), 1);
    }
}
