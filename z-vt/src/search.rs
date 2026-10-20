//! Screen search and copy-mode primitives.
//!
//! Search is regex-based and bounded so a hostile screen cannot make the UI
//! hang. Copy mode is plain text selection with vi motions; it never mutates
//! the screen or the shell.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchOptions {
    /// Regex pattern (literal patterns are escaped by the caller if desired).
    pub pattern: String,
    pub case_sensitive: bool,
    pub max_results: usize,
    /// Skip lines longer than this (protects against pathological screens).
    pub max_line_bytes: usize,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            case_sensitive: false,
            max_results: 1000,
            max_line_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    /// Zero-based line number in the searched buffer.
    pub line: usize,
    /// Byte column in the line.
    pub col: usize,
    pub len: usize,
    pub text: String,
}

/// Compile a search pattern. Returns an error for invalid regex; the UI shows
/// it instead of silently doing a literal search.
pub fn compile(pattern: &str, case_sensitive: bool) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .size_limit(4 * 1024 * 1024)
        .dfa_size_limit(4 * 1024 * 1024)
        .build()
}

/// Search a text buffer line by line. Deterministic and bounded.
pub fn search_text(text: &str, options: &SearchOptions) -> Result<Vec<SearchHit>, regex::Error> {
    if options.pattern.is_empty() {
        return Ok(Vec::new());
    }
    let re = compile(&options.pattern, options.case_sensitive)?;
    let mut hits = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        if line.len() > options.max_line_bytes {
            continue;
        }
        for m in re.find_iter(line) {
            hits.push(SearchHit {
                line: line_no,
                col: m.start(),
                len: m.end().saturating_sub(m.start()),
                text: m.as_str().to_string(),
            });
            if hits.len() >= options.max_results {
                return Ok(hits);
            }
        }
    }
    Ok(hits)
}

/// A copy-mode selection. `anchor` is where visual mode started; `cursor` is
/// the current cell. Rows/cols are zero-based and screen-relative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    pub anchor_row: u16,
    pub anchor_col: u16,
    pub cursor_row: u16,
    pub cursor_col: u16,
}

impl Selection {
    pub fn new(row: u16, col: u16) -> Self {
        Self {
            anchor_row: row,
            anchor_col: col,
            cursor_row: row,
            cursor_col: col,
        }
    }

    /// Normalised (start, end) in reading order.
    pub fn normalized(&self) -> ((u16, u16), (u16, u16)) {
        if (self.cursor_row, self.cursor_col) < (self.anchor_row, self.anchor_col) {
            (
                (self.cursor_row, self.cursor_col),
                (self.anchor_row, self.anchor_col),
            )
        } else {
            (
                (self.anchor_row, self.anchor_col),
                (self.cursor_row, self.cursor_col),
            )
        }
    }

    pub fn is_empty(&self) -> bool {
        self.anchor_row == self.cursor_row && self.anchor_col == self.cursor_col
    }

    pub fn move_to(&mut self, row: u16, col: u16) {
        self.cursor_row = row;
        self.cursor_col = col;
    }

    pub fn move_by(&mut self, rows: i32, cols: i32, max_rows: u16, max_cols: u16) {
        self.cursor_row = clamp_add(self.cursor_row, rows, max_rows.saturating_sub(1));
        self.cursor_col = clamp_add(self.cursor_col, cols, max_cols.saturating_sub(1));
    }

    /// Extract selected text from a `vt100` screen. Wide cells are handled by
    /// the terminal's own `contents_between`.
    pub fn text(&self, screen: &vt100::Screen) -> String {
        let ((sr, sc), (er, ec)) = self.normalized();
        screen.contents_between(sr, sc, er, ec)
    }

    /// Extract selection from a plain line buffer (used by blocks/export).
    pub fn text_from_lines(&self, lines: &[String]) -> String {
        let ((sr, sc), (er, ec)) = self.normalized();
        let mut out = String::new();
        for row in sr..=er {
            let Some(line) = lines.get(row as usize) else {
                continue;
            };
            let chars: Vec<char> = line.chars().collect();
            let start = if row == sr { sc as usize } else { 0 };
            let end = if row == er {
                (ec as usize + 1).min(chars.len())
            } else {
                chars.len()
            };
            if start < end {
                out.extend(&chars[start..end]);
            }
            if row != er {
                out.push('\n');
            }
        }
        out
    }
}

fn clamp_add(value: u16, delta: i32, max: u16) -> u16 {
    let next = value as i32 + delta;
    next.clamp(0, max as i32) as u16
}

/// Return the byte range of the word containing `col` on `line`.
pub fn word_at(line: &str, col: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut start = col.min(bytes.len().saturating_sub(1));
    while start > 0 && is_word_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = col.min(bytes.len());
    while end < bytes.len() && is_word_byte(bytes[end]) {
        end += 1;
    }
    if start == end {
        return None;
    }
    Some((start, end))
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte >= 0x80
}

/// Move one vi `w` step over a line: skip the current word, then whitespace.
pub fn next_word(line: &str, col: usize) -> usize {
    let bytes = line.as_bytes();
    let mut i = col.min(bytes.len());
    while i < bytes.len() && is_word_byte(bytes[i]) {
        i += 1;
    }
    while i < bytes.len() && !is_word_byte(bytes[i]) {
        i += 1;
    }
    i
}

/// Move one vi `b` step backwards.
pub fn prev_word(line: &str, col: usize) -> usize {
    let bytes = line.as_bytes();
    let mut i = col.min(bytes.len());
    if i > 0 {
        i -= 1;
    }
    while i > 0 && !is_word_byte(bytes[i]) {
        i -= 1;
    }
    while i > 0 && is_word_byte(bytes[i - 1]) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_search_reports_line_col() {
        let text = "alpha\nbeta 42\ngamma 42\n";
        let hits = search_text(
            text,
            &SearchOptions {
                pattern: r"\d+".to_string(),
                ..SearchOptions::default()
            },
        )
        .unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].line, 1);
        assert_eq!(hits[1].line, 2);
    }

    #[test]
    fn invalid_regex_is_an_error_not_a_literal_search() {
        assert!(search_text(
            "x",
            &SearchOptions {
                pattern: "(".to_string(),
                ..SearchOptions::default()
            }
        )
        .is_err());
    }

    #[test]
    fn search_is_bounded() {
        let text = "aaaa\naaaa\naaaa";
        let hits = search_text(
            text,
            &SearchOptions {
                pattern: "a".to_string(),
                max_results: 3,
                ..SearchOptions::default()
            },
        )
        .unwrap();
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn word_motions_are_stable() {
        assert_eq!(word_at("cargo test --all", 7), Some((6, 10)));
        assert_eq!(next_word("cargo test", 0), 6);
        assert_eq!(prev_word("cargo test", 8), 6);
    }

    #[test]
    fn selection_text_from_lines() {
        let lines = vec!["hello world".to_string(), "second".to_string()];
        let mut sel = Selection::new(0, 6);
        sel.move_to(1, 2);
        assert_eq!(sel.text_from_lines(&lines), "world\nsec");
    }
}
