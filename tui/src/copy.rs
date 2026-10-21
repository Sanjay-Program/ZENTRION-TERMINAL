//! Vi-style copy mode over a terminal snapshot.
//!
//! The buffer is plain text (scrollback + screen) captured when copy mode
//! starts. Motions and selections are pure functions so they can be tested
//! without a terminal.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyBuffer {
    pub lines: Vec<String>,
    /// Cursor row within `lines`.
    pub row: usize,
    /// Cursor column in characters.
    pub col: usize,
    /// Selection anchor; `None` means no visual selection.
    pub anchor: Option<(usize, usize)>,
    pub matches: Vec<(usize, usize)>,
    pub match_index: Option<usize>,
}

impl CopyBuffer {
    pub fn from_text(text: &str) -> Self {
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        if lines.is_empty() {
            lines.push(String::new());
        }
        let row = lines.len().saturating_sub(1);
        let col = lines[row].chars().count();
        Self {
            lines,
            row,
            col,
            anchor: None,
            matches: Vec::new(),
            match_index: None,
        }
    }

    pub fn line(&self) -> &str {
        self.lines.get(self.row).map(String::as_str).unwrap_or("")
    }

    pub fn line_len(&self) -> usize {
        self.line().chars().count()
    }

    pub fn clamp(&mut self) {
        if self.lines.is_empty() {
            self.lines.push(String::new());
        }
        self.row = self.row.min(self.lines.len().saturating_sub(1));
        self.col = self.col.min(self.line_len());
    }

    pub fn move_left(&mut self) {
        self.col = self.col.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        self.col = (self.col + 1).min(self.line_len());
    }

    pub fn move_up(&mut self) {
        self.row = self.row.saturating_sub(1);
        self.clamp();
    }

    pub fn move_down(&mut self) {
        self.row = (self.row + 1).min(self.lines.len().saturating_sub(1));
        self.clamp();
    }

    pub fn line_start(&mut self) {
        self.col = 0;
    }

    pub fn line_end(&mut self) {
        self.col = self.line_len().saturating_sub(1);
    }

    pub fn top(&mut self) {
        self.row = 0;
        self.col = 0;
    }

    pub fn bottom(&mut self) {
        self.row = self.lines.len().saturating_sub(1);
        self.col = self.line_len();
    }

    pub fn word_forward(&mut self) {
        let chars: Vec<char> = self.line().chars().collect();
        let mut index = self.col;
        while index < chars.len() && !is_word(chars[index]) {
            index += 1;
        }
        while index < chars.len() && is_word(chars[index]) {
            index += 1;
        }
        while index < chars.len() && !is_word(chars[index]) {
            index += 1;
        }
        if index >= chars.len() && self.row + 1 < self.lines.len() {
            // `w` at end of line goes to the start of the next line.
            self.row += 1;
            self.col = 0;
        } else {
            self.col = index.min(chars.len());
        }
    }

    pub fn word_backward(&mut self) {
        if self.col == 0 {
            if self.row > 0 {
                self.row -= 1;
                self.col = self.line_len();
                self.word_backward();
            }
            return;
        }
        let chars: Vec<char> = self.line().chars().collect();
        let mut index = self.col.saturating_sub(1);
        while index > 0 && !is_word(chars[index]) {
            index -= 1;
        }
        while index > 0 && is_word(chars[index - 1]) {
            index -= 1;
        }
        self.col = index;
    }

    /// Toggle selection at the cursor.
    pub fn toggle_anchor(&mut self) {
        if self.anchor.is_some() {
            self.anchor = None;
        } else {
            self.anchor = Some((self.row, self.col));
        }
    }

    pub fn selected_text(&self) -> Option<String> {
        let (start, end) = self.ordered_selection()?;
        Some(extract(&self.lines, start, end))
    }

    pub fn ordered_selection(&self) -> Option<((usize, usize), (usize, usize))> {
        let anchor = self.anchor?;
        let cursor = (self.row, self.col);
        if anchor == cursor {
            return None;
        }
        Some(if anchor <= cursor {
            (anchor, cursor)
        } else {
            (cursor, anchor)
        })
    }

    pub fn is_selected(&self, row: usize, col: usize) -> bool {
        let Some((start, end)) = self.ordered_selection() else {
            return false;
        };
        let position = (row, col);
        position >= start && position <= end
    }

    /// Find the next case-insensitive match from the cursor, wrapping.
    pub fn search(&mut self, query: &str) -> bool {
        self.matches.clear();
        if query.is_empty() {
            self.match_index = None;
            return false;
        }
        let needle = query.to_lowercase();
        for (row, line) in self.lines.iter().enumerate() {
            let lower = line.to_lowercase();
            let mut offset = 0usize;
            while let Some(found) = lower[offset..].find(&needle) {
                let byte_index = offset + found;
                let char_index = lower[..byte_index].chars().count();
                self.matches.push((row, char_index));
                offset = byte_index + needle.len().max(1);
                if offset >= lower.len() {
                    break;
                }
            }
        }
        if self.matches.is_empty() {
            self.match_index = None;
            return false;
        }
        let cursor = (self.row, self.col);
        let index = self
            .matches
            .iter()
            .position(|position| *position >= cursor)
            .unwrap_or(0);
        self.match_index = Some(index);
        self.jump_to_match(index);
        true
    }

    pub fn next_match(&mut self) -> bool {
        if self.matches.is_empty() {
            return false;
        }
        let next = match self.match_index {
            Some(index) => (index + 1) % self.matches.len(),
            None => 0,
        };
        self.match_index = Some(next);
        self.jump_to_match(next);
        true
    }

    pub fn previous_match(&mut self) -> bool {
        if self.matches.is_empty() {
            return false;
        }
        let previous = match self.match_index {
            Some(index) => {
                if index == 0 {
                    self.matches.len() - 1
                } else {
                    index - 1
                }
            }
            None => self.matches.len() - 1,
        };
        self.match_index = Some(previous);
        self.jump_to_match(previous);
        true
    }

    fn jump_to_match(&mut self, index: usize) {
        if let Some((row, col)) = self.matches.get(index).copied() {
            self.row = row;
            self.col = col;
        }
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn extract(lines: &[String], start: (usize, usize), end: (usize, usize)) -> String {
    if start.0 == end.0 {
        let chars: Vec<char> = lines[start.0].chars().collect();
        let from = start.1.min(chars.len());
        let to = (end.1 + 1).min(chars.len());
        return chars[from..to].iter().collect();
    }
    let mut out = String::new();
    for (row, line) in lines.iter().enumerate().take(end.0 + 1).skip(start.0) {
        let chars: Vec<char> = line.chars().collect();
        if row == start.0 {
            let from = start.1.min(chars.len());
            out.extend(&chars[from..]);
        } else if row == end.0 {
            let to = (end.1 + 1).min(chars.len());
            out.extend(&chars[..to]);
        } else {
            out.extend(&chars);
        }
        if row != end.0 {
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer() -> CopyBuffer {
        CopyBuffer::from_text("alpha beta gamma\ndelta epsilon\nzeta\n")
    }

    #[test]
    fn starts_at_the_end_and_clamps() {
        let mut buffer = buffer();
        assert_eq!(buffer.row, 2);
        assert_eq!(buffer.col, 4);
        buffer.bottom();
        buffer.move_right();
        assert_eq!(buffer.col, 4);
        buffer.top();
        assert_eq!((buffer.row, buffer.col), (0, 0));
    }

    #[test]
    fn motions_move_by_words_and_lines() {
        let mut buffer = buffer();
        buffer.top();
        buffer.word_forward();
        assert_eq!(buffer.col, 6);
        buffer.word_forward();
        assert_eq!(buffer.col, 11);
        buffer.word_forward();
        assert_eq!(buffer.row, 1);
        assert_eq!(buffer.col, 0);
        buffer.word_backward();
        assert_eq!(buffer.row, 0);
        assert_eq!(buffer.col, 11);
        buffer.line_end();
        assert_eq!(buffer.col, 15);
        buffer.line_start();
        assert_eq!(buffer.col, 0);
    }

    #[test]
    fn selection_is_inclusive_and_ordered() {
        let mut buffer = buffer();
        buffer.top();
        buffer.col = 6;
        buffer.anchor = Some((0, 6));
        buffer.row = 0;
        buffer.col = 9;
        assert_eq!(buffer.selected_text().as_deref(), Some("beta"));
        buffer.row = 1;
        buffer.col = 4;
        assert_eq!(buffer.selected_text().as_deref(), Some("beta gamma\ndelta"));
        // Reverse selection yields the same text.
        buffer.anchor = Some((1, 4));
        buffer.row = 0;
        buffer.col = 6;
        assert_eq!(buffer.selected_text().as_deref(), Some("beta gamma\ndelta"));
    }

    #[test]
    fn selection_on_one_line_handles_unicode() {
        let mut buffer = CopyBuffer::from_text("héllo wörld\n");
        buffer.col = 1;
        buffer.anchor = Some((0, 1));
        buffer.col = 4;
        assert_eq!(buffer.selected_text().as_deref(), Some("éllo"));
    }

    #[test]
    fn search_wraps_and_finds_case_insensitively() {
        let mut buffer = buffer();
        assert!(buffer.search("GAMMA"));
        assert_eq!((buffer.row, buffer.col), (0, 11));
        assert!(buffer.next_match());
        assert_eq!((buffer.row, buffer.col), (0, 11)); // only one match, wraps
        assert!(buffer.search("delta"));
        assert_eq!((buffer.row, buffer.col), (1, 0));
        assert!(!buffer.search("missing"));
        assert!(buffer.matches.is_empty());
    }

    #[test]
    fn selection_helpers_are_bounds_safe() {
        let mut buffer = CopyBuffer::from_text("short\n");
        buffer.col = 999;
        assert_eq!(buffer.line_len(), 5);
        buffer.clamp();
        assert_eq!(buffer.col, 5);
        buffer.anchor = Some((0, 0));
        buffer.col = 5;
        assert_eq!(buffer.selected_text().as_deref(), Some("short"));
    }
}
