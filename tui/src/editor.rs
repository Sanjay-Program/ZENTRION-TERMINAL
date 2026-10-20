//! A small, dependency-free text editor used by the Mini IDE pane.
//!
//! It is intentionally modest (plain text, line/column cursor, save) but it is
//! real: it opens existing files, edits them, and writes them back atomically.

use crate::theme::Theme;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use std::path::{Path, PathBuf};

pub struct Editor {
    pub path: Option<PathBuf>,
    pub lines: Vec<String>,
    pub row: usize,
    pub col: usize,
    pub scroll: usize,
    pub dirty: bool,
    pub status: String,
    pub prompt: Option<String>,
    /// True when the prompt is a "save as" name rather than "open file".
    pub prompt_is_save: bool,
    pub save_as: String,
}

impl Default for Editor {
    fn default() -> Self {
        Self {
            path: None,
            lines: vec![String::new()],
            row: 0,
            col: 0,
            scroll: 0,
            dirty: false,
            status: "Ctrl+S save · Ctrl+O open · Esc close".into(),
            prompt: None,
            prompt_is_save: false,
            save_as: String::new(),
        }
    }
}

impl Editor {
    pub fn open(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
                if lines.is_empty() {
                    lines.push(String::new());
                }
                Self {
                    path: Some(path.clone()),
                    lines,
                    status: format!("Opened {}", path.display()),
                    ..Self::default()
                }
            }
            Err(e) => Self {
                path: Some(path.clone()),
                status: format!("Cannot open {}: {e}", path.display()),
                ..Self::default()
            },
        }
    }

    pub fn open_prompt(&mut self) {
        self.prompt = Some(String::new());
        self.prompt_is_save = false;
        self.status = "Open file".into();
    }

    pub fn save(&mut self) -> bool {
        let Some(path) = self.path.clone() else {
            self.prompt = Some(self.save_as.clone());
            self.prompt_is_save = true;
            self.status = "No filename yet — type a path and press Enter".into();
            return false;
        };
        let mut text = self.lines.join("\n");
        text.push('\n');
        match write_atomic(&path, &text) {
            Ok(()) => {
                self.dirty = false;
                self.status = format!("Saved {}", path.display());
                true
            }
            Err(e) => {
                self.status = format!("Save failed: {e}");
                false
            }
        }
    }

    pub fn save_to(&mut self, path: PathBuf) -> bool {
        self.path = Some(path);
        self.dirty = true;
        self.save()
    }

    pub fn handle_prompt_key(&mut self, code: crossterm::event::KeyCode) -> bool {
        use crossterm::event::KeyCode;
        let Some(buffer) = self.prompt.as_mut() else {
            return false;
        };
        match code {
            KeyCode::Enter => {
                let typed = buffer.trim().to_string();
                self.prompt = None;
                if typed.is_empty() {
                    self.status = "No filename entered".into();
                    return true;
                }
                let path = PathBuf::from(typed);
                let save_mode = self.prompt_is_save;
                self.prompt_is_save = false;
                if save_mode {
                    self.save_to(path);
                    return true;
                }
                if path.exists() {
                    let opened = Self::open(&path);
                    self.path = opened.path;
                    self.lines = opened.lines;
                    self.row = 0;
                    self.col = 0;
                    self.scroll = 0;
                    self.dirty = false;
                    self.status = format!("Opened {}", path.display());
                } else {
                    self.path = Some(path.clone());
                    self.lines = vec![String::new()];
                    self.row = 0;
                    self.col = 0;
                    self.scroll = 0;
                    self.dirty = true;
                    self.status = format!("New file {}", path.display());
                }
                true
            }
            KeyCode::Esc => {
                self.prompt = None;
                true
            }
            KeyCode::Backspace => {
                buffer.pop();
                true
            }
            KeyCode::Char(c) => {
                buffer.push(c);
                true
            }
            _ => true,
        }
    }

    pub fn handle_key(&mut self, code: crossterm::event::KeyCode) -> bool {
        use crossterm::event::KeyCode;
        if self.prompt.is_some() {
            return self.handle_prompt_key(code);
        }
        match code {
            KeyCode::Esc => return false,
            KeyCode::Left => {
                if self.col > 0 {
                    self.col -= 1;
                } else if self.row > 0 {
                    self.row -= 1;
                    self.col = self.lines[self.row].chars().count();
                }
            }
            KeyCode::Right => {
                let len = self.lines[self.row].chars().count();
                if self.col < len {
                    self.col += 1;
                } else if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = 0;
                }
            }
            KeyCode::Up => {
                if self.row > 0 {
                    self.row -= 1;
                    self.col = self.col.min(self.lines[self.row].chars().count());
                }
            }
            KeyCode::Down => {
                if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = self.col.min(self.lines[self.row].chars().count());
                }
            }
            KeyCode::Home => self.col = 0,
            KeyCode::End => self.col = self.lines[self.row].chars().count(),
            KeyCode::PageUp => {
                self.row = self.row.saturating_sub(20);
                self.col = self.col.min(self.lines[self.row].chars().count());
            }
            KeyCode::PageDown => {
                self.row = (self.row + 20).min(self.lines.len() - 1);
                self.col = self.col.min(self.lines[self.row].chars().count());
            }
            KeyCode::Enter => {
                let (left, right) = split_at_char(&self.lines[self.row], self.col);
                self.lines[self.row] = left;
                self.lines.insert(self.row + 1, right);
                self.row += 1;
                self.col = 0;
                self.dirty = true;
            }
            KeyCode::Backspace => {
                if self.col > 0 {
                    let (left, right) = split_at_char(&self.lines[self.row], self.col - 1);
                    let mut new = left;
                    new.push_str(&right.chars().skip(1).collect::<String>());
                    self.lines[self.row] = new;
                    self.col -= 1;
                    self.dirty = true;
                } else if self.row > 0 {
                    let current = self.lines.remove(self.row);
                    self.row -= 1;
                    self.col = self.lines[self.row].chars().count();
                    self.lines[self.row].push_str(&current);
                    self.dirty = true;
                }
            }
            KeyCode::Delete => {
                let len = self.lines[self.row].chars().count();
                if self.col < len {
                    let (left, right) = split_at_char(&self.lines[self.row], self.col);
                    let mut new = left;
                    new.push_str(&right.chars().skip(1).collect::<String>());
                    self.lines[self.row] = new;
                    self.dirty = true;
                } else if self.row + 1 < self.lines.len() {
                    let next = self.lines.remove(self.row + 1);
                    self.lines[self.row].push_str(&next);
                    self.dirty = true;
                }
            }
            KeyCode::Tab => {
                for _ in 0..4 {
                    self.insert_char(' ');
                }
            }
            KeyCode::Char(c) => {
                self.insert_char(c);
            }
            _ => {}
        }
        true
    }

    /// Insert pasted text, splitting on newlines.
    pub fn insert_str(&mut self, text: &str) {
        for c in text.chars() {
            if c == '\n' {
                self.handle_key(crossterm::event::KeyCode::Enter);
            } else if c != '\r' {
                self.insert_char(c);
            }
        }
    }

    fn insert_char(&mut self, c: char) {
        let line = &mut self.lines[self.row];
        let byte = char_to_byte(line, self.col);
        line.insert(byte, c);
        self.col += 1;
        self.dirty = true;
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, theme: &Theme) {
        let chunks = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(2)])
            .split(area);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(format!(
                " Mini IDE · {} {} ",
                self.path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "untitled".into()),
                if self.dirty { "●" } else { "" }
            ));
        let inner = block.inner(chunks[0]);
        f.render_widget(block, chunks[0]);
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        // Keep the cursor visible.
        let height = inner.height as usize;
        if self.row < self.scroll {
            self.scroll = self.row;
        } else if self.row >= self.scroll + height {
            self.scroll = self.row + 1 - height;
        }

        let digits = (self.lines.len().max(1)).to_string().len().max(3);
        let mut lines = Vec::new();
        for (index, text) in self.lines.iter().enumerate().skip(self.scroll).take(height) {
            let number = format!("{:>digits$} │ ", index + 1, digits = digits);
            lines.push(Line::from(vec![
                Span::styled(number, Style::default().fg(theme.secondary)),
                Span::raw(text.clone()),
            ]));
        }

        f.render_widget(Paragraph::new(lines), inner);

        let cursor_row = self.row.saturating_sub(self.scroll);
        if cursor_row < height {
            let prefix = format!("{:>digits$} │ ", self.row + 1, digits = digits);
            let x = inner.x + prefix.chars().count() as u16 + self.col as u16;
            let y = inner.y + cursor_row as u16;
            if x < inner.x + inner.width && y < inner.y + inner.height {
                f.set_cursor_position((x, y));
            }
        }

        let footer = if let Some(buffer) = &self.prompt {
            if self.prompt_is_save {
                format!("Save as: {buffer}▏  (Enter to save, Esc to cancel)")
            } else {
                format!("Open: {buffer}▏  (Enter to open, Esc to cancel)")
            }
        } else {
            format!(
                "{}  ·  line {}, col {}",
                self.status,
                self.row + 1,
                self.col + 1
            )
        };
        let hint = Paragraph::new(Line::from(Span::styled(
            footer,
            Style::default()
                .fg(if self.prompt.is_some() {
                    theme.accent
                } else {
                    theme.secondary
                })
                .add_modifier(if self.prompt.is_some() {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        )))
        .block(Block::default().borders(Borders::TOP));
        f.render_widget(hint, chunks[1]);
    }
}

fn split_at_char(text: &str, index: usize) -> (String, String) {
    let byte = char_to_byte(text, index);
    (text[..byte].to_string(), text[byte..].to_string())
}

fn char_to_byte(text: &str, char_index: usize) -> usize {
    text.char_indices()
        .nth(char_index)
        .map(|(byte, _)| byte)
        .unwrap_or(text.len())
}

fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("zentrion")
    ));
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_tracks_dirty_state() {
        let mut editor = Editor::default();
        for c in "hello".chars() {
            editor.handle_key(crossterm::event::KeyCode::Char(c));
        }
        assert_eq!(editor.lines[0], "hello");
        assert_eq!(editor.col, 5);
        assert!(editor.dirty);
        editor.handle_key(crossterm::event::KeyCode::Enter);
        assert_eq!(editor.lines.len(), 2);
        editor.handle_key(crossterm::event::KeyCode::Backspace);
        assert_eq!(editor.lines, vec!["hello".to_string()]);
    }

    #[test]
    fn unicode_editing_is_char_safe() {
        let mut editor = Editor {
            lines: vec!["héllo".into()],
            col: 5,
            ..Editor::default()
        };
        editor.handle_key(crossterm::event::KeyCode::Backspace);
        assert_eq!(editor.lines[0], "héll");
        editor.handle_key(crossterm::event::KeyCode::Char('ø'));
        assert_eq!(editor.lines[0], "héllø");
    }

    #[test]
    fn saves_and_reloads() {
        let dir = std::env::temp_dir().join(format!("zentrion-editor-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("note.txt");
        let mut editor = Editor {
            lines: vec!["hello".into(), "world".into()],
            dirty: true,
            ..Editor::default()
        };
        assert!(editor.save_to(path.clone()));
        let opened = Editor::open(&path);
        assert_eq!(opened.lines, vec!["hello".to_string(), "world".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
