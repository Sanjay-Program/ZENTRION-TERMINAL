//! Rendering of a [`Session`] into a ratatui pane.

use crate::session::Session;
use crate::theme::Theme;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

/// Draw the live screen of `session` inside `area`.
pub fn render_session(f: &mut Frame, area: Rect, session: &Session, theme: &Theme, focused: bool) {
    if area.width < 2 || area.height < 2 {
        return;
    }

    let status = match &session.exit_status {
        Some(s) => format!(" exited · {s} "),
        None if session.is_busy() => " ● ".to_string(),
        None => " ".to_string(),
    };
    let scroll = if session.scroll_offset > 0 {
        format!(" scroll -{} ", session.scroll_offset)
    } else {
        String::new()
    };
    let title = format!(" {} {}{} ", session.title, status, scroll);

    let border_style = if focused {
        Style::default().fg(theme.primary)
    } else {
        Style::default().fg(theme.secondary)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(
            title,
            Style::default()
                .fg(if focused {
                    theme.primary
                } else {
                    theme.secondary
                })
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let screen = session.parser.screen();
    let mut lines: Vec<Line> = Vec::with_capacity(inner.height as usize);

    for row in 0..inner.height {
        let mut spans: Vec<Span> = Vec::new();
        let mut run = String::new();
        let mut run_style: Option<Style> = None;

        for col in 0..inner.width {
            let Some(cell) = screen.cell(row, col) else {
                break;
            };
            if cell.is_wide_continuation() {
                // The previous cell already occupies this column.
                continue;
            }

            let style = cell_style(cell, theme);
            let contents = if cell.has_contents() {
                cell.contents()
            } else {
                " "
            };

            if run_style == Some(style) {
                run.push_str(contents);
            } else {
                if let Some(previous) = run_style.take() {
                    spans.push(Span::styled(std::mem::take(&mut run), previous));
                }
                run.push_str(contents);
                run_style = Some(style);
            }

            if cell.is_wide() {
                // Wide glyph occupies two grid columns; ratatui advances by
                // the glyph width, and the continuation cell is skipped above.
            }
        }

        if let Some(style) = run_style {
            spans.push(Span::styled(run, style));
        }
        lines.push(Line::from(spans));
    }

    f.render_widget(Paragraph::new(lines), inner);

    if focused && session.scroll_offset == 0 && !screen.hide_cursor() {
        let (row, col) = screen.cursor_position();
        if row < inner.height && col < inner.width {
            f.set_cursor_position((inner.x + col, inner.y + row));
        }
    }
}

fn cell_style(cell: &vt100::Cell, theme: &Theme) -> Style {
    let mut fg = map_color(cell.fgcolor(), theme.text);
    let mut bg = map_color(cell.bgcolor(), theme.background);

    if cell.inverse() {
        std::mem::swap(&mut fg, &mut bg);
    }

    let mut style = Style::default().fg(fg).bg(bg);
    let mut modifier = Modifier::empty();
    if cell.bold() {
        modifier |= Modifier::BOLD;
    }
    if cell.dim() {
        modifier |= Modifier::DIM;
    }
    if cell.italic() {
        modifier |= Modifier::ITALIC;
    }
    if cell.underline() {
        modifier |= Modifier::UNDERLINED;
    }
    style = style.add_modifier(modifier);
    style
}

fn map_color(color: vt100::Color, fallback: Color) -> Color {
    match color {
        vt100::Color::Default => fallback,
        vt100::Color::Idx(index) => Color::Indexed(index),
        vt100::Color::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

/// Renders a minimal "no shell" error in the terminal area.
pub fn render_terminal_error(f: &mut Frame, area: Rect, message: &str, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.error))
        .title(" Terminal unavailable ");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let text = Paragraph::new(vec![
        Line::from(Span::styled(
            "Could not start a shell for the terminal pane.",
            Style::default()
                .fg(theme.error)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(message),
        Line::from(""),
        Line::from(Span::styled(
            "Set $SHELL to a valid shell, then restart `z ui`.",
            Style::default().fg(theme.secondary),
        )),
    ])
    .wrap(ratatui::widgets::Wrap { trim: false });
    f.render_widget(text, inner);
}
