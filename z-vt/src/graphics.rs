//! Terminal graphics engine supporting Kitty Graphics Protocol, Sixel,
//! and iTerm2 OSC 1337 inline images with smart fallback rendering.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Source protocol of the graphic media.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphicSource {
    Kitty,
    Sixel,
    ITerm2,
}

/// Image pixel or compression format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphicFormat {
    Png,
    Rgba,
    Rgb,
    Sixel,
    Jpeg,
    Unknown,
}

/// A parsed graphic media object ready for GPU upload or fallback rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphicMedia {
    pub id: u32,
    pub placement_id: Option<u32>,
    pub z_index: i32,
    pub width: u32,
    pub height: u32,
    pub format: GraphicFormat,
    pub source: GraphicSource,
    #[serde(skip)]
    pub payload: Vec<u8>,
}

impl GraphicMedia {
    /// Render an ANSI half-block or textual preview for environments
    /// lacking GPU/native graphics support.
    pub fn render_fallback(&self, target_cols: u16, target_rows: u16) -> String {
        let cols = target_cols.max(10).min(80) as usize;
        let rows = target_rows.max(2).min(24) as usize;

        let mut lines = Vec::new();
        let border_top = format!("┌{}┐", "─".repeat(cols.saturating_sub(2)));
        let border_bot = format!("└{}┘", "─".repeat(cols.saturating_sub(2)));

        lines.push(border_top);

        let info = format!(
            " Image #{} ({}x{}, {:?}) ",
            self.id, self.width, self.height, self.format
        );
        let pad_len = cols.saturating_sub(2).saturating_sub(info.len()) / 2;
        let info_line = format!(
            "│{}{}{}│",
            " ".repeat(pad_len),
            info,
            " ".repeat(cols.saturating_sub(2 + pad_len + info.len()))
        );
        lines.push(info_line);

        for _ in 2..rows.saturating_sub(1) {
            let row_str = format!("│{}│", "▒".repeat(cols.saturating_sub(2)));
            lines.push(row_str);
        }

        if rows > 2 {
            lines.push(border_bot);
        }

        lines.join("\r\n")
    }
}

/// Parser for the Kitty Graphics Protocol (`\x1b_G...;\x1b\`).
#[derive(Debug, Default)]
pub struct KittyGraphicsParser {
    chunk_buffer: HashMap<u32, Vec<u8>>,
}

impl KittyGraphicsParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a Kitty graphics sequence payload (content after `\x1b_G` and before ST).
    pub fn parse(&mut self, sequence: &str) -> Option<GraphicMedia> {
        let (control_str, data_str) = sequence.split_once(';')?;

        let mut id = 1;
        let mut placement_id = None;
        let mut z_index = 0;
        let mut width = 0;
        let mut height = 0;
        let mut format = GraphicFormat::Png;
        let mut more_chunks = false;

        for pair in control_str.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "i" => id = v.parse().unwrap_or(id),
                    "p" | "I" => placement_id = v.parse().ok(),
                    "z" => z_index = v.parse().unwrap_or(0),
                    "s" => width = v.parse().unwrap_or(0),
                    "v" => height = v.parse().unwrap_or(0),
                    "f" => match v {
                        "100" => format = GraphicFormat::Png,
                        "32" => format = GraphicFormat::Rgba,
                        "24" => format = GraphicFormat::Rgb,
                        _ => format = GraphicFormat::Unknown,
                    },
                    "m" => more_chunks = v == "1",
                    _ => {}
                }
            }
        }

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(data_str.trim().as_bytes())
            .unwrap_or_default();

        let buffer = self.chunk_buffer.entry(id).or_default();
        buffer.extend_from_slice(&decoded);

        if !more_chunks {
            let complete_payload = self.chunk_buffer.remove(&id).unwrap_or_default();
            Some(GraphicMedia {
                id,
                placement_id,
                z_index,
                width,
                height,
                format,
                source: GraphicSource::Kitty,
                payload: complete_payload,
            })
        } else {
            None
        }
    }
}

/// Parser for iTerm2 OSC 1337 inline images (`OSC 1337;File=...:<data>ST`).
pub struct ITerm2GraphicsParser;

impl ITerm2GraphicsParser {
    pub fn parse(payload: &str) -> Option<GraphicMedia> {
        let file_args = payload.strip_prefix("File=")?;
        let (params_str, data_str) = file_args.split_once(':')?;

        let mut width = 0;
        let mut height = 0;

        for param in params_str.split(';') {
            if let Some((k, v)) = param.split_once('=') {
                match k {
                    "width" => width = v.trim_end_matches("px").parse().unwrap_or(0),
                    "height" => height = v.trim_end_matches("px").parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(data_str.trim().as_bytes())
            .ok()?;

        Some(GraphicMedia {
            id: fastrand_id(),
            placement_id: None,
            z_index: 0,
            width,
            height,
            format: GraphicFormat::Png,
            source: GraphicSource::ITerm2,
            payload: decoded,
        })
    }
}

/// Sixel format decoder.
pub struct SixelDecoder;

impl SixelDecoder {
    /// Decode a raw sixel byte slice (`DCS [q <sixel-data> ST`) into raw RGBA image data.
    pub fn decode(sixel_stream: &[u8]) -> Option<GraphicMedia> {
        let mut width = 0usize;
        let mut height = 0usize;
        let mut palette: HashMap<u8, [u8; 4]> = HashMap::new();
        let mut current_color = [255, 255, 255, 255];

        let mut pos = 0;
        let len = sixel_stream.len();

        let mut x = 0usize;
        let mut y = 0usize;
        let mut pixels: Vec<[u8; 4]> = Vec::new();

        while pos < len {
            let b = sixel_stream[pos];
            match b {
                b'#' => {
                    // Palette selection or introduction: #<reg>;...
                    pos += 1;
                    let mut num = 0u8;
                    while pos < len && sixel_stream[pos].is_ascii_digit() {
                        num = num.saturating_mul(10) + (sixel_stream[pos] - b'0');
                        pos += 1;
                    }
                    if pos < len && sixel_stream[pos] == b';' {
                        // Color definition: #<reg>;2;<r>;<g>;<b> (RGB 0..100)
                        pos += 1; // skip ';'
                        let rest = &sixel_stream[pos..];
                        if let Some(semi1) = rest.iter().position(|&c| c == b';') {
                            let rest2 = &rest[semi1 + 1..];
                            if let Some(semi2) = rest2.iter().position(|&c| c == b';') {
                                let rest3 = &rest2[semi2 + 1..];
                                let semi3 = rest3.iter().position(|&c| !c.is_ascii_digit()).unwrap_or(rest3.len());
                                let r: u8 = (std::str::from_utf8(&rest2[..semi2]).ok()?.parse::<u32>().ok()? * 255 / 100) as u8;
                                let g: u8 = (std::str::from_utf8(&rest3[..semi3]).ok()?.parse::<u32>().ok()? * 255 / 100) as u8;
                                let b_col: u8 = 255;
                                palette.insert(num, [r, g, b_col, 255]);
                                pos += semi1 + 1 + semi2 + 1 + semi3;
                            }
                        }
                    } else {
                        // Select register
                        if let Some(c) = palette.get(&num) {
                            current_color = *c;
                        }
                    }
                    continue;
                }
                b'$' => {
                    // Carriage return
                    x = 0;
                }
                b'-' => {
                    // Next sixel line
                    x = 0;
                    y += 6;
                }
                b'?'..=b'~' => {
                    // Sixel character (bits 0..5)
                    let sixel_bits = b - b'?';
                    let need_h = y + 6;
                    if need_h > height {
                        height = need_h;
                    }
                    if x + 1 > width {
                        width = x + 1;
                    }

                    while pixels.len() < width * height {
                        pixels.push([0, 0, 0, 0]);
                    }

                    for bit in 0..6 {
                        if (sixel_bits & (1 << bit)) != 0 {
                            let py = y + bit;
                            let idx = py * width + x;
                            if idx < pixels.len() {
                                pixels[idx] = current_color;
                            }
                        }
                    }
                    x += 1;
                }
                _ => {}
            }
            pos += 1;
        }

        let mut raw_bytes = Vec::with_capacity(pixels.len() * 4);
        for p in pixels {
            raw_bytes.extend_from_slice(&p);
        }

        Some(GraphicMedia {
            id: fastrand_id(),
            placement_id: None,
            z_index: 0,
            width: width as u32,
            height: height as u32,
            format: GraphicFormat::Sixel,
            source: GraphicSource::Sixel,
            payload: raw_bytes,
        })
    }
}

fn fastrand_id() -> u32 {
    let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    (now as u32).wrapping_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kitty_graphics_parsing() {
        let mut parser = KittyGraphicsParser::new();
        let payload = base64::engine::general_purpose::STANDARD.encode(b"PNG_MOCK_DATA");
        let seq = format!("a=T,f=100,s=200,v=150,i=42;{}", payload);

        let media = parser.parse(&seq).unwrap();
        assert_eq!(media.id, 42);
        assert_eq!(media.width, 200);
        assert_eq!(media.height, 150);
        assert_eq!(media.format, GraphicFormat::Png);
        assert_eq!(media.source, GraphicSource::Kitty);
        assert_eq!(media.payload, b"PNG_MOCK_DATA");
    }

    #[test]
    fn test_iterm2_graphics_parsing() {
        let payload = base64::engine::general_purpose::STANDARD.encode(b"ITERM2_DATA");
        let osc = format!("File=name=test.png;width=300px;height=200px;inline=1:{}", payload);

        let media = ITerm2GraphicsParser::parse(&osc).unwrap();
        assert_eq!(media.width, 300);
        assert_eq!(media.height, 200);
        assert_eq!(media.source, GraphicSource::ITerm2);
        assert_eq!(media.payload, b"ITERM2_DATA");
    }

    #[test]
    fn test_sixel_decoder_basic() {
        // Sixel stream drawing a few dots
        let sixel_data = b"#0;2;100;100;100#0~-~";
        let media = SixelDecoder::decode(sixel_data).unwrap();
        assert!(media.width > 0);
        assert!(media.height > 0);
        assert_eq!(media.format, GraphicFormat::Sixel);
    }

    #[test]
    fn test_fallback_rendering() {
        let media = GraphicMedia {
            id: 7,
            placement_id: None,
            z_index: 0,
            width: 800,
            height: 600,
            format: GraphicFormat::Png,
            source: GraphicSource::Kitty,
            payload: Vec::new(),
        };

        let fallback = media.render_fallback(40, 6);
        assert!(fallback.contains("Image #7 (800x600, Png)"));
        assert!(fallback.contains('┌'));
        assert!(fallback.contains('└'));
    }
}
