//! Styled underlines and RGB underline colors according to modern VT specs.
//!
//! Supports SGR `4:0` (none), `4:1` (straight), `4:2` (double), `4:3` (curly/wavy),
//! `4:4` (dotted), and `4:5` (dashed), plus SGR `58;2;r;g;b` (RGB underline color)
//! and `59` (reset underline color).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum UnderlineStyle {
    #[default]
    None = 0,
    Straight = 1,
    Double = 2,
    Curly = 3,
    Dotted = 4,
    Dashed = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum UnderlineColor {
    #[default]
    Default,
    Rgb(u8, u8, u8),
}

/// SGR Underline state for a terminal cell or text run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StyledUnderline {
    pub style: UnderlineStyle,
    pub color: UnderlineColor,
}

impl StyledUnderline {
    pub fn new(style: UnderlineStyle, color: UnderlineColor) -> Self {
        Self { style, color }
    }

    /// Parse an SGR parameter sequence for underline styling or coloring.
    pub fn parse_sgr_sequence(params: &[u16]) -> Option<Self> {
        let mut style = None;
        let mut color = None;

        let mut i = 0;
        while i < params.len() {
            match params[i] {
                4 => {
                    // Check if subparameter follows: e.g. 4;1 or next parameter
                    if i + 1 < params.len() && params[i + 1] <= 5 {
                        style = Some(match params[i + 1] {
                            0 => UnderlineStyle::None,
                            1 => UnderlineStyle::Straight,
                            2 => UnderlineStyle::Double,
                            3 => UnderlineStyle::Curly,
                            4 => UnderlineStyle::Dotted,
                            5 => UnderlineStyle::Dashed,
                            _ => UnderlineStyle::Straight,
                        });
                        i += 1;
                    } else {
                        style = Some(UnderlineStyle::Straight);
                    }
                }
                24 => {
                    style = Some(UnderlineStyle::None);
                }
                58 => {
                    // SGR 58;2;r;g;b (or 58:2::r:g:b)
                    if i + 4 < params.len() && params[i + 1] == 2 {
                        let r = (params[i + 2] & 0xFF) as u8;
                        let g = (params[i + 3] & 0xFF) as u8;
                        let b = (params[i + 4] & 0xFF) as u8;
                        color = Some(UnderlineColor::Rgb(r, g, b));
                        i += 4;
                    }
                }
                59 => {
                    // SGR 59: Reset underline color
                    color = Some(UnderlineColor::Default);
                }
                _ => {}
            }
            i += 1;
        }

        if style.is_some() || color.is_some() {
            Some(Self {
                style: style.unwrap_or_default(),
                color: color.unwrap_or_default(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_underline_styles() {
        assert_eq!(
            StyledUnderline::parse_sgr_sequence(&[4, 3]).unwrap().style,
            UnderlineStyle::Curly
        );
        assert_eq!(
            StyledUnderline::parse_sgr_sequence(&[4, 4]).unwrap().style,
            UnderlineStyle::Dotted
        );
        assert_eq!(
            StyledUnderline::parse_sgr_sequence(&[4, 5]).unwrap().style,
            UnderlineStyle::Dashed
        );
        assert_eq!(
            StyledUnderline::parse_sgr_sequence(&[4, 2]).unwrap().style,
            UnderlineStyle::Double
        );
        assert_eq!(
            StyledUnderline::parse_sgr_sequence(&[24]).unwrap().style,
            UnderlineStyle::None
        );
    }

    #[test]
    fn test_underline_rgb_colors() {
        let parsed = StyledUnderline::parse_sgr_sequence(&[4, 3, 58, 2, 255, 0, 128]).unwrap();
        assert_eq!(parsed.style, UnderlineStyle::Curly);
        assert_eq!(parsed.color, UnderlineColor::Rgb(255, 0, 128));

        let reset = StyledUnderline::parse_sgr_sequence(&[59]).unwrap();
        assert_eq!(reset.color, UnderlineColor::Default);
    }
}
