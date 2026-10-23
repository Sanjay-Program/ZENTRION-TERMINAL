//! Kitty Keyboard Protocol implementation.
//!
//! Implements progressive enhancement flags, key event type reporting (press,
//! repeat, release), modifier encoding, and query/response handling according
//! to the Kitty keyboard protocol specification:
//! <https://sw.kovidgoyal.net/kitty/keyboard-protocol/>

use serde::{Deserialize, Serialize};

/// Progressive enhancement flags.
pub mod flags {
    pub const DISAMBIGUATE_ESCAPE_CODES: u8 = 1;
    pub const REPORT_EVENT_TYPES: u8 = 2;
    pub const REPORT_ALTERNATE_KEYS: u8 = 4;
    pub const REPORT_ALL_KEYS_AS_ESCAPE_CODES: u8 = 8;
    pub const REPORT_ASSOCIATED_TEXT: u8 = 16;
}

/// Key event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyEventType {
    Press = 1,
    Repeat = 2,
    Release = 3,
}

impl Default for KeyEventType {
    fn default() -> Self {
        KeyEventType::Press
    }
}

/// Keyboard modifiers bitmask.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyModifiers {
    pub shift: bool,
    pub alt: bool,
    pub ctrl: bool,
    pub super_key: bool,
    pub hyper: bool,
    pub meta: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
}

impl KeyModifiers {
    /// Convert to Kitty protocol modifier number (`1 + bitmask`).
    pub fn to_kitty_val(&self) -> u32 {
        let mut bits = 0;
        if self.shift {
            bits |= 1;
        }
        if self.alt {
            bits |= 2;
        }
        if self.ctrl {
            bits |= 4;
        }
        if self.super_key {
            bits |= 8;
        }
        if self.hyper {
            bits |= 16;
        }
        if self.meta {
            bits |= 32;
        }
        if self.caps_lock {
            bits |= 64;
        }
        if self.num_lock {
            bits |= 128;
        }
        1 + bits
    }

    /// Parse from Kitty protocol modifier number (`1 + bitmask`).
    pub fn from_kitty_val(val: u32) -> Self {
        let bits = val.saturating_sub(1);
        Self {
            shift: (bits & 1) != 0,
            alt: (bits & 2) != 0,
            ctrl: (bits & 4) != 0,
            super_key: (bits & 8) != 0,
            hyper: (bits & 16) != 0,
            meta: (bits & 32) != 0,
            caps_lock: (bits & 64) != 0,
            num_lock: (bits & 128) != 0,
        }
    }
}

/// A parsed or constructed Kitty key event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KittyKeyEvent {
    pub key_code: u32,
    pub shifted_key: Option<u32>,
    pub base_key: Option<u32>,
    pub modifiers: KeyModifiers,
    pub event_type: KeyEventType,
    pub text: Option<String>,
}

impl KittyKeyEvent {
    pub fn new(key_code: u32) -> Self {
        Self {
            key_code,
            shifted_key: None,
            base_key: None,
            modifiers: KeyModifiers::default(),
            event_type: KeyEventType::Press,
            text: None,
        }
    }

    pub fn with_modifiers(mut self, modifiers: KeyModifiers) -> Self {
        self.modifiers = modifiers;
        self
    }

    pub fn with_event_type(mut self, event_type: KeyEventType) -> Self {
        self.event_type = event_type;
        self
    }

    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// Encode this key event as a Kitty escape sequence (e.g. `\x1b[97;1u`).
    pub fn encode(&self) -> String {
        let mut key_part = self.key_code.to_string();
        if let Some(shifted) = self.shifted_key {
            key_part.push(':');
            key_part.push_str(&shifted.to_string());
            if let Some(base) = self.base_key {
                key_part.push(':');
                key_part.push_str(&base.to_string());
            }
        }

        let mod_val = self.modifiers.to_kitty_val();
        let event_num = self.event_type as u32;

        let mod_part = if event_num != 1 {
            format!("{mod_val}:{event_num}")
        } else if mod_val != 1 {
            format!("{mod_val}")
        } else {
            String::new()
        };

        if let Some(ref txt) = self.text {
            let encoded_text = txt
                .chars()
                .map(|c| (c as u32).to_string())
                .collect::<Vec<_>>()
                .join(":");
            if mod_part.is_empty() {
                format!("\x1b[{key_part};1;{encoded_text}u")
            } else {
                format!("\x1b[{key_part};{mod_part};{encoded_text}u")
            }
        } else if mod_part.is_empty() {
            format!("\x1b[{key_part}u")
        } else {
            format!("\x1b[{key_part};{mod_part}u")
        }
    }

    /// Parse a Kitty escape sequence (`\x1b[...u`).
    pub fn decode(seq: &str) -> Option<Self> {
        let content = seq.strip_prefix("\x1b[")?.strip_suffix('u')?;
        let parts: Vec<&str> = content.split(';').collect();

        if parts.is_empty() {
            return None;
        }

        let key_subparts: Vec<&str> = parts[0].split(':').collect();
        let key_code: u32 = key_subparts.first()?.parse().ok()?;
        let shifted_key: Option<u32> = key_subparts.get(1).and_then(|s| s.parse().ok());
        let base_key: Option<u32> = key_subparts.get(2).and_then(|s| s.parse().ok());

        let mut modifiers = KeyModifiers::default();
        let mut event_type = KeyEventType::Press;

        if let Some(mod_str) = parts.get(1) {
            let mod_subparts: Vec<&str> = mod_str.split(':').collect();
            if let Some(m) = mod_subparts.first().and_then(|s| s.parse::<u32>().ok()) {
                modifiers = KeyModifiers::from_kitty_val(m);
            }
            if let Some(e) = mod_subparts.get(1).and_then(|s| s.parse::<u8>().ok()) {
                event_type = match e {
                    1 => KeyEventType::Press,
                    2 => KeyEventType::Repeat,
                    3 => KeyEventType::Release,
                    _ => KeyEventType::Press,
                };
            }
        }

        let mut text = None;
        if let Some(txt_str) = parts.get(2) {
            let chars: Result<String, _> = txt_str
                .split(':')
                .filter_map(|s| s.parse::<u32>().ok())
                .map(|cp| char::from_u32(cp).ok_or(()))
                .collect();
            if let Ok(t) = chars {
                if !t.is_empty() {
                    text = Some(t);
                }
            }
        }

        Some(Self {
            key_code,
            shifted_key,
            base_key,
            modifiers,
            event_type,
            text,
        })
    }
}

/// State tracker for Kitty keyboard protocol flags in a terminal session.
#[derive(Debug, Default, Clone)]
pub struct KittyKeyboardState {
    flags: u8,
    stack: Vec<u8>,
}

impl KittyKeyboardState {
    pub fn new() -> Self {
        Self {
            flags: 0,
            stack: Vec::new(),
        }
    }

    pub fn current_flags(&self) -> u8 {
        self.flags
    }

    /// Check if a specific enhancement flag is active.
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }

    /// Handle `CSI = <flags> ; <mode> u` command.
    pub fn set_flags(&mut self, flags: u8, mode: u8) {
        match mode {
            1 => self.flags = flags,
            2 => self.flags |= flags,
            3 => self.flags &= !flags,
            _ => self.flags = flags,
        }
    }

    /// Handle `CSI > <flags> u` command (push flags onto stack).
    pub fn push_flags(&mut self, new_flags: u8) {
        self.stack.push(self.flags);
        self.flags = new_flags;
    }

    /// Handle `CSI < <n> u` command (pop `n` flags from stack).
    pub fn pop_flags(&mut self, n: usize) {
        for _ in 0..n {
            if let Some(prev) = self.stack.pop() {
                self.flags = prev;
            } else {
                self.flags = 0;
                break;
            }
        }
    }

    /// Generate terminal response to query `CSI ? u`.
    pub fn query_response(&self) -> String {
        format!("\x1b[?{}u", self.flags)
    }

    /// Process control sequences that manipulate the Kitty keyboard state.
    pub fn handle_csi(&mut self, params: &str) -> Option<String> {
        if params == "?u" || params == "u" {
            return Some(self.query_response());
        }

        if let Some(rest) = params.strip_prefix('=') {
            if let Some(body) = rest.strip_suffix('u') {
                let parts: Vec<&str> = body.split(';').collect();
                let flags: u8 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                let mode: u8 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
                self.set_flags(flags, mode);
            }
        } else if let Some(rest) = params.strip_prefix('>') {
            if let Some(body) = rest.strip_suffix('u') {
                let flags: u8 = body.parse().ok().unwrap_or(0);
                self.push_flags(flags);
            }
        } else if let Some(rest) = params.strip_prefix('<') {
            if let Some(body) = rest.strip_suffix('u') {
                let n: usize = body.parse().ok().unwrap_or(1);
                self.pop_flags(n);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kitty_event_round_trip() {
        let event = KittyKeyEvent::new('a' as u32)
            .with_modifiers(KeyModifiers {
                ctrl: true,
                shift: true,
                ..Default::default()
            })
            .with_event_type(KeyEventType::Release);

        let encoded = event.encode();
        assert_eq!(encoded, "\x1b[97;6:3u");

        let decoded = KittyKeyEvent::decode(&encoded).unwrap();
        assert_eq!(decoded.key_code, 'a' as u32);
        assert!(decoded.modifiers.ctrl);
        assert!(decoded.modifiers.shift);
        assert!(!decoded.modifiers.alt);
        assert_eq!(decoded.event_type, KeyEventType::Release);
    }

    #[test]
    fn test_simple_key_press_encoding() {
        let event = KittyKeyEvent::new(13); // Enter key
        let encoded = event.encode();
        assert_eq!(encoded, "\x1b[13u");

        let decoded = KittyKeyEvent::decode(&encoded).unwrap();
        assert_eq!(decoded.key_code, 13);
        assert_eq!(decoded.event_type, KeyEventType::Press);
    }

    #[test]
    fn test_kitty_state_push_pop_and_query() {
        let mut state = KittyKeyboardState::new();
        assert_eq!(state.query_response(), "\x1b[?0u");

        state.handle_csi("=3;1u"); // set flags to 3 (modes 1 & 2)
        assert_eq!(state.current_flags(), 3);
        assert!(state.has_flag(flags::DISAMBIGUATE_ESCAPE_CODES));
        assert!(state.has_flag(flags::REPORT_EVENT_TYPES));

        state.handle_csi(">7u"); // push and set to 7
        assert_eq!(state.current_flags(), 7);

        state.handle_csi("<1u"); // pop 1
        assert_eq!(state.current_flags(), 3);
    }
}
