//! Key chords, named actions and conflict detection.
//!
//! Keybindings name *actions*, never implementation details. The same action
//! is reachable from the command palette, so a missing binding never removes
//! functionality.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// A normalized key chord.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyChord {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    /// Lower-case key name: `a`..`z`, `0`..`9`, `f1`..`f12`, `space`, ...
    pub key: String,
}

impl KeyChord {
    pub fn parse(input: &str) -> Result<Self, String> {
        let raw = input.trim().to_ascii_lowercase();
        if raw.is_empty() {
            return Err("empty key chord".into());
        }
        let mut chord = KeyChord {
            ctrl: false,
            alt: false,
            shift: false,
            key: String::new(),
        };
        let parts: Vec<&str> = raw.split('+').collect();
        for (index, part) in parts.iter().enumerate() {
            let part: &str = part.trim();
            if part.is_empty() {
                return Err(format!("empty component in key chord `{input}`"));
            }
            match part {
                "ctrl" | "control" => chord.ctrl = true,
                "alt" | "option" | "meta" => chord.alt = true,
                "shift" => chord.shift = true,
                _ => {
                    if index + 1 != parts.len() {
                        return Err(format!("unknown modifier `{part}` in key chord `{input}`"));
                    }
                    if !chord.key.is_empty() {
                        return Err(format!("multiple keys in key chord `{input}`"));
                    }
                    chord.key = normalize_key(part)?;
                }
            }
        }
        if chord.key.is_empty() {
            return Err(format!("`{input}` has modifiers but no key"));
        }
        if chord.ctrl
            && chord.shift
            && chord.key.len() == 1
            && chord.key.as_bytes()[0].is_ascii_alphabetic()
        {
            // Terminals generally cannot distinguish Ctrl+Shift+<letter> from
            // Ctrl+<letter>. Reject instead of shipping a binding that only
            // works in some terminals.
            return Err(format!(
                "`{input}` is not portable: terminals cannot distinguish Ctrl+Shift+<letter>"
            ));
        }
        Ok(chord)
    }

    pub fn to_string_normalized(&self) -> String {
        let mut out = String::new();
        if self.ctrl {
            out.push_str("ctrl+");
        }
        if self.alt {
            out.push_str("alt+");
        }
        if self.shift {
            out.push_str("shift+");
        }
        out.push_str(&self.key);
        out
    }
}

impl fmt::Display for KeyChord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_normalized())
    }
}

fn normalize_key(key: &str) -> Result<String, String> {
    let key = match key {
        "return" | "enter" => "enter",
        "escape" | "esc" => "esc",
        "pageup" | "pgup" => "pgup",
        "pagedown" | "pgdn" => "pgdn",
        "backspace" | "bs" => "backspace",
        "delete" | "del" => "delete",
        "insert" | "ins" => "insert",
        "space" | "spacebar" => "space",
        "arrowup" | "up" => "up",
        "arrowdown" | "down" => "down",
        "arrowleft" | "left" => "left",
        "arrowright" | "right" => "right",
        "home" => "home",
        "end" => "end",
        "tab" => "tab",
        other => other,
    };
    let valid = key.len() == 1
        || (key.starts_with('f')
            && key[1..]
                .parse::<u8>()
                .map(|n| (1..=24).contains(&n))
                .unwrap_or(false))
        || matches!(
            key,
            "enter"
                | "esc"
                | "space"
                | "tab"
                | "backspace"
                | "delete"
                | "insert"
                | "up"
                | "down"
                | "left"
                | "right"
                | "home"
                | "end"
                | "pgup"
                | "pgdn"
        );
    if !valid {
        return Err(format!("unknown key `{key}`"));
    }
    Ok(key.to_string())
}

/// A named action, optionally with an argument (`tab.select:1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionBinding {
    pub action: String,
    pub arg: Option<String>,
}

impl ActionBinding {
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("empty action".into());
        }
        let (action, arg) = match input.split_once(':') {
            Some((action, arg)) => (action.trim(), Some(arg.trim().to_string())),
            None => (input, None),
        };
        if !action
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        {
            return Err(format!("invalid action name `{action}`"));
        }
        let spec = action_spec(action)
            .ok_or_else(|| format!("unknown action `{action}` (see `z config actions`)"))?;
        if !spec.takes_arg && arg.is_some() {
            return Err(format!("action `{action}` does not take an argument"));
        }
        Ok(Self {
            action: action.to_string(),
            arg: arg.filter(|a| !a.is_empty()),
        })
    }
}

impl fmt::Display for ActionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.arg {
            Some(arg) => write!(f, "{}:{arg}", self.action),
            None => f.write_str(&self.action),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActionSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub takes_arg: bool,
}

macro_rules! actions {
    ($(($name:literal, $desc:literal, $category:literal, $arg:literal)),* $(,)?) => {
        pub const ACTIONS: &[ActionSpec] = &[
            $(ActionSpec { name: $name, description: $desc, category: $category, takes_arg: $arg }),*
        ];
    };
}

actions![
    ("palette.open", "Open the command palette", "app", false),
    ("app.quit", "Quit Zentrion", "app", false),
    ("app.help", "Open help", "app", false),
    ("editor.toggle", "Toggle the editor pane", "editor", false),
    ("copilot.toggle", "Toggle the agent panel", "agent", false),
    ("sysmon.toggle", "Toggle the system monitor", "view", false),
    ("chat.toggle", "Toggle LAN chat", "view", false),
    ("search.open", "Search the active pane", "search", false),
    ("search.all", "Search all tabs", "search", false),
    ("copy_mode.toggle", "Toggle vi copy mode", "copy", false),
    ("tab.new", "Create a tab", "tab", false),
    ("tab.close", "Close the active tab", "tab", false),
    ("tab.next", "Next tab", "tab", false),
    ("tab.prev", "Previous tab", "tab", false),
    ("tab.select", "Select tab by number", "tab", true),
    ("pane.split", "Split the active pane", "pane", false),
    ("pane.close", "Close the active pane", "pane", false),
    ("pane.next", "Focus the next pane", "pane", false),
    ("blocks.toggle", "Toggle the block list", "blocks", false),
    ("blocks.rerun", "Re-run the selected block", "blocks", false),
    ("blocks.share", "Share the selected block", "blocks", false),
    (
        "blocks.pin",
        "Pin the selected block to agent context",
        "blocks",
        false
    ),
    (
        "agents.dashboard",
        "Open the agent dashboard",
        "agent",
        false
    ),
    (
        "agents.approve",
        "Approve the focused request",
        "agent",
        false
    ),
    ("agents.deny", "Deny the focused request", "agent", false),
    (
        "workspace.save",
        "Save the current workspace",
        "workspace",
        false
    ),
    ("workspace.open", "Open a workspace", "workspace", false),
    ("session.attach", "Attach to a session", "session", false),
    ("home.open", "Open the home dashboard", "app", false),
    ("dashboard.open", "Open the dashboard", "app", false),
    ("notification.dnd", "Toggle do-not-disturb", "app", false),
    ("font.increase", "Increase font size", "ui", false),
    ("font.decrease", "Decrease font size", "ui", false),
    ("leader", "Leader key prefix", "app", false),
    ("workflow.run", "Run a workflow", "workflow", false),
    (
        "security.engagement",
        "Open the security workbench",
        "security",
        false
    ),
];

pub fn action_spec(name: &str) -> Option<&'static ActionSpec> {
    ACTIONS.iter().find(|spec| spec.name == name)
}

/// Parsed, validated keymap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keymap {
    bindings: BTreeMap<KeyChord, ActionBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeymapIssue {
    pub path: String,
    pub message: String,
}

impl Keymap {
    pub fn from_table(table: &BTreeMap<String, String>) -> (Self, Vec<KeymapIssue>) {
        let mut bindings: BTreeMap<KeyChord, ActionBinding> = BTreeMap::new();
        let mut issues = Vec::new();
        for (chord, action) in table {
            let parsed_chord = match KeyChord::parse(chord) {
                Ok(chord) => chord,
                Err(message) => {
                    issues.push(KeymapIssue {
                        path: format!("keybindings.{chord}"),
                        message,
                    });
                    continue;
                }
            };
            let parsed_action = match ActionBinding::parse(action) {
                Ok(action) => action,
                Err(message) => {
                    issues.push(KeymapIssue {
                        path: format!("keybindings.{chord}"),
                        message,
                    });
                    continue;
                }
            };
            if let Some(previous) = bindings.get(&parsed_chord) {
                issues.push(KeymapIssue {
                    path: format!("keybindings.{chord}"),
                    message: format!(
                        "`{chord}` is bound twice: `{previous}` and `{parsed_action}`"
                    ),
                });
                continue;
            }
            bindings.insert(parsed_chord, parsed_action);
        }
        (Self { bindings }, issues)
    }

    pub fn bindings(&self) -> &BTreeMap<KeyChord, ActionBinding> {
        &self.bindings
    }

    pub fn resolve(&self, chord: &KeyChord) -> Option<&ActionBinding> {
        self.bindings.get(chord)
    }

    pub fn binding_for(&self, action: &str) -> Option<(&KeyChord, &ActionBinding)> {
        self.bindings
            .iter()
            .find(|(_, binding)| binding.action == action)
    }
}

/// The built-in keymap. Every action is rebindable.
pub fn default_keybindings() -> BTreeMap<String, String> {
    [
        ("f2", "palette.open"),
        ("f3", "editor.toggle"),
        ("f4", "copilot.toggle"),
        ("f5", "sysmon.toggle"),
        ("f6", "chat.toggle"),
        ("f7", "tab.new"),
        ("f8", "pane.split"),
        ("f9", "pane.close"),
        ("f10", "app.quit"),
        ("f11", "search.open"),
        ("f12", "copy_mode.toggle"),
        ("alt+1", "tab.select:1"),
        ("alt+2", "tab.select:2"),
        ("alt+3", "tab.select:3"),
        ("alt+4", "tab.select:4"),
        ("alt+5", "tab.select:5"),
        ("alt+6", "tab.select:6"),
        ("alt+7", "tab.select:7"),
        ("alt+8", "tab.select:8"),
        ("alt+9", "tab.select:9"),
        ("alt+left", "tab.prev"),
        ("alt+right", "tab.next"),
        ("alt+o", "pane.next"),
        ("alt+v", "agents.dashboard"),
        ("alt+h", "home.open"),
        ("ctrl+space", "leader"),
    ]
    .into_iter()
    .map(|(chord, action)| (chord.to_string(), action.to_string()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_unique() {
        let (keymap, issues) = Keymap::from_table(&default_keybindings());
        assert!(issues.is_empty(), "{issues:?}");
        assert!(keymap.bindings().len() >= 20);
        assert_eq!(
            keymap
                .binding_for("palette.open")
                .map(|(chord, _)| chord.to_string()),
            Some("f2".to_string())
        );
    }

    #[test]
    fn chords_normalize() {
        let chord = KeyChord::parse("Ctrl + Shift + PgUp").unwrap();
        assert!(chord.ctrl && chord.shift);
        assert_eq!(chord.key, "pgup");
        assert_eq!(chord.to_string(), "ctrl+shift+pgup");
        assert_eq!(KeyChord::parse("Alt+1").unwrap().to_string(), "alt+1");
    }

    #[test]
    fn ambiguous_ctrl_shift_letter_is_rejected() {
        assert!(KeyChord::parse("ctrl+shift+t").is_err());
        assert!(KeyChord::parse("ctrl+shift+pgup").is_ok());
    }

    #[test]
    fn unknown_action_is_rejected() {
        let err = ActionBinding::parse("does.not.exist").unwrap_err();
        assert!(err.contains("unknown action"));
        assert!(ActionBinding::parse("tab.select:2").is_ok());
        assert!(ActionBinding::parse("app.quit:now").is_err());
    }

    #[test]
    fn conflict_is_reported_not_silently_overwritten() {
        let mut table = BTreeMap::new();
        table.insert("ctrl+a".to_string(), "search.open".to_string());
        table.insert("ctrl+A".to_string(), "copy_mode.toggle".to_string());
        let (_, issues) = Keymap::from_table(&table);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("bound twice"));
    }
}
