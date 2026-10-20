//! Configuration importers.
//!
//! Importers read a foreign configuration and return a *candidate* Zentrion
//! config plus a report of what was applied, skipped or unsupported. They never
//! write files, never overwrite the user's config and never invent settings.

use crate::keys::{ActionBinding, KeyChord};
use crate::schema::Config;
use regex::Regex;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportReport {
    pub source: String,
    pub format: String,
    pub applied: Vec<String>,
    pub skipped: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(skip)]
    pub config: Config,
}

impl ImportReport {
    fn new(source: &str, format: &str, config: Config) -> Self {
        Self {
            source: source.to_string(),
            format: format.to_string(),
            applied: Vec::new(),
            skipped: Vec::new(),
            warnings: Vec::new(),
            config,
        }
    }

    fn apply(&mut self, field: &str) {
        self.applied.push(field.to_string());
    }

    fn skip(&mut self, what: &str, why: &str) {
        self.skipped.push(format!("{what}: {why}"));
    }
}

pub fn safe_scheme(scheme: &str) -> bool {
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "mailto" | "file"
    )
}

pub fn secretish_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "api_key",
        "apikey",
        "private_key",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

/// Import a foreign config file. The format is selected by file name/content.
pub fn import_file(path: &Path, base: &Config) -> Result<ImportReport, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let source = path.display().to_string();
    if name.ends_with(".json") || text.trim_start().starts_with("// This file") {
        import_windows_terminal(&source, &text, base)
    } else if name.ends_with(".plist") || text.contains("<plist") {
        import_iterm2(&source, &text, base)
    } else if text.contains("[ui]") || text.contains("font_family") {
        import_zentrion(&source, &text, base)
    } else {
        import_ghostty(&source, &text, base)
    }
}

/// Import an existing Zentrion TOML config through the strict parser.
pub fn import_zentrion(source: &str, text: &str, _base: &Config) -> Result<ImportReport, String> {
    let parsed: Config = toml::from_str(text).map_err(|e| format!("{source}: {e}"))?;
    let mut report = ImportReport::new(source, "zentrion-toml", parsed);
    report.apply("ui, shell, input, blocks, agents, models, profiles, keybindings");
    Ok(report)
}

/// Windows Terminal `settings.json`.
pub fn import_windows_terminal(
    source: &str,
    text: &str,
    base: &Config,
) -> Result<ImportReport, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("{source}: invalid JSON: {e}"))?;
    let mut report = ImportReport::new(source, "windows-terminal", base.clone());

    if let Some(defaults) = value.pointer("/profiles/defaults") {
        if let Some(face) = defaults.pointer("/font/face").and_then(|v| v.as_str()) {
            report.config.ui.font_family = face.to_string();
            report.apply("ui.font_family");
        }
        if let Some(size) = defaults.pointer("/font/size").and_then(|v| v.as_f64()) {
            report.config.ui.font_size = size as f32;
            report.apply("ui.font_size");
        }
        if let Some(opacity) = defaults.get("opacity").and_then(|v| v.as_f64()) {
            report.config.ui.opacity = opacity as f32;
            report.apply("ui.opacity");
        }
        if let Some(cursor) = defaults.get("cursorShape").and_then(|v| v.as_str()) {
            report.config.ui.cursor_style = match cursor.to_ascii_lowercase().as_str() {
                "filledbox" | "vintage" => crate::CursorStyle::Block,
                "underscore" => crate::CursorStyle::Underline,
                _ => crate::CursorStyle::Bar,
            };
            report.apply("ui.cursor_style");
        }
        if defaults.get("colorScheme").is_some() {
            report.skip(
                "colorScheme",
                "Zentrion themes are not 1:1 with Windows Terminal schemes",
            );
        }
    }
    if let Some(scheme) = value.get("defaultProfile").and_then(|v| v.as_str()) {
        report.skip(
            &format!("defaultProfile {scheme}"),
            "profiles are not migrated automatically; create a [profiles] entry",
        );
    }

    if let Some(bindings) = value.get("keybindings").and_then(|v| v.as_array()) {
        for binding in bindings {
            let keys = binding.get("keys").and_then(|v| v.as_str());
            let command = binding.get("command").and_then(|v| {
                v.as_str()
                    .map(str::to_string)
                    .or_else(|| v.get("action").and_then(|a| a.as_str()).map(str::to_string))
            });
            let (Some(keys), Some(command)) = (keys, command) else {
                continue;
            };
            let action = match command.as_str() {
                "newTab" => Some("tab.new"),
                "closeTab" => Some("tab.close"),
                "nextTab" => Some("tab.next"),
                "prevTab" => Some("tab.prev"),
                "splitPane" => Some("pane.split"),
                "closePane" => Some("pane.close"),
                "commandPalette" => Some("palette.open"),
                "find" => Some("search.open"),
                "toggleFullscreen" => None,
                _ => None,
            };
            let Some(action) = action else {
                report.skip(
                    &format!("keybinding {keys} → {command}"),
                    "no equivalent named action",
                );
                continue;
            };
            if KeyChord::parse(keys).is_err() {
                report.skip(
                    &format!("keybinding {keys} → {command}"),
                    "not portable across terminal keyboard protocols",
                );
                continue;
            }
            if ActionBinding::parse(action).is_err() {
                report.skip(&format!("keybinding {keys}"), "invalid target action");
                continue;
            }
            report
                .config
                .keybindings
                .insert(keys.to_ascii_lowercase(), action.to_string());
            report.apply(&format!("keybindings.{keys}"));
        }
    }

    if report.config.ui.font_family == base.ui.font_family {
        report.warnings.push(
            "no font settings were imported; Windows Terminal may keep them in a per-profile table"
                .into(),
        );
    }
    Ok(report)
}

/// Ghostty `config` (key = value lines).
pub fn import_ghostty(source: &str, text: &str, base: &Config) -> Result<ImportReport, String> {
    let mut report = ImportReport::new(source, "ghostty", base.clone());
    for (index, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            report.skip(
                &format!("line {}", index + 1),
                "not a key = value directive",
            );
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "font-family" => {
                report.config.ui.font_family = value.to_string();
                report.apply("ui.font_family");
            }
            "font-size" => match value.parse::<f32>() {
                Ok(size) if (6.0..=48.0).contains(&size) => {
                    report.config.ui.font_size = size;
                    report.apply("ui.font_size");
                }
                _ => report.skip("font-size", "not a valid point size"),
            },
            "background-opacity" => match value.parse::<f32>() {
                Ok(opacity) if (0.05..=1.0).contains(&opacity) => {
                    report.config.ui.opacity = opacity;
                    report.apply("ui.opacity");
                }
                _ => report.skip("background-opacity", "not a valid opacity"),
            },
            "theme" => {
                if matches!(
                    value.to_ascii_lowercase().as_str(),
                    "dracula" | "nord" | "solarized" | "gruvbox" | "zentrion"
                ) {
                    report.config.ui.theme = value.to_ascii_lowercase();
                    report.apply("ui.theme");
                } else {
                    report.skip("theme", "theme has no Zentrion equivalent");
                }
            }
            "keybind" => {
                // `keybind = ctrl+t=new_tab:right`
                let Some((chord, action)) = value.split_once('=') else {
                    report.skip("keybind", "expected chord=action");
                    continue;
                };
                let action = match action.split(':').next().unwrap_or(action) {
                    "new_tab" => Some("tab.new"),
                    "close_surface" | "close_tab" => Some("tab.close"),
                    "new_split" => Some("pane.split"),
                    "close_pane" => Some("pane.close"),
                    "command_palette" => Some("palette.open"),
                    "search" => Some("search.open"),
                    "quit" => Some("app.quit"),
                    "toggle_command_palette" => Some("palette.open"),
                    _ => None,
                };
                let Some(action) = action else {
                    report.skip(&format!("keybind {chord}"), "no equivalent named action");
                    continue;
                };
                if KeyChord::parse(chord).is_err() {
                    report.skip(
                        &format!("keybind {chord}"),
                        "not portable across terminal keyboard protocols",
                    );
                    continue;
                }
                report
                    .config
                    .keybindings
                    .insert(chord.trim().to_ascii_lowercase(), action.to_string());
                report.apply(&format!("keybindings.{chord}"));
            }
            other => report.skip(other, "unsupported Ghostty directive"),
        }
    }
    Ok(report)
}

/// iTerm2 `.plist`. Only the legible, stable keys are imported: font, size and
/// opacity. Colors, profiles and keymaps are reported as unsupported.
pub fn import_iterm2(source: &str, text: &str, base: &Config) -> Result<ImportReport, String> {
    let mut report = ImportReport::new(source, "iterm2-plist", base.clone());
    let font_re =
        Regex::new(r"(?s)<key>Normal Font</key>\s*<string>([^<]+)</string>").expect("static regex");
    if let Some(captures) = font_re.captures(text) {
        let raw = captures[1].trim();
        // "JetBrainsMono-Regular 13"
        let (family, size) = match raw.rsplit_once(' ') {
            Some((family, size)) => (family, size.parse::<f32>().ok()),
            None => (raw, None),
        };
        let family = family
            .split('-')
            .next()
            .unwrap_or(family)
            .replace("NerdFont", "")
            .trim()
            .to_string();
        if !family.is_empty() {
            report.config.ui.font_family = family;
            report.apply("ui.font_family");
        }
        if let Some(size) = size.filter(|size| (6.0..=48.0).contains(size)) {
            report.config.ui.font_size = size;
            report.apply("ui.font_size");
        }
    } else {
        report.warnings.push("no Normal Font found in plist".into());
    }
    let opacity_re =
        Regex::new(r"(?s)<key>Blur</key>\s*<real>([0-9.]+)</real>").expect("static regex");
    if let Some(captures) = opacity_re.captures(text) {
        if let Ok(blur) = captures[1].parse::<f32>() {
            // iTerm2 blur is not opacity; do not pretend to convert it.
            report.skip(
                &format!("Blur {blur}"),
                "blur is not the same setting as background opacity",
            );
        }
    }
    for (key, why) in [
        ("keymap", "iTerm2 keymaps use a different action model"),
        (
            "Color Preset",
            "colors cannot be mapped to a Zentrion theme",
        ),
        (
            "Profiles",
            "profiles are not migrated; create [profiles] entries",
        ),
    ] {
        if text.contains(key) {
            report.skip(key, why);
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_terminal_imports_font_and_safe_bindings() {
        let text = r#"{
          "defaultProfile": "{guid}",
          "profiles": {"defaults": {"font": {"face": "Cascadia Code", "size": 12}, "opacity": 90}},
          "keybindings": [
            {"keys": "ctrl+shift+t", "command": "newTab"},
            {"keys": "alt+1", "command": "newTab"}
          ]
        }"#;
        let report = import_windows_terminal("settings.json", text, &Config::default()).unwrap();
        assert_eq!(report.config.ui.font_family, "Cascadia Code");
        assert_eq!(report.config.ui.font_size, 12.0);
        assert_eq!(
            report.config.keybindings.get("alt+1").map(String::as_str),
            Some("tab.new")
        );
        assert!(!report.config.keybindings.contains_key("ctrl+shift+t"));
        assert!(report.skipped.iter().any(|s| s.contains("not portable")));
    }

    #[test]
    fn ghostty_imports_known_keys_and_reports_unknown() {
        let text = "font-family = JetBrains Mono\nfont-size = 14\ntheme = Dracula\nkeybind = ctrl+t=new_tab\nwindow-padding-x = 4\n";
        let report = import_ghostty("ghostty", text, &Config::default()).unwrap();
        assert_eq!(report.config.ui.font_family, "JetBrains Mono");
        assert_eq!(report.config.ui.theme, "dracula");
        assert_eq!(report.config.keybindings["ctrl+t"], "tab.new");
        assert!(report
            .skipped
            .iter()
            .any(|s| s.contains("window-padding-x")));
    }

    #[test]
    fn iterm2_imports_font_without_pretending_colors() {
        let text = r#"<plist><dict>
          <key>Normal Font</key><string>JetBrainsMono-Regular 13</string>
          <key>Color Preset</key><string>Dracula</string>
        </dict></plist>"#;
        let report = import_iterm2("iterm.plist", text, &Config::default()).unwrap();
        assert_eq!(report.config.ui.font_family, "JetBrainsMono");
        assert_eq!(report.config.ui.font_size, 13.0);
        assert!(report.skipped.iter().any(|s| s.contains("Color Preset")));
    }

    #[test]
    fn secrets_are_not_valid_profile_env() {
        assert!(secretish_key("OPENAI_API_KEY"));
        assert!(!secretish_key("PATH"));
        let mut config = Config::default();
        config.profiles.insert(
            "dev".into(),
            crate::ProfileConfig {
                env: [("API_TOKEN".to_string(), "x".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        );
        assert!(config
            .validate()
            .iter()
            .any(|issue| issue.message.contains("secret")));
    }
}
