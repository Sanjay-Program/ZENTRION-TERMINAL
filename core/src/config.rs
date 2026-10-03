//! Layered configuration (04-CORE-RUNTIME §Configuration).
//!
//! Precedence (lowest → highest):
//! built-in defaults → user config → project config → env (ZENTRION_*) → CLI flags.
//! Secrets are never stored in config files (24-SECRETS).

use crate::error::{Area, ZenError, ZenResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Runtime configuration values. Strict parsing: unknown keys are an error
/// (mirrors the policy philosophy — typos must not silently disable settings).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Log level: trace|debug|info|warn|error
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Telemetry is opt-in and OFF by default (32-PRIVACY).
    #[serde(default = "default_telemetry")]
    pub telemetry_enabled: bool,
    #[serde(default)]
    pub default_project: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_telemetry() -> bool {
    false
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            telemetry_enabled: default_telemetry(),
            default_project: None,
        }
    }
}

impl Config {
    /// Parse with strict unknown-key rejection.
    pub fn parse_yaml(text: &str) -> ZenResult<Self> {
        serde_yaml::from_str(text).map_err(|e| {
            ZenError::new(Area::Cfg, 10, format!("invalid configuration: {e}"))
                .with_remediation("Fix the YAML or remove the file to reset to defaults.")
        })
    }

    /// Merge `other` on top of `self` (higher layer wins for set values).
    pub fn merge(&mut self, other: Config) {
        self.log_level = other.log_level;
        self.telemetry_enabled = other.telemetry_enabled || self.telemetry_enabled;
        if other.default_project.is_some() {
            self.default_project = other.default_project;
        }
    }

    /// Apply ZENTRION_* environment overrides.
    pub fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("ZENTRION_LOG_LEVEL") {
            self.log_level = v;
        }
        if let Ok(v) = std::env::var("ZENTRION_TELEMETRY") {
            // Only explicit true/1 enables telemetry; anything else stays off.
            self.telemetry_enabled = v == "true" || v == "1";
        }
    }

    /// Load a config layer. Missing file is not an error; corrupt file IS
    /// an error (fail-closed: never silently fall back to defaults).
    pub fn load_layer(path: &Path) -> ZenResult<Option<Config>> {
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(path).map_err(|e| {
            ZenError::new(
                Area::Cfg,
                11,
                format!("cannot read config {}: {e}", path.display()),
            )
            .with_remediation("Check file permissions or remove the file to reset to defaults.")
        })?;
        Ok(Some(Config::parse_yaml(&text)?))
    }
}

/// Resolve home directory without hard-coding paths (Phase 1 §15).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Platform-appropriate user configuration directory (11-CROSS-PLATFORM).
pub fn user_config_dir() -> Option<PathBuf> {
    if let Ok(x) = std::env::var("ZENTRION_CONFIG_DIR") {
        if !x.is_empty() {
            return Some(PathBuf::from(x));
        }
    }
    if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .ok()
            .map(|d| PathBuf::from(d).join("Zentrion"))
    } else if cfg!(target_os = "macos") {
        home_dir().map(|h| h.join("Library/Application Support/Zentrion"))
    } else {
        match std::env::var("XDG_CONFIG_HOME") {
            Ok(x) if !x.is_empty() => Some(PathBuf::from(x).join("zentrion")),
            _ => home_dir().map(|h| h.join(".config/zentrion")),
        }
    }
}

/// Platform-appropriate user data directory (audit log lives here).
pub fn user_data_dir() -> Option<PathBuf> {
    if let Ok(x) = std::env::var("ZENTRION_DATA_DIR") {
        if !x.is_empty() {
            return Some(PathBuf::from(x));
        }
    }
    if cfg!(target_os = "windows") {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|d| PathBuf::from(d).join("Zentrion"))
    } else if cfg!(target_os = "macos") {
        home_dir().map(|h| h.join("Library/Application Support/Zentrion"))
    } else {
        match std::env::var("XDG_DATA_HOME") {
            Ok(x) if !x.is_empty() => Some(PathBuf::from(x).join("zentrion")),
            _ => home_dir().map(|h| h.join(".local/share/zentrion")),
        }
    }
}

pub fn cache_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|d| PathBuf::from(d).join("Zentrion/Cache"))
    } else if cfg!(target_os = "macos") {
        home_dir().map(|h| h.join("Library/Caches/Zentrion"))
    } else {
        match std::env::var("XDG_CACHE_HOME") {
            Ok(x) if !x.is_empty() => Some(PathBuf::from(x).join("zentrion")),
            _ => home_dir().map(|h| h.join(".cache/zentrion")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_secure() {
        let c = Config::default();
        assert!(!c.telemetry_enabled, "telemetry must be off by default");
        assert_eq!(c.log_level, "info");
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(Config::parse_yaml("log_level: info\nsecret_sauce: yes\n").is_err());
    }

    #[test]
    fn valid_config_parses() {
        let c = Config::parse_yaml("log_level: debug\ntelemetry_enabled: false\n").unwrap();
        assert_eq!(c.log_level, "debug");
    }

    #[test]
    fn corrupt_config_is_error_not_fallback() {
        assert!(Config::parse_yaml("log_level: [unclosed").is_err());
    }

    #[test]
    fn missing_layer_is_not_error() {
        let p = std::env::temp_dir().join("zen-nonexistent-config-xyz.yaml");
        let _ = std::fs::remove_file(&p);
        assert!(Config::load_layer(&p).unwrap().is_none());
    }

    #[test]
    fn corrupt_layer_is_error() {
        let p = std::env::temp_dir().join(format!("zen-bad-config-{}.yaml", std::process::id()));
        std::fs::write(&p, "log_level: {{{{").unwrap();
        assert!(Config::load_layer(&p).is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn merge_higher_layer_wins() {
        let mut base = Config::default();
        let higher = Config {
            log_level: "warn".into(),
            telemetry_enabled: false,
            default_project: None,
        };
        base.merge(higher);
        assert_eq!(base.log_level, "warn");
    }

    #[test]
    fn telemetry_cannot_be_enabled_by_junk_env() {
        std::env::set_var("ZENTRION_TELEMETRY", "maybe");
        let mut c = Config::default();
        c.apply_env();
        assert!(!c.telemetry_enabled);
        std::env::remove_var("ZENTRION_TELEMETRY");
    }
}
