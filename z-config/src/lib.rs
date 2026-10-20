//! `z-config` — layered configuration, keybindings, profiles and importers.
//!
//! Precedence (lowest to highest):
//! built-in defaults → user `config.toml` → project `.zentrion/terminal.toml`
//! → `ZENTRION_*` environment → explicit CLI overrides.
//!
//! Parsing is strict: unknown keys, wrong types and invalid values fail with
//! the file and (where determinable) line number. A bad config never silently
//! falls back to defaults, because that is how safety settings disappear.

pub mod import;
pub mod keys;
pub mod layers;
pub mod schema;

pub use keys::{ActionBinding, ActionSpec, KeyChord, Keymap, KeymapIssue, ACTIONS};
pub use layers::{
    default_user_config_path, load, load_from_paths, write_user_config, LayerInfo, LoadOptions,
    LoadedConfig, Overrides,
};
pub use schema::{
    AgentsConfig, BlocksConfig, ComposerMode, Config, ContextConfig, CursorStyle, InputConfig,
    ModelRouting, ModelsConfig, ProfileConfig, ProviderConfig, RemoteConfig, RestorePolicy,
    SecurityConfig, SessionConfig, ShellConfig, ShellIntegration, SshBackend, TelemetryConfig,
    UiConfig, WorkflowConfig,
};

use serde::{Deserialize, Serialize};
use std::fmt;

/// A validation finding tied to a configuration path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigIssue {
    pub path: String,
    pub message: String,
    pub line: Option<usize>,
}

impl fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{} (line {line}): {}", self.path, self.message),
            None => write!(f, "{}: {}", self.path, self.message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigError {
    Io {
        path: String,
        message: String,
    },
    Syntax {
        path: String,
        line: Option<usize>,
        message: String,
    },
    Schema {
        path: String,
        line: Option<usize>,
        message: String,
    },
    Invalid(Vec<ConfigIssue>),
    Internal(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(f, "cannot read {path}: {message}"),
            Self::Syntax {
                path,
                line,
                message,
            } => match line {
                Some(line) => write!(f, "{path}:{line}: {message}"),
                None => write!(f, "{path}: {message}"),
            },
            Self::Schema {
                path,
                line,
                message,
            } => match line {
                Some(line) => write!(f, "{path}:{line}: {message}"),
                None => write!(f, "{path}: {message}"),
            },
            Self::Invalid(issues) => {
                write!(f, "invalid configuration:")?;
                for issue in issues {
                    write!(f, "\n  - {issue}")?;
                }
                Ok(())
            }
            Self::Internal(message) => write!(f, "configuration error: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Validate semantic constraints that serde cannot express.
    pub fn validate(&self) -> Vec<ConfigIssue> {
        let mut issues = Vec::new();
        let mut push = |path: &str, message: String| {
            issues.push(ConfigIssue {
                path: path.to_string(),
                message,
                line: None,
            })
        };

        if self.ui.font_family.trim().is_empty() {
            push("ui.font_family", "font family must not be empty".into());
        }
        if !(6.0..=48.0).contains(&self.ui.font_size) {
            push("ui.font_size", "must be between 6 and 48".into());
        }
        if !(0.05..=1.0).contains(&self.ui.opacity) {
            push("ui.opacity", "must be between 0.05 and 1.0".into());
        }
        if self.ui.scrollback_lines < 100 {
            push("ui.scrollback_lines", "must be at least 100".into());
        }
        if self.ui.scrollback_lines > 10_000_000 {
            push("ui.scrollback_lines", "must not exceed 10000000".into());
        }
        for scheme in &self.ui.hyperlink_schemes {
            if !crate::import::safe_scheme(scheme) {
                push(
                    "ui.hyperlink_schemes",
                    format!("scheme `{scheme}` is not safe to open (allowed: http, https, mailto, file)"),
                );
            }
        }
        if !self.remote.verify_host_keys
            && std::env::var("ZENTRION_ALLOW_INSECURE_HOST_KEYS").as_deref() != Ok("1")
        {
            push(
                "remote.verify_host_keys",
                "host-key verification cannot be disabled without ZENTRION_ALLOW_INSECURE_HOST_KEYS=1".into(),
            );
        }
        if self.blocks.retention_days > 3_650 {
            push("blocks.retention_days", "must not exceed 3650".into());
        }
        if self.blocks.max_output_bytes < 1024 {
            push("blocks.max_output_bytes", "must be at least 1024".into());
        }
        if !(1..=32).contains(&self.agents.max_parallel) {
            push("agents.max_parallel", "must be between 1 and 32".into());
        }
        if self.agents.tool_timeout_seconds == 0 || self.agents.tool_timeout_seconds > 86_400 {
            push(
                "agents.tool_timeout_seconds",
                "must be between 1 and 86400".into(),
            );
        }
        const AGENT_STATES: &[&str] = &[
            "starting",
            "running",
            "waiting_input",
            "waiting_approval",
            "completed",
            "failed",
        ];
        for state in &self.agents.notify_on {
            if !AGENT_STATES.contains(&state.as_str()) {
                push("agents.notify_on", format!("unknown agent state `{state}`"));
            }
        }
        if self.models.budget_usd_per_day < 0.0 || !self.models.budget_usd_per_day.is_finite() {
            push(
                "models.budget_usd_per_day",
                "must be a finite value >= 0".into(),
            );
        }
        if self.models.default.trim().is_empty() {
            push("models.default", "must name a provider/model".into());
        }
        if self.models.routing == ModelRouting::LocalOnly && self.models.allow_cloud {
            push(
                "models.allow_cloud",
                "local-only routing cannot allow cloud providers".into(),
            );
        }
        if self.models.budget_usd_per_day == 0.0
            && self.models.routing != ModelRouting::LocalOnly
            && !self.models.default.starts_with("local/")
        {
            push(
                "models.budget_usd_per_day",
                "a zero budget requires local-only routing or a local model".into(),
            );
        }
        for (id, provider) in &self.models.providers {
            if provider.kind.trim().is_empty() {
                push(
                    &format!("models.providers.{id}.kind"),
                    "provider kind must not be empty".into(),
                );
            }
            if provider.context < 1024 {
                push(
                    &format!("models.providers.{id}.context"),
                    "context window must be at least 1024".into(),
                );
            }
            if let Some(env) = &provider.api_key_env {
                let lower = env.to_ascii_lowercase();
                if lower.contains("sk-") || lower.contains('=') || lower.contains(' ') {
                    push(
                        &format!("models.providers.{id}.api_key_env"),
                        "must name an environment variable, not contain the key".into(),
                    );
                }
            }
        }
        if self.context.model_context_tokens < 1024 {
            push(
                "context.model_context_tokens",
                "must be at least 1024".into(),
            );
        }
        if self.context.max_file_bytes < 1024 {
            push("context.max_file_bytes", "must be at least 1024".into());
        }
        if self.session.scrollback_lines < 100 {
            push("session.scrollback_lines", "must be at least 100".into());
        }
        if self.remote.web_enabled {
            if !self.remote.web_bind.starts_with("127.")
                && !self.remote.web_bind.starts_with("localhost")
                && !self.remote.web_bind.starts_with("[::1]")
            {
                push(
                    "remote.web_bind",
                    "the web client binds to loopback unless explicitly overridden in the policy layer".into(),
                );
            }
        }
        if self.workflow.allow_http && self.workflow.http_allowlist.is_empty() {
            push(
                "workflow.http_allowlist",
                "allowing HTTP steps requires an explicit host allowlist".into(),
            );
        }
        for host in &self.workflow.http_allowlist {
            if host.contains('/') || host.contains(' ') || host.is_empty() {
                push(
                    "workflow.http_allowlist",
                    format!("`{host}` is not a hostname"),
                );
            }
        }
        const COMPLETION_SOURCES: &[&str] = &["history", "shell", "files", "git", "packages", "ai"];
        for source in &self.input.completions {
            if !COMPLETION_SOURCES.contains(&source.as_str()) {
                push(
                    "input.completions",
                    format!("unknown completion source `{source}`"),
                );
            }
        }
        if let Some(name) = &self.default_profile {
            if !self.profiles.contains_key(name) {
                push(
                    "default_profile",
                    format!("profile `{name}` is not defined"),
                );
            }
        }
        let mut profile_names: Vec<&String> = self.profiles.keys().collect();
        profile_names.sort();
        for name in profile_names {
            let profile = &self.profiles[name];
            if profile
                .font_size
                .map(|size| !(6.0..=48.0).contains(&size))
                .unwrap_or(false)
            {
                push(
                    &format!("profiles.{name}.font_size"),
                    "must be between 6 and 48".into(),
                );
            }
            for key in profile.env.keys() {
                if crate::import::secretish_key(key) {
                    push(
                        &format!("profiles.{name}.env.{key}"),
                        "configuration must not carry secret values".into(),
                    );
                }
            }
        }

        // Keymap validation is reported through the same issue list so a
        // single `z config validate` shows everything at once.
        let (_, keymap_issues) = Keymap::from_table(&self.keybindings);
        for issue in keymap_issues {
            issues.push(ConfigIssue {
                path: issue.path,
                message: issue.message,
                line: None,
            });
        }

        issues
    }

    /// Validate and convert to a typed error.
    pub fn checked(self) -> Result<Self, ConfigError> {
        let issues = self.validate();
        if issues.is_empty() {
            Ok(self)
        } else {
            Err(ConfigError::Invalid(issues))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        Config::default()
            .checked()
            .expect("default config is valid");
    }

    #[test]
    fn invalid_values_are_reported_with_paths() {
        let mut config = Config::default();
        config.ui.font_size = 100.0;
        config.agents.max_parallel = 0;
        config
            .keybindings
            .insert("f2".into(), "does.not.exist".into());
        let issues = config.validate();
        assert!(issues.iter().any(|i| i.path == "ui.font_size"));
        assert!(issues.iter().any(|i| i.path == "agents.max_parallel"));
        assert!(issues.iter().any(|i| i.path.starts_with("keybindings.f2")));
    }

    #[test]
    fn web_bind_must_be_loopback_by_default() {
        let mut config = Config::default();
        config.remote.web_enabled = true;
        config.remote.web_bind = "0.0.0.0:8080".into();
        assert!(config
            .validate()
            .iter()
            .any(|i| i.path == "remote.web_bind"));
        config.remote.web_bind = "127.0.0.1:8080".into();
        assert!(!config
            .validate()
            .iter()
            .any(|i| i.path == "remote.web_bind"));
    }

    #[test]
    fn dangerous_hyperlink_schemes_are_rejected() {
        let mut config = Config::default();
        config.ui.hyperlink_schemes.push("javascript".into());
        assert!(config
            .validate()
            .iter()
            .any(|i| i.path == "ui.hyperlink_schemes"));
    }
}
