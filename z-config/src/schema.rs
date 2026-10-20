//! Typed configuration schema.
//!
//! Every field has a default so a partial user file only overrides what it
//! names. Parsing is strict (`deny_unknown_fields`): a typo must never silently
//! disable a security setting.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn default_scrollback() -> usize {
    100_000
}
fn default_font_family() -> String {
    "JetBrains Mono".to_string()
}
fn default_font_size() -> f32 {
    13.0
}
fn default_opacity() -> f32 {
    1.0
}
fn default_theme() -> String {
    "zentrion".to_string()
}
fn default_cursor() -> CursorStyle {
    CursorStyle::Bar
}
fn default_shell() -> String {
    if cfg!(windows) {
        "pwsh".to_string()
    } else {
        "/bin/bash".to_string()
    }
}
fn default_composer() -> ComposerMode {
    ComposerMode::Overlay
}
fn default_retention() -> u32 {
    30
}
fn default_agent() -> String {
    "claude-code".to_string()
}
fn default_parallel() -> u8 {
    4
}
fn default_agent_profile() -> String {
    "agent-readonly".to_string()
}
fn default_model() -> String {
    "local/qwen2.5-coder".to_string()
}
fn default_routing() -> ModelRouting {
    ModelRouting::LocalFirst
}
fn default_budget() -> f64 {
    5.0
}
fn default_ssh() -> SshBackend {
    SshBackend::Native
}
fn default_context_tokens() -> usize {
    32_768
}
fn default_max_output_tokens() -> u32 {
    4_096
}
fn default_cache() -> bool {
    true
}
fn default_max_file_bytes() -> u64 {
    512 * 1024
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorStyle {
    Block,
    Bar,
    Underline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComposerMode {
    Off,
    Overlay,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellIntegration {
    Auto,
    Off,
    Bash,
    Zsh,
    Fish,
    Pwsh,
    Nushell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorePolicy {
    Never,
    Layout,
    #[serde(rename = "layout+cwd")]
    LayoutAndCwd,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRouting {
    LocalOnly,
    LocalFirst,
    Cost,
    Latency,
    Quality,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshBackend {
    Native,
    System,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UiConfig {
    pub theme: String,
    pub font_family: String,
    pub font_size: f32,
    pub opacity: f32,
    pub cursor_style: CursorStyle,
    pub scrollback_lines: usize,
    pub gpu: bool,
    /// OSC 52 clipboard writes are opt-in and still require confirmation.
    pub allow_clipboard_write: bool,
    /// Schemes that may be opened from an OSC 8 hyperlink.
    pub hyperlink_schemes: Vec<String>,
    pub high_contrast: bool,
    pub reduced_motion: bool,
    pub screen_reader: bool,
    pub status_widgets: Vec<String>,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            font_family: default_font_family(),
            font_size: default_font_size(),
            opacity: default_opacity(),
            cursor_style: default_cursor(),
            scrollback_lines: default_scrollback(),
            gpu: true,
            allow_clipboard_write: false,
            hyperlink_schemes: vec!["https".into(), "http".into(), "mailto".into()],
            high_contrast: false,
            reduced_motion: false,
            screen_reader: false,
            status_widgets: vec!["cwd".into(), "git".into(), "agent".into()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ShellConfig {
    pub default: String,
    pub integration: ShellIntegration,
    /// Extra arguments passed to the shell before the integration arguments.
    pub args: Vec<String>,
    /// Launch the shell as a login shell.
    pub login: bool,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            default: default_shell(),
            integration: ShellIntegration::Auto,
            args: Vec::new(),
            login: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InputConfig {
    pub composer: ComposerMode,
    pub completions: Vec<String>,
    pub danger_confirm: bool,
    /// Show an approval prompt for paste of more than N lines (0 disables).
    pub multiline_paste_warn: usize,
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            composer: default_composer(),
            completions: vec![
                "history".into(),
                "shell".into(),
                "files".into(),
                "git".into(),
                "packages".into(),
            ],
            danger_confirm: true,
            multiline_paste_warn: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BlocksConfig {
    pub persist: bool,
    pub retention_days: u32,
    pub share_redaction: bool,
    pub max_output_bytes: u64,
    pub search_limit: usize,
}

impl Default for BlocksConfig {
    fn default() -> Self {
        Self {
            persist: true,
            retention_days: default_retention(),
            share_redaction: true,
            max_output_bytes: 8 * 1024 * 1024,
            search_limit: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentsConfig {
    pub default_agent: String,
    pub max_parallel: u8,
    pub auto_approve_read_only: bool,
    pub default_profile: String,
    pub notify_on: Vec<String>,
    /// Extra adapter manifest directories.
    pub adapter_dirs: Vec<String>,
    /// Hard per-tool-call timeout.
    pub tool_timeout_seconds: u64,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            default_agent: default_agent(),
            max_parallel: default_parallel(),
            auto_approve_read_only: true,
            default_profile: default_agent_profile(),
            notify_on: vec![
                "waiting_approval".into(),
                "completed".into(),
                "failed".into(),
            ],
            adapter_dirs: Vec::new(),
            tool_timeout_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModelsConfig {
    pub default: String,
    pub fallback: Vec<String>,
    pub budget_usd_per_day: f64,
    /// Optional per-agent daily budget caps (USD).
    pub agent_budgets: BTreeMap<String, f64>,
    pub routing: ModelRouting,
    pub allow_cloud: bool,
    pub max_output_tokens: u32,
    /// Cache successful responses when the prompt carries no detected secrets.
    pub cache: bool,
    /// Provider definitions keyed by id, e.g. `local/ollama`.
    pub providers: BTreeMap<String, ProviderConfig>,
}

impl Default for ModelsConfig {
    fn default() -> Self {
        Self {
            default: default_model(),
            fallback: Vec::new(),
            budget_usd_per_day: default_budget(),
            agent_budgets: BTreeMap::new(),
            routing: default_routing(),
            allow_cloud: false,
            max_output_tokens: default_max_output_tokens(),
            cache: default_cache(),
            providers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProviderConfig {
    pub kind: String,
    pub models: Vec<String>,
    pub caps: Vec<String>,
    pub cost_per_mtok: f64,
    /// Optional output-token price; defaults to `cost_per_mtok`.
    pub output_cost_per_mtok: Option<f64>,
    pub context: usize,
    pub base_url: Option<String>,
    /// Name of an environment variable holding the API key. Never the key.
    pub api_key_env: Option<String>,
    /// Advertised latency for routing; local providers default to 50 ms.
    pub latency_ms: Option<u64>,
    /// Advertised quality score (1–100) for quality routing.
    pub quality: Option<u8>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            kind: "local".into(),
            models: Vec::new(),
            caps: vec!["chat".into()],
            cost_per_mtok: 0.0,
            output_cost_per_mtok: None,
            context: 32_768,
            base_url: None,
            api_key_env: None,
            latency_ms: None,
            quality: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RemoteConfig {
    pub ssh_backend: SshBackend,
    pub verify_host_keys: bool,
    pub web_enabled: bool,
    pub web_bind: String,
    pub web_tls: bool,
    pub connect_timeout_seconds: u64,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            ssh_backend: default_ssh(),
            verify_host_keys: true,
            web_enabled: false,
            web_bind: "127.0.0.1:0".into(),
            web_tls: false,
            connect_timeout_seconds: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    /// Off unless the user explicitly opts in. Never prompts/output/clipboard.
    pub enabled: bool,
    pub crash_reports: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ContextConfig {
    pub enabled: bool,
    /// Local embeddings are opt-in and disabled by default.
    pub embeddings: bool,
    pub model_context_tokens: usize,
    pub max_file_bytes: u64,
    pub max_files: usize,
    pub ignore: Vec<String>,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            embeddings: false,
            model_context_tokens: default_context_tokens(),
            max_file_bytes: default_max_file_bytes(),
            max_files: 100_000,
            ignore: vec![
                ".git".into(),
                "target".into(),
                "node_modules".into(),
                ".venv".into(),
                "dist".into(),
                ".env".into(),
                "*.pem".into(),
                "*.key".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SessionConfig {
    pub restore: RestorePolicy,
    pub workspace_dir: Option<String>,
    pub socket_path: Option<String>,
    pub scrollback_lines: usize,
    pub persist_output: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            restore: RestorePolicy::LayoutAndCwd,
            workspace_dir: None,
            socket_path: None,
            scrollback_lines: default_scrollback(),
            persist_output: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WorkflowConfig {
    pub dir: Option<String>,
    pub default_timeout_seconds: u64,
    pub allow_http: bool,
    pub http_allowlist: Vec<String>,
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            dir: None,
            default_timeout_seconds: 3_600,
            allow_http: false,
            http_allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct SecurityConfig {
    pub require_scope: bool,
    pub engagement_dir: Option<String>,
    pub evidence_dir: Option<String>,
    pub break_glass_requires_reason: bool,
    pub redaction_profile: Option<String>,
}

/// Per-shell/host/project profile. Profiles never carry secrets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ProfileConfig {
    pub shell: Option<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub theme: Option<String>,
    pub font_family: Option<String>,
    pub font_size: Option<f32>,
    pub agent: Option<String>,
    pub policy_profile: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub ui: UiConfig,
    pub shell: ShellConfig,
    pub input: InputConfig,
    pub blocks: BlocksConfig,
    pub agents: AgentsConfig,
    pub models: ModelsConfig,
    pub remote: RemoteConfig,
    pub telemetry: TelemetryConfig,
    pub context: ContextConfig,
    pub session: SessionConfig,
    pub workflow: WorkflowConfig,
    pub security: SecurityConfig,
    /// Chord string (e.g. `"f2"`) to action string (e.g. `"palette.open"`).
    pub keybindings: BTreeMap<String, String>,
    pub profiles: BTreeMap<String, ProfileConfig>,
    /// Default profile name; `None` means none.
    pub default_profile: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ui: UiConfig::default(),
            shell: ShellConfig::default(),
            input: InputConfig::default(),
            blocks: BlocksConfig::default(),
            agents: AgentsConfig::default(),
            models: ModelsConfig::default(),
            remote: RemoteConfig::default(),
            telemetry: TelemetryConfig::default(),
            context: ContextConfig::default(),
            session: SessionConfig::default(),
            workflow: WorkflowConfig::default(),
            security: SecurityConfig::default(),
            keybindings: crate::keys::default_keybindings(),
            profiles: BTreeMap::new(),
            default_profile: None,
        }
    }
}

impl Config {
    /// Merge a higher-precedence JSON layer on top of this config.
    ///
    /// Objects merge recursively, arrays and scalars replace. A profile table
    /// merges per key so a project profile can override only its agent.
    pub fn apply_json_layer(
        &mut self,
        layer: &serde_json::Value,
    ) -> Result<(), crate::ConfigError> {
        let mut current = serde_json::to_value(&*self)
            .map_err(|e| crate::ConfigError::Internal(e.to_string()))?;
        merge_json(&mut current, layer);
        *self = serde_json::from_value(current).map_err(|e| crate::ConfigError::Schema {
            path: "<merged>".into(),
            line: None,
            message: e.to_string(),
        })?;
        Ok(())
    }

    /// Resolve the profile named by `name` (or the default profile).
    pub fn profile(&self, name: Option<&str>) -> Option<(&str, &ProfileConfig)> {
        let name = name.or(self.default_profile.as_deref())?;
        self.profiles
            .get_key_value(name)
            .map(|(k, v)| (k.as_str(), v))
    }
}

/// Recursively merge `src` into `dst`; `src` wins.
pub fn merge_json(dst: &mut serde_json::Value, src: &serde_json::Value) {
    match (dst, src) {
        (serde_json::Value::Object(dst), serde_json::Value::Object(src)) => {
            for (key, value) in src {
                match dst.get_mut(key) {
                    Some(existing) => merge_json(existing, value),
                    None => {
                        dst.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (dst, src) => *dst = src.clone(),
    }
}

/// Convert a TOML table into JSON.
pub fn toml_to_json(value: &toml::Value) -> Result<serde_json::Value, String> {
    let text = value.to_string();
    let parsed: toml::Value =
        toml::from_str(&text).map_err(|e| format!("cannot normalize TOML layer: {e}"))?;
    let json = serde_json::to_value(parsed).map_err(|e| e.to_string())?;
    Ok(json)
}

/// Empty keybinding table helper (defaults live in [`crate::keys`]).
pub fn default_keybindings() -> BTreeMap<String, String> {
    crate::keys::default_keybindings()
}
