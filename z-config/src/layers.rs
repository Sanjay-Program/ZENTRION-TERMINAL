//! Layer discovery, strict parsing, merging and atomic writes.

use crate::keys::Keymap;
use crate::schema::Config;
use crate::{ConfigError, ConfigIssue};
use serde_json::Value as Json;
use std::path::{Path, PathBuf};

/// CLI overrides applied after every file and environment layer.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub theme: Option<String>,
    pub shell: Option<String>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub profile: Option<String>,
    pub gpu: Option<bool>,
}

impl Overrides {
    fn to_json(&self) -> Option<Json> {
        let mut root = serde_json::Map::new();
        let mut ui = serde_json::Map::new();
        let mut shell = serde_json::Map::new();
        let mut agents = serde_json::Map::new();
        let mut models = serde_json::Map::new();
        if let Some(value) = &self.theme {
            ui.insert("theme".to_string(), Json::String(value.clone()));
        }
        if let Some(value) = self.gpu {
            ui.insert("gpu".to_string(), Json::Bool(value));
        }
        if let Some(value) = &self.shell {
            shell.insert("default".to_string(), Json::String(value.clone()));
        }
        if let Some(value) = &self.agent {
            agents.insert("default_agent".to_string(), Json::String(value.clone()));
        }
        if let Some(value) = &self.model {
            models.insert("default".to_string(), Json::String(value.clone()));
        }
        for (key, table) in [
            ("ui", ui),
            ("shell", shell),
            ("agents", agents),
            ("models", models),
        ] {
            if !table.is_empty() {
                root.insert(key.to_string(), Json::Object(table));
            }
        }
        if let Some(value) = &self.profile {
            root.insert("default_profile".to_string(), Json::String(value.clone()));
        }
        if root.is_empty() {
            None
        } else {
            Some(Json::Object(root))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LayerInfo {
    /// `user`, `project`, `env` or `cli`.
    pub layer: String,
    pub path: Option<PathBuf>,
    pub loaded: bool,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub layers: Vec<LayerInfo>,
    pub warnings: Vec<String>,
}

impl LoadedConfig {
    pub fn keymap(&self) -> (Keymap, Vec<crate::KeymapIssue>) {
        Keymap::from_table(&self.config.keybindings)
    }
}

#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    pub user_config: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
    pub apply_env: bool,
    pub overrides: Overrides,
}

impl LoadOptions {
    pub fn with_env() -> Self {
        Self {
            apply_env: true,
            ..Self::default()
        }
    }
}

pub fn default_user_config_path() -> Option<PathBuf> {
    z_core::config::user_config_dir().map(|dir| dir.join("config.toml"))
}

/// Load the effective configuration from the standard locations.
pub fn load(options: &LoadOptions) -> Result<LoadedConfig, ConfigError> {
    let user = options
        .user_config
        .clone()
        .or_else(default_user_config_path);
    let root = options
        .project_root
        .clone()
        .or_else(|| std::env::current_dir().ok());
    load_from_paths(user.as_deref(), root.as_deref(), options)
}

/// Load from explicit paths (used by tests and `z config --file`).
pub fn load_from_paths(
    user_config: Option<&Path>,
    project_root: Option<&Path>,
    options: &LoadOptions,
) -> Result<LoadedConfig, ConfigError> {
    let mut config = Config::default();
    let mut layers = vec![LayerInfo {
        layer: "defaults".into(),
        path: None,
        loaded: true,
    }];
    let mut warnings = Vec::new();

    if let Some(path) = user_config {
        match load_layer(path, "user")? {
            Some(json) => {
                config
                    .apply_json_layer(&json)
                    .map_err(|e| annotate(e, path))?;
                layers.push(LayerInfo {
                    layer: "user".into(),
                    path: Some(path.to_path_buf()),
                    loaded: true,
                });
            }
            None => layers.push(LayerInfo {
                layer: "user".into(),
                path: Some(path.to_path_buf()),
                loaded: false,
            }),
        }
    }

    // Legacy YAML configuration (pre-blueprint `config.yaml`) is never read
    // silently; it is reported so the user can migrate deliberately.
    if let Some(dir) = z_core::config::user_config_dir() {
        let legacy = dir.join("config.yaml");
        if legacy.exists() {
            warnings.push(format!(
                "legacy config {} is not read; move supported settings into config.toml",
                legacy.display()
            ));
        }
    }

    if let Some(root) = project_root {
        let candidates = [
            root.join(".zentrion").join("terminal.toml"),
            root.join(".zentrion").join("config.toml"),
        ];
        if let Some(path) = candidates.iter().find(|path| path.exists()) {
            if let Some(json) = load_layer(path, "project")? {
                config
                    .apply_json_layer(&json)
                    .map_err(|e| annotate(e, path))?;
            }
            layers.push(LayerInfo {
                layer: "project".into(),
                path: Some(path.clone()),
                loaded: true,
            });
        } else {
            layers.push(LayerInfo {
                layer: "project".into(),
                path: Some(candidates[0].clone()),
                loaded: false,
            });
        }
    }

    if options.apply_env {
        let env_layer = environment_layer();
        if let Some(json) = env_layer {
            config.apply_json_layer(&json)?;
            layers.push(LayerInfo {
                layer: "env".into(),
                path: None,
                loaded: true,
            });
        }
    }

    if let Some(json) = options.overrides.to_json() {
        config.apply_json_layer(&json)?;
        layers.push(LayerInfo {
            layer: "cli".into(),
            path: None,
            loaded: true,
        });
    }

    let issues = config.validate();
    if !issues.is_empty() {
        return Err(ConfigError::Invalid(issues));
    }
    Ok(LoadedConfig {
        config,
        layers,
        warnings,
    })
}

/// Explicit environment overrides. There is deliberately no generic
/// `ZENTRION_*` catch-all: every override is named and documented.
fn environment_layer() -> Option<Json> {
    let mut root = serde_json::Map::new();
    let mut ui = serde_json::Map::new();
    let mut shell = serde_json::Map::new();
    let mut agents = serde_json::Map::new();
    let mut models = serde_json::Map::new();
    let mut telemetry = serde_json::Map::new();
    let mut remote = serde_json::Map::new();

    if let Ok(theme) = std::env::var("ZENTRION_THEME") {
        if !theme.trim().is_empty() {
            ui.insert("theme".into(), Json::String(theme));
        }
    }
    if let Ok(gpu) = std::env::var("ZENTRION_GPU") {
        match gpu.as_str() {
            "1" | "true" | "on" => {
                ui.insert("gpu".into(), Json::Bool(true));
            }
            "0" | "false" | "off" => {
                ui.insert("gpu".into(), Json::Bool(false));
            }
            other => eprintln!("z: ignoring ZENTRION_GPU={other} (expected true/false)"),
        }
    }
    if let Ok(value) = std::env::var("ZENTRION_SHELL") {
        if !value.trim().is_empty() {
            shell.insert("default".into(), Json::String(value));
        }
    }
    if let Ok(value) = std::env::var("ZENTRION_SHELL_INTEGRATION") {
        if !value.trim().is_empty() {
            shell.insert("integration".into(), Json::String(value));
        }
    }
    if let Ok(value) = std::env::var("ZENTRION_AGENT") {
        if !value.trim().is_empty() {
            agents.insert("default_agent".into(), Json::String(value));
        }
    }
    if let Ok(value) = std::env::var("ZENTRION_MODEL") {
        if !value.trim().is_empty() {
            models.insert("default".into(), Json::String(value));
        }
    }
    if let Ok(value) = std::env::var("ZENTRION_TELEMETRY") {
        let enabled = value == "1" || value.eq_ignore_ascii_case("true");
        telemetry.insert("enabled".into(), Json::Bool(enabled));
    }
    if let Ok(value) = std::env::var("ZENTRION_WEB_BIND") {
        if !value.trim().is_empty() {
            remote.insert("web_enabled".into(), Json::Bool(true));
            remote.insert("web_bind".into(), Json::String(value));
        }
    }

    for (key, table) in [
        ("ui", ui),
        ("shell", shell),
        ("agents", agents),
        ("models", models),
        ("telemetry", telemetry),
        ("remote", remote),
    ] {
        if !table.is_empty() {
            root.insert(key.into(), Json::Object(table));
        }
    }
    if root.is_empty() {
        None
    } else {
        Some(Json::Object(root))
    }
}

fn load_layer(path: &Path, label: &str) -> Result<Option<Json>, ConfigError> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    let value: toml::Value = match toml::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            let line = error.span().map(|span| line_of_offset(&text, span.start));
            return Err(ConfigError::Syntax {
                path: format!("{} ({label})", path.display()),
                line,
                message: error.message().to_string(),
            });
        }
    };
    let json = serde_json::to_value(&value).map_err(|e| ConfigError::Schema {
        path: path.display().to_string(),
        line: None,
        message: e.to_string(),
    })?;

    // Strict shape checks before merging: unknown keys and wrong types must
    // name the file and line, not surface later as a merged-config error.
    let defaults = serde_json::to_value(Config::default()).expect("config serializes");
    let mut issues = Vec::new();
    check_layer(&defaults, &json, "", &text, &mut issues);
    if let Some(issue) = issues.into_iter().next() {
        return Err(ConfigError::Schema {
            path: format!("{} ({label})", path.display()),
            line: issue.line,
            message: format!("{}: {}", issue.path, issue.message),
        });
    }
    Ok(Some(json))
}

/// Where free-form string keys are allowed.
fn dynamic_table(path: &str) -> bool {
    matches!(path, "keybindings" | "profiles" | "models.providers")
}

fn check_layer(
    defaults: &Json,
    layer: &Json,
    path: &str,
    text: &str,
    issues: &mut Vec<ConfigIssue>,
) {
    let (Json::Object(default_map), Json::Object(layer_map)) = (defaults, layer) else {
        if !types_compatible(defaults, layer) {
            issues.push(ConfigIssue {
                path: if path.is_empty() {
                    "<root>".into()
                } else {
                    path.into()
                },
                message: format!(
                    "expected {}, found {}",
                    json_kind(defaults),
                    json_kind(layer)
                ),
                line: find_line(text, path),
            });
        }
        return;
    };
    let mut keys: Vec<&String> = layer_map.keys().collect();
    keys.sort();
    for key in keys {
        let child_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        let value = &layer_map[key];
        match default_map.get(key) {
            None if dynamic_table(path) => {}
            None => {
                issues.push(ConfigIssue {
                    path: child_path,
                    message: "unknown configuration key".into(),
                    line: find_line(text, key),
                });
            }
            Some(default_value) => {
                if dynamic_table(path) {
                    continue;
                }
                if default_value.is_object() && value.is_object() {
                    check_layer(default_value, value, &child_path, text, issues);
                } else if !types_compatible(default_value, value) {
                    issues.push(ConfigIssue {
                        path: child_path.clone(),
                        message: format!(
                            "expected {}, found {}",
                            json_kind(default_value),
                            json_kind(value)
                        ),
                        line: find_line(text, key),
                    });
                }
            }
        }
    }
}

fn types_compatible(expected: &Json, actual: &Json) -> bool {
    match (expected, actual) {
        (Json::Number(_), Json::Number(_)) => true,
        (Json::Null, _) => true,
        (Json::Array(_), Json::Array(_)) => true,
        (Json::Object(expected), Json::Object(actual)) => {
            actual.iter().all(|(key, value)| match expected.get(key) {
                Some(expected) => types_compatible(expected, value),
                None => true,
            })
        }
        (a, b) => json_kind(a) == json_kind(b),
    }
}

fn json_kind(value: &Json) -> &'static str {
    match value {
        Json::Null => "null",
        Json::Bool(_) => "boolean",
        Json::Number(_) => "number",
        Json::String(_) => "string",
        Json::Array(_) => "array",
        Json::Object(_) => "table",
    }
}

fn line_of_offset(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn find_line(text: &str, key: &str) -> Option<usize> {
    if key.is_empty() {
        return None;
    }
    let bare = key.rsplit('.').next().unwrap_or(key);
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&format!("{bare} "))
            || trimmed.starts_with(&format!("{bare}="))
            || trimmed.starts_with(&format!("{bare}."))
            || trimmed.starts_with(&format!("[{bare}]"))
            || trimmed.starts_with(&format!("[{}", key))
            || trimmed.starts_with(&format!("\"{bare}\""))
        {
            return Some(index + 1);
        }
    }
    None
}

fn annotate(error: ConfigError, path: &Path) -> ConfigError {
    match error {
        ConfigError::Schema { line, message, .. } => ConfigError::Schema {
            path: path.display().to_string(),
            line,
            message,
        },
        other => other,
    }
}

/// Validate a config file without loading the environment.
pub fn validate_file(path: &Path) -> Result<Config, ConfigError> {
    let json = load_layer(path, "user")?.ok_or_else(|| ConfigError::Io {
        path: path.display().to_string(),
        message: "file does not exist".into(),
    })?;
    let mut config = Config::default();
    config.apply_json_layer(&json)?;
    let issues = config.validate();
    if issues.is_empty() {
        Ok(config)
    } else {
        Err(ConfigError::Invalid(issues))
    }
}

/// Write the user config atomically, keeping a single backup of the previous
/// file. Validation happens before anything is written.
pub fn write_user_config(path: &Path, config: &Config) -> Result<(), ConfigError> {
    config.clone().checked()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
            path: parent.display().to_string(),
            message: e.to_string(),
        })?;
    }
    let text = toml::to_string_pretty(config)
        .map_err(|e| ConfigError::Internal(format!("cannot serialize config: {e}")))?;
    // Round-trip before writing: never leave a file we cannot read.
    let _: Config = toml::from_str(&text)
        .map_err(|e| ConfigError::Internal(format!("serialized config is invalid: {e}")))?;

    if path.exists() {
        let backup = path.with_extension("toml.bak");
        std::fs::copy(path, &backup).map_err(|e| ConfigError::Io {
            path: backup.display().to_string(),
            message: e.to_string(),
        })?;
    }
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text.as_bytes()).map_err(|e| ConfigError::Io {
        path: tmp.display().to_string(),
        message: e.to_string(),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    Ok(())
}

/// Render the effective config with its source layers.
pub fn render_effective(loaded: &LoadedConfig) -> String {
    let mut out = String::new();
    out.push_str("# effective Zentrion configuration\n");
    for layer in &loaded.layers {
        match &layer.path {
            Some(path) => out.push_str(&format!(
                "# {:<9} {} ({})\n",
                layer.layer,
                path.display(),
                if layer.loaded { "loaded" } else { "absent" }
            )),
            None => out.push_str(&format!(
                "# {:<9} {}\n",
                layer.layer,
                if layer.loaded { "applied" } else { "off" }
            )),
        }
    }
    for warning in &loaded.warnings {
        out.push_str(&format!("# warning: {warning}\n"));
    }
    out.push('\n');
    match toml::to_string_pretty(&loaded.config) {
        Ok(text) => out.push_str(&text),
        Err(error) => out.push_str(&format!("# cannot serialize: {error}\n")),
    }
    out
}

/// Find the nearest project root containing `.zentrion/`.
pub fn discover_project_root(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(dir) = current {
        if dir.join(".zentrion").is_dir() || dir.join(".git").is_dir() {
            return Some(dir.to_path_buf());
        }
        current = dir.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("zentrion-zconfig-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, text: &str) {
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn partial_layer_keeps_defaults() {
        let dir = temp_dir("partial");
        let path = dir.join("config.toml");
        write(&path, "[ui]\ntheme = \"dracula\"\nfont_size = 15.0\n");
        let options = LoadOptions::default();
        let loaded = load_from_paths(Some(&path), None, &options).unwrap();
        assert_eq!(loaded.config.ui.theme, "dracula");
        assert_eq!(loaded.config.ui.font_size, 15.0);
        assert_eq!(
            loaded.config.ui.font_family,
            crate::UiConfig::default().font_family
        );
        assert!(loaded.layers.iter().any(|l| l.layer == "user" && l.loaded));
    }

    #[test]
    fn unknown_key_fails_with_line() {
        let dir = temp_dir("unknown");
        let path = dir.join("config.toml");
        write(&path, "[ui]\ntheme = \"x\"\nnot_a_key = 1\n");
        let error = load_from_paths(Some(&path), None, &LoadOptions::default()).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("not_a_key"), "{text}");
        assert!(text.contains("line 3") || text.contains(":3:"), "{text}");
    }

    #[test]
    fn syntax_error_reports_line() {
        let dir = temp_dir("syntax");
        let path = dir.join("config.toml");
        write(&path, "[ui\ntheme = \"x\"\n");
        let error = load_from_paths(Some(&path), None, &LoadOptions::default()).unwrap_err();
        assert!(matches!(error, ConfigError::Syntax { line: Some(1), .. }));
    }

    #[test]
    fn project_layer_overrides_user() {
        let dir = temp_dir("precedence");
        let user = dir.join("user.toml");
        let project = dir.join("project");
        std::fs::create_dir_all(project.join(".zentrion")).unwrap();
        write(&user, "[ui]\ntheme = \"user\"\nfont_size = 11.0\n");
        write(
            &project.join(".zentrion/terminal.toml"),
            "[ui]\ntheme = \"project\"\n",
        );
        let loaded = load_from_paths(Some(&user), Some(&project), &LoadOptions::default()).unwrap();
        assert_eq!(loaded.config.ui.theme, "project");
        assert_eq!(loaded.config.ui.font_size, 11.0);
    }

    #[test]
    fn env_and_cli_override_files() {
        let dir = temp_dir("cli");
        let user = dir.join("user.toml");
        write(&user, "[ui]\ntheme = \"file\"\n");
        let options = LoadOptions {
            overrides: Overrides {
                theme: Some("cli".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let loaded = load_from_paths(Some(&user), None, &options).unwrap();
        assert_eq!(loaded.config.ui.theme, "cli");
    }

    #[test]
    fn atomic_write_round_trips_and_backs_up() {
        let dir = temp_dir("write");
        let path = dir.join("config.toml");
        write(&path, "[ui]\ntheme = \"old\"\n");
        let mut config = Config::default();
        config.ui.theme = "new".into();
        write_user_config(&path, &config).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("theme = \"new\""));
        assert!(path.with_extension("toml.bak").exists());
        let reloaded = load_from_paths(Some(&path), None, &LoadOptions::default()).unwrap();
        assert_eq!(reloaded.config.ui.theme, "new");
    }

    #[test]
    fn invalid_config_is_never_written() {
        let dir = temp_dir("invalid-write");
        let path = dir.join("config.toml");
        let mut config = Config::default();
        config.ui.opacity = 5.0;
        assert!(write_user_config(&path, &config).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn keymap_round_trips_through_config() {
        let mut config = Config::default();
        config.keybindings.insert("f2".into(), "search.open".into());
        let text = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.keybindings["f2"], "search.open");
        assert!(parsed.validate().is_empty());
    }
}
