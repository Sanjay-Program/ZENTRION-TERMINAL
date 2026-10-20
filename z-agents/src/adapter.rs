//! CLI agent adapter manifests.
//!
//! An adapter describes how to launch an agent, how to detect its state and how
//! to resume it. Adapters never grant permissions: the profile and policy do.
//! Screen/hook pattern detection is labelled approximate — the UI must not
//! claim exact state when the adapter uses heuristics.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const ADAPTER_VERSION: u32 = 1;

fn default_adapter_version() -> u32 {
    ADAPTER_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Adapter {
    #[serde(default = "default_adapter_version")]
    pub version: u32,
    pub id: String,
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub detect: Detect,
    #[serde(default)]
    pub events: Events,
    #[serde(default)]
    pub resume: Option<Resume>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub ui: Ui,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    #[serde(default)]
    pub binaries: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Events {
    /// `hooks`, `jsonl`, `screen` or `osc`.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Hook names/descriptions declared by the adapter (for example `stop`).
    /// The current supervisor does not invoke agent hooks; it uses the status
    /// patterns and the process exit code, and labels state approximate.
    #[serde(default)]
    pub hooks: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub status_patterns: Vec<StatusPattern>,
}

fn default_mode() -> String {
    "screen".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatusPattern {
    pub regex: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Resume {
    #[serde(default)]
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default = "default_profile")]
    pub default_profile: String,
    #[serde(default)]
    pub allow_write: bool,
    #[serde(default)]
    pub allow_network: bool,
}

fn default_profile() -> String {
    "agent-readonly".into()
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            default_profile: default_profile(),
            allow_write: false,
            allow_network: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Ui {
    #[serde(default)]
    pub badge: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Starting,
    Running,
    WaitingInput,
    WaitingApproval,
    Done,
    Failed,
}

impl AgentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::WaitingInput => "waiting_input",
            Self::WaitingApproval => "waiting_approval",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "starting" => Self::Starting,
            "running" => Self::Running,
            "waiting_input" => Self::WaitingInput,
            "waiting_approval" => Self::WaitingApproval,
            "done" | "completed" => Self::Done,
            "failed" => Self::Failed,
            _ => return None,
        })
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed)
    }
}

impl Adapter {
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.version != ADAPTER_VERSION {
            issues.push(format!("unsupported adapter version {}", self.version));
        }
        if self.id.trim().is_empty()
            || !self
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            issues.push("adapter id must be a simple name".into());
        }
        if self.command.trim().is_empty() {
            issues.push("adapter command must not be empty".into());
        }
        if !matches!(
            self.events.mode.as_str(),
            "hooks" | "jsonl" | "screen" | "osc"
        ) {
            issues.push(format!("unknown event mode `{}`", self.events.mode));
        }
        for pattern in &self.events.status_patterns {
            if Regex::new(&pattern.regex).is_err() {
                issues.push(format!("invalid status regex `{}`", pattern.regex));
            }
            if AgentState::parse(&pattern.state).is_none() {
                issues.push(format!("unknown state `{}`", pattern.state));
            }
        }
        for arg in &self.args {
            if arg.contains('\0') {
                issues.push("adapter args contain a NUL byte".into());
            }
        }
        issues
    }

    pub fn checked(self) -> Result<Self, String> {
        let issues = self.validate();
        if issues.is_empty() {
            Ok(self)
        } else {
            Err(issues.join("; "))
        }
    }

    /// True when the adapter uses heuristics for state.
    pub fn approximate(&self) -> bool {
        self.events.mode != "hooks" && self.events.mode != "jsonl"
    }

    pub fn detected(&self) -> bool {
        if self.detect.binaries.is_empty() && self.detect.env.is_empty() {
            return true;
        }
        let binary_found = self
            .detect
            .binaries
            .iter()
            .any(|binary| which(binary).is_some());
        let env_found = self
            .detect
            .env
            .iter()
            .any(|name| std::env::var_os(name).is_some());
        binary_found || env_found
    }
}

#[derive(Debug, Clone)]
pub struct StatusParser {
    patterns: Vec<(Regex, AgentState)>,
}

impl StatusParser {
    pub fn new(adapter: &Adapter) -> Self {
        let patterns = adapter
            .events
            .status_patterns
            .iter()
            .filter_map(|pattern| {
                Some((
                    Regex::new(&pattern.regex).ok()?,
                    AgentState::parse(&pattern.state)?,
                ))
            })
            .collect();
        Self { patterns }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Feed a chunk of output and return a state transition, if any.
    pub fn feed(&self, chunk: &str) -> Option<AgentState> {
        let plain = z_blocks::strip_ansi(chunk);
        for line in plain.lines() {
            for (regex, state) in &self.patterns {
                if regex.is_match(line) {
                    return Some(*state);
                }
            }
        }
        None
    }
}

/// Built-in adapters for agents that are commonly installed.
pub fn builtins() -> Vec<Adapter> {
    vec![
        Adapter {
            version: ADAPTER_VERSION,
            id: "claude-code".into(),
            name: "Claude Code".into(),
            command: "claude".into(),
            args: vec![],
            detect: Detect {
                binaries: vec!["claude".into()],
                env: vec!["ANTHROPIC_API_KEY".into()],
            },
            events: Events {
                mode: "screen".into(),
                hooks: Default::default(),
                status_patterns: vec![
                    StatusPattern {
                        regex: r"(?i)do you want to proceed\?".into(),
                        state: "waiting_approval".into(),
                    },
                    StatusPattern {
                        regex: r"(?i)(esc to interrupt|running|thinking)".into(),
                        state: "running".into(),
                    },
                    StatusPattern {
                        regex: r"(?i)(session complete|done)".into(),
                        state: "done".into(),
                    },
                ],
            },
            resume: Some(Resume {
                command: vec!["claude".into(), "--continue".into()],
            }),
            permissions: Permissions {
                default_profile: "agent-readonly".into(),
                allow_write: false,
                allow_network: false,
            },
            ui: Ui {
                badge: Some("CC".into()),
                color: Some("#d97757".into()),
            },
        },
        Adapter {
            version: ADAPTER_VERSION,
            id: "codex".into(),
            name: "Codex CLI".into(),
            command: "codex".into(),
            args: vec![],
            detect: Detect {
                binaries: vec!["codex".into()],
                env: vec!["OPENAI_API_KEY".into()],
            },
            events: Events {
                mode: "screen".into(),
                hooks: Default::default(),
                status_patterns: vec![StatusPattern {
                    regex: r"(?i)(approve|allow command\?)".into(),
                    state: "waiting_approval".into(),
                }],
            },
            resume: None,
            permissions: Permissions {
                default_profile: "agent-readonly".into(),
                allow_write: false,
                allow_network: false,
            },
            ui: Ui {
                badge: Some("CX".into()),
                color: Some("#10a37f".into()),
            },
        },
        Adapter {
            version: ADAPTER_VERSION,
            id: "gemini-cli".into(),
            name: "Gemini CLI".into(),
            command: "gemini".into(),
            args: vec![],
            detect: Detect {
                binaries: vec!["gemini".into()],
                env: vec!["GEMINI_API_KEY".into()],
            },
            events: Events {
                mode: "screen".into(),
                hooks: Default::default(),
                status_patterns: vec![],
            },
            resume: None,
            permissions: Permissions::default(),
            ui: Ui {
                badge: Some("GM".into()),
                color: Some("#4285f4".into()),
            },
        },
        Adapter {
            version: ADAPTER_VERSION,
            id: "opencode".into(),
            name: "OpenCode".into(),
            command: "opencode".into(),
            args: vec![],
            detect: Detect {
                binaries: vec!["opencode".into()],
                env: vec![],
            },
            events: Events {
                mode: "screen".into(),
                hooks: Default::default(),
                status_patterns: vec![],
            },
            resume: None,
            permissions: Permissions::default(),
            ui: Ui {
                badge: Some("OC".into()),
                color: Some("#22c55e".into()),
            },
        },
        Adapter {
            version: ADAPTER_VERSION,
            id: "aider".into(),
            name: "Aider".into(),
            command: "aider".into(),
            args: vec![],
            detect: Detect {
                binaries: vec!["aider".into()],
                env: vec![],
            },
            events: Events {
                mode: "screen".into(),
                hooks: Default::default(),
                status_patterns: vec![StatusPattern {
                    regex: r"(?i)(\by\)es|\bn\)o|apply edit\?)".into(),
                    state: "waiting_approval".into(),
                }],
            },
            resume: None,
            permissions: Permissions::default(),
            ui: Ui {
                badge: Some("AI".into()),
                color: Some("#a855f7".into()),
            },
        },
    ]
}

/// Default adapter directories.
pub fn default_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(data) = z_core::config::user_data_dir() {
        dirs.push(data.join("agents"));
    }
    if let Some(config) = z_core::config::user_config_dir() {
        dirs.push(config.join("agents"));
    }
    dirs
}

/// Load built-ins and any user adapters. A user adapter with the same id
/// replaces the built-in entirely (validated first).
pub fn discover(dirs: &[PathBuf]) -> Vec<Adapter> {
    let mut adapters: Vec<Adapter> = builtins();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();
        files.sort();
        for path in files {
            match load_adapter(&path) {
                Ok(adapter) => {
                    if let Some(existing) = adapters.iter_mut().find(|a| a.id == adapter.id) {
                        *existing = adapter;
                    } else {
                        adapters.push(adapter);
                    }
                }
                Err(error) => eprintln!("z agent: skipping adapter {}: {error}", path.display()),
            }
        }
    }
    adapters.sort_by(|a, b| a.id.cmp(&b.id));
    adapters
}

pub fn load_adapter(path: &Path) -> Result<Adapter, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let adapter: Adapter =
        serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    adapter.checked()
}

pub fn which(binary: &str) -> Option<PathBuf> {
    if binary.contains('/') || binary.contains('\\') {
        let path = PathBuf::from(binary);
        return path.is_file().then_some(path);
    }
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let mut candidate = dir.join(binary);
        if cfg!(windows) && candidate.extension().is_none() {
            candidate.set_extension("exe");
        }
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_validate_and_have_unique_ids() {
        let adapters = builtins();
        let mut ids = std::collections::BTreeSet::new();
        for adapter in &adapters {
            assert!(adapter.validate().is_empty(), "{:?}", adapter.validate());
            assert!(ids.insert(adapter.id.clone()));
        }
        assert!(adapters.iter().any(|a| a.id == "claude-code"));
    }

    #[test]
    fn status_patterns_are_compiled_and_approximate_is_labelled() {
        let adapter = builtins()
            .into_iter()
            .find(|a| a.id == "claude-code")
            .unwrap();
        let parser = StatusParser::new(&adapter);
        assert_eq!(
            parser.feed("\x1b[31mDo you want to proceed?\x1b[0m"),
            Some(AgentState::WaitingApproval)
        );
        assert!(adapter.approximate());
    }

    #[test]
    fn user_adapter_replaces_builtin() {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-adapters-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("claude.yaml"),
            r##"
version: 1
id: claude-code
name: Claude Code Custom
command: claude
args: ["--custom"]
detect: {binaries: ["claude"], env: []}
events: {mode: screen, status_patterns: []}
resume: {command: ["claude", "--continue"]}
permissions: {default_profile: agent-dev, allow_write: true, allow_network: false}
ui: {badge: CC, color: "#fff"}
"##,
        )
        .unwrap();
        let adapters = discover(&[dir.clone()]);
        let adapter = adapters.iter().find(|a| a.id == "claude-code").unwrap();
        assert_eq!(adapter.name, "Claude Code Custom");
        assert!(adapter.permissions.allow_write);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_regex_is_rejected() {
        let adapter = Adapter {
            version: 1,
            id: "bad".into(),
            name: "Bad".into(),
            command: "bad".into(),
            args: vec![],
            detect: Detect::default(),
            events: Events {
                mode: "screen".into(),
                hooks: Default::default(),
                status_patterns: vec![StatusPattern {
                    regex: "(".into(),
                    state: "running".into(),
                }],
            },
            resume: None,
            permissions: Permissions::default(),
            ui: Ui::default(),
        };
        assert!(!adapter.validate().is_empty());
    }
}
