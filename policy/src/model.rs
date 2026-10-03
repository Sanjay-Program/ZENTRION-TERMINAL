//! Policy data model matching 09-POLICY-SPEC / schemas/policy-v1.json.

use serde::{Deserialize, Serialize};

pub const POLICY_API_VERSION: &str = "zentrion.policy/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub delete: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub listen: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct SecretsPolicy {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct SystemPolicy {
    #[serde(default)]
    pub admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicy {
    #[serde(default)]
    pub spawn: Vec<String>,
}

/// Tool allowlist (Phase 2 §38). A tool must be named here to be executed;
/// permissions declared in a tool manifest never grant themselves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolsPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    /// Whether `z install` may add tools to the store from this project.
    #[serde(default = "default_true")]
    pub install: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ToolsPolicy {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            install: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Policy {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub secrets: SecretsPolicy,
    #[serde(default)]
    pub system: SystemPolicy,
    #[serde(default)]
    pub process: ProcessPolicy,
    #[serde(default)]
    pub tools: ToolsPolicy,
}

/// Secure default policy (built-in): deny everything except workspace read.
/// Matches `projects` default template and 09 §9.3 defaults.
impl Default for Policy {
    fn default() -> Self {
        Self {
            api_version: POLICY_API_VERSION.to_string(),
            kind: "Policy".to_string(),
            metadata: Metadata {
                name: "built-in-default".into(),
                description: Some("secure default".into()),
            },
            filesystem: FilesystemPolicy {
                read: vec!["./**".to_string()],
                write: vec!["./**".to_string()],
                delete: vec![],
            },
            network: NetworkPolicy::default(),
            secrets: SecretsPolicy::default(),
            system: SystemPolicy::default(),
            process: ProcessPolicy::default(),
            tools: ToolsPolicy::default(),
        }
    }
}
