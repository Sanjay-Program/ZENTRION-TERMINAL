//! Built-in agent profiles.
//!
//! A profile is the agent half of policy: filesystem scopes, executables,
//! network hosts, secrets and tools. Profiles are conservative by default and
//! can require approval for actions even when policy would allow them.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentProfile {
    pub name: String,
    pub description: String,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub delete: Vec<String>,
    pub exec: Vec<String>,
    pub shell: Vec<String>,
    pub net: Vec<String>,
    pub secrets: Vec<String>,
    pub tools: Vec<String>,
    /// Actions that always require explicit approval in this profile.
    pub require_approval: Vec<String>,
    pub max_parallel: u8,
    pub non_interactive: bool,
}

impl AgentProfile {
    pub fn builtin(name: &str) -> Option<Self> {
        let profile = match name {
            "agent-readonly" | "readonly" => Self {
                name: "agent-readonly".into(),
                description: "Read files only; no writes, network, execution or secrets".into(),
                read: vec!["./**".into()],
                write: vec![],
                delete: vec![],
                exec: vec![],
                shell: vec![],
                net: vec![],
                secrets: vec![],
                tools: vec!["zentrion/read_file".into(), "zentrion/list_dir".into()],
                require_approval: vec![],
                max_parallel: 4,
                non_interactive: false,
            },
            "agent-dev" | "dev" => Self {
                name: "agent-dev".into(),
                description: "Workspace read/write and allowlisted build/test commands".into(),
                read: vec!["./**".into()],
                write: vec!["./**".into()],
                delete: vec![],
                exec: [
                    "cargo",
                    "rustc",
                    "rustfmt",
                    "clippy-driver",
                    "git",
                    "make",
                    "cmake",
                    "npm",
                    "pnpm",
                    "yarn",
                    "node",
                    "npx",
                    "python3",
                    "python",
                    "pytest",
                    "go",
                    "rustup",
                    "just",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
                shell: vec![
                    "cargo ".into(),
                    "git status".into(),
                    "git diff".into(),
                    "git log".into(),
                    "npm test".into(),
                    "pnpm test".into(),
                ],
                net: vec![],
                secrets: vec![],
                tools: vec!["*".into()],
                require_approval: vec![
                    "agent.exec".into(),
                    "agent.fs.delete".into(),
                    "agent.net".into(),
                    "agent.secret.read".into(),
                ],
                max_parallel: 4,
                non_interactive: false,
            },
            "agent-security" | "security" => Self {
                name: "agent-security".into(),
                description: "Authorized scanners with read-only workspace access".into(),
                read: vec!["./**".into()],
                write: vec![],
                delete: vec![],
                exec: [
                    "nmap",
                    "nikto",
                    "sqlmap",
                    "ffuf",
                    "gobuster",
                    "dirb",
                    "whatweb",
                    "subfinder",
                    "httpx",
                    "naabu",
                    "nuclei",
                    "amass",
                    "dnsx",
                    "katana",
                    "feroxbuster",
                    "wpscan",
                    "z",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
                shell: vec![],
                net: vec![],
                secrets: vec![],
                tools: vec!["*".into()],
                require_approval: vec![
                    "agent.fs.write".into(),
                    "agent.fs.delete".into(),
                    "agent.net".into(),
                    "agent.secret.read".into(),
                ],
                max_parallel: 2,
                non_interactive: false,
            },
            "agent-ci" | "ci" => Self {
                name: "agent-ci".into(),
                description: "Non-interactive build/test allowlist with hard timeouts".into(),
                read: vec!["./**".into()],
                write: vec!["./**".into()],
                delete: vec![],
                exec: [
                    "cargo", "rustc", "make", "npm", "pnpm", "yarn", "node", "python3", "pytest",
                    "go",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
                shell: vec!["cargo ".into(), "npm test".into(), "pnpm test".into()],
                net: vec![],
                secrets: vec![],
                tools: vec![
                    "zentrion/read_file".into(),
                    "zentrion/list_dir".into(),
                    "zentrion/run_command".into(),
                ],
                require_approval: vec![],
                max_parallel: 4,
                non_interactive: true,
            },
            _ => return None,
        };
        Some(profile)
    }

    pub fn builtin_names() -> &'static [&'static str] {
        &["agent-readonly", "agent-dev", "agent-security", "agent-ci"]
    }

    /// Build an effective policy by applying this profile.
    ///
    /// Profile scopes are authoritative for `agent.*` actions; other policy
    /// sections (filesystem for the human, tools, network for plugins) are
    /// preserved unchanged. The broker still evaluates every request.
    pub fn apply(&self, base: &z_policy::Policy) -> z_policy::Policy {
        let mut policy = base.clone();
        policy.agent.read = self.read.clone();
        policy.agent.write = self.write.clone();
        policy.agent.delete = self.delete.clone();
        policy.agent.exec = self.exec.clone();
        policy.agent.shell = self.shell.clone();
        policy.agent.net = self.net.clone();
        policy.agent.secrets = self.secrets.clone();
        policy.agent.tools = self.tools.clone();
        policy
    }

    pub fn requires_approval(&self, action: &str) -> bool {
        self.require_approval
            .iter()
            .any(|required| required == action)
    }

    /// Serialize the profile as the policy agent table for `z policy show`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "description": self.description,
            "read": self.read,
            "write": self.write,
            "delete": self.delete,
            "exec": self.exec,
            "shell": self.shell,
            "net": self.net,
            "secrets": self.secrets,
            "tools": self.tools,
            "require_approval": self.require_approval,
            "non_interactive": self.non_interactive,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_cover_the_documented_profiles() {
        for name in AgentProfile::builtin_names() {
            let profile = AgentProfile::builtin(name).unwrap();
            assert!(!profile.description.is_empty());
            let policy = profile.apply(&z_policy::Policy::default());
            assert!(!policy.agent.read.is_empty() || name == &"agent-ci");
        }
    }

    #[test]
    fn readonly_has_no_write_or_exec() {
        let profile = AgentProfile::builtin("agent-readonly").unwrap();
        let policy = profile.apply(&z_policy::Policy::default());
        assert!(policy.agent.write.is_empty());
        assert!(policy.agent.exec.is_empty());
        assert!(policy.agent.net.is_empty());
        let decision = z_policy::evaluate(
            &policy,
            &z_policy::PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.fs.write".into(),
                resource: "src/main.rs".into(),
            },
        );
        assert_eq!(decision.decision, z_policy::Decision::Deny);
    }

    #[test]
    fn dev_can_write_workspace_but_not_delete() {
        let profile = AgentProfile::builtin("agent-dev").unwrap();
        let policy = profile.apply(&z_policy::Policy::default());
        let write = z_policy::evaluate(
            &policy,
            &z_policy::PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.fs.write".into(),
                resource: "src/main.rs".into(),
            },
        );
        assert_eq!(write.decision, z_policy::Decision::Allow);
        assert!(profile.requires_approval("agent.fs.delete"));
        let delete = z_policy::evaluate(
            &policy,
            &z_policy::PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.fs.delete".into(),
                resource: "src/main.rs".into(),
            },
        );
        assert_eq!(delete.decision, z_policy::Decision::Deny);
    }

    #[test]
    fn unknown_profile_is_none() {
        assert!(AgentProfile::builtin("agent-root").is_none());
    }
}
