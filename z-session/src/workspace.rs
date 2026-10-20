//! Workspaces, layouts and restore planning.
//!
//! Layouts are versioned YAML. Validation happens before anything is spawned.
//! `restore` policy decides how much is restored, and commands are never run
//! automatically unless the file opts in with `auto_run` (or the user passes an
//! explicit approval flag).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const WORKSPACE_VERSION: u32 = 1;
pub const MAX_PANES: usize = 64;
pub const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Horizontal,
    Vertical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Pane {
    pub cwd: Option<String>,
    pub command: Option<String>,
    pub profile: Option<String>,
    pub agent: Option<String>,
    /// Nested split: direction of the children.
    pub split: Option<Direction>,
    pub panes: Vec<Pane>,
    /// Alternative nested form: `layout: { direction, panes }`.
    pub layout: Option<Layout>,
    pub weight: Option<u16>,
    /// Explicit opt-in to run `command` on restore.
    pub auto_run: bool,
    pub title: Option<String>,
}

impl Default for Pane {
    fn default() -> Self {
        Self {
            cwd: None,
            command: None,
            profile: None,
            agent: None,
            split: None,
            panes: Vec::new(),
            layout: None,
            weight: None,
            auto_run: false,
            title: None,
        }
    }
}

impl Pane {
    pub fn is_leaf(&self) -> bool {
        self.panes.is_empty() && self.layout.is_none()
    }

    fn children(&self) -> Option<(Direction, &[Pane])> {
        if let Some(layout) = &self.layout {
            return Some((layout.direction, &layout.panes));
        }
        if !self.panes.is_empty() {
            return Some((self.split.unwrap_or(Direction::Horizontal), &self.panes));
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Layout {
    pub direction: Direction,
    pub panes: Vec<Pane>,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            direction: Direction::Horizontal,
            panes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tab {
    pub title: String,
    #[serde(default)]
    pub layout: Layout,
    #[serde(default)]
    pub focus: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default = "default_restore")]
    pub restore: z_config::RestorePolicy,
    #[serde(default)]
    pub auto_run: bool,
    #[serde(default)]
    pub tabs: Vec<Tab>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

fn default_restore() -> z_config::RestorePolicy {
    z_config::RestorePolicy::LayoutAndCwd
}

impl Workspace {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            version: WORKSPACE_VERSION,
            name: name.into(),
            root: None,
            restore: z_config::RestorePolicy::LayoutAndCwd,
            auto_run: false,
            tabs: Vec::new(),
            profile: None,
            created_at: Some(Utc::now()),
            metadata: None,
        }
    }

    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.version != WORKSPACE_VERSION {
            issues.push(format!(
                "unsupported workspace version {} (expected {WORKSPACE_VERSION})",
                self.version
            ));
        }
        if self.name.trim().is_empty() {
            issues.push("workspace name must not be empty".into());
        }
        if self.name.contains(['/', '\\', '\0']) || self.name == "." || self.name == ".." {
            issues.push("workspace name must be a file name, not a path".into());
        }
        if let Some(root) = &self.root {
            if root.trim().is_empty() {
                issues.push("root must not be empty when present".into());
            }
            if root.contains('\0') {
                issues.push("root contains a NUL byte".into());
            }
        }
        if self.tabs.is_empty() {
            issues.push("workspace must have at least one tab".into());
        }
        let mut titles = std::collections::BTreeSet::new();
        let mut panes = 0usize;
        for (index, tab) in self.tabs.iter().enumerate() {
            if tab.title.trim().is_empty() {
                issues.push(format!("tab {index} has an empty title"));
            }
            if !titles.insert(tab.title.clone()) {
                issues.push(format!("duplicate tab title `{}`", tab.title));
            }
            if tab.layout.panes.is_empty() {
                issues.push(format!("tab `{}` has no panes", tab.title));
            }
            validate_panes(
                &tab.layout.panes,
                1,
                &format!("tab `{}`", tab.title),
                &mut panes,
                &mut issues,
            );
        }
        if panes > MAX_PANES {
            issues.push(format!("workspace has {panes} panes (maximum {MAX_PANES})"));
        }
        issues
    }

    pub fn checked(self) -> Result<Self, WorkspaceError> {
        let issues = self.validate();
        if issues.is_empty() {
            Ok(self)
        } else {
            Err(WorkspaceError::Invalid(issues))
        }
    }
}

fn validate_panes(
    panes: &[Pane],
    depth: usize,
    context: &str,
    count: &mut usize,
    issues: &mut Vec<String>,
) {
    *count += panes.len();
    if depth > MAX_DEPTH {
        issues.push(format!("{context}: layout nesting exceeds {MAX_DEPTH}"));
        return;
    }
    for (index, pane) in panes.iter().enumerate() {
        let label = format!("{context} pane {}", index + 1);
        if pane.command.is_some() && pane.agent.is_some() {
            issues.push(format!("{label}: cannot be both a command and an agent"));
        }
        if let Some(command) = &pane.command {
            if command.trim().is_empty() {
                issues.push(format!("{label}: command must not be empty"));
            }
            if command.contains('\0') {
                issues.push(format!("{label}: command contains a NUL byte"));
            }
        }
        if let Some(agent) = &pane.agent {
            if agent.trim().is_empty() {
                issues.push(format!("{label}: agent name must not be empty"));
            }
        }
        if let Some(cwd) = &pane.cwd {
            if cwd.trim().is_empty() || cwd.contains('\0') {
                issues.push(format!("{label}: invalid cwd"));
            }
        }
        match pane.children() {
            Some((_, children)) => {
                if children.len() < 2 {
                    issues.push(format!("{label}: a split needs at least two panes"));
                }
                validate_panes(children, depth + 1, &label, count, issues);
            }
            None => {
                if pane.panes.is_empty()
                    && pane.layout.is_none()
                    && pane.command.is_none()
                    && pane.agent.is_none()
                    && pane.cwd.is_none()
                {
                    // A bare pane is a valid request for "just a shell here".
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceError {
    Io { path: String, message: String },
    Parse { path: String, message: String },
    Invalid(Vec<String>),
    NotFound(String),
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, message } => write!(f, "{path}: {message}"),
            Self::Parse { path, message } => write!(f, "{path}: {message}"),
            Self::Invalid(issues) => {
                write!(f, "invalid workspace:")?;
                for issue in issues {
                    write!(f, "\n  - {issue}")?;
                }
                Ok(())
            }
            Self::NotFound(name) => write!(f, "workspace `{name}` not found"),
        }
    }
}

impl std::error::Error for WorkspaceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaneAction {
    Shell {
        cwd: Option<String>,
    },
    Command {
        command: String,
        cwd: Option<String>,
    },
    Agent {
        agent: String,
        cwd: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanePlan {
    pub tab: String,
    pub pane_index: usize,
    pub action: PaneAction,
    pub requires_approval: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestorePlan {
    pub actions: Vec<PanePlan>,
    pub pending_approval: Vec<PanePlan>,
    pub warnings: Vec<String>,
}

/// Build a restore plan without spawning anything.
pub fn plan_restore(
    workspace: &Workspace,
    policy: z_config::RestorePolicy,
    approve_commands: bool,
) -> RestorePlan {
    use z_config::RestorePolicy;
    let mut plan = RestorePlan::default();
    if policy == RestorePolicy::Never {
        plan.warnings
            .push("restore policy is `never`; starting a clean workspace".into());
        return plan;
    }
    let root = workspace.root.clone();
    let mut pane_index = 0usize;
    for tab in &workspace.tabs {
        collect_plan(
            &tab.layout.panes,
            &tab.title,
            policy,
            workspace.auto_run,
            approve_commands,
            &root,
            &mut pane_index,
            &mut plan,
        );
    }
    if !plan.pending_approval.is_empty() {
        plan.warnings.push(format!(
            "{} command/agent pane(s) need approval before running",
            plan.pending_approval.len()
        ));
    }
    plan
}

#[allow(clippy::too_many_arguments)]
fn collect_plan(
    panes: &[Pane],
    tab: &str,
    policy: z_config::RestorePolicy,
    workspace_auto_run: bool,
    approve_commands: bool,
    root: &Option<String>,
    pane_index: &mut usize,
    plan: &mut RestorePlan,
) {
    use z_config::RestorePolicy;
    for pane in panes {
        if let Some((_, children)) = pane.children() {
            collect_plan(
                children,
                tab,
                policy,
                workspace_auto_run,
                approve_commands,
                root,
                pane_index,
                plan,
            );
            continue;
        }
        *pane_index += 1;
        let cwd = if policy == RestorePolicy::Layout {
            root.clone()
        } else {
            pane.cwd.clone().or_else(|| root.clone())
        };
        let requires_approval = !(workspace_auto_run || pane.auto_run || approve_commands);
        if let Some(command) = &pane.command {
            let entry = PanePlan {
                tab: tab.to_string(),
                pane_index: *pane_index,
                action: PaneAction::Command {
                    command: command.clone(),
                    cwd: cwd.clone(),
                },
                requires_approval,
                reason: Some(if requires_approval {
                    "command panes only auto-run with `auto_run: true` or --approve".into()
                } else {
                    "approved to auto-run".into()
                }),
            };
            if policy == RestorePolicy::Full {
                if requires_approval {
                    plan.pending_approval.push(entry);
                } else {
                    plan.actions.push(entry);
                }
            } else {
                plan.warnings.push(format!(
                    "{tab} pane {}: command not restored under `{:?}` policy",
                    pane_index, policy
                ));
                plan.actions.push(PanePlan {
                    tab: tab.to_string(),
                    pane_index: *pane_index,
                    action: PaneAction::Shell { cwd },
                    requires_approval: false,
                    reason: Some("command skipped by restore policy".into()),
                });
            }
            continue;
        }
        if let Some(agent) = &pane.agent {
            let entry = PanePlan {
                tab: tab.to_string(),
                pane_index: *pane_index,
                action: PaneAction::Agent {
                    agent: agent.clone(),
                    cwd: cwd.clone(),
                },
                requires_approval,
                reason: Some(if requires_approval {
                    "agent panes only auto-start with `auto_run: true` or --approve".into()
                } else {
                    "approved to auto-start".into()
                }),
            };
            if policy == RestorePolicy::Full {
                if requires_approval {
                    plan.pending_approval.push(entry);
                } else {
                    plan.actions.push(entry);
                }
            } else {
                plan.warnings.push(format!(
                    "{tab} pane {}: agent not started under `{:?}` policy",
                    pane_index, policy
                ));
                plan.actions.push(PanePlan {
                    tab: tab.to_string(),
                    pane_index: *pane_index,
                    action: PaneAction::Shell { cwd },
                    requires_approval: false,
                    reason: Some("agent skipped by restore policy".into()),
                });
            }
            continue;
        }
        plan.actions.push(PanePlan {
            tab: tab.to_string(),
            pane_index: *pane_index,
            action: PaneAction::Shell { cwd },
            requires_approval: false,
            reason: None,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceSummary {
    pub name: String,
    pub path: String,
    pub tabs: usize,
    pub panes: usize,
    pub restore: z_config::RestorePolicy,
}

pub struct WorkspaceStore {
    dir: PathBuf,
}

impl WorkspaceStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn default_dir() -> Option<PathBuf> {
        z_core::config::user_data_dir().map(|dir| dir.join("workspaces"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_for(&self, name: &str) -> Result<PathBuf, WorkspaceError> {
        if name.contains(['/', '\\', '\0']) || name == "." || name == ".." || name.is_empty() {
            return Err(WorkspaceError::Invalid(vec![
                "workspace name must be a file name".into(),
            ]));
        }
        Ok(self.dir.join(format!("{name}.yaml")))
    }

    pub fn save(&self, workspace: &Workspace) -> Result<PathBuf, WorkspaceError> {
        workspace.clone().checked()?;
        std::fs::create_dir_all(&self.dir).map_err(|e| WorkspaceError::Io {
            path: self.dir.display().to_string(),
            message: e.to_string(),
        })?;
        let mut workspace = workspace.clone();
        if workspace.created_at.is_none() {
            workspace.created_at = Some(Utc::now());
        }
        let text = serde_yaml::to_string(&workspace).map_err(|e| WorkspaceError::Parse {
            path: workspace.name.clone(),
            message: e.to_string(),
        })?;
        let path = self.path_for(&workspace.name)?;
        let tmp = path.with_extension("yaml.tmp");
        std::fs::write(&tmp, text).map_err(|e| WorkspaceError::Io {
            path: tmp.display().to_string(),
            message: e.to_string(),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path).map_err(|e| WorkspaceError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        Ok(path)
    }

    pub fn load(&self, name: &str) -> Result<Workspace, WorkspaceError> {
        self.load_path(&self.path_for(name)?)
    }

    pub fn load_path(&self, path: &Path) -> Result<Workspace, WorkspaceError> {
        if !path.exists() {
            return Err(WorkspaceError::NotFound(path.display().to_string()));
        }
        let text = std::fs::read_to_string(path).map_err(|e| WorkspaceError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let workspace: Workspace =
            serde_yaml::from_str(&text).map_err(|e| WorkspaceError::Parse {
                path: path.display().to_string(),
                message: e.to_string(),
            })?;
        workspace.checked()
    }

    pub fn list(&self) -> Result<Vec<WorkspaceSummary>, WorkspaceError> {
        let mut summaries = Vec::new();
        if !self.dir.exists() {
            return Ok(summaries);
        }
        let entries = std::fs::read_dir(&self.dir).map_err(|e| WorkspaceError::Io {
            path: self.dir.display().to_string(),
            message: e.to_string(),
        })?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }
            if let Ok(workspace) = self.load_path(&path) {
                summaries.push(WorkspaceSummary {
                    name: workspace.name.clone(),
                    path: path.display().to_string(),
                    tabs: workspace.tabs.len(),
                    panes: count_panes(&workspace),
                    restore: workspace.restore,
                });
            }
        }
        summaries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(summaries)
    }

    pub fn delete(&self, name: &str) -> Result<(), WorkspaceError> {
        let path = self.path_for(name)?;
        if !path.exists() {
            return Err(WorkspaceError::NotFound(name.to_string()));
        }
        std::fs::remove_file(&path).map_err(|e| WorkspaceError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })
    }
}

fn count_panes(workspace: &Workspace) -> usize {
    fn recurse(panes: &[Pane]) -> usize {
        panes
            .iter()
            .map(|pane| match pane.children() {
                Some((_, children)) => recurse(children),
                None => 1,
            })
            .sum()
    }
    workspace
        .tabs
        .iter()
        .map(|tab| recurse(&tab.layout.panes))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
version: 1
name: payments-api
root: /work/payments
restore: layout+cwd
tabs:
  - title: api
    layout:
      direction: horizontal
      panes:
        - cwd: /work/payments
          command: cargo watch -x run
        - cwd: /work/payments
          split: vertical
          panes:
            - command: cargo test
            - command: git status
  - title: agents
    layout:
      direction: vertical
      panes:
        - agent: claude-code
        - agent: codex
"#;

    #[test]
    fn blueprint_example_parses_and_validates() {
        let workspace: Workspace = serde_yaml::from_str(EXAMPLE).unwrap();
        let issues = workspace.validate();
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(workspace.name, "payments-api");
        assert_eq!(workspace.restore, z_config::RestorePolicy::LayoutAndCwd);
        assert_eq!(count_panes(&workspace), 5);
    }

    #[test]
    fn invalid_layouts_are_rejected() {
        let mut workspace = Workspace::new("bad");
        workspace.tabs.push(Tab {
            title: "one".into(),
            layout: Layout {
                direction: Direction::Horizontal,
                panes: vec![
                    Pane {
                        command: Some("echo hi".into()),
                        agent: Some("claude-code".into()),
                        ..Default::default()
                    },
                    Pane {
                        split: Some(Direction::Vertical),
                        panes: vec![Pane::default()],
                        ..Default::default()
                    },
                ],
            },
            focus: false,
        });
        let issues = workspace.validate();
        assert!(issues
            .iter()
            .any(|i| i.contains("both a command and an agent")));
        assert!(issues.iter().any(|i| i.contains("at least two")));
    }

    #[test]
    fn commands_never_auto_run_without_opt_in() {
        let workspace: Workspace = serde_yaml::from_str(EXAMPLE).unwrap();
        let plan = plan_restore(&workspace, z_config::RestorePolicy::Full, false);
        assert!(plan
            .actions
            .iter()
            .all(|action| !matches!(action.action, PaneAction::Command { .. })));
        assert!(plan
            .pending_approval
            .iter()
            .any(|action| matches!(action.action, PaneAction::Command { .. })));
        let approved = plan_restore(&workspace, z_config::RestorePolicy::Full, true);
        assert!(approved
            .actions
            .iter()
            .any(|action| matches!(action.action, PaneAction::Command { .. })));
    }

    #[test]
    fn layout_policy_restores_shells_only() {
        let workspace: Workspace = serde_yaml::from_str(EXAMPLE).unwrap();
        let plan = plan_restore(&workspace, z_config::RestorePolicy::Layout, false);
        assert_eq!(plan.actions.len(), 5);
        assert!(plan
            .actions
            .iter()
            .all(|action| matches!(action.action, PaneAction::Shell { .. })));
    }

    #[test]
    fn store_round_trips_and_rejects_traversal() {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-workspaces-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let store = WorkspaceStore::new(&dir);
        let mut workspace: Workspace = serde_yaml::from_str(EXAMPLE).unwrap();
        workspace.created_at = Some(Utc::now());
        let path = store.save(&workspace).unwrap();
        assert!(path.exists());
        let loaded = store.load("payments-api").unwrap();
        assert_eq!(loaded, workspace);
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.load("../etc/passwd").is_err());
        store.delete("payments-api").unwrap();
        assert!(store.load("payments-api").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
