//! Notebook schema and validation.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

pub const NOTEBOOK_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Notebook {
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, z_workflow::ParamSpec>,
    #[serde(default)]
    pub working_dir: Option<String>,
    pub cells: Vec<Cell>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellKind {
    Markdown,
    Shell,
    Ai,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    pub id: String,
    pub kind: CellKind,
    pub source: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub continue_on_error: bool,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotebookError(pub Vec<String>);

impl std::fmt::Display for NotebookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid notebook:")?;
        for issue in &self.0 {
            write!(f, "\n  - {issue}")?;
        }
        Ok(())
    }
}

impl std::error::Error for NotebookError {}

impl Notebook {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            version: NOTEBOOK_VERSION,
            name: name.into(),
            description: Some("A Zentrion notebook".into()),
            params: BTreeMap::new(),
            working_dir: None,
            cells: vec![
                Cell {
                    id: "intro".into(),
                    kind: CellKind::Markdown,
                    source: "# New notebook\n\nDescribe the task here.".into(),
                    cwd: None,
                    timeout: None,
                    continue_on_error: false,
                    model: None,
                    tags: Vec::new(),
                },
                Cell {
                    id: "check".into(),
                    kind: CellKind::Shell,
                    source: "echo \"hello from Zentrion\"".into(),
                    cwd: None,
                    timeout: Some("30s".into()),
                    continue_on_error: false,
                    model: None,
                    tags: Vec::new(),
                },
            ],
        }
    }

    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.version != NOTEBOOK_VERSION {
            issues.push(format!("unsupported notebook version {}", self.version));
        }
        if self.name.trim().is_empty() {
            issues.push("notebook name must not be empty".into());
        }
        if self.cells.is_empty() {
            issues.push("notebook must have at least one cell".into());
        }
        let mut ids = BTreeSet::new();
        for cell in &self.cells {
            if cell.id.trim().is_empty() {
                issues.push("cell id must not be empty".into());
            } else if !ids.insert(cell.id.clone()) {
                issues.push(format!("duplicate cell id `{}`", cell.id));
            }
            if let Some(timeout) = &cell.timeout {
                if z_workflow::parse_duration(timeout).is_none() {
                    issues.push(format!(
                        "cell `{}` has invalid timeout `{timeout}`",
                        cell.id
                    ));
                }
            }
            if cell.kind != CellKind::Markdown && cell.source.trim().is_empty() {
                issues.push(format!("cell `{}` has empty source", cell.id));
            }
            if let Some(cwd) = &cell.cwd {
                if cwd.contains('\0') || cwd.is_empty() {
                    issues.push(format!("cell `{}` has invalid cwd", cell.id));
                }
            }
        }
        for (name, spec) in &self.params {
            if spec.kind != "string"
                && spec.kind != "number"
                && spec.kind != "bool"
                && spec.kind != "boolean"
                && spec.kind != "enum"
            {
                issues.push(format!(
                    "parameter `{name}` has unknown type `{}`",
                    spec.kind
                ));
            }
            if spec.kind == "enum" && spec.allowed.is_empty() {
                issues.push(format!("enum parameter `{name}` needs an enum list"));
            }
            if spec.secret && spec.default.is_some() {
                issues.push(format!("secret parameter `{name}` must not have a default"));
            }
        }
        issues
    }

    pub fn checked(self) -> Result<Self, NotebookError> {
        let issues = self.validate();
        if issues.is_empty() {
            Ok(self)
        } else {
            Err(NotebookError(issues))
        }
    }

    pub fn resolved_working_dir(&self, notebook_path: &Path) -> PathBuf {
        let base = notebook_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        match &self.working_dir {
            Some(dir) => {
                let path = Path::new(dir);
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    base.join(path)
                }
            }
            None => base,
        }
    }
}

/// Reject `..` components and absolute paths for cell cwd overrides.
pub fn safe_relative(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);
    if path.is_absolute() {
        return Err("path must be relative".into());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("path must not contain `..`".into());
    }
    Ok(path.to_path_buf())
}

pub fn load(path: &Path) -> Result<Notebook, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let notebook: Notebook =
        serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    notebook.checked().map_err(|e| e.to_string())
}

pub fn save(path: &Path, notebook: &Notebook) -> Result<(), String> {
    notebook.clone().checked().map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let text = serde_yaml::to_string(notebook).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_validates() {
        let notebook = Notebook::new("demo");
        assert!(notebook.validate().is_empty());
    }

    #[test]
    fn duplicate_ids_and_bad_timeouts_are_rejected() {
        let mut notebook = Notebook::new("bad");
        notebook.cells.push(notebook.cells[0].clone());
        notebook.cells[0].timeout = Some("2d".into());
        let issues = notebook.validate();
        assert!(issues.iter().any(|issue| issue.contains("duplicate")));
        assert!(issues.iter().any(|issue| issue.contains("timeout")));
    }

    #[test]
    fn traversal_paths_are_rejected() {
        assert!(safe_relative("../etc").is_err());
        assert!(safe_relative("/etc").is_err());
        assert!(safe_relative("src").is_ok());
    }
}
