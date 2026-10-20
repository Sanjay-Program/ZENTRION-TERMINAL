//! AI bill of materials derived from the actual project and environment.
//!
//! The BOM reports what is configured or declared, never invented providers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct AiBom {
    pub project_name: String,
    pub timestamp: DateTime<Utc>,
    pub components: Vec<Component>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub component_type: String,
    pub version: Option<String>,
    pub provider: Option<String>,
    pub source: String,
}

pub fn generate_ai_bom(project_name: &str) -> anyhow::Result<AiBom> {
    let mut components = Vec::new();
    let mut seen = BTreeSet::new();

    // 1. Runtime environment configuration.
    let provider = std::env::var("ZENTRION_AI_PROVIDER").ok();
    let model = std::env::var("ZENTRION_AI_MODEL").ok();
    if provider.is_some() || model.is_some() {
        let name = model.clone().unwrap_or_else(|| "default model".into());
        if seen.insert(format!("model:{name}")) {
            components.push(Component {
                name,
                component_type: "Model".into(),
                version: None,
                provider,
                source: "environment (ZENTRION_AI_*)".into(),
            });
        }
    }

    // 2. Project AI configuration.
    for relative in [".zentrion/ai.yaml", "ai.yaml"] {
        let path = Path::new(relative);
        if let Ok(text) = std::fs::read_to_string(path) {
            let mut file_provider = None;
            let mut file_model: Option<String> = None;
            for line in text.lines() {
                let line = line.trim();
                if let Some(value) = line.strip_prefix("provider:") {
                    file_provider = Some(value.trim().trim_matches('"').to_string());
                }
                if let Some(value) = line.strip_prefix("model:") {
                    let value = value.trim().trim_matches('"');
                    if !value.is_empty() {
                        file_model = Some(value.to_string());
                    }
                }
            }
            if file_provider.is_some() || file_model.is_some() {
                let name = file_model.unwrap_or_else(|| "configured model".into());
                if seen.insert(format!("model:{name}")) {
                    components.push(Component {
                        name,
                        component_type: "Model".into(),
                        version: None,
                        provider: file_provider,
                        source: relative.to_string(),
                    });
                }
            }
        }
    }

    // 3. MCP servers declared in the project manifest.
    for relative in [".zentrion/project.yaml", "project.yaml"] {
        if let Ok(text) = std::fs::read_to_string(relative) {
            let mut in_servers = false;
            for line in text.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("servers:") {
                    in_servers = true;
                    continue;
                }
                if in_servers {
                    if !line.starts_with(' ') && !line.trim().is_empty() {
                        in_servers = false;
                        continue;
                    }
                    if let Some(name) = trimmed.strip_prefix("- name:") {
                        let name = name.trim().trim_matches('"').to_string();
                        if seen.insert(format!("mcp:{name}")) {
                            components.push(Component {
                                name,
                                component_type: "MCP Server".into(),
                                version: None,
                                provider: None,
                                source: relative.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // 4. Declared AI SDK dependencies.
    let sdk_markers = [
        "openai",
        "anthropic",
        "langchain",
        "ollama",
        "transformers",
        "pytorch",
        "torch",
        "llama-cpp",
        "mistralai",
        "cohere",
    ];
    for manifest in [
        "Cargo.toml",
        "package.json",
        "requirements.txt",
        "pyproject.toml",
    ] {
        if let Ok(text) = std::fs::read_to_string(manifest) {
            for marker in sdk_markers {
                if text.to_ascii_lowercase().contains(marker) {
                    let label = format!("{marker} (declared dependency)");
                    if seen.insert(format!("sdk:{marker}")) {
                        components.push(Component {
                            name: label,
                            component_type: "AI Library".into(),
                            version: None,
                            provider: Some(marker.to_string()),
                            source: manifest.to_string(),
                        });
                    }
                }
            }
        }
    }

    if components.is_empty() {
        components.push(Component {
            name: "none configured".into(),
            component_type: "Provider".into(),
            version: None,
            provider: None,
            source: "environment/project scan".into(),
        });
    }

    Ok(AiBom {
        project_name: project_name.to_string(),
        timestamp: Utc::now(),
        components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_project_reports_none_instead_of_inventing_models() {
        let bom = generate_ai_bom("empty").unwrap();
        assert!(!bom.components.is_empty());
        assert!(bom
            .components
            .iter()
            .any(|c| c.name == "none configured" && c.component_type == "Provider"));
        assert!(!bom.components.iter().any(|c| c.name.contains("Claude")));
    }
}
