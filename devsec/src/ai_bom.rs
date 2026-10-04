use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

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
}

pub fn generate_ai_bom(project_name: &str) -> anyhow::Result<AiBom> {
    Ok(AiBom {
        project_name: project_name.to_string(),
        timestamp: Utc::now(),
        components: vec![
            Component {
                name: "Claude 3.5 Sonnet".to_string(),
                component_type: "Model".to_string(),
                version: Some("3.5".to_string()),
                provider: Some("Anthropic".to_string()),
            },
            Component {
                name: "DevSecOps Agent".to_string(),
                component_type: "Agent".to_string(),
                version: Some("1.0.0".to_string()),
                provider: Some("Zentrion".to_string()),
            },
            Component {
                name: "Github MCP Server".to_string(),
                component_type: "MCP Server".to_string(),
                version: None,
                provider: Some("OpenSource".to_string()),
            },
        ],
    })
}
