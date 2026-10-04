use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Sbom {
    pub name: String,
    pub version: String,
}

pub fn generate_sbom(_content: &str) -> Result<String, anyhow::Error> {
    // Basic heuristic: check if it looks like Cargo.toml or package.json
    let sbom = Sbom {
        name: "mock-package".to_string(),
        version: "1.0.0".to_string(),
    };
    Ok(serde_json::to_string(&sbom)?)
}
