use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PluginType {
    Wasm,
    Native,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub plugin_type: PluginType,
    pub entrypoint: String,
}

pub struct PluginManager {
    plugins: Vec<PluginManifest>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    pub async fn load<P: AsRef<Path>>(&mut self, wasm_path: P) -> Result<()> {
        let path = wasm_path.as_ref();
        if !path.exists() {
            return Err(anyhow!("WASM file does not exist: {:?}", path));
        }

        let manifest = PluginManifest {
            name: path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            version: "1.0.0".to_string(),
            plugin_type: PluginType::Wasm,
            entrypoint: path.to_string_lossy().into_owned(),
        };

        self.plugins.push(manifest);
        Ok(())
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}
