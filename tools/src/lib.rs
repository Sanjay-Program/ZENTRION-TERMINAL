use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use z_package::{download_tool, verify_checksum};

pub struct ToolManager {
    tools_dir: PathBuf,
}

impl ToolManager {
    pub fn new<P: AsRef<Path>>(tools_dir: P) -> Self {
        Self {
            tools_dir: tools_dir.as_ref().to_path_buf(),
        }
    }

    pub async fn install_tool(
        &self,
        name: &str,
        url: &str,
        expected_sha256: Option<&str>,
    ) -> Result<()> {
        let dest_path = self.tools_dir.join(name);

        download_tool(url, &dest_path)
            .await
            .context("Failed to download tool")?;

        if let Some(checksum) = expected_sha256 {
            let is_valid = verify_checksum(&dest_path, checksum).await?;
            if !is_valid {
                // Remove the invalid file
                let _ = std::fs::remove_file(&dest_path);
                anyhow::bail!("Checksum verification failed for tool: {}", name);
            }
        }

        Ok(())
    }

    pub fn list_tools(&self) -> Result<Vec<String>> {
        if !self.tools_dir.exists() {
            return Ok(Vec::new());
        }

        let mut tools = Vec::new();
        for entry in std::fs::read_dir(&self.tools_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    tools.push(name.to_string());
                }
            }
        }

        Ok(tools)
    }

    pub fn remove_tool(&self, name: &str) -> Result<()> {
        let tool_path = self.tools_dir.join(name);
        if tool_path.exists() {
            std::fs::remove_file(&tool_path).context("Failed to remove tool")?;
        }
        Ok(())
    }
}
