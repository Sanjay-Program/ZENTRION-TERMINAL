use crate::registry::BundledTool;
use anyhow::Result;
use async_trait::async_trait;

pub struct SysinfoTool;

#[async_trait]
impl BundledTool for SysinfoTool {
    async fn execute(&self, _args: &[String]) -> Result<()> {
        println!("CPU Architecture: {}", std::env::consts::ARCH);
        println!("OS: {}", std::env::consts::OS);
        Ok(())
    }
}
