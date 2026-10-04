use crate::registry::BundledTool;
use anyhow::{anyhow, Result};
use async_trait::async_trait;

pub struct CurlTool;

#[async_trait]
impl BundledTool for CurlTool {
    async fn execute(&self, args: &[String]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Missing URL argument"));
        }
        let url = &args[0];
        let resp = reqwest::get(url).await?;
        println!("Status: {}", resp.status());
        let body = resp.text().await?;
        println!("Body: {}", body);
        Ok(())
    }
}
