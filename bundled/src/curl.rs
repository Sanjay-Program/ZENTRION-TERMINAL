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
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            // Redirects could move the request to a host that policy did not
            // authorize; the caller can follow them explicitly.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let resp = client.get(url).send().await?;
        println!("Status: {}", resp.status());
        let body = resp.text().await?;
        if body.len() > 1024 * 1024 {
            println!("Body (truncated to 1 MiB):\n{}", &body[..1024 * 1024]);
        } else {
            println!("Body: {}", body);
        }
        Ok(())
    }
}
