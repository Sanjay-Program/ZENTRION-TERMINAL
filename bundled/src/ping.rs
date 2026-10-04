use crate::registry::BundledTool;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::TcpStream;

pub struct PingTool;

#[async_trait]
impl BundledTool for PingTool {
    async fn execute(&self, args: &[String]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Missing host:port argument"));
        }
        let addr = &args[0];
        match TcpStream::connect(addr).await {
            Ok(_) => {
                println!("Successfully connected to {}", addr);
                Ok(())
            }
            Err(e) => Err(anyhow!("Failed to connect to {}: {}", addr, e)),
        }
    }
}
