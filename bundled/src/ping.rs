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
        let attempt =
            tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(addr)).await;
        let attempt = match attempt {
            Ok(result) => result,
            Err(_) => return Err(anyhow!("Timed out connecting to {}", addr)),
        };
        match attempt {
            Ok(_) => {
                println!("Successfully connected to {}", addr);
                Ok(())
            }
            Err(e) => Err(anyhow!("Failed to connect to {}: {}", addr, e)),
        }
    }
}
