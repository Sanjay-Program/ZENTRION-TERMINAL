use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait BundledTool: Send + Sync {
    async fn execute(&self, args: &[String]) -> Result<()>;
}

pub struct BundledRegistry {
    tools: HashMap<String, Arc<dyn BundledTool>>,
}

impl BundledRegistry {
    pub fn new() -> Self {
        let mut tools: HashMap<String, Arc<dyn BundledTool>> = HashMap::new();
        tools.insert("z-curl".to_string(), Arc::new(crate::curl::CurlTool));
        tools.insert("z-sysinfo".to_string(), Arc::new(crate::sysinfo::SysinfoTool));
        tools.insert("z-ping".to_string(), Arc::new(crate::ping::PingTool));
        Self { tools }
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn BundledTool>> {
        self.tools.get(name).cloned()
    }
}

impl Default for BundledRegistry {
    fn default() -> Self {
        Self::new()
    }
}
