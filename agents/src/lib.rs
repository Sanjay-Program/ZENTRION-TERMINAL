use anyhow::Result;

pub struct AgentRuntime {
    memory_limit: usize,
}

impl AgentRuntime {
    pub fn new(memory_limit: usize) -> Self {
        Self { memory_limit }
    }

    pub async fn start(&self) -> Result<()> {
        loop {
            // loop for checking memory and limits
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            self.check_limits()?;
        }
    }

    fn check_limits(&self) -> Result<()> {
        // Dummy check
        Ok(())
    }
}
