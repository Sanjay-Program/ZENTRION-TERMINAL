use crate::models::{ChatRequest, ChatResponse};
use crate::provider::Provider;
use anyhow::Result;

pub struct AIGateway {
    provider: Box<dyn Provider>,
}

impl AIGateway {
    pub fn new(provider: Box<dyn Provider>) -> Self {
        Self { provider }
    }

    pub async fn chat(&self, mut request: ChatRequest) -> Result<ChatResponse> {
        self.redact_secrets(&mut request);
        self.check_policy(&request)?;
        
        self.provider.chat(request).await
    }

    fn redact_secrets(&self, request: &mut ChatRequest) {
        for msg in &mut request.messages {
            msg.content = msg.content.replace("SECRET", "[REDACTED]");
        }
    }

    fn check_policy(&self, _request: &ChatRequest) -> Result<()> {
        Ok(())
    }
}
