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
        // Advanced Data Firewall utilizing regex to scrub sensitive data before outbound calls
        let aws_regex = regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
        let rsa_regex = regex::Regex::new(r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----").unwrap();
        let email_regex = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();

        for msg in &mut request.messages {
            let mut content = aws_regex.replace_all(&msg.content, "[REDACTED AWS KEY]").to_string();
            content = rsa_regex.replace_all(&content, "[REDACTED PRIVATE KEY]").to_string();
            content = email_regex.replace_all(&content, "[REDACTED PII EMAIL]").to_string();
            msg.content = content;
        }
    }

    fn check_policy(&self, _request: &ChatRequest) -> Result<()> {
        Ok(())
    }
}
