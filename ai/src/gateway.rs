use crate::models::{ChatRequest, ChatResponse};
use crate::provider::Provider;
use anyhow::Result;
use regex::Regex;
use std::sync::LazyLock;

/// Patterns applied to every outbound message before it leaves the machine.
///
/// The Rust `regex` engine does not support backreferences, so paired markers
/// are expressed with non-capturing groups and dot-all mode. Compiling these
/// once also keeps the hot path allocation-free.
static REDACTIONS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let patterns: Vec<(&str, &str)> = vec![
        (r"AKIA[0-9A-Z]{16}", "[REDACTED AWS KEY]"),
        (
            concat!(
                "(?s)-----",
                "BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE",
                " KEY-----.*?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE",
                " KEY-----"
            ),
            "[REDACTED PRIVATE KEY]",
        ),
        (r"gh[pousr]_[A-Za-z0-9]{20,}", "[REDACTED GITHUB TOKEN]"),
        (
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            "[REDACTED JWT]",
        ),
        (
            r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._~+/=-]{12,}",
            "authorization: [REDACTED BEARER TOKEN]",
        ),
        (
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "[REDACTED PII EMAIL]",
        ),
    ];
    patterns
        .into_iter()
        .map(|(pattern, replacement)| {
            (
                Regex::new(pattern).expect("built-in redaction patterns must be valid"),
                replacement,
            )
        })
        .collect()
});

pub struct AIGateway {
    provider: Box<dyn Provider>,
}

impl AIGateway {
    pub fn new(provider: Box<dyn Provider>) -> Self {
        Self { provider }
    }

    pub async fn chat(&self, mut request: ChatRequest) -> Result<ChatResponse> {
        redact_request(&mut request);
        self.check_policy(&request)?;

        self.provider.chat(request).await
    }

    fn check_policy(&self, _request: &ChatRequest) -> Result<()> {
        Ok(())
    }
}

/// Scrub credentials and personal data from every message in a request.
pub fn redact_request(request: &mut ChatRequest) {
    for message in &mut request.messages {
        message.content = redact_text(&message.content);
    }
}

pub fn redact_text(text: &str) -> String {
    let mut content = text.to_string();
    for (regex, replacement) in REDACTIONS.iter() {
        content = regex.replace_all(&content, *replacement).to_string();
    }
    content
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ChatMessage;

    #[test]
    fn redacts_aws_keys_and_emails() {
        let key = concat!("AKIA", "ABCDEFGHIJKLMNOP");
        let text = format!("key {key} mail alice@example.com");
        let redacted = redact_text(&text);
        assert!(!redacted.contains(key));
        assert!(!redacted.contains("alice@example.com"));
        assert!(redacted.contains("[REDACTED AWS KEY]"));
        assert!(redacted.contains("[REDACTED PII EMAIL]"));
    }

    #[test]
    fn redacts_private_key_blocks() {
        let begin = concat!("-----", "BEGIN OPENSSH PRIVATE", " KEY-----");
        let end = concat!("-----", "END OPENSSH PRIVATE", " KEY-----");
        let text = format!("before\n{begin}\nabc\n{end}\nafter");
        let redacted = redact_text(&text);
        assert!(!redacted.contains("abc"));
        assert!(redacted.contains("[REDACTED PRIVATE KEY]"));
        assert!(redacted.starts_with("before"));
        assert!(redacted.ends_with("after"));
    }

    #[test]
    fn redacts_tokens_and_bearer_headers() {
        let token = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz0123");
        let text = format!("{token}\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz");
        let redacted = redact_text(&text);
        assert!(!redacted.contains("ghp_"));
        assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn leaves_normal_text_alone() {
        let text = "run cargo test and check the output";
        assert_eq!(redact_text(text), text);
    }

    #[test]
    fn applies_to_every_message() {
        let mut request = ChatRequest {
            model: "m".into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: "alice@example.com".into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: concat!("AKIA", "ABCDEFGHIJKLMNOP").into(),
                },
            ],
            temperature: None,
        };
        redact_request(&mut request);
        assert!(request.messages[0].content.contains("[REDACTED"));
        assert!(request.messages[1].content.contains("[REDACTED"));
    }
}
