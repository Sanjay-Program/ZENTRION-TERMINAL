//! Provider transports. Only HTTP(S) endpoints; credentials are read from the
//! environment variable named by the provider and never logged.

use crate::registry::ProviderKind;
use crate::router::Route;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".into(),
            content: content.into(),
        }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".into(),
            content: content.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatOutput {
    pub text: String,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_micros: u64,
    pub cached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    MissingCredential { provider: String, env: String },
    Network(String),
    Status { status: u16, body: String },
    InvalidResponse(String),
    Timeout,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCredential { provider, env } => {
                write!(
                    f,
                    "provider `{provider}` needs environment variable `{env}`"
                )
            }
            Self::Network(error) => write!(f, "network error: {error}"),
            Self::Status { status, body } => write!(f, "provider returned HTTP {status}: {body}"),
            Self::InvalidResponse(error) => write!(f, "invalid provider response: {error}"),
            Self::Timeout => f.write_str("provider request timed out"),
        }
    }
}

impl std::error::Error for TransportError {}

pub trait Transport: Send + Sync {
    fn chat(
        &self,
        route: &Route,
        messages: &[ChatMessage],
        max_tokens: u32,
        timeout: Duration,
    ) -> Result<ChatOutput, TransportError>;
}

impl<T: Transport + ?Sized> Transport for std::sync::Arc<T> {
    fn chat(
        &self,
        route: &Route,
        messages: &[ChatMessage],
        max_tokens: u32,
        timeout: Duration,
    ) -> Result<ChatOutput, TransportError> {
        (**self).chat(route, messages, max_tokens, timeout)
    }
}

pub struct HttpTransport;

impl HttpTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for HttpTransport {
    fn chat(
        &self,
        route: &Route,
        messages: &[ChatMessage],
        max_tokens: u32,
        timeout: Duration,
    ) -> Result<ChatOutput, TransportError> {
        let spec = route
            .spec
            .as_ref()
            .ok_or_else(|| TransportError::InvalidResponse("route has no provider spec".into()))?;
        let base = spec
            .base_url
            .as_deref()
            .ok_or_else(|| TransportError::InvalidResponse("provider has no base URL".into()))?;
        let key = match &spec.api_key_env {
            Some(env) => {
                Some(
                    std::env::var(env).map_err(|_| TransportError::MissingCredential {
                        provider: spec.id.clone(),
                        env: env.clone(),
                    })?,
                )
            }
            None => None,
        };
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        let (url, body, auth_header) = match spec.kind {
            ProviderKind::Anthropic => {
                let url = format!("{}/v1/messages", base.trim_end_matches('/'));
                let body = serde_json::json!({
                    "model": route.model,
                    "max_tokens": max_tokens,
                    "messages": messages.iter().filter(|m| m.role != "system").map(|m| {
                        serde_json::json!({"role": m.role, "content": m.content})
                    }).collect::<Vec<_>>(),
                    "system": messages.iter().filter(|m| m.role == "system").map(|m| m.content.clone()).collect::<Vec<_>>().join("\n\n"),
                });
                (
                    url,
                    body,
                    Some(("x-api-key", key.clone().unwrap_or_default())),
                )
            }
            _ => {
                let url = format!("{}/chat/completions", base.trim_end_matches('/'));
                let body = serde_json::json!({
                    "model": route.model,
                    "max_tokens": max_tokens,
                    "messages": messages,
                });
                (
                    url,
                    body,
                    key.clone()
                        .map(|key| ("authorization", format!("Bearer {key}"))),
                )
            }
        };
        let mut request = agent.post(&url).set("content-type", "application/json");
        if let Some((name, value)) = auth_header {
            if !value.is_empty() {
                request = request.set(name, &value);
            }
        }
        if spec.kind == ProviderKind::Anthropic {
            request = request.set("anthropic-version", "2023-06-01");
        }
        let response = match request.send_json(body) {
            Ok(response) => response,
            Err(ureq::Error::Status(status, response)) => {
                let body = response
                    .into_string()
                    .unwrap_or_default()
                    .chars()
                    .take(500)
                    .collect::<String>();
                let (body, _) = z_blocks::redact(&body);
                return Err(TransportError::Status { status, body });
            }
            Err(ureq::Error::Transport(error)) => {
                let text = error.to_string();
                let (text, _) = z_blocks::redact(&text);
                return Err(TransportError::Network(text));
            }
        };
        let value: serde_json::Value = response
            .into_json()
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))?;
        let (text, tokens_in, tokens_out) = match spec.kind {
            ProviderKind::Anthropic => {
                let text = value
                    .get("content")
                    .and_then(|content| content.as_array())
                    .map(|blocks| {
                        blocks
                            .iter()
                            .filter_map(|block| block.get("text").and_then(|text| text.as_str()))
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .unwrap_or_default();
                let tokens_in = value
                    .pointer("/usage/input_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| estimate_tokens(messages));
                let tokens_out = value
                    .pointer("/usage/output_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| estimate_tokens_text(&text));
                (text, tokens_in, tokens_out)
            }
            _ => {
                let text = value
                    .pointer("/choices/0/message/content")
                    .and_then(|content| content.as_str())
                    .unwrap_or_default()
                    .to_string();
                let tokens_in = value
                    .pointer("/usage/prompt_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| estimate_tokens(messages));
                let tokens_out = value
                    .pointer("/usage/completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| estimate_tokens_text(&text));
                (text, tokens_in, tokens_out)
            }
        };
        if text.is_empty() {
            return Err(TransportError::InvalidResponse(
                "response contained no text".into(),
            ));
        }
        let cost_micros = crate::ledger::estimate_micros(
            spec.input_cost_per_mtok,
            spec.output_cost_per_mtok,
            tokens_in as usize,
            tokens_out as u32,
        );
        Ok(ChatOutput {
            text,
            tokens_in,
            tokens_out,
            cost_micros,
            cached: false,
        })
    }
}

pub fn estimate_tokens(messages: &[ChatMessage]) -> u64 {
    messages
        .iter()
        .map(|message| estimate_tokens_text(&message.content))
        .sum::<u64>()
        + 16
}

pub fn estimate_tokens_text(text: &str) -> u64 {
    (text.chars().count() as u64).div_ceil(4) + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_estimation_is_conservative() {
        assert!(estimate_tokens_text("hello world") >= 3);
        assert_eq!(estimate_tokens_text(""), 1);
    }

    #[test]
    fn missing_credentials_are_named_not_leaked() {
        let error = TransportError::MissingCredential {
            provider: "openai".into(),
            env: "OPENAI_API_KEY".into(),
        };
        assert!(error.to_string().contains("OPENAI_API_KEY"));
    }
}
