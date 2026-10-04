use crate::models::{ChatChoice, ChatRequest, ChatResponse};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn chat(&self, request: ChatRequest) -> anyhow::Result<ChatResponse>;
}

pub struct OpenAIProvider {
    api_key: String,
    client: Client,
}

impl OpenAIProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: Client::new(),
        }
    }
}

#[async_trait]
impl Provider for OpenAIProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    async fn chat(&self, request: ChatRequest) -> anyhow::Result<ChatResponse> {
        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(&self.api_key)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("OpenAI API error ({}): {}", status, error_text));
        }

        let chat_response: ChatResponse = response.json().await?;
        Ok(chat_response)
    }
}

pub struct OllamaProvider {
    base_url: String,
    client: Client,
}

impl OllamaProvider {
    pub fn new(base_url: Option<String>) -> Self {
        Self {
            base_url: base_url.unwrap_or_else(|| "http://localhost:11434".to_string()),
            client: Client::new(),
        }
    }
}

#[async_trait]
impl Provider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn chat(&self, request: ChatRequest) -> anyhow::Result<ChatResponse> {
        let mut body = serde_json::to_value(&request)?;
        if let Some(obj) = body.as_object_mut() {
            obj.insert("stream".to_string(), json!(false));
        }

        let response = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("Ollama API error ({}): {}", status, error_text));
        }

        let ollama_resp: serde_json::Value = response.json().await?;
        let message = ollama_resp.get("message").ok_or_else(|| anyhow::anyhow!("Missing 'message' in Ollama response"))?.clone();
        
        let chat_message = serde_json::from_value(message)?;

        let chat_response = ChatResponse {
            id: String::new(),
            choices: vec![ChatChoice {
                index: 0,
                message: chat_message,
                finish_reason: Some("stop".to_string()),
            }],
        };

        Ok(chat_response)
    }
}
