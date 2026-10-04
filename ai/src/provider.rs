use crate::models::{ChatChoice, ChatRequest, ChatResponse};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::env;

#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn chat(&self, request: ChatRequest) -> anyhow::Result<ChatResponse>;
}

pub fn provider_from_env() -> anyhow::Result<Box<dyn Provider>> {
    let provider = env::var("ZENTRION_AI_PROVIDER")
        .unwrap_or_else(|_| "ollama".to_string())
        .to_ascii_lowercase();

    match provider.as_str() {
        "ollama" | "local" => Ok(Box::new(OllamaProvider::new(
            env::var("ZENTRION_AI_BASE_URL")
                .ok()
                .or_else(|| env::var("OLLAMA_HOST").ok()),
        ))),
        "openai" => {
            let api_key = env::var("ZENTRION_AI_API_KEY")
                .or_else(|_| env::var("OPENAI_API_KEY"))
                .map_err(|_| {
                    anyhow::anyhow!("OPENAI_API_KEY or ZENTRION_AI_API_KEY is required")
                })?;
            Ok(Box::new(OpenAIProvider::new(api_key)))
        }
        "qwen" | "dashscope" => {
            let api_key = env::var("ZENTRION_AI_API_KEY")
                .or_else(|_| env::var("DASHSCOPE_API_KEY"))
                .map_err(|_| {
                    anyhow::anyhow!("DASHSCOPE_API_KEY or ZENTRION_AI_API_KEY is required")
                })?;
            Ok(Box::new(OpenAICompatibleProvider::from_config(
                OpenAICompatibleConfig::qwen_dashscope(api_key),
            )))
        }
        "openai-compatible" | "compatible" | "custom" => {
            let base_url = env::var("ZENTRION_AI_BASE_URL")
                .or_else(|_| env::var("OPENAI_BASE_URL"))
                .map_err(|_| {
                    anyhow::anyhow!("ZENTRION_AI_BASE_URL or OPENAI_BASE_URL is required")
                })?;
            let api_key = env::var("ZENTRION_AI_API_KEY")
                .or_else(|_| env::var("OPENAI_API_KEY"))
                .unwrap_or_else(|_| "local".to_string());
            let name = env::var("ZENTRION_AI_PROVIDER_NAME")
                .unwrap_or_else(|_| "openai-compatible".to_string());
            Ok(Box::new(OpenAICompatibleProvider::from_config(
                OpenAICompatibleConfig::new(name, base_url, api_key),
            )))
        }
        other => Err(anyhow::anyhow!(
            "unsupported ZENTRION_AI_PROVIDER `{}`; use ollama, openai, qwen, or openai-compatible",
            other
        )),
    }
}

pub struct OpenAIProvider {
    inner: OpenAICompatibleProvider,
}

impl OpenAIProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            inner: OpenAICompatibleProvider::new(
                "openai",
                "https://api.openai.com/v1".to_string(),
                api_key,
            ),
        }
    }
}

#[async_trait]
impl Provider for OpenAIProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    async fn chat(&self, request: ChatRequest) -> anyhow::Result<ChatResponse> {
        self.inner.chat(request).await
    }
}

#[derive(Debug, Clone)]
pub struct OpenAICompatibleConfig {
    pub name: String,
    pub base_url: String,
    pub api_key: String,
}

impl OpenAICompatibleConfig {
    pub fn new(
        name: impl Into<String>,
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.into(),
            api_key: api_key.into(),
        }
    }

    pub fn qwen_dashscope(api_key: impl Into<String>) -> Self {
        Self::new(
            "qwen-dashscope",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
            api_key,
        )
    }

    pub fn local(base_url: impl Into<String>) -> Self {
        Self::new("local-openai-compatible", base_url, "local")
    }
}

pub struct OpenAICompatibleProvider {
    name: String,
    base_url: String,
    api_key: String,
    client: Client,
}

impl OpenAICompatibleProvider {
    pub fn new(name: impl Into<String>, base_url: String, api_key: String) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            client: Client::new(),
        }
    }

    pub fn from_config(config: OpenAICompatibleConfig) -> Self {
        Self::new(config.name, config.base_url, config.api_key)
    }
}

#[async_trait]
impl Provider for OpenAICompatibleProvider {
    fn name(&self) -> &'static str {
        "openai-compatible"
    }

    async fn chat(&self, request: ChatRequest) -> anyhow::Result<ChatResponse> {
        let url = format!("{}/chat/completions", self.base_url);
        let mut req = self.client.post(url).json(&request);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }

        let response = req.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "{} API error ({}): {}",
                self.name,
                status,
                error_text
            ));
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
            return Err(anyhow::anyhow!(
                "Ollama API error ({}): {}",
                status,
                error_text
            ));
        }

        let ollama_resp: serde_json::Value = response.json().await?;
        let message = ollama_resp
            .get("message")
            .ok_or_else(|| anyhow::anyhow!("Missing 'message' in Ollama response"))?
            .clone();

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
