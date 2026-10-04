use crate::models::{ChatRequest, ChatResponse};
use async_trait::async_trait;

#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn chat(&self, request: ChatRequest) -> anyhow::Result<ChatResponse>;
}
