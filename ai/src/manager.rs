use crate::provider::{OpenAIProvider, OllamaProvider, Provider};
use anyhow::Result;
use std::collections::HashMap;

/// Manages multiple AI model connections and connection pools simultaneously.
pub struct AIModelManager {
    providers: HashMap<String, Box<dyn Provider>>,
}

impl AIModelManager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn register_provider(&mut self, name: &str, provider: Box<dyn Provider>) {
        self.providers.insert(name.to_string(), provider);
    }

    pub fn get_provider(&self, name: &str) -> Option<&Box<dyn Provider>> {
        self.providers.get(name)
    }
}

/// Routes an intent to the most appropriate AI model.
pub struct ModelRouter {
    manager: AIModelManager,
}

impl ModelRouter {
    pub fn new(manager: AIModelManager) -> Self {
        Self { manager }
    }

    /// Determines the best model based on the complexity of the request.
    pub fn route_intent(&self, intent: &str) -> Result<&Box<dyn Provider>> {
        let intent_lower = intent.to_lowercase();
        
        // Fast, cheap, local tasks like quick tokenization or simple renaming
        if intent_lower.contains("fast") || intent_lower.contains("rename") {
            if let Some(p) = self.manager.get_provider("ollama") {
                return Ok(p);
            }
        }
        
        // Default to a heavy reasoning cloud model (e.g. OpenAI) for complex tasks
        if let Some(p) = self.manager.get_provider("openai") {
            return Ok(p);
        }

        Err(anyhow::anyhow!("No suitable AI provider found for this intent"))
    }
}
