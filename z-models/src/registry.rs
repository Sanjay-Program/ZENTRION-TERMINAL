//! Provider registry and model reference resolution.
//!
//! Built-in providers are conservative defaults; a `[models.providers]` entry
//! replaces a built-in with the same id. Credentials are only ever referenced
//! by environment-variable name.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use z_config::{ModelRouting, ModelsConfig, ProviderConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Local,
    OpenAi,
    Anthropic,
    Gemini,
    OpenRouter,
    Groq,
    Custom,
}

impl ProviderKind {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "local" | "ollama" | "lmstudio" | "vllm" => Self::Local,
            "openai" => Self::OpenAi,
            "anthropic" | "claude" => Self::Anthropic,
            "gemini" | "google" => Self::Gemini,
            "openrouter" => Self::OpenRouter,
            "groq" => Self::Groq,
            _ => Self::Custom,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
            Self::OpenRouter => "openrouter",
            Self::Groq => "groq",
            Self::Custom => "custom",
        }
    }

    pub fn is_local(self) -> bool {
        self == Self::Local
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderSpec {
    pub id: String,
    pub kind: ProviderKind,
    pub models: Vec<String>,
    pub caps: Vec<String>,
    pub input_cost_per_mtok: f64,
    pub output_cost_per_mtok: f64,
    pub context: usize,
    pub base_url: Option<String>,
    pub api_key_env: Option<String>,
    pub latency_ms: u64,
    pub quality: u8,
}

impl ProviderSpec {
    pub fn from_config(id: &str, config: &ProviderConfig) -> Self {
        let kind = ProviderKind::parse(&config.kind);
        let default_base = match kind {
            ProviderKind::Local => Some("http://127.0.0.1:11434/v1".to_string()),
            ProviderKind::OpenAi => Some("https://api.openai.com/v1".to_string()),
            ProviderKind::Anthropic => Some("https://api.anthropic.com".to_string()),
            ProviderKind::Gemini => {
                Some("https://generativelanguage.googleapis.com/v1beta/openai".to_string())
            }
            ProviderKind::OpenRouter => Some("https://openrouter.ai/api/v1".to_string()),
            ProviderKind::Groq => Some("https://api.groq.com/openai/v1".to_string()),
            ProviderKind::Custom => None,
        };
        Self {
            id: id.to_string(),
            kind,
            models: if config.models.is_empty() {
                vec!["default".into()]
            } else {
                config.models.clone()
            },
            caps: if config.caps.is_empty() {
                vec!["chat".into()]
            } else {
                config.caps.clone()
            },
            input_cost_per_mtok: config.cost_per_mtok,
            output_cost_per_mtok: config.output_cost_per_mtok.unwrap_or(config.cost_per_mtok),
            context: config.context,
            base_url: config.base_url.clone().or(default_base),
            api_key_env: config.api_key_env.clone().or_else(|| match kind {
                ProviderKind::OpenAi => Some("OPENAI_API_KEY".into()),
                ProviderKind::Anthropic => Some("ANTHROPIC_API_KEY".into()),
                ProviderKind::Gemini => Some("GEMINI_API_KEY".into()),
                ProviderKind::OpenRouter => Some("OPENROUTER_API_KEY".into()),
                ProviderKind::Groq => Some("GROQ_API_KEY".into()),
                _ => None,
            }),
            latency_ms: config
                .latency_ms
                .unwrap_or(if kind.is_local() { 50 } else { 900 }),
            quality: config
                .quality
                .unwrap_or(if kind.is_local() { 60 } else { 85 }),
        }
    }

    pub fn credential_present(&self) -> bool {
        match &self.api_key_env {
            None => true,
            Some(name) => std::env::var_os(name).is_some(),
        }
    }

    pub fn supports(&self, caps: &[String]) -> bool {
        caps.iter().all(|cap| self.caps.iter().any(|c| c == cap))
    }

    pub fn model_refs(&self) -> Vec<String> {
        self.models
            .iter()
            .map(|model| format!("{}/{}", self.id, model))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Registry {
    providers: Vec<ProviderSpec>,
    default: String,
    fallback: Vec<String>,
    allow_cloud: bool,
    routing: ModelRouting,
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub provider: ProviderSpec,
    pub model: String,
    /// The model reference as configured (provider/model).
    pub reference: String,
}

impl Registry {
    pub fn from_config(config: &ModelsConfig) -> Self {
        let mut providers: BTreeMap<String, ProviderSpec> = builtins()
            .into_iter()
            .map(|provider| (provider.id.clone(), provider))
            .collect();
        for (id, provider) in &config.providers {
            providers.insert(id.clone(), ProviderSpec::from_config(id, provider));
        }
        // Make sure every referenced model has a provider entry.
        for reference in std::iter::once(&config.default).chain(config.fallback.iter()) {
            if resolve_in(&providers, reference).is_none() {
                if let Some(provider) = synthesize(reference) {
                    match providers.get_mut(&provider.id) {
                        Some(existing) => {
                            for model in provider.models {
                                if !existing.models.contains(&model) {
                                    existing.models.push(model);
                                }
                            }
                        }
                        None => {
                            providers.insert(provider.id.clone(), provider);
                        }
                    }
                }
            }
        }
        let mut list: Vec<ProviderSpec> = providers.into_values().collect();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        Self {
            providers: list,
            default: config.default.clone(),
            fallback: config.fallback.clone(),
            allow_cloud: config.allow_cloud,
            routing: config.routing,
        }
    }

    pub fn providers(&self) -> &[ProviderSpec] {
        &self.providers
    }

    pub fn routing(&self) -> ModelRouting {
        self.routing
    }

    pub fn allow_cloud(&self) -> bool {
        self.allow_cloud
    }

    pub fn default_reference(&self) -> &str {
        &self.default
    }

    pub fn fallback_references(&self) -> &[String] {
        &self.fallback
    }

    pub fn resolve(&self, reference: &str) -> Option<Resolved> {
        let map: BTreeMap<String, ProviderSpec> = self
            .providers
            .iter()
            .map(|provider| (provider.id.clone(), provider.clone()))
            .collect();
        resolve_in(&map, reference)
    }

    /// All model references the registry knows, in a deterministic order.
    pub fn all_references(&self) -> Vec<String> {
        let mut refs = Vec::new();
        for provider in &self.providers {
            refs.extend(provider.model_refs());
        }
        refs.sort();
        refs.dedup();
        refs
    }

    /// Ordered candidates for a request.
    pub fn candidates(
        &self,
        override_reference: Option<&str>,
        required_caps: &[String],
    ) -> Vec<Resolved> {
        let mut references: Vec<String> = Vec::new();
        if let Some(reference) = override_reference {
            references.push(reference.to_string());
        }
        references.push(self.default.clone());
        references.extend(self.fallback.iter().cloned());
        references.dedup();

        let mut resolved: Vec<Resolved> = references
            .iter()
            .filter_map(|reference| self.resolve(reference))
            .filter(|resolved| resolved.provider.supports(required_caps))
            .filter(|resolved| self.allow_cloud || resolved.provider.kind.is_local())
            .collect();

        // Manual/local-only still need a deterministic order.
        if resolved.is_empty() && override_reference.is_none() {
            // Nothing configured is usable; fall back to any local model that
            // satisfies the request, then any model at all if cloud is allowed.
            for provider in &self.providers {
                if (self.allow_cloud || provider.kind.is_local())
                    && provider.supports(required_caps)
                {
                    for model in &provider.models {
                        resolved.push(Resolved {
                            provider: provider.clone(),
                            model: model.clone(),
                            reference: format!("{}/{}", provider.id, model),
                        });
                    }
                }
            }
        }
        resolved
    }
}

fn resolve_in(providers: &BTreeMap<String, ProviderSpec>, reference: &str) -> Option<Resolved> {
    // Longest provider-id prefix first, so `local/ollama/...` beats `local`.
    let mut ids: Vec<&String> = providers.keys().collect();
    ids.sort_by_key(|id| std::cmp::Reverse(id.len()));
    for id in ids {
        if let Some(model) = reference
            .strip_prefix(id.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
        {
            if !model.is_empty() {
                return Some(Resolved {
                    provider: providers[id].clone(),
                    model: model.to_string(),
                    reference: reference.to_string(),
                });
            }
        }
    }
    // Match by kind prefix (`openai/gpt-4o`) or by model name alone.
    let (prefix, model) = reference.split_once('/').unwrap_or(("", reference));
    for provider in providers.values() {
        if provider.kind.as_str() == prefix && provider.models.iter().any(|m| m == model) {
            return Some(Resolved {
                provider: provider.clone(),
                model: model.to_string(),
                reference: reference.to_string(),
            });
        }
    }
    for provider in providers.values() {
        if provider.models.iter().any(|m| m == reference || m == model) {
            return Some(Resolved {
                provider: provider.clone(),
                model: model.to_string(),
                reference: reference.to_string(),
            });
        }
    }
    None
}

fn synthesize(reference: &str) -> Option<ProviderSpec> {
    let (prefix, model) = reference.split_once('/')?;
    let kind = ProviderKind::parse(prefix);
    if kind == ProviderKind::Custom
        && !matches!(
            prefix,
            "local" | "openai" | "anthropic" | "gemini" | "openrouter" | "groq"
        )
    {
        return None;
    }
    let template = builtins()
        .into_iter()
        .find(|provider| provider.kind == kind)?;
    Some(ProviderSpec {
        id: template.id.clone(),
        models: vec![model.to_string()],
        ..template
    })
}

pub fn builtins() -> Vec<ProviderSpec> {
    vec![
        ProviderSpec {
            id: "local/ollama".into(),
            kind: ProviderKind::Local,
            models: vec!["qwen2.5-coder:7b".into()],
            caps: vec!["chat".into(), "tools".into(), "code".into()],
            input_cost_per_mtok: 0.0,
            output_cost_per_mtok: 0.0,
            context: 32_768,
            base_url: Some("http://127.0.0.1:11434/v1".into()),
            api_key_env: None,
            latency_ms: 50,
            quality: 60,
        },
        ProviderSpec {
            id: "openai".into(),
            kind: ProviderKind::OpenAi,
            models: vec!["gpt-4o-mini".into()],
            caps: vec![
                "chat".into(),
                "tools".into(),
                "code".into(),
                "vision".into(),
            ],
            input_cost_per_mtok: 0.15,
            output_cost_per_mtok: 0.60,
            context: 128_000,
            base_url: Some("https://api.openai.com/v1".into()),
            api_key_env: Some("OPENAI_API_KEY".into()),
            latency_ms: 900,
            quality: 85,
        },
        ProviderSpec {
            id: "anthropic".into(),
            kind: ProviderKind::Anthropic,
            models: vec!["claude-sonnet-4-20250514".into()],
            caps: vec![
                "chat".into(),
                "tools".into(),
                "code".into(),
                "vision".into(),
            ],
            input_cost_per_mtok: 3.0,
            output_cost_per_mtok: 15.0,
            context: 200_000,
            base_url: Some("https://api.anthropic.com".into()),
            api_key_env: Some("ANTHROPIC_API_KEY".into()),
            latency_ms: 1_100,
            quality: 92,
        },
        ProviderSpec {
            id: "gemini".into(),
            kind: ProviderKind::Gemini,
            models: vec!["gemini-2.5-pro".into()],
            caps: vec![
                "chat".into(),
                "tools".into(),
                "code".into(),
                "vision".into(),
            ],
            input_cost_per_mtok: 1.25,
            output_cost_per_mtok: 10.0,
            context: 1_000_000,
            base_url: Some("https://generativelanguage.googleapis.com/v1beta/openai".into()),
            api_key_env: Some("GEMINI_API_KEY".into()),
            latency_ms: 1_000,
            quality: 90,
        },
        ProviderSpec {
            id: "openrouter".into(),
            kind: ProviderKind::OpenRouter,
            models: vec!["openai/gpt-4o-mini".into()],
            caps: vec!["chat".into(), "tools".into(), "code".into()],
            input_cost_per_mtok: 0.15,
            output_cost_per_mtok: 0.60,
            context: 128_000,
            base_url: Some("https://openrouter.ai/api/v1".into()),
            api_key_env: Some("OPENROUTER_API_KEY".into()),
            latency_ms: 1_000,
            quality: 85,
        },
        ProviderSpec {
            id: "groq".into(),
            kind: ProviderKind::Groq,
            models: vec!["llama-3.3-70b-versatile".into()],
            caps: vec!["chat".into(), "tools".into()],
            input_cost_per_mtok: 0.59,
            output_cost_per_mtok: 0.79,
            context: 128_000,
            base_url: Some("https://api.groq.com/openai/v1".into()),
            api_key_env: Some("GROQ_API_KEY".into()),
            latency_ms: 300,
            quality: 78,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ModelsConfig {
        let mut config = ModelsConfig::default();
        config.default = "local/qwen2.5-coder:7b".into();
        config.fallback = vec!["openai/gpt-4o-mini".into()];
        config.allow_cloud = true;
        config
    }

    #[test]
    fn resolves_builtin_and_configured_models() {
        let registry = Registry::from_config(&config());
        let local = registry.resolve("local/qwen2.5-coder:7b").unwrap();
        assert_eq!(local.provider.kind, ProviderKind::Local);
        assert_eq!(local.model, "qwen2.5-coder:7b");
        let openai = registry.resolve("openai/gpt-4o-mini").unwrap();
        assert_eq!(openai.provider.id, "openai");
        assert!(registry.providers().len() >= 5);
    }

    #[test]
    fn config_provider_overrides_builtin() {
        let mut config = config();
        config.providers.insert(
            "openai".into(),
            ProviderConfig {
                kind: "openai".into(),
                models: vec!["custom-model".into()],
                cost_per_mtok: 9.0,
                base_url: Some("https://proxy.example/v1".into()),
                api_key_env: Some("PROXY_KEY".into()),
                ..Default::default()
            },
        );
        let registry = Registry::from_config(&config);
        let resolved = registry.resolve("openai/custom-model").unwrap();
        assert_eq!(resolved.provider.input_cost_per_mtok, 9.0);
        assert_eq!(
            resolved.provider.base_url.as_deref(),
            Some("https://proxy.example/v1")
        );
    }

    #[test]
    fn cloud_models_are_excluded_when_not_allowed() {
        let mut config = config();
        config.allow_cloud = false;
        let registry = Registry::from_config(&config);
        let candidates = registry.candidates(None, &["chat".into()]);
        assert!(candidates.iter().all(|c| c.provider.kind.is_local()));
    }

    #[test]
    fn unknown_references_do_not_silently_route() {
        let registry = Registry::from_config(&config());
        assert!(registry.resolve("nonsense/model").is_none());
    }

    #[test]
    fn capability_filtering_works() {
        let mut config = config();
        config.default = "openai/gpt-4o-mini".into();
        config.allow_cloud = true;
        let registry = Registry::from_config(&config);
        let candidates = registry.candidates(None, &["vision".into()]);
        assert!(!candidates.is_empty());
        assert!(candidates
            .iter()
            .all(|c| c.provider.supports(&["vision".into()])));
    }
}
