//! Policy-aware model routing, budgets, fallback, circuit breaking and caching.

use crate::ledger::{estimate_micros, UsageLedger, UsageSummary};
use crate::registry::{ProviderKind, ProviderSpec, Registry};
use crate::transport::{estimate_tokens, ChatMessage, ChatOutput, Transport, TransportError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use z_config::{ModelRouting, ModelsConfig};

const FAILURE_THRESHOLD: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(30);
const CACHE_TTL: Duration = Duration::from_secs(600);
const CACHE_MAX_ENTRIES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Route {
    pub provider: String,
    pub provider_kind: String,
    pub model: String,
    pub reference: String,
    pub estimated_micros: u64,
    pub estimated_usd: f64,
    pub latency_ms: u64,
    pub quality: u8,
    pub reason: String,
    #[serde(skip)]
    pub spec: Option<ProviderSpec>,
}

#[derive(Debug, Clone)]
pub struct RouteRequest {
    pub messages: Vec<ChatMessage>,
    pub agent: Option<String>,
    pub session: Option<String>,
    pub task: String,
    pub model_override: Option<String>,
    pub required_caps: Vec<String>,
    pub max_output_tokens: Option<u32>,
    pub routing_override: Option<ModelRouting>,
    pub timeout: Duration,
}

impl RouteRequest {
    pub fn new(task: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            messages,
            agent: None,
            session: None,
            task: task.into(),
            model_override: None,
            required_caps: vec!["chat".into()],
            max_output_tokens: None,
            routing_override: None,
            timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attempt {
    pub provider: String,
    pub model: String,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub skipped_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatOutcome {
    pub text: String,
    pub route: Route,
    pub attempts: Vec<Attempt>,
    pub cached: bool,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_micros: u64,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RouterError {
    NoProvider(String),
    BudgetExceeded(String),
    MissingCredentials(Vec<String>),
    AllFailed(Vec<Attempt>),
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProvider(reason) => write!(f, "no model is available: {reason}"),
            Self::BudgetExceeded(reason) => write!(f, "{reason}"),
            Self::MissingCredentials(providers) => write!(
                f,
                "no usable credentials for: {} (set the named environment variables)",
                providers.join(", ")
            ),
            Self::AllFailed(attempts) => {
                write!(f, "all model attempts failed:")?;
                for attempt in attempts {
                    if let Some(error) = &attempt.error {
                        write!(f, "\n  - {} {}: {error}", attempt.provider, attempt.model)?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for RouterError {}

#[derive(Debug, Clone)]
struct Breaker {
    failures: u32,
    open_until: Option<Instant>,
}

impl Default for Breaker {
    fn default() -> Self {
        Self {
            failures: 0,
            open_until: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredBreaker {
    failures: u32,
    #[serde(default)]
    open_until: Option<u64>,
}

struct CacheEntry {
    output: ChatOutput,
    route: Route,
    inserted: Instant,
}

pub struct Router {
    pub registry: Registry,
    ledger: UsageLedger,
    transport: Box<dyn Transport>,
    max_output_tokens: u32,
    cache_enabled: bool,
    breakers: Mutex<HashMap<String, Breaker>>,
    cache: Mutex<HashMap<String, CacheEntry>>,
    breaker_path: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("providers", &self.registry.providers().len())
            .finish()
    }
}

impl Router {
    pub fn new(config: &ModelsConfig, ledger: UsageLedger, transport: Box<dyn Transport>) -> Self {
        Self {
            registry: Registry::from_config(config),
            ledger,
            transport,
            max_output_tokens: config.max_output_tokens,
            cache_enabled: config.cache,
            breakers: Mutex::new(HashMap::new()),
            cache: Mutex::new(HashMap::new()),
            breaker_path: None,
        }
    }

    /// Persist circuit-breaker state so one-shot CLI calls share health.
    pub fn with_breaker_path(mut self, path: std::path::PathBuf) -> Self {
        self.breaker_path = Some(path.clone());
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(stored) = serde_json::from_str::<HashMap<String, StoredBreaker>>(&text) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut breakers = self.breakers.lock().expect("breaker lock");
                for (reference, state) in stored {
                    let open_until = state
                        .open_until
                        .filter(|until| *until > now)
                        .map(|until| Instant::now() + Duration::from_secs(until - now));
                    breakers.insert(
                        reference,
                        Breaker {
                            failures: state.failures,
                            open_until,
                        },
                    );
                }
            }
        }
        self
    }

    pub fn with_registry(
        registry: Registry,
        ledger: UsageLedger,
        transport: Box<dyn Transport>,
        max_output_tokens: u32,
        cache_enabled: bool,
    ) -> Self {
        Self {
            registry,
            ledger,
            transport,
            max_output_tokens,
            cache_enabled,
            breakers: Mutex::new(HashMap::new()),
            cache: Mutex::new(HashMap::new()),
            breaker_path: None,
        }
    }

    pub fn usage(&self, day: Option<&str>) -> UsageSummary {
        self.ledger.summary(day)
    }

    pub fn ledger(&self) -> &UsageLedger {
        &self.ledger
    }

    /// Plan every affordable candidate in policy order.
    pub fn plan(&self, request: &RouteRequest) -> Result<Vec<Route>, RouterError> {
        let max_output = request
            .max_output_tokens
            .unwrap_or(self.max_output_tokens)
            .clamp(1, 1_000_000);
        let prompt_tokens = estimate_tokens(&request.messages) as usize;
        let mut routes: Vec<Route> = Vec::new();
        let mut missing_credentials: Vec<String> = Vec::new();
        let mut budget_skipped = false;
        let candidates = self
            .registry
            .candidates(request.model_override.as_deref(), &request.required_caps);
        let routing = request.routing_override.unwrap_or(self.registry.routing());
        for resolved in candidates {
            if routing == ModelRouting::LocalOnly && !resolved.provider.kind.is_local() {
                continue;
            }
            if !self.registry.allow_cloud() && !resolved.provider.kind.is_local() {
                continue;
            }
            if !resolved.provider.credential_present() {
                missing_credentials.push(resolved.provider.id.clone());
                continue;
            }
            let estimated = estimate_micros(
                resolved.provider.input_cost_per_mtok,
                resolved.provider.output_cost_per_mtok,
                prompt_tokens,
                max_output,
            );
            if !self.ledger.can_afford(request.agent.as_deref(), estimated) {
                budget_skipped = true;
                continue;
            }
            routes.push(Route {
                provider: resolved.provider.id.clone(),
                provider_kind: resolved.provider.kind.as_str().to_string(),
                model: resolved.model.clone(),
                reference: resolved.reference.clone(),
                estimated_micros: estimated,
                estimated_usd: estimated as f64 / 1_000_000.0,
                latency_ms: resolved.provider.latency_ms,
                quality: resolved.provider.quality,
                reason: String::new(),
                spec: Some(resolved.provider.clone()),
            });
        }
        if routes.is_empty() {
            if budget_skipped {
                return Err(RouterError::BudgetExceeded(format!(
                    "daily model budget cannot cover this request (budget ${:.2}, spent ${:.2})",
                    self.ledger.summary(None).budget_usd,
                    self.ledger.summary(None).spent_usd
                )));
            }
            if !missing_credentials.is_empty() {
                return Err(RouterError::MissingCredentials(missing_credentials));
            }
            return Err(RouterError::NoProvider(
                "check [models] default/fallback and [models.providers]".into(),
            ));
        }
        // De-duplicate identical provider/model references.
        let mut seen = std::collections::HashSet::new();
        routes.retain(|route| seen.insert(route.reference.clone()));
        sort_routes(&mut routes, routing);
        for route in &mut routes {
            route.reason = format!(
                "{} routing: ${:.4} est., {} ms, quality {}",
                format!("{routing:?}").to_lowercase(),
                route.estimated_usd,
                route.latency_ms,
                route.quality
            );
        }
        Ok(routes)
    }

    /// Execute a request with fallback, retries, budget reservations and cache.
    pub fn chat(&self, request: RouteRequest) -> Result<ChatOutcome, RouterError> {
        // Credential-shaped strings never leave the machine. Redaction can
        // change the prompt, so such prompts are not cached.
        let mut messages = request.messages.clone();
        let mut prompt_redacted = false;
        for message in &mut messages {
            let (redacted, found) = z_blocks::redact(&message.content);
            if !found.is_empty() {
                prompt_redacted = true;
            }
            message.content = redacted;
        }
        let routes = self.plan(&request)?;
        let max_output = request
            .max_output_tokens
            .unwrap_or(self.max_output_tokens)
            .clamp(1, 1_000_000);
        let cache_key = cache_key(&request, max_output);
        let cacheable = self.cache_enabled
            && request
                .messages
                .iter()
                .all(|message| z_blocks::redact(&message.content).1.is_empty());
        if cacheable {
            if let Some((cached, cached_route)) = self.cache_get(&cache_key) {
                return Ok(ChatOutcome {
                    text: cached.text.clone(),
                    route: cached_route,
                    attempts: Vec::new(),
                    cached: true,
                    tokens_in: cached.tokens_in,
                    tokens_out: cached.tokens_out,
                    cost_micros: 0,
                    redacted: false,
                });
            }
        }
        let mut attempts = Vec::new();
        for route in routes {
            if self.breaker_open(&route.reference) {
                attempts.push(Attempt {
                    provider: route.provider.clone(),
                    model: route.model.clone(),
                    error: None,
                    duration_ms: 0,
                    skipped_reason: Some("circuit breaker open".into()),
                });
                continue;
            }
            let mut last_error = None;
            for attempt_index in 0..2u32 {
                let reservation = match self.ledger.reserve(
                    route.estimated_micros,
                    request.agent.as_deref(),
                    request.session.as_deref(),
                    &request.task,
                ) {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        last_error = Some(error.to_string());
                        break;
                    }
                };
                let started = Instant::now();
                let result = self
                    .transport
                    .chat(&route, &messages, max_output, request.timeout);
                let duration_ms = started.elapsed().as_millis() as u64;
                match result {
                    Ok(mut output) => {
                        output.cached = false;
                        let cost = output.cost_micros;
                        let _ = self.ledger.commit(
                            &reservation,
                            cost,
                            output.tokens_in,
                            output.tokens_out,
                        );
                        self.record_success(&route.reference);
                        attempts.push(Attempt {
                            provider: route.provider.clone(),
                            model: route.model.clone(),
                            error: None,
                            duration_ms,
                            skipped_reason: None,
                        });
                        if cacheable {
                            self.cache_put(
                                cache_key,
                                ChatOutput {
                                    cached: true,
                                    ..output.clone()
                                },
                                route.clone(),
                            );
                        }
                        return Ok(ChatOutcome {
                            text: output.text,
                            route,
                            attempts,
                            cached: false,
                            tokens_in: output.tokens_in,
                            tokens_out: output.tokens_out,
                            cost_micros: cost,
                            redacted: prompt_redacted,
                        });
                    }
                    Err(error) => {
                        self.ledger.release(&reservation);
                        let message = redact_error(&error);
                        attempts.push(Attempt {
                            provider: route.provider.clone(),
                            model: route.model.clone(),
                            error: Some(message.clone()),
                            duration_ms,
                            skipped_reason: None,
                        });
                        last_error = Some(message);
                        if !retryable(&error) || attempt_index == 1 {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(
                            100 + (Instant::now().elapsed().as_nanos() % 100) as u64,
                        ));
                    }
                }
            }
            let _ = last_error;
            self.record_failure(&route.reference);
        }
        Err(RouterError::AllFailed(attempts))
    }

    fn breaker_open(&self, reference: &str) -> bool {
        let breakers = self.breakers.lock().expect("breaker lock");
        breakers
            .get(reference)
            .and_then(|breaker| breaker.open_until)
            .map(|until| until > Instant::now())
            .unwrap_or(false)
    }

    fn record_failure(&self, reference: &str) {
        {
            let mut breakers = self.breakers.lock().expect("breaker lock");
            let breaker = breakers.entry(reference.to_string()).or_default();
            breaker.failures = breaker.failures.saturating_add(1);
            if breaker.failures >= FAILURE_THRESHOLD {
                breaker.open_until = Some(Instant::now() + COOLDOWN);
            }
        }
        self.persist_breakers();
    }

    fn record_success(&self, reference: &str) {
        {
            let mut breakers = self.breakers.lock().expect("breaker lock");
            breakers.remove(reference);
        }
        self.persist_breakers();
    }

    fn persist_breakers(&self) {
        let Some(path) = &self.breaker_path else {
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let stored: HashMap<String, StoredBreaker> = {
            let breakers = self.breakers.lock().expect("breaker lock");
            breakers
                .iter()
                .map(|(reference, breaker)| {
                    let open_until = breaker.open_until.and_then(|until| {
                        until
                            .checked_duration_since(Instant::now())
                            .map(|remaining| now + remaining.as_secs())
                    });
                    (
                        reference.clone(),
                        StoredBreaker {
                            failures: breaker.failures,
                            open_until,
                        },
                    )
                })
                .collect()
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(&stored) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    fn cache_get(&self, key: &str) -> Option<(ChatOutput, Route)> {
        let mut cache = self.cache.lock().expect("cache lock");
        let entry = cache.get(key)?;
        if entry.inserted.elapsed() > CACHE_TTL {
            cache.remove(key);
            return None;
        }
        Some((entry.output.clone(), entry.route.clone()))
    }

    fn cache_put(&self, key: String, output: ChatOutput, route: Route) {
        let mut cache = self.cache.lock().expect("cache lock");
        if cache.len() >= CACHE_MAX_ENTRIES {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            key,
            CacheEntry {
                output,
                route,
                inserted: Instant::now(),
            },
        );
    }
}

fn sort_routes(routes: &mut [Route], routing: ModelRouting) {
    match routing {
        ModelRouting::Manual => {}
        ModelRouting::LocalOnly => routes.sort_by(|a, b| {
            a.estimated_micros
                .cmp(&b.estimated_micros)
                .then_with(|| b.quality.cmp(&a.quality))
        }),
        ModelRouting::LocalFirst => routes.sort_by(|a, b| {
            let a_local = a.provider_kind == ProviderKind::Local.as_str();
            let b_local = b.provider_kind == ProviderKind::Local.as_str();
            b_local
                .cmp(&a_local)
                .then_with(|| a.estimated_micros.cmp(&b.estimated_micros))
                .then_with(|| b.quality.cmp(&a.quality))
        }),
        ModelRouting::Cost => routes.sort_by(|a, b| {
            a.estimated_micros
                .cmp(&b.estimated_micros)
                .then_with(|| b.quality.cmp(&a.quality))
        }),
        ModelRouting::Latency => routes.sort_by(|a, b| {
            a.latency_ms
                .cmp(&b.latency_ms)
                .then_with(|| a.estimated_micros.cmp(&b.estimated_micros))
        }),
        ModelRouting::Quality => routes.sort_by(|a, b| {
            b.quality
                .cmp(&a.quality)
                .then_with(|| a.estimated_micros.cmp(&b.estimated_micros))
        }),
    }
}

fn retryable(error: &TransportError) -> bool {
    match error {
        TransportError::Network(_) | TransportError::Timeout => true,
        TransportError::Status { status, .. } => *status >= 500,
        _ => false,
    }
}

fn redact_error(error: &TransportError) -> String {
    let (message, _) = z_blocks::redact(&error.to_string());
    message
}

fn cache_key(request: &RouteRequest, max_output: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.task.as_bytes());
    hasher.update([0]);
    hasher.update(
        request
            .model_override
            .clone()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(max_output.to_be_bytes());
    for message in &request.messages {
        hasher.update(message.role.as_bytes());
        hasher.update([0]);
        hasher.update(message.content.as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;
    use crate::transport::{ChatMessage, Transport};
    use std::collections::BTreeMap;

    struct MockTransport {
        calls: Mutex<Vec<String>>,
        prompts: Mutex<Vec<String>>,
        failures: Mutex<HashMap<String, u32>>,
        delay: Duration,
    }

    impl MockTransport {
        fn new(failures: &[(&str, u32)]) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                prompts: Mutex::new(Vec::new()),
                failures: Mutex::new(
                    failures
                        .iter()
                        .map(|(provider, count)| (provider.to_string(), *count))
                        .collect(),
                ),
                delay: Duration::from_millis(0),
            })
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Transport for MockTransport {
        fn chat(
            &self,
            route: &Route,
            messages: &[ChatMessage],
            _max_tokens: u32,
            _timeout: Duration,
        ) -> Result<ChatOutput, TransportError> {
            self.calls.lock().unwrap().push(route.provider.clone());
            self.prompts
                .lock()
                .unwrap()
                .extend(messages.iter().map(|message| message.content.clone()));
            if self.delay > Duration::from_millis(0) {
                std::thread::sleep(self.delay);
            }
            let mut failures = self.failures.lock().unwrap();
            if let Some(remaining) = failures.get_mut(&route.provider) {
                if *remaining > 0 {
                    *remaining -= 1;
                    return Err(TransportError::Network("connection refused".into()));
                }
            }
            Ok(ChatOutput {
                text: format!("answer from {}", route.provider),
                tokens_in: 100,
                tokens_out: 50,
                cost_micros: route.estimated_micros,
                cached: false,
            })
        }
    }

    fn test_config() -> ModelsConfig {
        let mut config = ModelsConfig::default();
        config.default = "local/qwen2.5-coder:7b".into();
        config.fallback = vec!["openai/gpt-4o-mini".into()];
        config.allow_cloud = true;
        config.budget_usd_per_day = 10.0;
        config
    }

    fn test_router(
        config: &ModelsConfig,
        transport: std::sync::Arc<MockTransport>,
        budget: f64,
    ) -> Router {
        Router::new(config, UsageLedger::in_memory(budget), Box::new(transport))
    }

    #[test]
    fn local_first_routes_local_and_returns_usage() {
        let transport = MockTransport::new(&[]);
        let router = test_router(&test_config(), transport.clone(), 10.0);
        let outcome = router
            .chat(RouteRequest::new("chat", vec![ChatMessage::user("hello")]))
            .unwrap();
        assert_eq!(outcome.route.provider, "local/ollama");
        assert_eq!(outcome.text, "answer from local/ollama");
        assert!(outcome.tokens_in > 0);
        assert_eq!(transport.calls(), vec!["local/ollama"]);
        assert!(router.usage(None).requests == 1);
    }

    #[test]
    fn falls_back_when_the_first_provider_fails() {
        let transport = MockTransport::new(&[("local/ollama", 2)]);
        let mut config = test_config();
        config.cache = false;
        config.providers.insert(
            "fallbacktest".into(),
            z_config::ProviderConfig {
                kind: "custom".into(),
                models: vec!["model".into()],
                base_url: Some("https://fallback.example/v1".into()),
                ..Default::default()
            },
        );
        config.fallback = vec!["fallbacktest/model".into()];
        let router = test_router(&config, transport.clone(), 10.0);
        let outcome = router
            .chat(RouteRequest::new("chat", vec![ChatMessage::user("hello")]))
            .unwrap();
        assert_eq!(outcome.route.provider, "fallbacktest");
        assert!(outcome
            .attempts
            .iter()
            .any(|attempt| attempt.provider == "local/ollama" && attempt.error.is_some()));
        assert!(outcome
            .attempts
            .iter()
            .any(|attempt| attempt.provider == "fallbacktest" && attempt.error.is_none()));
    }

    #[test]
    fn budget_is_enforced_before_any_call() {
        let transport = MockTransport::new(&[]);
        let mut config = test_config();
        config.providers.insert(
            "budgettest".into(),
            z_config::ProviderConfig {
                kind: "custom".into(),
                models: vec!["model".into()],
                cost_per_mtok: 100.0,
                base_url: Some("https://budget.example/v1".into()),
                ..Default::default()
            },
        );
        config.default = "budgettest/model".into();
        config.fallback.clear();
        let router = test_router(&config, transport.clone(), 0.0);
        let error = router
            .chat(RouteRequest::new("chat", vec![ChatMessage::user("hello")]))
            .unwrap_err();
        assert!(matches!(error, RouterError::BudgetExceeded(_)), "{error}");
        assert!(transport.calls().is_empty());
    }

    #[test]
    fn local_only_and_missing_credentials_are_handled() {
        let transport = MockTransport::new(&[]);
        let mut config = test_config();
        config.allow_cloud = false;
        let router = test_router(&config, transport.clone(), 10.0);
        let routes = router
            .plan(&RouteRequest::new("chat", vec![ChatMessage::user("hi")]))
            .unwrap();
        assert!(routes.iter().all(|route| route.provider_kind == "local"));

        let mut config = test_config();
        config.allow_cloud = true;
        config.providers.insert(
            "needs-key".into(),
            z_config::ProviderConfig {
                kind: "custom".into(),
                models: vec!["model".into()],
                base_url: Some("https://key.example/v1".into()),
                api_key_env: Some("ZENTRION_TEST_MISSING_KEY".into()),
                ..Default::default()
            },
        );
        config.default = "needs-key/model".into();
        config.fallback.clear();
        std::env::remove_var("ZENTRION_TEST_MISSING_KEY");
        let router = test_router(&config, transport, 10.0);
        let error = router
            .plan(&RouteRequest::new("chat", vec![ChatMessage::user("hi")]))
            .unwrap_err();
        assert!(
            matches!(error, RouterError::MissingCredentials(_)),
            "{error}"
        );
    }

    #[test]
    fn cache_avoids_second_call_unless_prompt_has_a_secret() {
        let transport = MockTransport::new(&[]);
        let router = test_router(&test_config(), transport.clone(), 10.0);
        let request = || RouteRequest::new("chat", vec![ChatMessage::user("same prompt")]);
        router.chat(request()).unwrap();
        let second = router.chat(request()).unwrap();
        assert!(second.cached);
        assert_eq!(transport.calls().len(), 1);

        let secret = || {
            RouteRequest::new(
                "chat",
                vec![ChatMessage::user(
                    "key AKIAABCDEFGHIJKLMNOP should not be cached",
                )],
            )
        };
        router.chat(secret()).unwrap();
        let calls = transport.calls().len();
        router.chat(secret()).unwrap();
        assert_eq!(transport.calls().len(), calls + 1);
    }

    #[test]
    fn circuit_breaker_skips_a_failing_provider() {
        let transport = MockTransport::new(&[("local/ollama", 100)]);
        let mut config = test_config();
        config.cache = false;
        config.providers.insert(
            "fallbacktest".into(),
            z_config::ProviderConfig {
                kind: "custom".into(),
                models: vec!["model".into()],
                cost_per_mtok: 0.0,
                base_url: Some("https://fallback.example/v1".into()),
                ..Default::default()
            },
        );
        config.fallback = vec!["fallbacktest/model".into()];
        let router = test_router(&config, transport.clone(), 10.0);
        for _ in 0..3 {
            let _ = router.chat(RouteRequest::new("chat", vec![ChatMessage::user("hello")]));
        }
        let local_calls = || {
            transport
                .calls()
                .iter()
                .filter(|provider| provider.as_str() == "local/ollama")
                .count()
        };
        let before = local_calls();
        let outcome = router
            .chat(RouteRequest::new("chat", vec![ChatMessage::user("hello")]))
            .unwrap();
        assert_eq!(outcome.route.provider, "fallbacktest");
        assert_eq!(local_calls(), before, "open breaker must not be retried");
        assert!(outcome
            .attempts
            .iter()
            .any(|attempt| attempt.skipped_reason.as_deref() == Some("circuit breaker open")));
    }

    #[test]
    fn cost_routing_chooses_the_cheaper_cloud_model() {
        let mut config = test_config();
        config.allow_cloud = true;
        config.routing = ModelRouting::Cost;
        config.providers.insert(
            "cheap".into(),
            z_config::ProviderConfig {
                kind: "custom".into(),
                models: vec!["cheap-model".into()],
                cost_per_mtok: 0.01,
                base_url: Some("https://cheap.example/v1".into()),
                ..Default::default()
            },
        );
        config.providers.insert(
            "pricey".into(),
            z_config::ProviderConfig {
                kind: "custom".into(),
                models: vec!["pricey-model".into()],
                cost_per_mtok: 10.0,
                base_url: Some("https://pricey.example/v1".into()),
                ..Default::default()
            },
        );
        config.default = "cheap/cheap-model".into();
        config.fallback = vec!["pricey/pricey-model".into()];
        let transport = MockTransport::new(&[]);
        let router = test_router(&config, transport, 10.0);
        let routes = router
            .plan(&RouteRequest::new("chat", vec![ChatMessage::user("hi")]))
            .unwrap();
        assert_eq!(routes[0].provider, "cheap");
    }

    #[test]
    fn registry_is_seeded_with_local_models() {
        let registry = Registry::from_config(&test_config());
        assert!(registry
            .providers()
            .iter()
            .any(|provider| provider.kind.is_local()));
    }

    #[test]
    fn circuit_breaker_state_persists_across_router_instances() {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-breakers-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("breakers.json");
        let transport = MockTransport::new(&[("local/ollama", 100)]);
        let mut config = test_config();
        config.cache = false;
        config.providers.insert(
            "fallbacktest".into(),
            z_config::ProviderConfig {
                kind: "custom".into(),
                models: vec!["model".into()],
                base_url: Some("https://fallback.example/v1".into()),
                ..Default::default()
            },
        );
        config.fallback = vec!["fallbacktest/model".into()];
        {
            let router =
                test_router(&config, transport.clone(), 10.0).with_breaker_path(path.clone());
            for _ in 0..3 {
                let _ = router.chat(RouteRequest::new("chat", vec![ChatMessage::user("hello")]));
            }
        }
        assert!(path.exists());
        let before = transport
            .calls()
            .iter()
            .filter(|provider| provider.as_str() == "local/ollama")
            .count();
        let router = test_router(&config, transport.clone(), 10.0).with_breaker_path(path);
        let outcome = router
            .chat(RouteRequest::new("chat", vec![ChatMessage::user("hello")]))
            .unwrap();
        assert_eq!(outcome.route.provider, "fallbacktest");
        let after = transport
            .calls()
            .iter()
            .filter(|provider| provider.as_str() == "local/ollama")
            .count();
        assert_eq!(before, after);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prompts_are_redacted_before_the_provider() {
        let transport = MockTransport::new(&[]);
        let mut config = test_config();
        config.cache = false;
        let router = test_router(&config, transport.clone(), 10.0);
        let outcome = router
            .chat(RouteRequest::new(
                "chat",
                vec![ChatMessage::user("use key AKIAABCDEFGHIJKLMNOP for this")],
            ))
            .unwrap();
        assert!(outcome.redacted);
        let prompts = transport.prompts.lock().unwrap().join("\n");
        assert!(!prompts.contains("AKIAABCDEFGHIJKLMNOP"), "{prompts}");
        assert!(prompts.contains("[REDACTED"), "{prompts}");
    }

    #[test]
    fn usage_ledger_budget_is_reported() {
        let transport = MockTransport::new(&[]);
        let router = test_router(&test_config(), transport, 10.0);
        let summary = router.usage(None);
        assert_eq!(summary.budget_usd, 10.0);
        assert_eq!(summary.requests, 0);
        let _ = BTreeMap::<String, f64>::new();
    }
}
