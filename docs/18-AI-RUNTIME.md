# 18 — AI RUNTIME (z-ai)

## 18.1 Structure

```
z-ai
 ├─ ProviderAdapter trait      (OpenAI, Anthropic, Gemini, OpenAI-compatible, Local)
 ├─ ModelRegistry              (local + remote catalogs, capabilities, pricing)
 ├─ Gateway (see 19-AI-GATEWAY)
 ├─ Session/Context manager    (conversation state, token budgets)
 └─ LocalInferenceAdapter      (llama.cpp / Ollama-compatible)
```

No provider logic in core; all providers implement one interface. New provider
= new adapter crate, registered in config.

## 18.2 Provider interface (Rust-flavored pseudocode)

```rust
trait Provider {
    fn id(&self) -> ProviderId;
    fn models(&self) -> Vec<ModelInfo>;          // name, ctx, capabilities, cost
    fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse>;
    fn stream(&self, req: CompletionRequest) -> BoxStream<Result<StreamChunk>>;
    fn tools(&self) -> ToolSchemaSupport;         // whether provider supports function/tool calling
    fn health(&self) -> Health;                   // reachable, auth valid, quota
}

struct CompletionRequest {
    model: ModelRef,
    messages: Vec<Message>,          // already redacted by gateway
    tools: Vec<ToolDef>,             // broker-approved tool schemas only
    params: {temperature, max_tokens, stop},
    cost_budget: Option<TokenOrUsdBudget>,
    timeout: Duration,
}

struct CompletionResponse {
    content: Message,
    tool_calls: Vec<ToolCall>,       // validated → broker, never executed directly
    usage: {prompt_tokens, completion_tokens},
    cost_usd: Option<f64>,           // from provider or local estimate
    provider_meta: {...},
    privacy: {sent_to: String, egress_policy: "byok-direct"},
}
```

## 18.3 Model abstraction
`ModelRef = provider/model-id`. Models carry metadata: context window, modalities
(text/vision/audio), function-calling support, local/remote, license, cost tier.

## 18.4 Errors, retries, timeouts
- Typed errors: auth, quota, rate-limit, timeout, provider-5xx, network, content-filter.
- Retry policy: exponential backoff + jitter, max 3, only for retryable classes; **never** retries on content/auth errors.
- Timeouts: default 60 s (configurable), streaming keeps alive via chunk timeout.
- Provider failover only if the *user* configured multiple providers with explicit consent that data goes to the fallback (privacy-relevant — must be opted in).

## 18.5 Local AI
- Adapters for llama.cpp server and Ollama-compatible endpoints; generic OpenAI-compatible endpoint adapter covers future runtimes.
- Hardware detection: CPU cores, RAM, GPU (CUDA/Metal/ROCm via vendor APIs), VRAM, NPU detection best-effort.
- Model discovery: scan configured local dirs + runtime's own registry; models recorded with quantization (q4/q5/q8), size, context.
- Recommendation: suggest largest model fitting in free VRAM−20% headroom; never auto-download without consent (size disclosed).
- Resource limits: local inference constrained by cgroup/rlimits when sandboxed (Phase 3).

## 18.6 Degradation ladder
full cloud BYOK → local model → no AI (terminal still fully functional).
`z ai status` states exactly which rung is active and why.
