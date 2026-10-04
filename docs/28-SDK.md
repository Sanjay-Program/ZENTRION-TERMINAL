# 28 — SDK

## 28.1 Common interface (defined once, implemented per language)

```ts
// TypeScript reference shape; same concepts in every SDK
interface Zentrion {
  readonly version: string;
  status(): Health;
  // Execution — the only way to affect the host
  exec(req: ExecRequest): Promise<ExecResult>;
  // Capability / policy introspection
  whoami(): ActorIdentity;
  listCapabilities(actor: string): Capability[];
  // Tools / projects
  tools(): ToolRegistry;
  projects(): ProjectApi;
  // AI
  ai: AiClient;               // gateway-mediated; same interface as CLI
  agents: AgentApi;           // create/inspect/kill
  secrets: SecretsApi;        // handle-based; values never returned by default
  audit: AuditApi;            // tail/verify/export
  scan(path: string): ScanReport;
}

interface ExecRequest {
  actor: ActorRef;            // must be an identity the SDK session owns
  action: string;             // "fs.read" etc.
  resource: string;           // scope expression
  reason?: string;            // shown in approval prompts / audit
  ttl?: Duration;
}
```

Rules for all SDKs:
- SDKs are **clients of the runtime** (over local IPC), not embedded libraries —
  security decisions stay in the runtime, one implementation, no per-language bypass.
- No SDK method grants capabilities; requesting a capability mirrors CLI consent flow.
- Language list: TypeScript + Python first (v1), Go, Rust, C++, Java later.
- Each SDK ships its JSON Schema types generated from `schemas/` (single source of truth).

## 28.2 Versioning
SDK SemVer tracks runtime API version; see 29.

## 28.3 Development Setup

Local development uses the CLI first and SDKs second. The SDK must never
reimplement policy or execution rules; it talks to the local daemon/runtime.

```sh
cargo build --workspace
cargo test
z doctor
z daemon start
```

Suggested client flow:

1. Call `status()` to confirm runtime and project state.
2. Call `whoami()` to bind the SDK session to an actor.
3. Request tool or execution operations through `exec()`.
4. Inspect audit events with `audit.tail()` during development.
5. Use `ai` and `agents` only through gateway-mediated methods.

## 28.4 AI Provider Configuration

SDK clients inherit the same provider environment as the CLI:

| Variable | Purpose |
|---|---|
| `ZENTRION_AI_PROVIDER` | `ollama`, `openai`, `qwen` or `openai-compatible` |
| `ZENTRION_AI_BASE_URL` | Local/proxy/API `/v1` root or Ollama host |
| `ZENTRION_AI_API_KEY` | Provider key when not using provider-specific variables |
| `ZENTRION_AI_MODEL` | Default model name |
| `DASHSCOPE_API_KEY` | Qwen/DashScope-compatible API key |
| `OPENAI_API_KEY` | OpenAI or compatible provider API key |

Provider setup is process-local. Do not store API keys in generated SDK code,
project manifests or example repositories.
