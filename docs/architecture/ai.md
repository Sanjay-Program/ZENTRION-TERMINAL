# AI Architecture

The AI layer is a gateway-mediated subsystem. It can call local or remote
models, but it cannot bypass runtime security.

## Goals

- Local-first by default.
- Provider-neutral: Ollama, OpenAI, Qwen/DashScope-compatible APIs and custom
  OpenAI-compatible endpoints.
- No secrets in project files.
- One gateway for CLI, agents, SDK clients and future UI.
- Model output is advice or a request; host effects still require brokered
  tool execution.

## Components

| Component | Crate | Responsibility |
|---|---|---|
| Chat models | `ai::models` | Common request/response structs |
| Gateway | `ai::gateway` | Redaction, policy checks and provider dispatch |
| Providers | `ai::provider` | Ollama, OpenAI and OpenAI-compatible transports |
| Agent runtime | `agents` | Profiles, handoffs, tool guardrails and traces |
| MCP gateway | `mcp` | External tool/context bridge |
| AI BOM | `devsec` | AI component inventory for supply-chain review |

## Provider Selection

`provider_from_env()` builds the runtime provider:

| Provider | Required setup |
|---|---|
| `ollama` | `ZENTRION_AI_PROVIDER=ollama`, optional `ZENTRION_AI_BASE_URL` or `OLLAMA_HOST` |
| `openai` | `ZENTRION_AI_PROVIDER=openai`, `OPENAI_API_KEY` or `ZENTRION_AI_API_KEY` |
| `qwen` | `ZENTRION_AI_PROVIDER=qwen`, `DASHSCOPE_API_KEY` or `ZENTRION_AI_API_KEY` |
| `openai-compatible` | `ZENTRION_AI_BASE_URL`, optional API key for local endpoints |

For OpenAI-compatible providers, configure the `/v1` root, not the full
`/v1/chat/completions` path. The provider appends `/chat/completions`.

## Safety Pipeline

```text
User / agent goal
  -> prompt and context assembly
  -> gateway redaction
  -> AI policy check
  -> provider call
  -> response
  -> agent/tool guardrails
  -> execution broker for any host effect
  -> audit event
```

The model never receives implicit filesystem, process, network or secret
permissions. Tool calls remain structured platform requests.

## Current Limits

- Streaming is not yet exposed through the common gateway.
- Responses API support is not yet modeled separately from Chat Completions.
- Provider credentials should come from environment variables until the secrets
  UX is completed.
