# AI Architecture

The AI layer is gateway-mediated. It can call local or remote models, but it
cannot bypass runtime security.

## Goals

- Local-first by default (Ollama).
- Provider-neutral: Ollama, OpenAI, Qwen/DashScope and any OpenAI-compatible
  endpoint.
- No secrets in project files.
- One gateway for CLI, copilot, agents and research.
- Model output is advice; host effects still require brokered tool execution.

## Components

| Component | Crate | Responsibility |
|---|---|---|
| Chat models | `ai::models` | Common request/response structs |
| Gateway | `ai::gateway` | Redaction and provider dispatch |
| Providers | `ai::provider` | Ollama, OpenAI and compatible transports |
| Agent runtime | `agents` | Profiles, guardrails and traces |
| MCP gateway | `mcp` | External tool/context bridge |
| AI BOM | `devsec` | Project-derived AI component inventory |

## Provider selection

| Provider | Required setup |
|---|---|
| `ollama` (default) | optional `ZENTRION_AI_BASE_URL` / `OLLAMA_HOST` |
| `openai` | `OPENAI_API_KEY` or `ZENTRION_AI_API_KEY` |
| `qwen` | `DASHSCOPE_API_KEY` or `ZENTRION_AI_API_KEY` |
| `openai-compatible` | `ZENTRION_AI_BASE_URL`, optional key |

Configure the `/v1` root for compatible providers; `/chat/completions` is
appended automatically.

## Safety pipeline

```text
prompt -> gateway redaction -> provider call -> advice
                                      |
                              tool request? -> execution broker -> audit
```

## Redaction

Before any outbound request, the gateway scrubs:

- AWS access keys (`AKIA…`, `ASIA…`)
- private key blocks
- GitHub tokens
- OpenAI-style keys
- JWTs
- bearer authorization headers
- email addresses

Patterns are compiled once and covered by tests.

## Current limits

- No streaming through the gateway.
- No prompt-injection classifier; model output is advisory and cannot execute.
- Credentials come from the environment until a full secrets UX lands.
- Research is model-synthesized, without web crawling.
