# AI

Zentrion supports local and API-backed model providers through one gateway.
The model can plan, summarize and help operate the platform, but it does not
receive direct operating-system authority. Tool execution still flows through
policy, capabilities, approval gates and audit.

## Provider Setup

Default local mode:

```sh
export ZENTRION_AI_PROVIDER=ollama
export ZENTRION_AI_BASE_URL=http://localhost:11434
export ZENTRION_AI_MODEL=qwen2.5-coder:7b
```

Qwen/DashScope-compatible API:

```sh
export ZENTRION_AI_PROVIDER=qwen
export DASHSCOPE_API_KEY="sk-..."
export ZENTRION_AI_MODEL=qwen3-coder-plus
```

OpenAI:

```sh
export ZENTRION_AI_PROVIDER=openai
export OPENAI_API_KEY="sk-..."
export ZENTRION_AI_MODEL=gpt-4.1-mini
```

Custom OpenAI-compatible endpoint:

```sh
export ZENTRION_AI_PROVIDER=openai-compatible
export ZENTRION_AI_PROVIDER_NAME=local-qwen
export ZENTRION_AI_BASE_URL=http://127.0.0.1:8080/v1
export ZENTRION_AI_API_KEY=local
export ZENTRION_AI_MODEL=qwen-local
```

Use the custom endpoint mode for LM Studio, llama.cpp servers exposing
`/v1/chat/completions`, OpenRouter, private gateways or enterprise proxies.

## Gateway Behavior

The `ai` crate provides:

| Component | Purpose |
|---|---|
| `AIGateway` | Redacts obvious secret markers and applies policy checks before provider calls |
| `OllamaProvider` | Talks to local Ollama `/api/chat` |
| `OpenAIProvider` | Talks to OpenAI `/v1/chat/completions` |
| `OpenAICompatibleProvider` | Talks to any configured `/v1/chat/completions` endpoint |
| `provider_from_env()` | Builds the selected provider from `ZENTRION_AI_*` variables |

Secrets should be provided by environment variables or the OS secret store, not
committed into `.zentrion/ai.yaml`.

## Agent Safety

Agents use the same gateway. They can be configured with profiles, handoffs,
tool allowlists and guardrails. A stronger model does not expand permissions:
host effects must still be explicitly allowed by policy and brokered by the
runtime.

## Quick Workflow

```sh
z doctor
z bundle list
z bundle plan devsecops
z ai status
z ai privacy
z ui
```

## Related docs

- [Phase 3 implementation report](PHASE-3-IMPLEMENTATION-REPORT.md)
- [Security model](SECURITY_MODEL.md)
- [Agents](agents.md)
- [Tool system](tools/README.md)
