# 19 — AI GATEWAY

## 19.1 Pipeline

```
Application / Agent / CLI
        │ prompt + tools
        ▼
Zentrion AI Gateway
 ├─ policy check      (which providers/models allowed; per-project)
 ├─ context budget    (token limits, cost budget)
 ├─ sensitive data detection (secrets, PII, credentials)
 ├─ redaction / blocking (replace with handles or refuse send)
 ├─ provider egress   (BYOK direct; no Zentrion servers)
 ├─ output validation (tool-call schema, size, format)
 └─ audit             (what was sent to whom, redacted record)
        │
        ▼
Provider ──▶ response ──▶ validation ──▶ caller
```

## 19.2 Sensitive data handling
- **Secrets**: registered secret handles and high-confidence secret patterns
  (AWS keys, tokens, private keys) are redacted before egress. `send_secrets:
  true` per-policy can permit specific handles only — never patterns like "all".
- **PII**: detection is heuristic (emails, phone numbers, IDs) with per-project
  config: `redact | warn | allow`. Heuristics are best-effort and documented as such.
- **Source code**: sending code to a cloud provider is the default for coding
  assistance but is always visible in `z ai status` and auditable; enterprise
  policy can deny cloud providers entirely (local-only mode).

## 19.3 What the gateway does NOT claim
- **Not perfect prompt-injection detection.** Injection is mitigated
  structurally: model output is never authority; tool calls require broker
  approval; policy cannot be changed by model output; secrets never enter context.
- Heuristic injection flags (tool-output that contains imperative "run…"
  patterns) can raise the risk level of the *next* tool call — a best-effort
  signal, never a bypass.

## 19.4 Tool-call validation
Every `ToolCall` from a model is checked against: tool existence, parameter
schema, actor capability, risk level, and approval requirement — the exact same
broker path as human commands.

## 19.5 Logging & privacy
Gateway logs store: model, token counts, cost, redaction counts, decision
outcomes. **Prompts are not persisted by default** (opt-in per project for
debugging, stored locally only, redacted).
