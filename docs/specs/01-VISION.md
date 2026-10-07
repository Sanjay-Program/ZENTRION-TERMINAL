# 01 — VISION

## Zentrion in one sentence
A universal, lightweight, fully modifiable developer + AI + cybersecurity runtime designed to be the world's #1 terminal that performs everything. **Nothing — human, AI agent, plugin, IDE, or CI job — touches the operating system without an explicit, policy-checked, audited capability.**

## The product principle

> **AI must not directly control the OS by default.**

Every caller passes through the same pipeline:

```
Human / AI / IDE / CI / Plugin / MCP
        │
        ▼
   ZENTRION INTERFACE
        │
        ▼
   ZENTRION RUNTIME
   ┌─────┬────────┬───────────┐
   │Identity│ Policy │ Execution │
   └─────┴────────┴───────────┘
        │
        ▼
   Capability System
        │
        ▼
   Security Layer
   ┌──────┬────────┬─────────┐
   │FS    │Network │Process  │
   └──────┴────────┴─────────┘
        │
        ▼
      Sandbox
        │
        ▼
   Host Abstraction
   ┌────────┬───────┬───────┐
   │Windows │ macOS │ Linux │
   └────────┴───────┴───────┘
```

Security must **not** depend on the AI model behaving correctly. Even a
fully prompt-injected model can only issue requests that the policy engine,
capability system, and sandbox still have to approve and constrain.

## What Zentrion serves

- Developers (backend, frontend, mobile, data)
- Cybersecurity professionals (defensive, authorized testing)
- AI/ML engineers and AI agents (local or BYOK)
- DevOps / cloud engineers
- Researchers and students
- MCP-based applications
- CI/CD systems
- Enterprise environments

## Non-goals for v1

- Not a cloud product. Cloud is optional (Phase 5+).
- Not a managed AI service. BYOK + local models first.
- Not an all-in-one security suite. Tools are installed on demand.
- Not a shell replacement. It hosts the shell experience.

## Design pillars

| Pillar | Meaning |
|---|---|
| Secure by default | Deny-by-default policy; capabilities expire; risky ops need approval |
| Local-first | Full function offline except downloads/model pulls |
| Privacy-first | No telemetry without explicit opt-in; no code/secret upload |
| Model-agnostic | OpenAI/Gemini/Anthropic/local adapters, no core hardcoding |
| Lightweight & Fast | Core runtime is blazing fast and minimal; tools/models are lazy-installed |
| Modifiable & Changeable | Every aspect of the terminal, policy, and workflow can be customized |
| Cross-platform | Windows/macOS/Linux, honest about per-OS isolation limits |
| Extensible | Plugins, tools, MCP servers via manifests + capability grants |
| Auditable | Every consequential action produces a signed-local audit event |

## Five-minute experience (target, validated in Phase 4)

```
z doctor          # sanity
z init my-project # scaffold .zentrion/
z install nmap    # on-demand tool (verified)
z scan .          # security scan
z ai run          # AI with policy-gated tools
z agent list      # see what agents did
```

Success metric: a new user reaches a useful, *safe* workflow within five
minutes without reading docs.
