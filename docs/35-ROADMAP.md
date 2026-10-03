# 35 — ROADMAP

| Phase | Duration (solo dev est.) | Scope | Gate |
|---|---|---|---|
| **0 — Architecture** | done | this package | docs complete & consistent |
| **1 — Skeleton** | 2–3 wks | repo scaffold, z-core skeleton (config, identity, error model), CLI with safe read-only commands (`version/doctor/status/config/policy validate`), schemas, CI (build+test on 3 OS), policy engine + capability store with in-memory broker, audit hash-chain, project scaffolding (`z init`), conformance test harness | all Phase 1 backlog tasks pass; deny-by-default demonstrable |
| **2 — Secure execution** | 3–4 wks | Execution Broker end-to-end, process/fs/network adapters, sandbox Linux (landlock+seccomp+cgroups), macOS (seatbelt), Windows (JobObjects+WSL option), secrets (OS keyring), tool manager + registry client with verification, `z run/exec/install` | security test gates green on 3 OS |
| **3 — AI + agents** | 3–4 wks | provider abstraction (OpenAI-compatible + Anthropic + local llama.cpp/Ollama), AI gateway (redaction, policy), agent runtime loop with approvals + resource governor, `z lockdown`, MCP basic (stdio), update system signed+rollback | injection battery green; 5-minute UX works |
| **4 — Ecosystem** | 3–4 wks | plugin system (wasm+native), MCP full (permissions, trust), SDKs (TS+Python), security scanner orchestration (`z scan`), AI-BOM/supply-chain, IDE extension prototypes | marketplace-ready manifests |
| **5 — Cloud/enterprise** | later | registry hosting, teams, central policy/audit, SSO, fleet, managed AI | separate spec batch |

Dependencies: 1→2→3→4→5 strictly; cloud never blocks local features.

Cost profile: Phases 0–4 are **FREE** (local dev, OSS CI, no paid services).
**OPTIONAL PAID**: signing certificates (Windows Authenticode/macOS notarization),
notarization requires Apple Developer account; optional cloud test runners.
**REQUIRED PAID** only for enterprise phase operations (Phase 5).
