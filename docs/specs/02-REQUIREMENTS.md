# 02 — REQUIREMENTS

Requirement IDs: `ZR-<AREA>-NNN`. Priority: **P0** (v1 gate), **P1** (v1.x),
**P2** (later), **P3** (research). Phase: 1–5.

## CORE

| ID | Requirement | P | Phase | Acceptance criteria |
|---|---|---|---|---|
| ZR-CORE-001 | Single `z` binary starts CLI ≤ 300 ms warm on mid-range x64 Linux | P0 | 2 | `time z version` ≤ 0.3 s on target reference machine |
| ZR-CORE-002 | Runtime exposes IPC (local, authenticated) for CLI/IDE/SDK/agents | P0 | 2 | SDK client can call broker over local IPC |
| ZR-CORE-003 | Config layering: defaults < user < project < env override | P0 | 2 | Merged config test suite passes |
| ZR-CORE-004 | Host detection reports OS/arch/virt/sandbox-capabilities at startup | P0 | 1 | `z doctor` output matches host reality |
| ZR-CORE-005 | Offline: all core commands work without network | P0 | 3 | Unplug test: `z init/run/exec/policy/secrets/audit` pass |
| ZR-CORE-006 | Structured logging with redaction hook | P0 | 2 | Secrets never appear in logs (test-gated) |

## SECURITY

| ID | Requirement | P | Phase | Acceptance criteria |
|---|---|---|---|---|
| ZR-SEC-001 | Deny-by-default capability model; every privileged action requires a valid capability | P0 | 2 | Broker rejects request without capability |
| ZR-SEC-002 | Declarative policy engine with precedence: enterprise > project > user > default | P0 | 2 | Conflict tests; deny wins ties |
| ZR-SEC-003 | Execution Broker is the only path to host effects from runtime components | P0 | 2 | No component bypasses broker (code review + test) |
| ZR-SEC-004 | Risk classification (LOW/MEDIUM/HIGH/CRITICAL) drives approval/sandbox/audit | P0 | 2 | Risk table tests |
| ZR-SEC-005 | Sandbox per-platform honest capability matrix; fail-closed if isolation unavailable | P0 | 3 | HIGH-risk ops denied when sandbox degraded (sole exception: explicit typed user opt-out `--allow-unsandboxed`, audited, user-identity-only — see 06 §6.6) |
| ZR-SEC-006 | Secrets in OS secure storage only; never plaintext on disk by default | P0 | 2 | `z secrets set` writes to OS keystore |
| ZR-SEC-007 | Secrets never sent to AI providers unless explicit per-scope opt-in | P0 | 2 | Gateway redaction test |
| ZR-SEC-008 | Audit events append-only, hash-chained locally | P0 | 2 | Tamper test detects modification |
| ZR-SEC-009 | `z lockdown` terminates agents, revokes caps, blocks tool exec | P0 | 3 | Kill-switch integration test |
| ZR-SEC-010 | Signed release artifacts; update verifies signature before install | P0 | 2 | Update rejects unsigned |
| ZR-SEC-011 | No telemetry by default; any network egress from core is logged and explainable | P0 | all | Network diff test: `z doctor` makes 0 unexpected connections |

## AI / AGENT

| ID | Requirement | P | Phase | Acceptance criteria |
|---|---|---|---|---|
| ZR-AI-001 | Provider abstraction: OpenAI, Anthropic, Gemini, local, generic OpenAI-compatible | P0 | 3 | 4 providers behind one interface |
| ZR-AI-002 | AI gateway enforces policy, redacts secrets/PII before provider egress | P0 | 3 | Redaction test suite |
| ZR-AI-003 | Local AI via adapter (llama.cpp first, Ollama compatible) | P1 | 3 | Works offline |
| ZR-AI-004 | Graceful AI degradation: no provider configured → AI features disabled, rest works | P0 | 3 | `z ai status` reports degraded, not broken |
| ZR-AGENT-001 | Agents have identity, policy, capabilities, TTL, resource limits | P0 | 3 | Agent without policy cannot start |
| ZR-AGENT-002 | Agent planner output requires broker approval before host effects | P0 | 3 | Injection test: injected shell cmd blocked |
| ZR-AGENT-003 | Resource governor (CPU/RAM/time/net) enforced for agent sandboxes | P1 | 3 | Limits applied on Linux first |
| ZR-AGENT-004 | Emergency termination (`z lockdown`, `z agent kill`) works in < 2 s | P0 | 3 | Kill test |

## MCP / ECOSYSTEM

| ID | Requirement | P | Phase | Acceptance criteria |
|---|---|---|---|---|
| ZR-MCP-001 | MCP servers registered with trust metadata + declared tool permissions | P0 | 4 | Unregistered server refused |
| ZR-MCP-002 | MCP tool calls flow through the same broker/policy as native tools | P0 | 4 | Same deny/audit behavior |
| ZR-ECO-001 | Tool manifest schema + verification (checksum/signature) before install | P0 | 2 | Tampered package refused |
| ZR-ECO-002 | Registry never executes downloaded code during install | P0 | 2 | Install flow review |
| ZR-ECO-003 | Plugin manifest declares permissions; grant requires user consent | P0 | 4 | Consent dialog test |

## PLATFORM

| ID | Requirement | P | Phase | Acceptance criteria |
|---|---|---|---|---|
| ZR-PLAT-001 | Windows x64+ARM64, macOS Intel+ARM64, Linux x64+ARM64 build matrix | P0 | 2 | CI builds all six |
| ZR-PLAT-002 | Honest per-OS sandbox support matrix surfaced in `z doctor` | P0 | 3 | Matrix matches runtime probe |
| ZR-PLAT-003 | WSL optional capability on Windows (detect, not assume) | P0 | 3 | Works with and without WSL |

## QUALITY

| ID | Requirement | P | Phase | Acceptance criteria |
|---|---|---|---|---|
| ZR-Q-001 | Unit + integration + policy conformance suites in CI | P0 | 2 | CI green gate |
| ZR-Q-002 | Fail-safe: security subsystem failure ⇒ deny, not bypass | P0 | 2 | Chaos tests (see 30-TESTING) |
| ZR-Q-003 | Reproducible core builds (lockfiles, pinned toolchain) | P1 | 2 | Two builds → identical hash (stretch: deterministic) |

## Constraints

- Zero-cost development: OSS tooling, local CI where possible.
- Modest hardware target: 4-core/8GB no-GPU machine must run everything except large local models.
- Solo-developer implementable: each Phase 1 task ≤ ~3 days effort (see 38-PHASE-1-BACKLOG).
