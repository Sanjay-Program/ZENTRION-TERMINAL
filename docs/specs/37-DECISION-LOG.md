# 37 — DECISION LOG (ADRs)

## ADR-001 Core language
**Context:** runtime must be fast, memory-safe, cross-platform, small binaries, solo-developable.
**Options:** Rust; C++; Go; TypeScript(Node/Deno); C.
**Decision:** **Rust** for core+CLI. **Reason:** memory safety without GC, small static binaries, excellent cross-platform story (landlock/seccomp/JobObjects crates), FFI to OS APIs. **Consequences:** slower iteration than Go/TS; steep learning curve; mitigated by modular crates. **Alternatives:** Go (fast dev, but GC + larger runtime + weaker syscall-level control); TS (great for SDKs/registry, not for sandbox hosts); C++ (safety burden unacceptable for a security product). SDKs and registry server may use TS/Go where justified.

## ADR-002 CLI architecture
**Decision:** single static `z` binary; commands as lazy modules; clap-style arg parsing; `--json` everywhere. **Reason:** install simplicity, fast startup, scriptable. **Consequences:** one code path for humans/scripts. **Alternatives:** plugin-per-command shells (slower, more attack surface), TUI-first (bad for CI).

## ADR-003 IPC
**Decision:** local Unix socket (Linux/macOS) + named pipe (Windows), auth via local keypair handshake + per-peer token; payload = canonical JSON. **Reason:** no network exposure, OS-native ACLs, no extra service. **Consequences:** remote access requires future relay design. **Alternatives:** gRPC (heavy), REST localhost (wider attack surface).

## ADR-004 Policy model
**Decision:** declarative YAML, deny-by-default, strict schema, intersection-merge across layers (higher layers may only narrow). **Reason:** auditable, diffable in git, machine-enforceable. **Consequences:** expressive limits (no arbitrary code in policy — deliberate). **Alternatives:** code-based policies (powerful, unauditable), OPA/Rego (heavy dependency, harder for end users).

## ADR-005 Capability model
**Decision:** broker-issued scoped tokens with expiry/revocation/delegation; non-cryptographic in-memory in v1. **Reason:** simple, revocable, sufficient when everything routes through one broker process. **Consequences:** restart loses grants (acceptable; re-evaluated on demand); crypto sealing deferred (Phase 3 decision). **Alternatives:** macaroons/JWT caps (needed only cross-process — later).

## ADR-006 Sandbox strategy
**Decision:** platform-native adapters (landlock+seccomp+cgroups/netns Linux; seatbelt macOS; JobObjects+restricted tokens+optional WSL2 Windows); fail-closed with explicit consent escape hatch. **Reason:** strongest available primitives; honest degradation. **Consequences:** uneven guarantees — documented in matrix; no third-party sandbox dependency.

## ADR-007 Windows strategy
**Decision:** native Windows first-class but with documented weaker native isolation; WSL2 optional strong path; JobObjects + restricted tokens for resources. **Reason:** meet users where they are without pretending. **Consequences:** HIGH/CRITICAL risk ops on native Windows need consent or WSL2.

## ADR-008 macOS strategy
**Decision:** Seatbelt profiles + rlimits/taskpolicy; optional virtualization.framework VM for strong isolation; Keychain for secrets. **Reason:** no kernel extensions needed; notarization-friendly. **Consequences:** sandbox-exec deprecation risk tracked (mitigation: VM path).

## ADR-009 Linux strategy
**Decision:** Linux is the reference platform: landlock + seccomp + cgroup v2 + namespaces; distro packages + tar.gz. **Reason:** strongest primitives, main target audience (security/dev users skew Linux). **Consequences:** other platforms lag until Phase 2–3 parity work.

## ADR-010 AI provider abstraction
**Decision:** single Provider trait; adapters per provider; generic OpenAI-compatible adapter for the long tail; gateway mediates everything. **Reason:** vendor churn isolation; BYOK privacy. **Consequences:** adapter maintenance; no core provider coupling.

## ADR-011 Agent architecture
**Decision:** agents as broker clients with own identity/policy/limits; planner outputs are *proposals* enforced by broker; no agent-spawns-agent in v1. **Reason:** same enforcement path as humans; injection-resistant by structure. **Consequences:** slightly more latency per action; massive robustness win.

## ADR-012 MCP strategy
**Decision:** first-class subsystem but zero special privileges; per-tool permission declarations; trust tiers. **Reason:** MCP is the emerging standard; security parity with native tools. **Consequences:** some server friction (permission declarations) — accepted tradeoff.

## ADR-013 Registry
**Decision:** registry is a signed catalog; publisher-signed artifacts; client-side verification; immutable versions; never executes code at install. **Reason:** supply-chain resilience; registry compromise ≠ RCE. **Consequences:** publisher key management is a UX burden (TOFU + web-of-trust later).

## ADR-014 Update system
**Decision:** signed staged updates with health check + auto-rollback; no auto-update by default; distro-managed installs defer to package manager. **Reason:** user control + integrity; avoids breaking managed environments. **Consequences:** users on old versions longer — mitigated by visible notifications.

## ADR-015 Licensing
**Decision:** open-core, Apache-2.0 core; proprietary cloud/enterprise/registry hosting later; legal review required before finalizing contribution policy. **Reason:** trust through auditability + sustainable model. **Consequences:** discipline needed to keep the core genuinely complete.
