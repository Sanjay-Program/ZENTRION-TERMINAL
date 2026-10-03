# 38 — PHASE 1 BACKLOG

Ordering is dependency-based. Difficulty: S ≤1d, M ≤2d, L ≤3d.
Each task: ID | title | deps | expected files | security impact | tests | acceptance | difficulty.

## Workstream A — Foundations

| ID | Task | Deps | Expected files | Sec impact | Tests | Acceptance | D |
|---|---|---|---|---|---|---|---|
| P1-001 | Cargo workspace + repo scaffold per 03 | — | `Cargo.toml`, `core/`, `cli/`, `schemas/`, `.github/workflows/ci.yml` | baseline | build on 3 OS | `cargo build && cargo test` green; CI matrix runs | M |
| P1-002 | JSON Schemas: policy, project, tool, plugin, mcp, ai, bom, errors | — | `schemas/*.json` | prevents malformed policy holes | schema round-trip tests | schemas validate fixtures | M |
| P1-003 | Error model + config layering | P1-001 | `core/src/error.rs`, `core/src/config.rs` | corrupt-config fail-safe | unit | layering precedence tests | M |
| P1-004 | Host probe (`z doctor` read-only) | P1-003 | `core/src/host/` | surfaces sandbox honesty | integration | matches platform reality | M |
| P1-005 | CLI skeleton: version/help/status/doctor | P1-003 | `cli/src/` | none | integration | commands run offline, `--json` works | S |

## Workstream B — Policy & capability

| ID | Task | Deps | Expected files | Sec impact | Tests | Acceptance | D |
|---|---|---|---|---|---|---|---|
| P1-010 | Policy parser + strict validation | P1-002 | `policy/src/parser.rs`, `policy/src/schema.rs` | unknown-key rejection | unit + conformance harness | invalid policies rejected | L |
| P1-011 | Policy merge engine (deny-wins, intersect) | P1-010 | `policy/src/merge.rs` | layers can't widen | conformance vectors | 50+ vectors pass | L |
| P1-012 | Capability store (issue/check/revoke/expire) | P1-011 | `capability/src/` | deny-by-default core | unit | expiry+revocation tests | M |
| P1-013 | Policy CLI: `z policy show/validate/test` | P1-011 | `cli/src/policy.rs` | authoring safety | integration | dry-run evaluation correct | S |
| P1-014 | Audit hash-chain store + `z audit tail/verify` | P1-003 | `audit/src/` | tamper-evidence | tamper test | chain verify detects edit | M |

## Workstream C — Project system

| ID | Task | Deps | Expected files | Sec impact | Tests | Acceptance | D |
|---|---|---|---|---|---|---|---|
| P1-020 | `z init` scaffold (6 manifest files) | P1-010 | `projects/src/` | secure default policy file | integration | scaffold validates | M |
| P1-021 | `z project check` | P1-020 | `cli/src/project.rs` | — | integration | rejects invalid manifests | S |
| P1-022 | Default secure policy template | P1-011 | `projects/templates/policy.yaml` | secure-by-default | conformance | workspace-only default | S |

## Workstream D — Broker skeleton (Phase 2 preview, minimal)

| ID | Task | Deps | Expected files | Sec impact | Tests | Acceptance | D |
|---|---|---|---|---|---|---|---|
| P1-030 | ExecRequest/ExecResult types + in-process broker | P1-012 | `exec/src/types.rs`, `exec/src/broker.rs` | single choke point | integration | deny without capability | M |
| P1-031 | Risk classification table + approval stub | P1-030 | `exec/src/risk.rs` | risk gating | unit | table matches 10/§risk | M |
| P1-032 | Identity service (actor types, local user) | P1-003 | `identity/src/` | every request has identity | unit | unauthenticated request rejected | M |

Phase 1 exit: `z doctor`, `z init`, `z policy validate`, `z audit verify`,
deny-by-default demo (`z exec` in-process broker denies unscoped write),
CI matrix green, conformance harness in place.

## Later phases (titles only)
Phase 2: sandbox adapters, fs/net/process enforcement, secrets keyring, tool
manager + registry client, `z run/exec/install`. Phase 3: providers, gateway,
agents, lockdown, updates. Phase 4: plugins, MCP full, SDKs, scanners, BOM.
