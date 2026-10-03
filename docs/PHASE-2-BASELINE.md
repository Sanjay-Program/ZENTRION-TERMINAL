# PHASE 2 — BASELINE

Recorded before any Phase 2 code was written.

**Date:** 2026-10-03
**Host:** Linux fedora 7.1.8-100.fc43.x86_64, x86_64, 8 cores, 7570 MB RAM
**Toolchain:** rustc 1.94.0 (4a4ef493e 2026-03-02) · cargo 1.94.0

## Phase 1 state at baseline

| Check | Result |
|---|---|
| `cargo build --workspace` | PASS |
| `cargo test --workspace` | **85 passed, 0 failed** |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `scripts/check-no-secrets.sh` | PASS |
| `cargo-audit` | not installed (no dependency advisory scan yet) |

## Artifact

| Metric | Value |
|---|---|
| Release binary `target/release/z` | 2,043,184 bytes (2.0 MB) |
| Source lines (all `.rs`, excl. `target/`) | 4,507 |
| Workspace members | core, cli, policy, capability, exec, audit, identity, projects, tests |

## Existing crates and their public contracts

| Crate | Provides |
|---|---|
| `z-core` | `ZenError`/`ZenResult`/`Area`, `Config`, `host::detect()` → `HostInfo`, `fs::{ensure_within,read_text,write_text,…}`, `process::{ProcessRequest,ProcessRunner,ProcessResult}`, `runtime::{Runtime,ProjectRef,discover_project}` |
| `z-policy` | `Policy`, `parse_policy`, `merge`, `evaluate` → `Decision{Allow,Deny,RequireApproval}`, `Risk`, `PolicyRequest` |
| `z-capability` | `Capability`, `CapabilityStore{issue,check,revoke,revoke_all_for_actor}` |
| `z-audit` | `AuditLog{open,append,tail}`, `verify`, `sha256_hex` |
| `z-identity` | `Actor`, `ActorType`, `local_user()`, `require()` |
| `z-projects` | `init_project`, `validate_project`, default manifest templates |
| `z-exec` | `Broker{new,evaluate,execute_process}`, `ExecRequest`, `ExecResult`, `ExecStatus` |
| `z-cli` | commands: version, doctor, status, config, init, project, policy, audit, run, lockdown |

## Verified Phase 1 behaviours that Phase 2 must not break

1. Deny-by-default: `z run echo hello` in a fresh project exits **2**.
2. No shell: `z run echo 'a; echo PWNED'` prints one literal line.
3. `z audit verify` detects tampering with the hash chain.
4. `z doctor` makes **zero** network socket calls (`strace` confirmed).
5. `z init --name '../evil'` is rejected, never silently rewritten.
6. Project discovery requires `.zentrion/project.yaml`, not a bare `.zentrion/`.
7. Policy layer merge can only narrow; strict parsing rejects unknown keys.
8. Telemetry is off by default and malformed env values cannot enable it.

## Phase 2 constraints derived from the baseline

- The full test suite must remain green (85 → N, with zero failures).
- `z doctor` must remain network-free by default (Phase 2 adds an explicit
  `--full` / opt-in network check rather than changing the default).
- No new mandatory runtime dependency: no Python, Node, Java, Bash, Docker,
  WSL or VM requirement for the core.
- Binary growth must be justified; the base install stays small and tools are
  installed on demand.

## Environment limitations for Phase 2 verification

- **Only Linux x64 is available here.** macOS and Windows code paths will be
  written behind platform abstractions and compiled only on those targets.
  Any claim about them will be marked UNVERIFIED, per the Phase 1 precedent.
- `cargo-audit` is not installed; dependency advisory scanning stays a CI step.
- Network access is used **only** for opt-in operations (registry fetch,
  download). All automated tests must run offline against a local registry.
