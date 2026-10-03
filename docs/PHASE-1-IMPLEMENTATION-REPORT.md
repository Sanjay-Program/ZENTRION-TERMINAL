# PHASE 1 IMPLEMENTATION REPORT

**Date:** 2026-10-03
**Scope:** Core runtime + cross-platform CLI foundation
**Status:** see the final section — this report states only what was verified.

---

## 1. What was implemented

A Rust workspace with eight library/binary crates implementing the Phase 0
security spine, plus an end-to-end test crate and documentation.

- **z-core** — structured error model, layered configuration, platform/host
  detection, filesystem helpers with traversal refusal, shell-free process
  abstraction, and the Runtime object with project discovery.
- **z-policy** — declarative YAML policy: strict parser, glob scopes,
  deny-by-default evaluation, risk classification, and a layer-merge engine
  that can only narrow.
- **z-capability** — in-memory capability store: issue, check (actor + action
  + resource), expiry, single-use revocation, revoke-all-for-actor.
- **z-audit** — append-only hash-chained event log with a self-contained
  SHA-256 implementation and a chain verifier.
- **z-identity** — actor types and local user resolution; unauthenticated
  requests are refused.
- **z-projects** — `z init` scaffolding and manifest validation.
- **z-exec** — the execution broker: the single choke point that ties
  identity, policy, capability, risk/approval, execution and audit together.
- **z-cli** — the `z` binary with `version`, `doctor`, `status`, `config`,
  `init`, `project`, `policy`, `audit`, `run` and `lockdown`.
- **z-integration-tests** — 17 end-to-end tests running the real binary in an
  isolated environment.

Interface placeholders for AI, agents, MCP, plugins, registry, tools,
sandbox and secrets are **not** implemented beyond the types needed by the
above; see §12.

## 2. Files created

Libraries
- `core/src/{lib,error,config,host,fs,process,runtime}.rs`
- `policy/src/{lib,model,parser,merge,eval}.rs`
- `capability/src/lib.rs`
- `audit/src/lib.rs`
- `identity/src/lib.rs`
- `projects/src/lib.rs`
- `exec/src/{lib,types,broker}.rs`

CLI and tests
- `cli/src/{main,commands,context}.rs`
- `tests/{Cargo.toml,cli_integration.rs}`

Tooling and CI
- `.github/workflows/ci.yml`
- `scripts/{build,test,lint,format,package,install,uninstall,check-no-secrets}.sh`

Documentation
- `README.md`
- `docs/{INSTALLATION,QUICKSTART,CLI,SECURITY-MODEL,DEVELOPMENT}.md`
- `docs/PHASE-1-IMPLEMENTATION-REPORT.md` (this file)

## 3. Files modified

The workspace scaffolding (`Cargo.toml`, per-crate `Cargo.toml`) and the CLI
entry point existed as empty stubs before this work and were replaced with
implementations. No other pre-existing file was changed. Nothing was deleted.

## 4. Architecture decisions

Phase 0 was treated as authoritative; no Phase 0 decision was changed.

Decisions made *within* Phase 1's freedom:

1. **SHA-256 implemented in-crate** rather than adding a crypto dependency.
   Rationale: keeps the dependency surface minimal for a security tool, and
   the implementation is only used for audit chain integrity. Verified against
   the standard empty-string and `"abc"` test vectors.

2. **Policy merge treats an empty lower layer as "unspecified" rather than
   "denied".** The built-in default is a floor, not an authoritative denial;
   denial is expressed by the absence of any grant. Without this, a project
   could never grant a scope the built-in default did not already contain.

3. **Project discovery requires `project.yaml`, not just a `.zentrion/`
   directory.** A bare `.zentrion` directory is used by other tools; requiring
   the manifest prevents an unrelated directory from silently shadowing the
   real project.

4. **Explicit `--name` is validated, never sanitized.** Directory-derived
   names are sanitized because the user did not type them; an explicit name is
   a deliberate instruction and must be refused rather than silently altered.

5. **Capabilities are single-use in the broker path.** Issued, checked, then
   immediately revoked. This matches the Phase 0 model and avoids a held grant
   outliving its request.

## 5. Commands available

| Command | Verified |
|---|---|
| `z` (banner) | yes |
| `z version [--json]` | yes |
| `z help` / `--help` | yes |
| `z doctor [--json]` | yes |
| `z status [--json]` | yes |
| `z config get/set/path` | yes |
| `z init [path] [--name N]` | yes |
| `z project [--check]` | yes |
| `z policy show/validate/test` | yes |
| `z audit tail/verify` | yes |
| `z run <prog> [args] [--approve]` | yes |
| `z lockdown` | reports state only (by design) |

## 6. Build instructions

```sh
cargo build --workspace            # debug
cargo build --workspace --release  # release
# binary: target/release/z
```

Or `scripts/build.sh release`. Tests: `cargo test --workspace`. Lint:
`cargo clippy --workspace --all-targets -- -D warnings`. Format:
`cargo fmt --all -- --check`.

## 7. Test results

Run on Linux x64 (Fedora), Rust stable, this machine:

```
cargo test --workspace   →  85 passed, 0 failed
```

Breakdown by crate:

| Crate | Tests |
|---|---|
| z-core | 24 |
| z-policy | 13 |
| z-capability | 9 |
| z-audit | 5 |
| z-identity | 3 |
| z-projects | 7 |
| z-exec | 5 |
| z-integration-tests | 17 |
| **Total** | **85** |

Notable security assertions that pass:

- Arguments are never shell-interpreted (semicolon, `&&`, `$( )`, backticks,
  redirects, newlines, quotes, Unicode) — each asserted literal.
- Timeout kills the child and reports `timed_out`.
- `ZENTRION_SECRET` is stripped from the child environment.
- Audit tampering is detected (`verify` returns an error after an edit).
- Traversal names (`../evil`, `a/b`) are rejected by `z init`.
- `z run` of an unlisted program exits 2 (policy denial).
- `z run` of a listed program succeeds; an unlisted one in the same project
  is still denied.

`cargo clippy --workspace --all-targets -- -D warnings` passes clean.
`cargo fmt --all -- --check` passes clean.

## 8. Cross-platform results

**Honest statement: only Linux x64 was built and tested here.**

| Target | Built | Tested | Notes |
|---|---|---|---|
| Linux x64 | yes | yes | 85/85 tests, full CLI exercised |
| Linux ARM64 | no | no | expected to compile; no cross-toolchain installed |
| macOS x64 / ARM64 | no | no | no macOS host available |
| Windows x64 / ARM64 | no | no | no Windows host available |

CI (`.github/workflows/ci.yml`) is configured for ubuntu/macos/windows
runners with build, test and CLI smoke steps. **It has not been run.**

Platform-specific code is confined to `core/src/config.rs` and
`core/src/host.rs` (path resolution and OS/arch detection), so portability
risk is low but unproven. The README states this limitation explicitly.

## 9. Performance measurements

Measured on this machine (Linux x64), release build, warm cache. These are
observations, not targets.

| Metric | Measured |
|---|---|
| Binary size (release, `z`) | 1.5 MB |
| `z version` startup — min / median / max (20 runs) | 1.4 / 2.2 / 3.1 ms |
| `z doctor` — min / median / max (10 runs) | 1.8 / 2.6 / 3.4 ms |
| `z init` — min / median / max (10 runs) | 1.9 / 2.9 / 4.2 ms |
| Peak RSS, `z doctor` | 2.4 MB |
| Peak RSS, `z version` | 2.0 MB |
| Peak RSS, `z status` | 2.5 MB |
| Network calls during `z doctor` (strace) | 0 |

Compare against Phase 0 targets (which were goals, not promises): the 300 ms
`z version` target, the 30 MB idle-memory target and the 40 MB install-size
target are all met with a wide margin.

No benchmark compares policy-evaluation throughput across a large rule set
yet — that remains untested.

## 10. Security findings

### Resolved during implementation

1. **`z init --name '../evil'` was silently sanitized to `evil`** instead of
   being rejected. The sanitization step ran before validation, defeating the
   guard. Now an explicit name is validated and refused. Regression test added.

2. **Policy merge dropped project grants.** An empty lower layer (the
   built-in default for `process.spawn`) caused the higher layer's grants to
   be discarded, so a project could never allow any program. Fixed by treating
   an empty lower layer as "unspecified" rather than "denied".

3. **A bare `.zentrion` directory was treated as a project.** An unrelated
   directory of that name could shadow the real project and produce confusing
   "missing files" errors. Discovery now requires `project.yaml`.

### Reviewed and clean

- **Command injection** — no shell is constructed anywhere. Verified by tests
  and by inspection of `process.rs` (a single `Command::new` with
  `args(&req.args)`; no `sh`, no `-c`, no `eval`).
- **Path traversal** — `ensure_within` refuses absolute paths, `..` and
  prefix/root components; `validate_project_name` refuses separators and `..`.
- **Privilege escalation** — there is no elevation code path in the codebase.
  `system.admin` is denied by default and classified CRITICAL.
- **Secret leakage** — the audit schema has no field capable of holding a
  value; the process layer strips `ZENTRION_SECRET` and `SSH_AUTH_SOCK`;
  `z status` states that secrets are never displayed.
- **Unsafe process execution** — programs must be explicitly listed in policy;
  HIGH/CRITICAL risk requires `--approve`.
- **Unsafe configuration** — unknown keys rejected; corrupt config is an error
  rather than a silent fallback.
- **Symlinks** — `ensure_within` operates on path components and does not
  currently canonicalize, so a symlink inside a workspace pointing outside it
  is **not** detected. This matters only once filesystem enforcement exists;
  logged as finding F1.
- **Race conditions** — audit appends use `O_APPEND` on a single line write.
  Concurrent processes could interleave; not exercised. Logged as F2.
- **Dependency risk** — dependency set is small (clap, serde, serde_json,
  serde_yaml, chrono, log). CI includes `cargo-audit`. Not yet run.
- **Update risk** — no update system exists in Phase 1; nothing to exploit.
- **Log leakage** — events carry handles and scopes, never contents.
- **Platform-specific issues** — macOS `os_version` is best-effort; Windows
  shell detection falls back to `ComSpec`. Neither is tested here.

### Open findings

| ID | Finding | Severity | Impact now |
|---|---|---|---|
| F1 | No symlink canonicalization in path checks | Medium | Low — no fs enforcement yet; fix with Phase 2 sandbox |
| F2 | Concurrent audit appends are not locked | Low | Low — interleaving could corrupt a line; `verify` would catch it |
| F3 | `z run --approve` confirms without interactive re-authentication | Medium | Accepted for Phase 1; interactive consent UX is Phase 3 |
| F4 | Registry/timeout bounds on process output are unbounded | Low | A permitted program can emit unlimited output into memory |

Phase 1 passes its tests, but **this is not a claim that it is secure.** The
confinement layer does not exist yet.

## 11. Known limitations

- No sandbox: permission is decided, confinement is not enforced.
- No secrets storage, no OS keyring integration.
- No AI, agents, MCP, plugins, tools, registry or update system beyond types.
- `z lockdown` reports state only.
- Capabilities are in-memory and do not survive process exit.
- Audit is tamper-evident, not tamper-proof against root.
- Only Linux x64 is verified; CI for other platforms has not run.
- No IPC or daemon; the broker is in-process only.
- Policy covers filesystem, network, secrets, system and process scopes only.

## 12. Remaining Phase 1 work

Each item maps to a Phase 0 backlog task that is not yet complete:

- **P1-002** JSON schemas for tool, plugin, mcp, ai, bom and errors exist in
  the Phase 0 docs but are not yet enforced at runtime; only policy and
  project schemas are exercised.
- **Phase 1 §30** `UpdateManager` interface (check/download/verify/install/
  rollback) is not defined in code.
- **Phase 1 §23–27** interface stubs for AIProvider, Agent, MCPServer, Plugin
  and Tool are not present as types.
- **Phase 1 §32** cross-platform test matrix has not been executed.
- **Phase 1 §29** packaging beyond the tarball script (MSI, pkg, deb, rpm)
  is not produced.
- F1–F4 from §10.

## 13. Phase 2 recommendations

1. **Build the Linux sandbox first** (Landlock + seccomp + cgroup v2), since
   Linux is the reference platform and has the strongest available primitives.
   Wire it into the broker as a required step before execution.
2. **Add filesystem enforcement** and resolve F1 by canonicalizing paths
   before capability scope checks.
3. **Implement the secrets layer** with OS keyring integration, keeping values
   out of the audit schema and out of AI context.
4. **Introduce the daemon and IPC** so capabilities can outlive one CLI
   invocation, with authenticated local sockets.
5. **Make `z lockdown` real** once agents exist.
6. **Run the CI matrix** and fix whatever the macOS and Windows jobs reveal,
   then mark those platforms verified or explicitly unsupported.
7. **Add the `UpdateManager` interface** with signature verification stubs,
   without enabling automatic updates.

Do not begin Phase 3 (AI/agents) until the sandbox from Phase 2 exists —
otherwise agent tool calls would be authorized but unconfined, which is
precisely the failure mode Phase 0 was designed to prevent.
