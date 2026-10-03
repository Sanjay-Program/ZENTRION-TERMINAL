# PHASE 2 — IMPLEMENTATION REPORT

**Date:** 2026-10-03
**Scope:** universal tool runtime, package manager, native API layer
**Status:** see §19. This report states only what was actually built and run.

---

## 1. Executive summary

Phase 2 turns Zentrion from a secured shell into a **tool platform**. A user can
now search a registry, install a verified tool, run it through the Phase 1
broker, update it, roll back, verify it and remove it — on any of the three
platforms, **without WSL, Docker, a VM or a shell dependency**.

The security spine is real: artifacts are checksum-verified before anything is
written, archives are hardened against the standard extraction attacks,
manifests are strictly validated, installations are transactional, and
execution is gated by policy and audited.

Two gaps are large and are stated rather than hidden: **signature verification
is not implemented**, and **there is still no sandbox**. Both have defined
Phase 3 work and, in the meantime, known-installable tools fail closed where
the missing capability would have been required.

## 2. Architecture

```
                       Z CLI  (thin: parse + render only)
                          |
                  +-------+--------+
                  |                |
            Tool Manager       Native Engines
                  |            (dnsx, sysinfo, procinfo)
        +---------+---------+
        |         |         |
   Registry   Installer   Tool Store
   (client)   (transactional) (versioned, active pointer)
        |         |
   Manifest   +---+--------+--------+--------+
   (strict)   |   |        |        |        |
          Checksum Extract  Signature Staging Audit
                   (safe)  (iface)  (private) (chained)
                          |
                    Execution Broker  (Phase 1)
                          |
              policy → capability → risk → execute
                          |
                     Native OS APIs
```

### New crates

| Crate | Responsibility |
|---|---|
| `z-native` | platform resolver, process/fs/sysinfo/DNS/HTTP/TLS abstractions |
| `z-compat` | the compatibility classification engine |
| `z-package` | checksum, safe extraction, signature interface |
| `z-tool` | manifest, store, transactional installer |
| `z-registry` | registry client, trust levels, local static registry |
| `z-version` | semantic versions and requirement matching |

### Extended

`z-policy` gained a `tools:` section (`allow`, `install`), `tool.execute` and
`tool.install` actions, and risk classification for both. `z-exec` gained
`execute_process_args`, which keys the policy resource on the **tool name**
rather than the binary path and escalates network-declaring tools to HIGH.
`z-projects` now emits a `tools:` section in the default policy.

## 3. Components implemented

**Platform resolution** — OS + architecture + **ABI**, because OS+arch alone is
insufficient (`linux-x86_64-gnu` ≠ `linux-x86_64-musl`).

**Compatibility engine** — six levels (Native, Portable, Adapted, Reimplemented,
External dependency, Unsupported), native-first precedence, star ratings that a
test asserts match the specification, and `assert_no_implicit_compat`, which
makes it impossible to force an unsupported tool or silently pull in an
external dependency.

**Native APIs** — process inspection reading `/proc` directly on Linux;
filesystem inspection with lexical and canonical path checks; system info; DNS
A/AAAA via the OS resolver; HTTP and TLS as interfaces that report
`Unsupported` rather than pretending.

**Manifest** — strict JSON schema, `deny_unknown_fields`, reverse-DNS identity
that must end with the tool name, length caps, URL scheme allowlist, checksum
validation, ABI rules, elevation-reason requirement.

**Store** — versioned layout, atomic active pointer, migration-safe listing,
validated name/version/cache keys.

**Installer** — 15-step transactional pipeline; stages outside the store;
renames into place only after every check passes; quarantines failed artifacts.

**Extraction** — hand-written tar and gzip/inflate, bounded, with two-phase
plan-then-write validation.

**Registry** — local static registry, trust levels where `unknown` is never
trusted and `revoked` is refused at load, index/manifest agreement checking.

**Native engines** — `dns.resolve`, `sysinfo`, `process.info`, `platform.info`,
usable with no external binary.

## 4. CLI commands

| Command | Notes |
|---|---|
| `z search <terms>` | offline; `--category`, `--json` |
| `z info <tool>` | metadata, permissions, compatibility |
| `z install <tool>` | `--dry-run`, `--offline`, `--approve`, `--version` |
| `z list` | `--installed`, `--outdated`, `--json` |
| `z run <tool> -- <args>` | through the broker |
| `z which <tool>` | path, publisher, source |
| `z verify <tool>` | health check |
| `z update [tool]` | one or all |
| `z rollback <tool>` | previous version |
| `z use <tool>@<ver>` | select active version |
| `z remove` / `z uninstall` | one version or all |
| `z compatibility <tool>` | per-platform support |
| `z platform` | native capability report |
| `z cache list\|clean` | artifact cache |

Phase 1 commands are unchanged and still pass their tests.

## 5. Registry

A local static registry (`index.json` + `tools/` + optional `artifacts/`) is the
default and is what every test uses. A remote registry is defined but its
transport is off by default; without it the client returns an explicit
`Unsupported` rather than an empty catalogue.

Trust levels: `official`, `verified-publisher`, `community-verified`, `unknown`
(requires `--approve`), `revoked` (blocked). They are labels, not verified
facts — documented as such.

## 6. Package system

Checksum verification (SHA-256, with the shared implementation), safe extraction
covering the full attack catalogue, quarantine on failure, a verified cache that
is re-verified on every use, and clean "not implemented" errors for zip and zstd
rather than partial handling.

## 7. Security model

Integrity: enforced. Authenticity: **not** enforced (no signature verifier).
Sandboxing: **not** implemented. Malware scanning: not implemented. No telemetry,
no account, no hidden network, no shell, no compatibility environment.

Full detail and the honest statement of the guarantee are in
[PHASE-2-SECURITY-REVIEW.md](PHASE-2-SECURITY-REVIEW.md) and
[tools/security.md](tools/security.md).

## 8. Platform support

| Target | Built | Tested |
|---|---|---|
| Linux x86_64 | **yes** | **yes** |
| Linux arm64 | no | no |
| macOS x86_64 / arm64 | no | no |
| Windows x86_64 / arm64 | no | no |

Only Linux x86_64 was built and run in this environment. Windows and macOS code
paths are written behind the platform traits and are marked **UNVERIFIED**
throughout the documentation. CI is configured for all three OSes; it has not
been executed.

## 9. Tests

```
cargo test --workspace   →  290 passed, 0 failed
```

| Crate | Tests |
|---|---|
| z-core | 26 |
| z-policy | 13 |
| z-capability | 9 |
| z-audit | 5 |
| z-identity | 3 |
| z-projects | 7 |
| z-exec | 10 |
| z-version | 15 |
| z-native | 26 |
| z-compat | 10 |
| z-package | 44 |
| z-tool | 64 |
| z-registry | 14 |
| integration (CLI, Phase 1) | 17 |
| integration (tools, Phase 2) | 27 |
| **Total** | **290** |

Baseline was 85; Phase 2 adds **205** tests and changes none of the Phase 1
assertions.

Gates: `cargo fmt --check` clean, `cargo clippy --workspace --all-targets -D
warnings` clean, `scripts/check-no-secrets.sh` clean.

**37 adversarial/negative tests** (measured: test functions whose names assert a refusal)
cover traversal, absolute and drive-letter paths,
symlinks, hardlinks, special files, extended headers, count/size/depth bombs,
duplicates, truncation, checksum mismatch, poisoned cache, size mismatch,
missing and symlinked executables, `http://` URLs, index path traversal,
index/manifest disagreement, revoked trust, elevation without a reason, shell
metacharacters, unapproved network tools, and removal outside the store.

## 10. Benchmarks

Measured on this host (Linux x86_64, 8 cores, release build, warm cache).
Observations, not targets.

| Metric | Value |
|---|---|
| Release binary | 2.83 MB (Phase 1: 2.04 MB) |
| `z version` | 21 ms median |
| `z platform` | 22 ms median |
| `z search` | 22 ms median |
| `z list` | 22 ms median |
| `z install` (local artifact, fresh store) | 30 ms median |
| `z verify` | 22 ms median |
| `z run <tool>` | 27 ms median |
| Peak RSS, `z install` | 3.9 MB |
| Peak RSS, `z run` | 3.4 MB |
| Direct child spawn vs `z run` | 1.9 ms vs 27 ms → ~25 ms broker overhead (policy + capability + store lookup + audit) |

The binary grew 0.79 MB. That is the cost of the tar/gzip decoder, the manifest
and store machinery, and the platform layer. It is justified by the
functionality, but it is a real increase and is recorded rather than glossed.

## 11. Security review

See [PHASE-2-SECURITY-REVIEW.md](PHASE-2-SECURITY-REVIEW.md). Eight findings
recorded, of which two are HIGH and accepted (no signatures, no sandbox) and
three are MEDIUM. No finding was suppressed.

## 12. Known limitations

- **No signature verification.** Authenticity rests on the manifest channel.
- **No sandbox.** A permitted tool runs with full user privileges.
- **No malware scanning** and no antivirus integration.
- **Trust levels are labels.**
- **No dependency solving** beyond validation.
- **No concurrency lock** during mutations (staging + atomic rename narrow the window).
- **Unbounded process output.**
- **`--approve` is a flag, not a challenge.**
- **Only Linux x86_64 verified.**
- **zip and zstd extraction not implemented** (refused explicitly).
- **Remote registry transport off by default.**
- **No `z dev` subcommands** — the index builder is a script, not a CLI verb.

## 13. Failed tests

None at completion. Six defects were found by tests during development and
fixed; two of them (truncated-archive acceptance, header-size disagreement)
were extraction-security bugs found during the security review rather than
pre-existing test failures. They are listed in §5 of the security review.

## 14. Deferred features

Signature verification; the `SandboxProvider` trait and its three
implementations; sandbox enforcement wired into the broker; a dependency
resolver; an advisory file lock; output caps; interactive consent; HTTP
transport; TLS inspection; port scanning; `z install --locked` with a
`.zentrion/tools.lock`; project-scoped tool resolution; `z pack install <name>`;
tool packs; the `ToolContext` SDK; `z dev` subcommands; IDE and CI integration.

## 15. Phase 3 recommendations

Ordered by dependency:

1. **Sandbox first.** `SandboxProvider` with Linux (landlock + seccomp + cgroup
   v2 + netns), macOS (Seatbelt) and Windows (Job Objects + restricted token),
   reporting the level each actually achieves. Wire it into the broker so a
   request whose risk needs level *N* is refused when the platform cannot reach
   *N*, unless the user explicitly opts out. **Do not start AI/agents before
   this exists** — an agent's tool calls would otherwise be authorised but
   unconfined, which is precisely the failure Phase 0 set out to prevent.
2. **Signature verification.** A real minisign/ed25519 verifier with publisher
   key pinning, making the trust levels meaningful and closing F1.
3. **Concurrency and robustness.** Advisory lock around mutations, capped
   process output, and a check that a partially-written version directory can
   never be activated.
4. **Fix the `--approve` consent path.** Require a TTY for `--approve` in
   non-interactive contexts, or add a challenge.
5. **Verify the other platforms.** Run the CI matrix and either make macOS and
   Windows supported with evidence or mark them explicitly unsupported.
6. **Lockfiles and project tools**, so a project can pin `nmap@7.95` and two
   projects can use different versions deterministically.
7. **Then** the AI and agent layers, on top of a runtime that confines what
   tools can reach.

## 16. Definition of done

| Requirement | Status |
|---|---|
| No mandatory WSL / Docker / VM / Kali | **yes** — verified by `z platform` and code inspection |
| Native Windows / macOS / Linux runtime | Linux verified; other two **UNVERIFIED** |
| x64 and ARM64 support | in the resolver; x64 tested |
| Native process / filesystem / system APIs | Linux verified; macOS/Windows interfaces written |
| Native DNS API | verified (A/AAAA) |
| Native HTTP / TLS API | interfaces; transport off by default |
| Platform resolver | yes, with ABI |
| Tool compatibility engine | yes, with an honesty guard |
| Tool manifest | yes, strictly validated |
| Tool registry | yes, local; remote interface |
| Tool installer / verifier / runner | yes |
| Tool sandbox abstraction | **no — deferred to Phase 3, documented** |
| Capability system + policy integration | yes |
| Elevation broker | declared in manifests with a mandatory reason; **no privilege elevation is performed** |
| Secure update / rollback | yes |
| Offline mode | yes |
| JSON API | yes, on every tool command |
| AI-compatible tool API | the CLI is a thin layer over library APIs, which is the prerequisite |
| Security finding schema | **no — deferred** |
| Cross-platform CI | configured, **not yet run** |
| Security tests | 37 adversarial/negative tests, passing (290 total) |
| Documentation | `docs/native-runtime/` and `docs/tools/` |

Two items are honestly not done: the sandbox abstraction and the security
finding schema. Neither is claimed.

## 17. What changed in the existing code

Phase 1 behaviour is preserved. Additions only:

- `z-policy`: `tools` section, two new actions, risk entries, merge handling.
- `z-exec`: `execute_process_args`; `Risk` now dereives `Ord`.
- `z-projects`: the default policy template gains a documented `tools:` section.
- `z-cli`: new subcommands; `z run` dispatches to the tool path when the name is
  an installed tool, otherwise to the Phase 1 raw-program path.
- `z-native`: `http` feature declared (off by default).

All 17 Phase 1 integration tests still pass, including deny-by-default exit
code 2, shell-metacharacter inertness, and audit chain verification.

## 18. Bottom line

Phase 2 delivers the platform: a real, verified, transactional tool runtime
with an honest compatibility model and no hidden compatibility environment.

It does not deliver a sandbox or signature verification, and it says so.
Trusting Phase 2 to run untrusted software would be a mistake; the runtime
verifies *integrity*, not *authorship*, and it does not yet confine what it
permits.
