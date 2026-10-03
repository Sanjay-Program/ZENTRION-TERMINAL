# Security model (Phase 1)

## The invariant

No component reaches the operating system except through the execution
broker. The CLI does not bypass policy; future AI and agent code must use the
same interfaces.

```
Caller → Identity → Policy → Capability → Risk/Approval → Execution → Audit
```

## What is enforced technically in Phase 1

### 1. No shell, ever
`z run` builds a `Command` with a structured argument array. There is no
`sh -c`, no string concatenation, no `eval`. Shell metacharacters in an
argument are ordinary characters.

Verified by tests: semicolons, `&&`, `$()`, backticks, redirects, newlines,
quotes, Unicode — each asserted to remain literal, with exactly one output
line proving no second command ran.

### 2. Deny by default
A request with no matching policy rule is denied. Unknown *actions* are denied
(`eval.rs` treats anything unrecognised as deny). The built-in default policy
grants workspace read/write and nothing else.

### 3. Strict policy parsing
Unknown YAML keys are rejected (`deny_unknown_fields`), so a typo cannot
silently disable a control. Absolute paths in a project policy are rejected.
Network scopes must be prefixed `host:`, `cidr:` or `port:`. A corrupt policy
is a hard error — never a silent fallback to permissive defaults.

### 4. Layering cannot widen
Higher-precedence layers (project over user over built-in) may only narrow
scopes. Merge is glob-aware: a broad `./**` narrowed by `./src/**` yields
`./src/**`, never the union.

### 5. Capabilities are scoped, expiring and single-use
The broker issues a capability bound to the exact (actor, action, resource)
triple with a risk-dependent TTL, checks it, then immediately revokes it.

### 6. Risk gating
HIGH and CRITICAL actions require explicit `--approve`. Without it the broker
returns `approval_required` and records the decision. There is no code path
that approves automatically.

### 7. Audit is hash-chained
Each event hashes the previous one. `z audit verify` recomputes the chain and
reports the first broken link. Tampering with any line invalidates the chain.

### 8. Secret hygiene in process spawning
`ZENTRION_SECRET` and `SSH_AUTH_SOCK` are removed from every child
environment before spawning.

### 9. Path traversal refusal
`z init --name '../evil'` is **rejected**, not silently rewritten. Only a name
derived from the on-disk directory is sanitized. Filesystem helpers refuse
absolute paths and `..` components.

### 10. No hidden network, no telemetry
The workspace has no network dependency. `strace -e trace=network z doctor`
reports **zero** socket calls. Telemetry defaults to off and only `true`/`1`
can enable it — malformed values leave it off.

## What is NOT enforced in Phase 1 (documented honestly)

| Gap | Consequence | Phase |
|---|---|---|
| No sandbox | A permitted program runs with the user's full privileges. Policy decides *whether*, not *how confined*. | 2 |
| No secrets store | No OS keyring integration; there is nowhere to put a secret yet — and therefore nothing to leak. | 2 |
| No filesystem enforcement | `filesystem.*` policy rules are evaluated and audited but not enforced at the syscall level. | 2 |
| No network enforcement | `network.*` rules are evaluated but no packet filter is installed. | 2 |
| In-memory capabilities | Grants do not survive process exit. | 3 |
| Audit not anchored | Chain detects local edits; a root attacker can rewrite the whole file. | 5 |

**Do not run untrusted binaries with Phase 1.** The policy layer is real, the
confinement layer is not yet built.

## Threat coverage matrix

| Threat | Phase 1 mitigation | Residual |
|---|---|---|
| Shell injection via arguments | structured args, no shell | none in this path |
| Prompt injection | n/a — no AI yet | deferred |
| Malicious policy file | strict schema, absolute-path refusal, deny-by-default | — |
| Path traversal | `..`/absolute refusal, name validation | — |
| Privilege escalation | no elevation code exists; `system.admin` denied by default and gated CRITICAL | — |
| Secret leakage into logs | no secret values exist in Phase 1; audit schema has no value field | — |
| Log tampering | hash chain, verified by `z audit verify` | root attacker |
| Silent permission widening | layer merge can only narrow; no auto-approve path | — |

## Reporting

Security issues must be reported privately, not via public issues. This file
will list a contact channel once one exists; until then treat this as a
development build with no security-response process.
