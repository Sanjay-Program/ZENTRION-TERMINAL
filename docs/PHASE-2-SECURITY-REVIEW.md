# PHASE 2 — SECURITY REVIEW

**Date:** 2026-10-03
**Scope:** the tool runtime, package system, registry client, native API layer.
**Method:** code inspection of every trust boundary, plus the adversarial test
suite. Findings are stated with their actual impact, not their category.

**Headline:** Phase 2 is materially safer than Phase 1 at the package boundary
(checksums, strict manifests, hardened extraction, transactional installs), but
it still has **no sandbox and no signature verification**. Both are stated
plainly rather than papered over.

---

## 1. Findings

### F1 — Signature verification is not implemented (HIGH, accepted)

`z_package::signature` defines the interface and returns
`SignatureOutcome::Unsupported`. Nothing fabricates a success.

**Impact.** For a tool that does not set `signature_required`, authenticity
rests on the SHA-256 checksum *plus the integrity of the channel the manifest
travelled over*. An attacker who controls a registry can serve a malicious
manifest with a matching checksum, and the client will accept it. Checksums
detect corruption and mismatched artifacts; they do not establish authorship.

**Mitigations present.** A tool may set `signature_required: true`, in which
case the install **fails closed** because the requirement cannot be met. The
`revoked` trust level blocks installation outright. `http://` artifact URLs are
refused, so a manifest cannot downgrade its own transport.

**Residual.** Accepted for Phase 2, but it is the single most important gap.
Phase 3 must add a real verifier (minisign/ed25519) and key pinning.

**Test coverage.** `unsupported_is_not_trust`, `signature_required_tool_fails_closed`,
`require_signature_rejects_unsupported_and_missing`, `supported_satisfies_requirement`.

### F2 — No sandbox: a permitted tool runs with full user privileges (HIGH, accepted)

Confirmed and documented. `SandboxLevel` reports what a platform *offers*;
no `SandboxProvider` enforces anything yet.

**Impact.** Policy gates *whether* a tool runs, not *what it can reach*. A
malicious-but-permitted tool can read anything the user can read.

**Mitigations present.** Tools are not runnable until named in the policy
(`tools.allow`). Tools declaring `network` are escalated to HIGH risk and need
`--approve` on every run. Everything is audited.

**Residual.** Accepted; explicitly called out in
`docs/native-runtime/sandbox.md` and the README. Do not run untrusted binaries.

### F3 — Trust levels are labels, not verified facts (MEDIUM, accepted)

`official` / `verified-publisher` / `community-verified` are claims from the
registry. Only `revoked` (blocks) and `unknown` (requires approval) have
mechanical effect.

**Impact.** A user may read "verified-publisher" as assurance it is not. It is
not, until signatures exist (F1).

**Mitigation.** Documented explicitly in `security.md`: "These are labels."
UI shows the trust level honestly. Phase 3 makes them real.

### F4 — Dependency resolution is recorded, not solved (MEDIUM, deferred)

A manifest's `dependencies` are validated as well-formed ids and checked
against the index, but Phase 2 does not resolve a transitive graph or detect
version conflicts between tools.

**Impact.** A tool whose dependency is missing installs and may fail at
runtime with a confusing error.

**Mitigation.** Externally declared dependencies still delegate to the
underlying tool/manifest correctly; the *tier-2* dependency check lives in the
tool manifest and the registry code, while *tier-1* verification (checksum,
ABI, path) is fully enforced.

**Residual.** Deferred to Phase 3 by design; Phase 2's requirement was "basic
dependency support" and the resolver does not pretend to be a SAT solver.

### F5 — No concurrency lock is acquired (MEDIUM, partly mitigated)

`ToolStore::lock_path()` exists but is not currently taken around mutations.
Two simultaneous installs of the same version could interleave.

**Impact.** A lost update or a partially-populated version directory. The
`active` pointer write is atomic (temp file + rename), and each install stages
into a private temp directory and renames into place, so the window is narrow
and a corrupt state is detectable by `z verify`.

**Mitigation present.** Staging is outside the store; activation is a rename;
`verify` detects a missing binary.

**Residual.** Fix in Phase 3 with an advisory file lock around mutations.

### F6 — Path checks are lexical before canonicalization where noted (LOW)

`ensure_within` is lexical by design and documented as such. Symlink escapes
are handled separately by `canonical_within`, which **is** used for the
installed-executable path and is covered by a test that plants a symlink
escaping the root.

**Impact.** Low: the lexical checker is only used to *construct* paths, and the
canonicalizer is applied before acting on an existing path.

**Residual.** Keep the distinction documented (it is).

### F7 — `--approve` is a flag, not an interactive re-authentication (MEDIUM, accepted)

As in Phase 1: `--approve` confirms without an out-of-band challenge.

**Impact.** A script or a user who habitually passes `--approve` weakens the
consent gate. An agent able to write the policy could also widen its own access
— but it cannot do so without the policy file changing, which is audited.

**Residual.** Accepted for Phase 2. Interactive consent UX (and a TTY check
before permitting `--approve` from a non-interactive context) is Phase 3.

### F8 — Process output is unbounded (LOW, accepted)

`ProcessRunner` reads a child's stdout/stderr into memory with no cap.

**Impact.** A permitted tool can emit unbounded output and exhaust memory.

**Residual.** Phase 3: cap output and stream to a file past a threshold.

---

## 2. Trust boundaries reviewed

| Boundary | Control | Verdict |
|---|---|---|
| Registry index → client | schema_version check, id/version validation, manifest path confined to the registry root, index/manifest agreement | sound |
| Manifest → client | `deny_unknown_fields`, length caps, URL scheme allowlist, checksum parse, ABI rules, self-dependency refused | sound |
| Artifact bytes → store | SHA-256 **before** any write, mismatch → quarantine, cache re-verified on use | sound |
| Archive → filesystem | two-phase plan-then-write; traversal, absolute, drive-letter, NUL, symlink, hardlink, special, duplicate, count/size/depth bombs, truncation and size-inconsistency all refused | sound |
| Store → execution | `canonical_within`, symlink refusal at the binary path, executable-bit check | sound |
| Tool identity → policy | policy resource is `tool:<name>`, never the binary path | sound (by design) |
| Manifest permissions → capabilities | manifest can only **raise** risk (network → HIGH); it never grants | sound |
| Child process env | `ZENTRION_SECRET`, `SSH_AUTH_SOCK` removed unconditionally | sound |
| Execution → audit | install/remove/update/rollback/execute all emit chained events | sound |

## 3. Attack-by-attack results

Every item below has a passing test unless marked otherwise.

| Attack | Result |
|---|---|
| `../../../../startup` in an archive | refused — "path traversal" |
| `/etc/cron.d/evil` | refused — absolute path |
| `..\..\evil` | refused after backslash normalization |
| `C:\Windows\evil.exe` | refused — drive letter |
| NUL byte in an entry name | refused |
| symlink entry | refused |
| hardlink entry | refused |
| device/fifo entry | refused |
| extended tar headers | refused, not misinterpreted |
| 50 entries against a limit of 10 | refused — entry count |
| expansion above the byte limit | refused — decompression bomb |
| single entry above the size limit | refused |
| depth > 32 | refused |
| component > 255 bytes | refused |
| duplicate entry names | refused — ambiguous overwrite |
| truncated archive (no end marker) | refused (**found during this review**) |
| archive cut mid-header / mid-data | refused |
| header size ≠ extracted size | refused (**added during this review**) |
| zip / zstd artifact | refused with an explicit "not implemented" message |
| checksum mismatch | refused; artifact quarantined; nothing activated |
| poisoned cache (right name, wrong bytes) | refused — cache is re-verified |
| size mismatch vs manifest | refused |
| declared executable absent | refused; nothing activated |
| declared executable is a symlink | refused |
| `http://` artifact URL | refused at manifest validation |
| `javascript:` URL | refused |
| URL with control characters | refused |
| index manifest path escaping the root | refused at index load |
| index/manifest version disagreement | refused |
| revoked trust level | refused |
| unknown trust without approval | refused |
| tool id not reverse-DNS / not matching name | refused |
| elevation without a reason | refused |
| self-dependency | refused |
| unlisted tool execution | denied (exit 2), audited |
| shell metacharacters in tool arguments | inert — asserted literal |
| network-declaring tool unapproved | escalated to HIGH, `approval_required` |
| traversal in a tool name / version | refused before any filesystem call |
| removal outside the store | refused |
| failed install over an existing version | existing version intact and still active |

**Total adversarial and negative tests: 37** (of 290 in the suite), all passing.
The count is measured, not estimated: it is the number of test functions whose
name asserts a refusal or a detected failure. Every attack listed in §3 below
has a named test.

## 4. Verified non-capabilities

Checked by inspection and confirmed absent:

- no `sh -c` / `cmd /c` / `eval` / `Command::new("sh")` anywhere
- no WSL, container or VM invocation
- no antivirus/SIP/Gatekeeper disabling or instructions to do so
- no telemetry, no hidden network call, no account requirement
- no plaintext credential storage (no secrets subsystem exists yet)
- no hard-coded credentials (CI scanner + review)
- no fake signature success
- no automatic execution of a downloaded artifact during install

## 5. Bugs found **during this review** and fixed

1. **Truncated archives were accepted.** A stream that simply ran out was
   treated as a complete archive, so a partial download could install. Now the
   end-of-archive marker is required.
2. **Header/extracted size disagreement was unchecked.** An archive whose
   header lied about an entry's length was accepted. Now cross-checked.
3. **`--json` was swallowed by `z search`.** A real defect in the machine
   interface: `trailing_var_arg` consumed the flag into the query.
4. **`dnsx --port 80 127.0.0.1` resolved `0.0.0.80`.** The argument parser took
   the option's value as the hostname.
5. **Native-engine manifests were rejected** because `size: 0` violated the
   artifact size rule, even though a runtime-provided tool has no artifact.
6. **Trust-level naming mismatch** between the index builder (`kebab-case`) and
   the Rust enum (`snake_case`), which would have rejected every index the
   documented tool produced.

Items 1 and 2 are extraction-security bugs and the most significant of these.

## 6. What passing tests do **not** prove

- They do not prove the absence of a sandbox escape, because there is no sandbox.
- They do not prove artifact authenticity, because signatures are not verified.
- They do not prove macOS or Windows behaviour, because neither was executed.
- They do not prove the archive parser is memory-safe against a hostile
  *decompression* stream beyond the tested cases; the inflate implementation is
  hand-written and bounded by an output cap, but it is not fuzzed.

Phase 2 passes its tests. That is not the same as being secure.
