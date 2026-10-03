# 30 — TESTING

## 30.1 Test pyramid
1. **Unit** (per crate): policy parsing/merging, capability logic, redaction, config layering.
2. **Integration**: broker end-to-end (request → policy → capability → sandbox → audit), CLI commands, project scaffolding.
3. **Conformance suite** (security-critical): policy language test vectors — request+policy → expected allow/deny. Every policy change must keep the suite green; vectors live in `tests/conformance/policy/`.
4. **Platform matrix**: same integration suite on all 6 CI targets; sandbox tests assert the *honest* capability matrix (e.g., assert landlock active on Linux, assert Windows gracefully downgrades with consent).
5. **Chaos / failure tests**: policy engine unavailable → deny; audit disk full → HIGH/CRITICAL abort; corrupt config → refuse start; registry unreachable → cached metadata path.
6. **Adversarial red-team tests**: scripted prompt injection against the agent loop; malicious tool manifest (bad signature); sandbox escape attempt probes (seccomp SIGSYS).

## 30.2 Security test gates (CI-blocking)
- Redaction: no secret value appears in any log/audit fixture output.
- Deny-by-default: request without capability must fail.
- Injection battery: 50+ crafted injection attempts must never cause host mutation beyond granted scopes.
- Update: unsigned/tampered artifact must be rejected.
- Registry: manifest permission mismatch must abort install.

## 30.3 Manual/periodic
- Pre-release: full `z doctor`, uninstall/reinstall, rollback drill on each OS.
- Quarterly threat-model review against new features.

## 30.4 Honest claims policy
A security property may be documented only if a named test asserts it. The
`07-THREAT-MODEL.md` residual risks are re-evaluated when tests change.
