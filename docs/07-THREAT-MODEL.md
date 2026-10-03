# 07 — THREAT MODEL

Method: STRIDE-lite per trust boundary. Likelihood: L/M/H. Impact: 1–5.

## Threats

| # | Threat actor / vector | Attack path | Impact | Likelihood | Mitigation | Residual risk | Detection | Recovery |
|---|---|---|---|---|---|---|---|---|
| T1 | Prompt injection via file/web content | Agent reads malicious README → model emits tool call to exfiltrate keys | secret theft, data exfil | H | Capability+policy enforcement outside model; secrets never in context; network deny-by-default | Med: agents can still read files they're granted | Audit chain shows anomalous tool calls; risk-level spikes | Revoke agent, `z lockdown`, rotate secrets |
| T2 | Malicious tool package | Attacker publishes lookalike tool | RCE | M | Signature/checksum, publisher identity, quarantine-first run, permission manifest | Low-Med: social engineering on approval prompt | Install-time signature fail; anomalous post-install behavior | Uninstall revokes caps; rollback |
| T3 | Malicious MCP server | Server declares benign tools, adds hidden destructive tool | data loss, exfil | M | Server trust metadata, tool allowlist at registration, per-tool capability mapping | Med | Audit shows unknown tool id | Revoke trust, kill server |
| T4 | Compromised dependency in zentrion itself | Supply-chain attack on crate/npm dep | full compromise | L | Vendored/audited deps, reproducible builds, SBOM, lockfiles, signature verification of our own releases | Low-Med | CI provenance checks; SBOM diff alerts | Emergency patch release, rollback |
| T5 | Malicious AI output (not injected, just wrong) | Model deletes wrong files | data loss | M | CRITICAL ops require human approval; sandbox limits blast radius; file versioning in workspace | Low-Med | Approval queue review | Restore from workspace snapshots |
| T6 | Malicious plugin | Plugin requests broad caps at install | privilege creep | M | Manifest declares needed caps; grant requires explicit consent; caps revocable | Low-Med | Permission diff on update | Uninstall |
| T7 | Stolen developer credentials | Attacker uses dev's machine/session | depends on session | M | Short-lived session tokens; keyring locks; lockdown on suspicious activity; no remote access by default | Med | New auth events in audit | Lockdown, re-key |
| T8 | Local attacker (same user/malware) | Reads config, spoofs IPC client | policy bypass attempt | M | Unix socket perms 0600/named pipe ACL; IPC handshake token; audit chain | Med: same-user attackers are fundamentally hard on Linux | Failed handshake events | Reinstall, secret rotation |
| T9 | Sandbox escape | Exploit in container/namespace/jail breakout | full host access | L-M | Defense in depth: caps also enforced in-broker, so escape still hits policy; keep kernel/seccomp default-deny for children | Low-Med | Escape detection hooks (seccomp SIGSYS logs) | Kill process, lockdown, incident report |
| T10 | Malicious model / provider | Provider returns malicious tool-call or exfiltrates prompts | exfil, manipulation | M | Output validation; tool-call schema validation; provider allowlist; BYOK keys never sent to our servers; no automatic provider trust | Med | Provider behavior diffs in audit | Disable provider |
| T11 | Compromised registry | Registry serves trojanized package | RCE | L | Client verifies publisher signature independently of registry; TOFU pinning of publisher keys | Low | Verification fail events | Pin previous version, rollback |
| T12 | Insider threat (malicious human user) | User exfiltrates company data via cloud AI | data loss | M | Enterprise central policy can deny all cloud AI; audit export to SIEM; data-loss heuristics (large upload) | Med | Central audit alerts | HR/security process |
| T13 | Prompt injection via MCP tool results | Tool output contains instructions that model follows | policy bypass attempt | M | Same as T1: model output is never authority; capability checks are structural | Low-Med | — | — |
| T14 | Update compromise | Attacker serves malicious update | RCE all users | L | Signed releases, staged rollout, hash pinning, rollback | Low | Signature fail, health-check fail | Automatic rollback |

## Threat → trust boundary mapping
- B1 (process identity) → T7, T8
- B2 (broker/policy) → T1, T5, T12, T13
- B3 (sandbox) → T2, T9
- Supply chain → T2, T4, T6, T10, T11, T14
- Network/cloud → T10, T11, T12

## Explicit non-goals
- Protection against kernel-level or root attacker (documented limitation).
- Perfect prompt-injection detection — not possible; we mitigate structurally instead.
- Protection against user approving a malicious action after full informed consent.

## Open questions
- Q-SEC-1: Should quarantine-first-run apply to plugins too, or only executable tools? (pending UX study)
- Q-SEC-2: Minimum viable attestation for "agent ran in sandbox" claim — pending platform research.
