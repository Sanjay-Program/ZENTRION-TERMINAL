# 32 — PRIVACY

## 32.1 Defaults (non-negotiable)
- **No telemetry.** `z-telemetry` exists as an opt-in module, disabled by default; when enabled it sends only crash reports/metrics the user reviewed in the settings preview.
- No source code upload: code reaches only providers the user explicitly configured (BYOK). `z ai status` states plainly where data goes.
- No secret upload, ever, unless a specific handle is policy-allowed (default never).
- No mandatory cloud account; full function locally.
- No hidden analytics, no hidden network calls: every egress is initiated by a user-visible action (install/search/update-check/provider call) and logged in audit.

## 32.2 Network behavior map
| Action | Contacts | Purpose |
|---|---|---|
| `z update --check` | release CDN | version check |
| `z install/search` | registry API + package source | fetch metadata/artifacts |
| `z ai` (cloud provider) | provider endpoint, with user's own API key | inference |
| `z ai` (local) | localhost only | inference |
| `z doctor` | **nothing** | local diagnostics |
| everything else | nothing | — |

## 32.3 Data residency
- Audit, config, agents, logs: local disk only. Cloud sync (Phase 5) requires explicit enrollment and shows exactly which fields leave.
- AI prompts persisted only if user opts in per project, locally, redacted.

## 32.4 Compliance posture (Phase 0 note)
- Designed to be compatible with GDPR data-minimization principles (no collection by default, local processing).
- Formal legal/compliance review (DPA processing registers, etc.) is a future enterprise-phase task requiring professional legal counsel — not claimed here.
