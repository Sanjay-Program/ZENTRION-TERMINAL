# 36 — RISK REGISTER (project-level)

| ID | Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|---|
| R1 | Solo-dev scope: security runtime is large; burnout/slip | H | H | ruthless Phase 1 scope (backlog sized ≤3d/tasks), Linux-first, defer plugins/cloud | PM (you) |
| R2 | Sandbox strength on Windows can't match Linux → weak-link criticism | M | M | honest matrix, WSL2 path, broker-level enforcement as primary control, documented limitations | Sec |
| R3 | Prompt injection defeats agent UX expectations (users blame model) | H | M | structural enforcement + clear UX on denials; education in docs | AI |
| R4 | Signing infrastructure cost (Authenticode/notarization) blocks releases | M | M | unsigned dev builds OK locally; buy certs when distributing (OPTIONAL PAID, ~$100–500/yr — budget line) | PM |
| R5 | Registry becomes abuse vector before review processes exist | M | H | launch registry read-only w/ curated first-party packages only; community publishing later | ECO |
| R6 | Model/provider API churn breaks adapters | M | M | adapter isolation, conformance tests, OpenAI-compatible generic path as fallback | AI |
| R7 | Zero-cost constraint limits testing (no macOS/Win hardware) | M | M | GH Actions runners (free tier) cover all 6 targets; emulator caveats documented | PM |
| R8 | AUR/COPR/deb publishing maintenance burden | M | L | tar.gz first-class; package managers later | ECO |
| R9 | Legal: license of bundled/rehosted tools (nmap NPSL etc.) | M | M | record licenses, link upstream, don't rehost where forbidden; legal review before marketplace | Legal |
| R10 | Policy language too complex → users disable it | M | H | secure defaults require zero config; complexity opt-in; UX testing | DX |

Open questions: Q-SEC-1, Q-SEC-2 (07), Q-OS-1 (33), plus Q-ARC-1: should
capability store persist across daemon restarts in v1 (favors simplicity: no).
