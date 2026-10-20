# Competitive Roadmap: How Zentrion Becomes the Category Leader

**Status:** research + strategy, 2026-10-20  
**Scope:** terminal emulators, multiplexers, agentic terminals and adjacent tools  
**Bottom line:** there is no single “#1 for everyone.” The credible path is to become
**the #1 secure, local-first agentic terminal** — the terminal that can host any
agent or model, on any machine, while proving exactly what happened — and then
expand into the table-stakes UX that Warp, Ghostty, WezTerm, iTerm2, Kitty,
Windows Terminal, Wave and Zellij have already trained users to expect.

The detailed engineering design for these features is in the [Implementation blueprint](IMPLEMENTATION-BLUEPRINT.md).

This document is deliberately blunt about gaps. Do not use the market-share
numbers or competitor summaries below in external marketing without re-checking
them; some come from vendor blogs and survey summaries.

---

## 1. TL;DR — the ten things that matter most

1. **Shell integration + command blocks.** This is the single highest-leverage
   feature. It unlocks prompt jumps, exit codes, cwd tracking, “select output,”
   rerun, notifications, agent context, history search and safe automation.
2. **Copy mode, search, hyperlinks and clipboard UX.** A terminal without
   find/copy/select is not a daily driver.
3. **Session restore, named workspaces and layouts.** Users expect to reopen
   exactly what they had, including panes and cwd.
4. **Config files, rebindable keys, profiles and migration/import.** Hardcoded
   keys and seven themes are not enough for power users.
5. **Agent host for the agents people already use.** Detect and wrap Claude
   Code, Codex, Gemini CLI, OpenCode, Aider and custom agents; show status,
   queue prompts, notify on approvals, resume sessions.
6. **An approval/audit broker for agent tool calls.** This is Zentrion’s
   differentiator: MCP/ACP tool calls go through policy, approval and a signed
   audit ledger, with a diff and checkpoint before changes land.
7. **Context engine.** Blocks, selections, files, repo index and `@` mentions;
   token budgeting; local-first retrieval. Agents are only as good as context.
8. **GPU rendering and measured performance.** Match the leaders within
   10–20%, publish benchmarks, and never claim “fastest” without evidence.
9. **Remote + team surface.** SSH domains, durable sessions, web/read-only
   sharing, team workspaces, SSO/SCIM, RBAC and SIEM export.
10. **Packaging + onboarding.** Homebrew/winget/apt/rpm/scoop, signed builds,
   `z import`, `z tour`, `z doctor --fix`, and a great first five minutes.

## 2. What “#1” should mean

No terminal is #1 for every persona at once:

- **Windows Terminal** wins default distribution on Windows.
- **iTerm2** wins long-time macOS power users.
- **Ghostty** wins “fast, correct, native, gets out of the way.”
- **WezTerm** wins programmable multiplexing and remote domains.
- **Kitty** wins GPU + remote control + “kittens.”
- **Warp** wins integrated blocks + agents + enterprise agent governance.
- **Wave** wins graphical widgets + durable remote sessions.
- **Zellij/tmux** win multiplexing, sessions and scriptability.
- **Tabby** wins all-in-one SSH/serial/terminal with plugins.

Zentrion should not try to win all of those simultaneously. The winning
position is:

> **The secure agentic terminal: bring your own agent, bring your own model,
> bring your own policy. Every action is brokered, reviewable and auditable.**

That position is defensible because the incumbents are weak exactly there:
Warp’s governance is tied to Warp’s cloud; Ghostty/Kitty/WezTerm/iTerm2 have no
agent governance; Wave’s AI is terminal-local; Zellij is a multiplexer, not a
governance layer. Zentrion already has the broker, audit chain and policy
engine. The missing pieces are UX, agent hosting and performance.

## 3. Research method and sources

Primary inputs:

- Official docs and feature pages for [Warp](https://docs.warp.dev/),
  [Ghostty](https://ghostty.org/docs/features),
  [WezTerm](https://wezterm.org/features.html),
  [iTerm2](https://iterm2.com/features.html),
  [Kitty](https://sw.kovidgoyal.net/kitty/overview/),
  [Windows Terminal](https://github.com/microsoft/terminal/releases/tag/v1.25.2733.0),
  [Tabby](https://github.com/Eugeny/tabby),
  [Wave](https://docs.waveterm.dev/) and
  [Zellij](https://zellij.dev/features/).
- Warp’s docs for
  [blocks](https://docs.warp.dev/terminal/blocks/),
  [agents](https://docs.warp.dev/agents/),
  [full terminal use](https://docs.warp.dev/agents/capabilities/full-terminal-use/),
  [workflows](https://docs.warp.dev/knowledge-and-collaboration/warp-drive/workflows/) and
  [notebooks](https://docs.warp.dev/knowledge-and-collaboration/warp-drive/notebooks).
- Warp’s [enterprise page](https://www.warp.dev/enterprise) for SSO/SCIM, RBAC,
  SOC 2, zero-data-retention, secret redaction/BYOLLM and agent budget claims.
- Windows Terminal’s release notes for settings search, actions editor,
  Kitty keyboard protocol, window persistence and Unicode width control.
- Windows Terminal’s
  [shell integration guide](https://learn.microsoft.com/en-us/windows/terminal/tutorials/shell-integration)
  for OSC 133/9 semantics.
- Wave’s [durable sessions](https://docs.waveterm.dev/durable-sessions),
  [local/BYOK AI modes](https://docs.waveterm.dev/waveai-modes) and
  [Claude Code tab badges](https://docs.waveterm.dev/claude-code).
- A 2026 survey summary of terminal usage
  ([MOLTamp blog](https://moltamp.com/blog/what-terminal-developers-use-2026/);
  vendor blog, treat as directional).
- “Your terminal is an AI runtime now”
  ([Adel Zaalouk](https://adelzaalouk.me/2026/feb/22/terminals-agents-and-the-control-plane-nobody-built/))
  for the CLI-agent trend and adoption numbers.
- Warp’s open-sourcing coverage
  ([It’s FOSS](https://itsfoss.com/news/warp-goes-open-source/)) for the
  competitive licensing shift.
- A small independent rendering benchmark
  ([TerminalOne](https://github.com/atinylittleshell/TerminalOne/blob/main/PERFORMANCE.md))
  for how much FPS varies by terminal on the same hardware.

**Confidence:** competitor feature lists are high confidence (public docs).
Market-share and adoption numbers are medium/low confidence (vendor or
secondary sources). Re-measure before publishing claims.

## 4. Market map (what each leader is actually good at)

| Product | Core strength | Weakness / opening for Zentrion |
|---|---|---|
| **Warp** | Blocks, modern input, agent mode, Oz cloud agent fleets, workflows/notebooks, built-in editor/LSP, code review, git worktrees, MCP, BYOK, enterprise SSO/SCIM/RBAC, SOC 2 | Cloud-centric; agent governance tied to Warp’s platform; heavier product; server remains proprietary even though the client opened up in 2026 |
| **Ghostty** | GPU rendering, native UI, ligatures, grapheme clustering, Kitty graphics, shell integration, quick terminal, secure keyboard entry, correctness | Minimal by design; no AI/blocks/agent governance; macOS/Linux now, Windows planned |
| **WezTerm** | GPU, Lua config, multiplexing domains (local/Unix/SSH/TLS), tabs/panes, copy/quick-select, images, serial, workspaces | Configuration-heavy; no AI or security governance; steeper learning curve |
| **iTerm2** | macOS depth: split panes, hotkey window, regex search, copy mode, paste history, instant replay, triggers, smart selection, shell integration, password manager, annotations, captured output | macOS only; no AI/blocks/team governance; aging UX |
| **Kitty** | GPU, layouts, kittens (icat/diff/hints/palette/SSH/file transfer), remote control, graphics, sessions, marks | Power-user oriented; no AI/team/security; not Windows |
| **Windows Terminal** | Default on Windows, panes/tabs, command palette, shell integration marks, Kitty keyboard protocol, window persistence, actions editor, settings search | Windows only; no AI/agent governance; less deep than iTerm2/Kitty |
| **Tabby** | Cross-platform terminal + SSH/Telnet/serial, connection manager, encrypted secrets, plugins, portable, web app, Zmodem | Electron weight; no AI-native agent governance; plugin quality varies |
| **Wave** | Graphical widgets, AI with tools, local models/BYOK, durable SSH sessions, Claude Code badges, workspaces, web-ish layout | Smaller ecosystem; AI is terminal-local; no policy/audit broker |
| **Zellij** | Floating/stacked panes, layouts, session resurrection, web client, WASM plugins, command panes, scrollback editing, remote sessions, scriptable CLI | Multiplexer, not a GUI terminal; no AI; users still bring their own terminal |
| **tmux** | Ubiquitous, stable, scriptable sessions | Dated UX; no GUI/AI; prefix-key friction |
| **Alacritty** | Minimal, fast, GPU | No tabs/splits (by design), no AI, no sessions |

## 5. Table stakes (what “world-class” now means)

These are no longer differentiators; they are the price of entry for a daily
driver in 2026:

- GPU or otherwise smooth rendering at 60+ FPS under heavy output.
- Shell integration: prompt marks, command start/end, exit codes, cwd.
- Command blocks or equivalent semantic command history.
- Tabs, splits, pane focus, resize, tab reorder/rename, session restore.
- Copy mode, regex search, select-all-output, hyperlinks (OSC 8), clipboard.
- Config file, rebindable keys, profiles, theme import, live reload.
- Fonts: ligatures, fallback, grapheme clustering, IME, wide/ambiguous width.
- SSH/remote sessions, port forwarding, SFTP/Zmodem or equivalent.
- Notifications/progress for long commands and agent completion.
- Image protocol (Kitty/iTerm2/sixel) and inline previews.
- Accessibility, i18n, Windows/macOS/Linux packaging and auto-update.
- Agent hosting: run Claude Code/Codex/Gemini or bring your own; status and
  approvals; context; diff review.
- Enterprise: SSO, SCIM, RBAC, audit export, centralized policy and spend.

## 6. Where Zentrion is today (honest gap analysis)

**Strengths already shipped**

- Real PTY terminal with tabs, four panes, mouse, bracketed paste and
  scrollback.
- Policy broker + capability + hash-chained audit; exact-match process grants.
- Built-in secret/SAST/IaC scanning and SBOM/AI-BOM.
- Local-first, no telemetry; Rust single binary.
- MCP client, daemon/SDK, encrypted P2P chat, verified updates.
- Theme/config persistence, editor, copilot, research, sysmon.

**Gaps that block “daily driver” adoption**

| Gap | Why it matters | Priority |
|---|---|---|
| No shell integration/blocks | No prompt navigation, exit codes, output selection, agent context | P0 |
| No copy mode/search/hyperlinks | Unusable for logs and everyday work | P0 |
| No session restore/layouts | Users lose work on restart | P0 |
| Hardcoded keys, limited config | Power users cannot adapt it | P0 |
| CPU TUI rendering | Throughput/latency behind GPU leaders | P0/P1 |
| No agent host/orchestration | Warp/Wave own this workflow | P1 |
| No repo context/index | AI answers are shallow | P1 |
| No agent tool approval/diff/checkpoint | The differentiator is incomplete | P1 |
| No SSH/remote/durable sessions | Cannot replace terminal + tmux | P2 |
| No team/web/SSO/SCIM | Cannot sell to enterprises | P2 |
| No plugin/runtime API | No ecosystem | P2/P3 |
| Linux-only release built | Most users are on macOS/Windows | P0 |
| No benchmarks/accessibility/i18n | Cannot substantiate “fast” claims | P0 |

## 7. The wedge: “the terminal that can prove what happened”

Zentrion should make agent work **governable** without making it slower:

1. **Bring your own agent.** Host Claude Code, Codex, Gemini CLI, OpenCode,
   Aider, Warp Agent CLI and custom commands as first-class panes.
2. **Bring your own model.** Local Ollama/LM Studio/vLLM, OpenAI, Anthropic,
   Gemini, OpenRouter, Groq, Azure, custom endpoints; per-task routing.
3. **Bring your own policy.** Every MCP/ACP/tool call is evaluated by the
   broker; approvals are explicit; diffs are reviewed; checkpoints allow
   rollback.
4. **Prove it.** Append-only signed audit ledger of prompt, tool call,
   approval, diff, output and result; export to SIEM; replay later.
5. **Stay local-first.** No account required; air-gapped mode; E2EE sync
   optional; self-hosted enterprise control plane.

This is a sharper position than “Warp but open source” and more defensible than
“Ghostty but with AI.” It also fits Zentrion’s existing broker/audit code.

## 8. Persona requirements

| Persona | Must-have | Delighters |
|---|---|---|
| **Beginner / non-technical** | Guided onboarding, natural-language command entry, safe preview, undo, “why did this fail?”, one-click fixes | `z tour`, templates, plain-English explanations, guided tasks |
| **Developer** | Blocks, completions, shell integration, editor/LSP, git diff/review, sessions, SSH, speed | Workflows, snippets, test/build panes, migration import |
| **AI developer / agent user** | Agent host, parallel sessions, context/@ mentions, approvals, diff review, checkpoints, model choice, cost | Agent queues, voice, memory, skills, evals, replay |
| **Cybersecurity** | Scope/authorization guard, sandbox levels, network allowlists, evidence chain, command provenance, reports, SIEM | Engagement workspace, MITRE mapping, break-glass, incident room, forensics viewers |
| **Business / enterprise** | SSO/SCIM, RBAC, audit export, compliance packs, spend caps, fleet policy, read-only observers | Dashboards, cost per task, risk summaries, self-hosted control plane |
| **Team lead** | Shared workflows/notebooks, session sharing, comments, roles | Live pair programming, read-only links, recorded incidents |
| **Platform / DevOps** | SSH/remote, containers/WSL, durable sessions, scripting/JSON, CI integration | Web client, headless mode, agent fleet, Kubernetes profiles |

## 9. Prioritized roadmap

Effort is rough person-weeks for a small senior team; treat as planning ranges,
not commitments.

### P0 — Credibility (0–90 days)

| # | Feature | Why / acceptance criteria | Effort | Reference |
|---|---|---|---|---|
| 1 | **Shell integration + block model** | Auto-inject bash/zsh/fish/pwsh integration; OSC 133 A/B/C/D, OSC 9;9 cwd, OSC 9;4 progress; command text, start/end, duration, exit code; sticky headers; select output; jump prompt; rerun. Blocks stored locally. | 6–10 pw | [Windows Terminal shell integration](https://learn.microsoft.com/en-us/windows/terminal/tutorials/shell-integration), [Warp blocks](https://docs.warp.dev/terminal/blocks/) |
| 2 | **Copy mode, search, hyperlinks, clipboard** | Vi copy mode; regex find in pane/all tabs; select command/output; OSC 8 link click; path:line detection; copy-on-select optional; paste history/advanced paste. | 3–5 pw | [iTerm2](https://iterm2.com/features.html), [WezTerm](https://wezterm.org/features.html), [Kitty](https://sw.kovidgoyal.net/kitty/overview/) |
| 3 | **Session restore, workspaces, layouts** | Persist tabs/panes/cwd/scrollback optionally; named workspaces; YAML layout files; `z workspace` CLI; survive crash/reboot; restore prompt. | 4–6 pw | [Warp sessions](https://docs.warp.dev/terminal/sessions/), [Zellij layouts](https://zellij.dev/features/) |
| 4 | **Config, keybindings, profiles, import** | TOML/YAML config; rebind every action; profiles per shell/host; live reload; import iTerm2/Ghostty/Windows Terminal/Warp themes and keys; `z config` validates. | 3–4 pw | [Ghostty config](https://ghostty.org/docs/features), [WezTerm Lua](https://wezterm.org/features.html) |
| 5 | **GPU renderer + performance** | `wgpu` + `glyphon` frontend or integrate an existing renderer; dedicated IO thread; 60 FPS at high throughput; CPU fallback; published benchmark suite. | 12–20 pw | [Ghostty performance](https://ghostty.org/docs/features), [TerminalOne benchmark](https://github.com/atinylittleshell/TerminalOne/blob/main/PERFORMANCE.md) |
| 6 | **Packaging, migration, onboarding** | Homebrew, winget, apt/rpm, scoop, signed Linux/macOS/Windows builds; `z import`, `z tour`, `z doctor --fix`; first-run safe defaults. | 4–6 pw | [Tabby](https://github.com/Eugeny/tabby), [Wave](https://docs.waveterm.dev/) |
| 7 | **Notifications and progress** | OSC 9;4 progress, command completion, agent approval/completion badges, tab rollup, desktop notifications, bell. | 2–3 pw | [Wave Claude Code badges](https://docs.waveterm.dev/claude-code), [Windows Terminal](https://github.com/microsoft/terminal/releases/tag/v1.25.2733.0) |

**P0 exit criteria:** a developer can replace their current terminal for a week
without missing copy/search, session restore, keybindings, shell integration or
agent notifications; benchmarks are public; macOS and Windows builds exist.

### P1 — Agentic differentiation (3–6 months)

| # | Feature | Why / acceptance criteria | Effort | Reference |
|---|---|---|---|---|
| 8 | **Agent host** | Detect/launch Claude Code, Codex, Gemini CLI, OpenCode, Aider, Warp Agent CLI, custom; one pane per agent; parallel status dashboard; prompt queue; notifications; resume/fork; remote control. | 8–12 pw | [Warp agents](https://docs.warp.dev/agents/), [Warp third-party CLI agents](https://docs.warp.dev/agents/cli-agents/overview/) |
| 9 | **Context engine** | Blocks, selection, files, `@` mentions, repo index (SQLite FTS5 + tree-sitter + optional embeddings), ignore rules, token budget, context preview. | 6–10 pw | [Warp codebase context](https://docs.warp.dev/agents/capabilities/codebase-context/), [Wave AI](https://docs.waveterm.dev/waveai) |
| 10 | **Agent approval broker** | MCP proxy/ACP adapter; every tool call evaluated by policy; approval inbox; per-agent profiles; allow/deny/dry-run; audit event. | 8–12 pw | [Warp profiles & permissions](https://docs.warp.dev/agents/capabilities/agent-profiles-permissions/), [MCP](https://modelcontextprotocol.io/) |
| 11 | **Diff review + checkpoints** | Snapshot worktree before agent edits; diff viewer; accept/reject hunks; rollback; signed checkpoint; compare agent runs. | 6–10 pw | [Warp code diffs](https://docs.warp.dev/agents/local-agents/code-diffs/), [Warp code review](https://docs.warp.dev/agents/local-agents/interactive-code-review/) |
| 12 | **Model router** | Provider presets; local/cloud; BYOK; cost/latency/quality routing; budget caps; fallback; offline mode; per-task model; usage report. | 3–5 pw | [Wave AI modes](https://docs.waveterm.dev/waveai-modes), [Warp inference](https://docs.warp.dev/agents/inference/model-choice/) |
| 13 | **Workflows + notebooks** | Parameterized YAML workflows; scheduled runs; approvals; shareable; notebook cells (shell/markdown/AI); run history; export. | 4–6 pw | [Warp workflows](https://docs.warp.dev/knowledge-and-collaboration/warp-drive/workflows/), [Warp notebooks](https://docs.warp.dev/knowledge-and-collaboration/warp-drive/notebooks) |
| 14 | **Agent memory, rules, skills** | Project rules (`AGENTS.md`/`CLAUDE.md`), skills packs, planning/task lists, conversation fork, local memory, MCP servers. | 5–8 pw | [Warp skills](https://docs.warp.dev/agents/capabilities/skills/), [Warp memory](https://docs.warp.dev/agents/agent-memory/) |
| 15 | **Agent evals + observability** | Per-run trace, tokens, cost, success, diff stats, replay, model comparison; export; regression suite. | 4–6 pw | [Warp enterprise metrics](https://www.warp.dev/enterprise) |

**P1 exit criteria:** a team can run three different CLI agents in parallel,
give them repo context, approve/deny tool calls, review diffs, roll back, and
export a signed trace — without leaving Zentrion.

### P2 — Remote, team and enterprise (6–12 months)

| # | Feature | Why / acceptance criteria | Effort |
|---|---|---|---|
| 16 | **SSH domains + durable sessions** | Native SSH with jump hosts, agent forwarding, port forwarding, SFTP/Zmodem; durable remote session manager; attach/detach; survive network loss and restarts; remote agent execution. | 8–12 pw |
| 17 | **Web client + sharing** | Browser client, read-only observer tokens, pair programming, session recording; no open remote ports by default. | 8–12 pw |
| 18 | **Team workspaces + E2EE sync** | Shared workflows/notebooks/themes; optional E2EE sync; comments; roles. | 6–10 pw |
| 19 | **Enterprise control plane** | SAML SSO, SCIM, RBAC, fleet policy, model allowlists, budget caps, audit export to SIEM, compliance packs; self-hosted option. | 10–16 pw |
| 20 | **Plugin/WASM API + registry** | Wasmtime host with capability grants; UI/status/command plugins; theme/workflow/agent-kit registry; SDKs. | 8–12 pw |

**P2 exit criteria:** a security team can deploy Zentrion to a fleet, enforce
policy, review signed audit trails, and let auditors observe sessions — without
Warp’s cloud.

### P3 — Moats (12+ months)

- **Security engagement workbench:** scope/authorization, evidence chain,
  chain-of-custody, MITRE mapping, findings, report generation, red-team
  collaboration, break-glass.
- **Signed agent audit ledger:** Ed25519-signed events; replayable; exportable;
  policy-as-code across MCP/ACP/CLI agents.
- **Time-travel terminal:** record/replay commands with semantic blocks,
  diffable output, shareable incident timelines.
- **Air-gapped AI appliance:** offline model registry, signed models, hardware
  acceleration, zero egress.
- **Incident room:** shared live terminal, annotations, roles, command
  approvals, postmortem export.
- **Universal agent adapter:** MCP, ACP, CLI agents, remote agents,
  agent-to-agent handoff.

## 10. Performance targets (publish, don't promise)

Benchmark on the same hardware with default config, three runs, report p50/p95.

| Metric | Target |
|---|---|
| Cold start (GUI ready) | ≤150 ms p95; warm ≤50 ms |
| Keystroke-to-photon latency | ≤16 ms p95 |
| Rendering under load | 60 FPS at 10 MB/s output; no dropped frames on 4K |
| Output throughput | ≥100 MB/s without UI stall |
| Idle RSS | ≤120 MB; four panes ≤250 MB |
| Scrollback | 100k lines; regex search ≤50 ms |
| Resize | ≤50 ms for 4 panes |
| Binary | ≤25 MB compressed |
| Memory growth | <5 MB/hour idle |

Use `vtebench`, DOOM-fire, a large-log replay, 4-pane stress and a 100k-line
search. Gate CI on regressions >10%. Independent FPS benchmarks show how much
results vary by terminal and hardware
([TerminalOne](https://github.com/atinylittleshell/TerminalOne/blob/main/PERFORMANCE.md)),
so always publish methodology.

## 11. Architecture changes required

1. **`z-session` daemon** — PTY multiplexer owning sessions, detach/attach,
   remote domains, durable sessions, survive UI crashes/restarts.
2. **`z-render` GPU frontend** — `wgpu` + `glyphon` (or an existing renderer),
   with the current ratatui UI as a fallback.
3. **`z-blocks` command model** — event-sourced command blocks in SQLite:
   command, cwd, start/end, exit, output hash, links, agent attribution.
4. **`z-agents` supervisor** — process supervision for CLI agents, status
   badges, prompt queue, approvals, MCP/ACP bridge, resume.
5. **`z-context` index** — SQLite FTS5 + tree-sitter symbols; optional local
   embeddings; ignore rules; token-budgeted context builder.
6. **Policy extension** — `agent.tool.call` action, MCP proxy, per-agent
   profiles, approval tokens, Ed25519-signed audit events.
7. **Web client** — WebSocket + xterm.js (or custom canvas) served by the
   session daemon; read-only tokens, RBAC.
8. **Plugin runtime** — wasmtime host with capability grants; no ambient
   filesystem/network.

## 12. Packaging, migration and go-to-market

- **Install:** Homebrew, winget, apt/rpm, scoop, signed DMG/MSI, `z` in PATH,
  auto-update with rollback.
- **Migration:** `z import iterm2|ghostty|warp|windows-terminal|tabby` for
  themes, keys, profiles; run side-by-side; no lock-in.
- **Onboarding:** `z tour`, `z doctor --fix`, safe defaults, “try a command”
  sandbox, undo, natural-language entry.
- **Positioning:** “The secure agentic terminal. Bring your own agent, model
  and policy.”
- **Pricing shape:** free local core; paid team sync/observability; enterprise
  self-hosted control plane; no token markup by default (BYOK).
- **License risk:** Warp’s client is now open source (MIT UI, AGPL remainder)
  ([It’s FOSS](https://itsfoss.com/news/warp-goes-open-source/)); BUSL may
  slow community adoption. Consider Apache-2.0/MIT for the client and SDKs,
  keeping the enterprise server source-available/commercial.
- **Community:** workflow/agent-kit/theme registry; “awesome Zentrion”;
  benchmarks; security advisories; plugin bounties.

## 13. Metrics that prove leadership

- Activation: first command in <60 s; first block in <2 min.
- Retention: D7/D30 by persona; daily active panes; sessions restored.
- Agent adoption: % users running external agents; agents per user; approval
  rate; time-to-approve; diff accept rate; rollback rate.
- Reliability: crash-free sessions, PTY failures, render FPS, p95 latency.
- Security: policy denials, approvals, audit-verified sessions, scanner
  findings fixed, zero secret leaks.
- Enterprise: SSO/SCIM adoption, fleet policy coverage, SIEM exports, seat
  expansion.
- Community: plugins, workflows, themes, external PRs.

## 14. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Warp’s open-source + 800k-dev distribution | Compete on local-first governance, BYO agent/model, no cloud lock-in; integrate Warp Agent CLI rather than fight it |
| Ghostty’s performance leadership | Match within 10–20%; publish benchmarks; win on blocks/agents/security |
| Microsoft default distribution | Be excellent on Windows, provide winget/MSI, import Windows Terminal settings |
| Scope explosion | Hold the wedge; ship P0 before P1; say no to full IDE/cloud |
| Security liability | Honest sandbox reporting; external audit; signed releases; bug bounty |
| AI cost/latency | Local-first, model router, budgets, caching, evals |
| Cross-platform complexity | Linux first, then macOS, then Windows; CI matrix; ConPTY tests |
| License friction | Re-evaluate BUSL for client; open SDK/protocol |

## 15. Do not build (yet)

- A full IDE/LSP from scratch — integrate editors/LSP first.
- A proprietary cloud sync service before local workflows are excellent.
- Your own foundation model.
- A native mobile app before a web client.
- A plugin runtime before blocks/session/config are stable.
- “Fastest terminal” marketing without published benchmarks.
- “Maximum sandbox” claims until Landlock/seccomp are actually wired.

## 16. 12-week execution plan

| Weeks | Ship |
|---|---|
| 1–2 | Shell integration spec + block data model; copy/search/hyperlinks; config file + keybindings |
| 3–4 | Session restore/workspaces/layouts; notifications/progress; benchmark harness |
| 5–6 | GPU renderer spike + CPU optimizations; packaging/import/onboarding |
| 7–8 | Agent host (Claude Code/Codex/Gemini/OpenCode); status badges; prompt queue |
| 9–10 | Context engine MVP (`@` files/blocks/index); approval broker; diff review |
| 11–12 | Model router; workflows/notebooks MVP; checkpoint/rollback; beta + metrics |

**Definition of done for the first release:** a developer can install with one
command, import their old terminal, run their shell and three agents, approve a
tool call, review and roll back a diff, search/copy output, restore the session,
and export a signed trace.

## 17. Source notes

- Warp feature map: [docs home](https://docs.warp.dev/), [blocks](https://docs.warp.dev/terminal/blocks/), [agents](https://docs.warp.dev/agents/), [full terminal use](https://docs.warp.dev/agents/capabilities/full-terminal-use/), [workflows](https://docs.warp.dev/knowledge-and-collaboration/warp-drive/workflows/), [notebooks](https://docs.warp.dev/knowledge-and-collaboration/warp-drive/notebooks), [enterprise](https://www.warp.dev/enterprise).
- Ghostty: [features](https://ghostty.org/docs/features), [shell integration](https://ghostty.org/docs/features/shell-integration).
- WezTerm: [features](https://wezterm.org/features.html), [multiplexing](https://wezterm.org/multiplexing.html).
- iTerm2: [features](https://iterm2.com/features.html).
- Kitty: [overview](https://sw.kovidgoyal.net/kitty/overview/).
- Windows Terminal: [1.25 release](https://github.com/microsoft/terminal/releases/tag/v1.25.2733.0), [shell integration](https://learn.microsoft.com/en-us/windows/terminal/tutorials/shell-integration).
- Tabby: [README](https://github.com/Eugeny/tabby).
- Wave: [docs](https://docs.waveterm.dev/), [durable sessions](https://docs.waveterm.dev/durable-sessions), [AI modes](https://docs.waveterm.dev/waveai-modes), [Claude Code badges](https://docs.waveterm.dev/claude-code).
- Zellij: [features](https://zellij.dev/features/).
- Market/adoption context: [MOLTamp survey summary](https://moltamp.com/blog/what-terminal-developers-use-2026/), [terminal as AI runtime](https://adelzaalouk.me/2026/feb/22/terminals-agents-and-the-control-plane-nobody-built/), [Warp open source](https://itsfoss.com/news/warp-goes-open-source/).
- Rendering benchmark example: [TerminalOne PERFORMANCE.md](https://github.com/atinylittleshell/TerminalOne/blob/main/PERFORMANCE.md).
