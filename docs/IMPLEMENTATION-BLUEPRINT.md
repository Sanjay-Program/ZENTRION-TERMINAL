# Zentrion Implementation Blueprint

**Status:** engineering design, 2026-10-20  
**Companion to:** [Competitive roadmap](COMPETITIVE-ROADMAP.md)  
**Purpose:** describe *how* to build the features that make Zentrion the leading
secure, local-first agentic terminal — with protocols, schemas, algorithms,
UX flows, security boundaries, performance budgets and delivery milestones.

> This is a design document. Features marked **existing** are implemented today;
> everything else is a build plan. Do not market planned work as shipped.

---

## 0. Product definition

Zentrion is one program with four layers:

1. **Terminal** — a fast, correct, native-feeling terminal for every shell.
2. **Workspace** — blocks, tabs, panes, sessions, layouts and search.
3. **Agent runtime** — host any CLI agent, give it context, govern its tools.
4. **Control plane** — policy, approvals, signed audit, security workbench and
   fleet/team management.

The invariant: **no agent, plugin or workflow gets a host effect that the user
has not authorized through the same broker as a human command.**

### Design principles

- **Local-first.** Full terminal, blocks, agents and audits work offline.
- **Bring your own everything.** Shell, agent, model, provider, policy, UI.
- **Composable, not monolithic.** Session daemon, renderer, agents, context and
  policy are separate crates with stable protocols.
- **Safe by default, powerful on request.** Read-only until a policy grants more.
- **Every action leaves evidence.** Commands and agent tool calls produce
  auditable events with a verifiable chain.
- **No fake success.** If a subsystem is unavailable, say so and degrade.
- **Fast is a feature, correctness is a requirement.** Benchmark it in CI.
- **The shell remains the shell.** Never silently replace shell line editing;
  layer optional rich input on top.

---

## 1. Target architecture

```text
┌────────────────────────────── Clients ──────────────────────────────────┐
│  z ui (ratatui)   z gui (wgpu)   z web   CLI/headless   SDK/IDE plugin  │
└───────────────┬──────────────────────┬───────────────┬──────────────────┘
                │  session protocol    │  HTTP/WS      │  stdin/stdout
                │  JSON-RPC + binary   │               │
┌───────────────▼──────────────────────▼───────────────▼──────────────────┐
│                          z-session daemon                              │
│  PTY manager │ session store │ blocks recorder │ shell integration     │
│  scrollback  │ replay       │ notifications  │ remote domains          │
│  policy hook │ approval gate│ agent supervisor│ plugin host            │
└──────┬───────────────┬──────────────┬──────────────┬───────────────────┘
       │               │              │              │
┌──────▼──────┐ ┌──────▼──────┐ ┌─────▼──────┐ ┌────▼──────────────┐
│ z-vt        │ │ z-blocks    │ │ z-agents   │ │ z-policy / audit  │
│ parser      │ │ SQLite      │ │ MCP / ACP  │ │ broker + ledger   │
└──────┬──────┘ └──────┬──────┘ └─────┬──────┘ └────┬──────────────┘
       │               │              │             │
┌──────▼───────────────▼──────────────▼─────────────▼──────────────────┐
│  z-render (GPU/TUI)  z-context (index)  z-remote (SSH)  z-sync       │
└──────────────────────────────────────────────────────────────────────┘
```

### Crate plan

| Crate | Responsibility | Status |
|---|---|---|
| `z-core` | host/config/process/error | existing |
| `z-policy`, `z-capability`, `z-exec`, `z-audit`, `z-identity` | broker stack | existing |
| `z-session` | PTY mux, sessions, blocks, replay, remote domains | new |
| `z-vt` | VT parsing, OSC dispatch, screen model, search | new (extract from `tui`) |
| `z-render` | GPU renderer, glyph atlas, damage tracking | new |
| `z-tui` | ratatui client | existing, refactor |
| `z-gui` | native window + GPU frontend | new |
| `z-web` | web client/server | new |
| `z-blocks` | block model, SQLite store, export/share | new |
| `z-agents` | agent adapters, supervisor, MCP/ACP bridge | new |
| `z-context` | repo index, ranking, context builder | new |
| `z-remote` | SSH/SFTP/port forwarding/durable remote | new |
| `z-sync` | E2EE settings/workflows/notebooks sync | new |
| `z-plugin-host` | wasmtime host + capability manifest | new |
| `z-security` | engagement/evidence/report workbench | new |
| `z-cli` | `z` command surface | existing |
| `z-sdk` | Rust/TS/Python clients | existing Rust, extend |

### Process model

- One **session daemon per user** (Unix socket `$XDG_RUNTIME_DIR/zentrion/session.sock`,
  mode `0600`; named pipe on Windows).
- UI processes attach/detach freely; the daemon owns PTYs, blocks, agents and
  audit writers.
- The daemon binds only to loopback/Unix sockets by default.
- A `--headless` mode runs the daemon without a UI for CI/agents.
- Remote/web access is opt-in, authenticated and separately policy-gated.

---

## 2. Wire protocols

### 2.1 Session protocol

Transport: Unix domain socket or TLS TCP. Framing:

```text
+--------+--------+-------------------+
| u32 BE | u8 type| payload           |
+--------+--------+-------------------+
type 0 = UTF-8 JSON-RPC 2.0
type 1 = binary terminal output (seq + bytes)
type 2 = binary scrollback chunk
```

JSON-RPC methods:

```json
{"jsonrpc":"2.0","id":1,"method":"session.create","params":{
  "shell":"/bin/bash","cwd":"/work/repo","profile":"developer",
  "size":{"rows":40,"cols":120},"env":{"TERM":"zentrion-256color"}}}
{"jsonrpc":"2.0","id":2,"method":"session.attach","params":{
  "session_id":"s_01J...","since_seq":1042,"replay":"blocks"}}
{"jsonrpc":"2.0","method":"session.input","params":{
  "session_id":"s_01J...","data":"bHMgLWxhCg=="}}
{"jsonrpc":"2.0","method":"session.resize","params":{
  "session_id":"s_01J...","rows":50,"cols":160}}
{"jsonrpc":"2.0","method":"session.signal","params":{
  "session_id":"s_01J...","signal":"SIGINT"}}
{"jsonrpc":"2.0","method":"session.close","params":{
  "session_id":"s_01J...","kill":true}}
```

Server notifications:

```json
{"jsonrpc":"2.0","method":"output","params":{"session_id":"s_01J","seq":1043}}
{"jsonrpc":"2.0","method":"block.started","params":{
  "session_id":"s_01J","block_id":"b_01J","command":"cargo test",
  "cwd":"/work/repo","started_at":"2026-10-20T14:00:00Z"}}
{"jsonrpc":"2.0","method":"block.finished","params":{
  "block_id":"b_01J","exit_code":0,"duration_ms":18422,
  "output_hash":"sha256:..."}}
{"jsonrpc":"2.0","method":"cwd.changed","params":{"path":"/work/repo/src"}}
{"jsonrpc":"2.0","method":"progress","params":{"state":"running","pct":42}}
{"jsonrpc":"2.0","method":"agent.status","params":{
  "agent_id":"a_01J","state":"waiting_approval","summary":"Run cargo test?"}}
{"jsonrpc":"2.0","method":"policy.request","params":{
  "request_id":"p_01J","actor":"agent:claude-code","action":"process.spawn",
  "resource":"cargo","risk":"medium","preview":"cargo test --workspace"}}
```

Reconnect semantics: each output frame carries a monotonic `seq`. The daemon
keeps a ring buffer plus persisted segments; an attaching client asks for
`since_seq` and receives a replay before live frames. Scrollback is persisted
asynchronously in 1 MiB chunks; the live ring buffer is bounded.

### 2.2 Agent adapter protocol

Adapters translate a CLI agent's native behavior into normalized events. A
manifest describes how to launch, detect state, request approval and resume:

```yaml
# ~/.local/share/zentrion/agents/claude-code.yaml
id: claude-code
name: Claude Code
command: claude
args: []
detect:
  binaries: ["claude"]
  env: ["ANTHROPIC_API_KEY"]
events:
  mode: hooks            # hooks | jsonl | screen | osc
  hooks:
    stop: "Session complete"
    notification: "Needs attention"
  status_patterns:
    - {regex: "Do you want to proceed\\?", state: "waiting_approval"}
    - {regex: "Running tests", state: "running"}
resume:
  command: ["claude", "--continue"]
permissions:
  default_profile: "agent-readonly"
  allow_write: false
  allow_network: false
ui:
  badge: "CC"
  color: "#d97757"
```

Why adapters: agents differ wildly; a terminal that only supports its own agent
loses users who already standardized on Claude Code, Codex or Gemini CLI.
Adapters let Zentrion host all of them without forking the terminal.

### 2.3 Policy and approval protocol

The existing broker evaluates `PolicyRequest`. Extend actions:

| Action | Resource | Risk |
|---|---|---|
| `agent.tool.call` | `mcp:<server>/<tool>` or `agent:<id>/<tool>` | medium |
| `agent.fs.write` | path glob | medium/high |
| `agent.fs.delete` | path glob | high |
| `agent.net` | host/url | medium |
| `agent.exec` | program | medium |
| `agent.shell` | command string | high |
| `agent.secret.read` | secret name | critical |

Approval flow:

```text
agent → MCP/ACP bridge → policy evaluate
  ├─ allow → issue short-lived capability → execute → audit
  ├─ deny  → return structured denial to agent → audit
  └─ approval required → UI modal → user approves/edits/denies
                          → capability token (nonce, TTL, one use)
                          → execute → audit
```

Approval tokens are single-use, bound to actor/action/resource/nonce, expire in
≤10 minutes, and are recorded in the audit ledger. A denied request cannot be
retried with the same token.

---

## 3. Data model

### 3.1 SQLite schema (blocks, sessions, audit index)

```sql
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  shell TEXT NOT NULL,
  cwd TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  closed_at INTEGER,
  status TEXT NOT NULL,
  workspace_id TEXT,
  agent_id TEXT,
  metadata_json TEXT
);

CREATE TABLE blocks (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  seq INTEGER NOT NULL,
  command TEXT NOT NULL,
  cwd TEXT NOT NULL,
  shell TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  exit_code INTEGER,
  status TEXT NOT NULL,          -- pending|running|ok|failed|cancelled|background
  duration_ms INTEGER,
  output_hash TEXT,
  output_bytes INTEGER,
  agent_id TEXT,
  policy_decision TEXT,
  approval_id TEXT,
  tags_json TEXT,
  risk TEXT,
  parent_block_id TEXT
);

CREATE TABLE block_output (
  block_id TEXT NOT NULL REFERENCES blocks(id),
  chunk_no INTEGER NOT NULL,
  encoding TEXT NOT NULL,       -- zstd
  data BLOB NOT NULL,
  PRIMARY KEY (block_id, chunk_no)
);

CREATE VIRTUAL TABLE blocks_fts USING fts5(
  command, output_text, cwd, tags,
  content='blocks_content', content_rowid='rowid'
);

CREATE TABLE context_files (
  id INTEGER PRIMARY KEY,
  path TEXT UNIQUE NOT NULL,
  language TEXT,
  hash TEXT NOT NULL,
  mtime INTEGER,
  size INTEGER,
  symbols_json TEXT
);

CREATE TABLE checkpoints (
  id TEXT PRIMARY KEY,
  repo TEXT NOT NULL,
  base_commit TEXT,
  tree_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  signature TEXT,
  metadata_json TEXT
);

CREATE TABLE agent_runs (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  goal TEXT,
  model TEXT,
  started_at INTEGER,
  ended_at INTEGER,
  state TEXT,
  tokens_in INTEGER,
  tokens_out INTEGER,
  cost_micros INTEGER,
  diff_stat_json TEXT,
  trace_path TEXT
);
```

Use WAL mode, `synchronous=NORMAL`, separate DB for the audit index (the audit
log itself remains append-only JSONL + hash chain). Block output is compressed
and chunked; enforce retention and optional encryption-at-rest.

### 3.2 Workspace/layout schema

```yaml
version: 1
name: "payments-api"
root: "/work/payments"
restore: layout+cwd        # never | layout | layout+cwd | full
tabs:
  - title: "api"
    layout:
      direction: horizontal
      panes:
        - cwd: "/work/payments"
          command: "cargo watch -x run"
          profile: "developer"
        - cwd: "/work/payments"
          split: vertical
          panes:
            - command: "cargo test"
            - command: "git status"
  - title: "agents"
    layout:
      direction: vertical
      panes:
        - agent: "claude-code"
        - agent: "codex"
```

`restore: full` restarts commands; `layout+cwd` only restores shells and cwd;
`never` starts a clean workspace. Risky commands are never auto-run without an
explicit opt-in.

### 3.3 Configuration schema

```toml
# ~/.config/zentrion/config.toml
[ui]
theme = "dracula"
font_family = "JetBrains Mono"
font_size = 13.0
opacity = 0.98
cursor_style = "bar"
scrollback_lines = 100_000
gpu = true

[shell]
default = "/bin/bash"
integration = "auto"       # auto | off | bash | zsh | fish | pwsh | nushell

[input]
composer = "overlay"       # off | overlay | full
completions = ["history", "shell", "files", "git", "packages", "ai"]
danger_confirm = true

[blocks]
persist = true
retention_days = 30
share_redaction = true

[agents]
default_agent = "claude-code"
max_parallel = 4
auto_approve_read_only = true
default_profile = "agent-readonly"
notify_on = ["waiting_approval", "completed", "failed"]

[models]
default = "local/qwen2.5-coder"
fallback = ["openai/gpt-4o-mini"]
budget_usd_per_day = 5.00

[remote]
ssh_backend = "native"
verify_host_keys = true

[telemetry]
enabled = false             # opt-in only; never prompts/code/output
```

Keybindings use stable action names, not hardcoded keys:

```toml
[keybindings]
"f2" = "palette.open"
"f3" = "editor.toggle"
"f4" = "copilot.toggle"
"f5" = "sysmon.toggle"
"f6" = "chat.toggle"
"f7" = "tab.new"
"f8" = "pane.split"
"f9" = "pane.close"
"f10" = "app.quit"
"f11" = "search.open"
"f12" = "copy_mode.toggle"
"alt+1" = "tab.select:1"
"ctrl+space" = "leader"
```

### 3.4 Audit ledger event

```json
{
  "id": "ev_01J...",
  "ts": "2026-10-20T14:00:00.123Z",
  "actor": "agent:claude-code",
  "actor_type": "agent",
  "action": "agent.tool.call",
  "resource": "mcp:github/create_issue",
  "decision": "allow",
  "result": "ok",
  "risk": "medium",
  "approval_id": "ap_01J...",
  "prev_hash": "sha256:...",
  "hash": "sha256:...",
  "signature": "ed25519:...",
  "metadata": {
    "session_id": "s_01J",
    "block_id": "b_01J",
    "model": "claude-sonnet",
    "tool_input_hash": "sha256:..."
  }
}
```

The chain already exists. Add optional Ed25519 signing for enterprise exports
and a separate object store for large tool payloads (hashes only in the log).

---

## 4. Feature blueprints

### 4.1 PTY and session daemon

**Goal:** sessions survive UI crashes/restarts and can be attached from a TUI,
GPU app, web client or SDK.

Implementation:

1. `z-session` owns `portable-pty` sessions in a dedicated runtime.
2. Each session has: PTY master, child, reader thread, writer, VT parser,
   scrollback store, block recorder, integration state.
3. Reader thread reads 16 KiB chunks, timestamps them, appends to the ring
   buffer, feeds the parser and emits binary frames to subscribers.
4. Subscribers are bounded; if a slow client falls behind, drop to a keyframe
   (`screen.contents_formatted`) + recent blocks rather than unbounded buffering.
5. Session persistence: metadata in SQLite, output in compressed chunks,
   optional scrollback persistence. Process lifetime is independent of clients.
6. Shutdown: `session.close` sends SIGHUP, waits 2 s, then SIGKILL; mark status.
7. Remote domains reuse the same session API but run the daemon on the remote
   host over SSH (see 4.13).

Acceptance:

- Kill the UI while `cargo build` runs; reopen; the process is still running and
  scrollback is complete.
- Attach two clients simultaneously; input from one is echoed to both.
- Detach/reattach over a simulated network loss; output resumes with no gap
  beyond the ring-buffer limit.

### 4.2 VT parser and OSC handling

Build on `vte`/`vt100`, but own the policy surface. Supported sequences:

| Sequence | Purpose | Notes |
|---|---|---|
| OSC 0/2 | window/tab title | sanitize; max 1 KiB |
| OSC 1 | icon title | ignore or store |
| OSC 7 | cwd (`file://host/path`) | drives tab/workspace cwd |
| OSC 8 | hyperlink | click requires confirmation; scheme allowlist |
| OSC 9 | notification | desktop notification; rate-limited |
| OSC 9;4 | progress | ConEmu-style state/percent |
| OSC 52 | clipboard | opt-in; size cap; never auto-read |
| OSC 133 | shell marks | prompt/command/output/exit |
| OSC 1337 | iTerm2 images/user vars | image size cap; vars namespaced |
| OSC 4/10/11/104/110/111/112 | colors | theme integration |
| CSI ? 2026 | synchronized output | batch frames |
| Kitty keyboard | key disambiguation | enable only if child requests |
| Kitty graphics / sixel | images | opt-in renderer path |

Security rules:

- Never execute text from OSC; only parse data.
- Clipboard writes require `ui.allow_clipboard_write = true` or an approval.
- Hyperlinks never auto-open; show target and require Enter/click confirmation.
- OSC 52 payload cap (e.g. 1 MiB) and no clipboard reads.
- Unknown OSC is ignored and optionally logged at trace level.

Acceptance: golden tests for every supported sequence; fuzz parser with random
bytes; no panic on malformed OSC/CSI.

### 4.3 Shell integration

**Goal:** reliable prompt/command/exit/cwd data for bash, zsh, fish, PowerShell
and Nushell without breaking user configs.

Mechanism:

1. Generate integration scripts at install/first run under
   `<data>/shell-integration/` with a manifest and checksum.
2. Launch the shell with a wrapper:
   - bash: `--rcfile <generated>` where generated sources the user's
     `.bashrc` then installs `PROMPT_COMMAND`/`PS0` hooks.
   - zsh: `ZDOTDIR=<generated>` shim; generated `.zshrc` sources the real
     `${ZENTRION_ORIG_ZDOTDIR:-$HOME}/.zshrc` and adds `preexec`/`precmd`.
   - fish: `--init-command "source <generated>"`; use `fish_preexec`,
     `fish_postexec`, `fish_prompt` events.
   - PowerShell: `-NoExit -Command ". <generated>"`; wrap the prompt function
     and use PSReadLine history.
   - Nushell: `--config <generated>` hook file.
3. Emit:
   - `OSC 133;A` prompt start
   - `OSC 133;B` command start
   - `OSC 133;C` output start
   - `OSC 133;D;<exit>` command finished
   - `OSC 9;9;<cwd>` cwd
   - `OSC 1337;Zentrion;...` namespaced metadata (base64 JSON: command text,
     shell PID, history ID)
4. Capture command text via shell hooks; never scrape the screen when hooks are
   available. Fall back to screen heuristics only for unsupported shells.
5. On Ctrl+C/exit, close the open block with `cancelled`/`exit`.

Acceptance:

- Prompt jump, select-output, exit code, duration and cwd work in all five
  shells, including `sudo -i`, nested shells and SSH.
- Existing `.bashrc`/`.zshrc` prompts (Starship, Oh My Posh) still work.
- Startup time overhead <10 ms and no duplicate prompt output.

### 4.4 Command blocks

**Model:** a block is the unit of command history, output, sharing, search,
agent context and audit.

Lifecycle:

```text
prompt ──OSC 133;B──▶ command_started ──OSC 133;C──▶ running
   ▲                                               │
   └──── cancelled/exit ──OSC 133;D ──▶ finished ◀─┘
```

Features:

- Sticky header while scrolling (command + cwd + exit + duration).
- Collapse/expand; background blocks; filter by exit != 0, agent, cwd, tag.
- Actions: rerun, edit, copy command/output, share (redacted link/file),
  explain, open output in editor, pin to agent context, diff against previous
  run, rollback (if command was an agent edit).
- Search: FTS5 over command + plain-text output; filters in palette.
- Sharing: strip ANSI, redact secrets/PII, generate markdown/HTML with metadata;
  never include environment values.
- Persistence: retention configurable; `z blocks export`/`import`.

Acceptance: 100k blocks searchable <100 ms; sharing a block never leaks a secret
covered by the gateway patterns; blocks survive restart.

### 4.5 Input, completions and safety

Two modes:

- **Overlay (default):** shell owns the line editor; Zentrion renders
  completions/suggestions above the prompt and accepts via Tab/Enter. Minimal
  risk, works with every shell.
- **Composer (opt-in):** Zentrion owns a multiline input box while the cursor is
  at a prompt; sends the completed line to the PTY. Enables syntax highlighting,
  multi-line editing, AI rewrite and rich completions. Must detect when the
  shell is not at a prompt and pass keys through immediately.

Completion pipeline:

```text
prefix + cwd + shell context
  → sources: shell completion bridge, history, files, git, packages, Fig specs, AI
  → normalize/dedupe
  → rank: exact prefix > frecency > cwd proximity > safety
  → render with description/risk
  → accept inserts into shell line (overlay) or composer
```

Safety:

- Dangerous patterns (`rm -rf /`, `curl | sh`, `chmod 777`, `git reset --hard`,
  `DROP TABLE`) show a warning, risk level and policy preview.
- `z do` / natural language generates a command, shows a diff/preview, and
  requires Enter; never auto-runs.
- Undo: keep the last N accepted edits; `Ctrl+Z` in composer.

Acceptance: no keystroke loss; no double execution; completion latency <30 ms
for local sources; AI completions clearly labeled and cancellable.

### 4.6 Search, copy mode and hyperlinks

- **Search:** incremental regex over the active pane; `F11`; next/prev; search
  all tabs from the palette; results show tab/block/line.
- **Copy mode:** vi motions (`hjkl`, `w/b`, `0/$`, `g/G`, `/`, `n/N`, `v`, `y`),
  visual selection, rectangular selection, select command/output, copy to
  system clipboard via OSC 52 or native clipboard.
- **Hyperlinks:** OSC 8 plus smart detection of URLs, emails, file paths,
  `path:line:col`; hover shows target; activation opens with confirmation and
  policy check; file paths open in the editor at the line.
- **Paste:** bracketed paste, multi-line warning, paste history, “paste as
  base64/escaped”, edit-before-paste.

Acceptance: copy/paste round-trips Unicode; 100k-line search <50 ms; no
accidental remote URL execution.

### 4.7 GPU renderer

Two frontends sharing `z-vt` and `z-session`:

- `z-tui` (ratatui) for SSH/terminals/fallback.
- `z-gui` native window with `wgpu` + `glyphon` (or `cosmic-text`) for the
  desktop.

Renderer design:

- Cell grid with damage tracking; only upload dirty rows.
- Glyph atlas with subpixel positioning; font fallback chain; ligatures;
  grapheme clustering; emoji; cursor styles; underline/strikethrough.
- Frame pacing: target 60 FPS; optional 120 FPS; synchronized output batches
  PTY output into frames.
- Dedicated IO thread; parser and renderer communicate through a bounded
  channel; no blocking on disk.
- GPU memory budget; fallback to CPU TUI on unsupported adapters.
- IME preedit rendering; dead keys; kitty keyboard protocol.

Acceptance: 60 FPS at 10 MB/s output on integrated graphics; p95 input latency
<16 ms; no frame drops on 4K with 4 panes; CPU fallback works.

### 4.8 Config, keybindings, profiles

- Config layers: defaults → user config → project `.zentrion/terminal.toml` →
  env → CLI flags.
- Strict validation with helpful errors; `z config validate`, `z config edit`.
- Keybinding actions are named; the same action is available in the palette.
- Profiles: per shell/host/project; can set cwd, env, theme, font, agent.
- Live reload for theme/keybindings/font/opacity; restart required for GPU/PTY.
- Import: iTerm2 plist, Ghostty config, WezTerm Lua subset, Windows Terminal
  JSON, Warp themes/keybindings, Tabby config. Report what was imported.

Acceptance: every built-in action is rebindable; invalid config fails closed
with a line number; import never overwrites the user's existing config without
confirmation.

### 4.9 Workspaces, session restore and layouts

- Workspace = named set of tabs/panes/layouts/cwd/profiles/agents.
- `z workspace save/list/restore/delete`, palette integration.
- Restore policy (`never|layout|layout+cwd|full`) and per-pane command opt-in.
- Crash recovery: daemon restores session metadata; UI reattaches on start.
- Layout files are YAML, versioned, shareable; validate before apply.
- “Save snapshot” also stores theme, env profile and agent config (no secrets).

Acceptance: restore after reboot; no command auto-runs unless policy allows and
`restore: full`; layout import from Zellij/tmux is best-effort with a report.

### 4.10 Agent host and orchestration

**Agent supervisor** responsibilities:

- Discover adapters and binaries.
- Launch an agent in its own session; set env/context/policy profile.
- Normalize status: `starting|running|waiting_input|waiting_approval|done|failed`.
- Maintain prompt queue; allow user messages while running; queue or interrupt.
- Detect approvals via hooks/JSONL/screen patterns; route to the approval UI.
- Track tokens/cost when the agent exposes usage.
- Resume/fork; capture trace; expose a dashboard.

Dashboard columns: agent, task, model, state, elapsed, cost, diff, approvals.
Actions: focus, queue prompt, interrupt, approve/deny, view diff, rollback,
resume, export trace.

Adapters for Claude Code, Codex, Gemini CLI, OpenCode, Aider, Warp Agent CLI,
generic command. For agents without hooks, use a PTY-side heuristic and label it
as approximate. Never claim exact state when using heuristics.

Acceptance: run three agents in parallel; see which needs approval without
focusing each tab; approve from the dashboard; the approval is audited.

### 4.11 Context engine

Sources:

- Current block/selection.
- Pinned blocks/files.
- Repo index: file tree, symbols, imports, tests.
- Git: branch, diff, recent commits.
- Docs and MCP resources.
- User notes/rules (AGENTS.md/CLAUDE.md).

Index:

- SQLite FTS5 for text; tree-sitter for symbols; optional local embeddings
  (sqlite-vec or a local vector store) disabled by default.
- Incremental update on file save/git checkout; ignore `.git`, `target`,
  `node_modules`, secrets patterns.
- Size limits and symlink protection.

Context builder:

```text
query → candidate retrieval (FTS + symbols + recency + graph)
      → rank (relevance, proximity, recency, pin boost)
      → dedupe/merge
      → token budget (model context window × 0.6)
      → secret/PII redaction
      → cited context pack (files/lines/blocks)
```

UI: `@` picker with file/block/symbol/URL; context drawer with token count;
“why is this included?”; remove individual items; preview what will be sent.

Acceptance: context pack is deterministic for the same inputs; no secret leaves
the machine; a 100k-file repo indexes incrementally in the background.

### 4.12 Approval broker, MCP and ACP

MCP proxy:

- Zentrion exposes a local MCP server to agents (`z mcp serve`).
- Tools are proxied through the policy broker: filesystem, process, network,
  secrets, custom MCP servers.
- Tool result limits (1 MiB), timeouts, cancellation.
- Deny by default; per-agent profile; approval UI.
- Record tool name, input hash, decision, approval, result hash.

ACP/other adapters: same bridge; normalize “tool call/approval” events. Support
CLI agents that do not speak MCP by wrapping their permission prompts.

Policy profiles:

- `agent-readonly`: read files, no writes, no network, no exec.
- `agent-dev`: read/write workspace, run allowlisted build/test commands, no
  network unless approved.
- `agent-security`: read scope, run allowlisted scanners, no destructive ops.
- `agent-ci`: non-interactive, pre-approved allowlist, hard timeouts.

Approval UI shows: agent, tool, exact input, files/diff, risk, policy reason,
cost estimate, expiry. Buttons: Approve once, Approve for session (scoped),
Edit, Deny. Editing creates a new request, never mutates the original.

Acceptance: an agent cannot write outside the workspace or reach the network
without an explicit approval; every decision is in the audit ledger; denial is
returned to the agent as structured data.

### 4.13 Diff review and checkpoints

Before any agent write:

1. Snapshot the workspace (git worktree or content-addressed copy of changed
   files) under `<data>/checkpoints/<id>/`.
2. Record base commit/tree hash and a manifest.
3. Let the agent edit.
4. Show a diff against the snapshot (file tree + hunks).
5. Accept all, accept file, accept hunk, reject, or rollback.
6. Sign the checkpoint manifest if enterprise signing is enabled.

Storage: content-addressed blobs; dedupe; GC after retention. Large repos:
use `git worktree add --detach` + `git diff`; non-git: file copy with hashes.

Acceptance: rollback returns the workspace byte-for-byte; concurrent agent
edits are serialized per workspace; no checkpoint captures ignored secrets.

### 4.14 Model router

Provider registry with capabilities:

```json
{"id":"local/ollama","kind":"local","models":["qwen2.5-coder:7b"],
 "caps":["chat","tools","code"],"cost":0,"context":32768}
```

Routing policy:

- `local-only` (air-gapped), `cost`, `latency`, `quality`, `manual`.
- Budget caps per day/task/agent; hard stop with a clear error.
- Fallback chain; retries with jitter; circuit breaker.
- Cache embeddings/responses where safe; never cache secrets.
- Streaming with cancellation; token accounting per run.
- Per-agent model override; per-task routing (plan vs edit vs review).

Acceptance: a provider outage falls back within 2 s; budgets cannot be exceeded;
usage is visible per agent/session/day.

### 4.15 Workflows and notebooks

Workflow YAML:

```yaml
name: release-check
params:
  version: {type: string, required: true}
steps:
  - id: test
    run: "cargo test --workspace"
    timeout: 20m
  - id: scan
    run: "z security scan ."
  - id: approve
    approve: "Ship ${version}?"
  - id: publish
    run: "cargo publish"
    when: "steps.approve.approved"
```

Steps: `run`, `agent`, `approve`, `parallel`, `if`, `http` (policy-gated),
`artifact`. Variables, secret handles, retries, timeouts, working dir, env.
Scheduling via daemon; runs are audited. Notebooks: shell/markdown/AI cells,
execution order, outputs, share/export, parameterized.

Acceptance: a failed step stops the workflow; approvals are explicit; runs are
reproducible and exportable.

### 4.16 Remote, SSH and durable sessions

- Native SSH client (`russh`): host key verification, keys/agent, jump hosts,
  port forwarding, SFTP, remote command.
- Remote domain: run a small `z-session` agent on the remote host over SSH;
  local UI attaches over the existing SSH channel. No new open port.
- Durable session: remote agent keeps PTY alive, buffers output, reconnects.
- Zmodem/SFTP transfer; remote file editing via editor.
- Web client: local daemon serves WebSocket; read-only observer tokens; TLS
  optional; no inbound exposure by default.

Acceptance: drop the network; reconnect; the remote build is still running;
host key mismatch refuses connection; no plaintext credentials in logs.

### 4.17 Team, sync and enterprise

- Identity: OIDC/SAML SSO; SCIM provisioning; RBAC roles
  (`owner|admin|auditor|member|viewer`).
- Fleet policy: signed policy bundle fetched from the control plane; local
  validation; last-known-good; audit on change.
- E2EE sync: settings/workflows/notebooks/themes via CRDT (automerge/Yjs-like),
  keys derived from a user passphrase + device keys; server stores ciphertext.
- Audit export: SIEM webhook, S3/Blob, syslog; signed batches; retention.
- Spend: per-team/agent model budgets; allowlists; usage reports.
- Compliance: SOC 2/ISO evidence exports; data residency; zero-retention
  provider settings; self-hosted control plane.
- Read-only auditor: view live sessions, approvals, audit; no input.

Acceptance: an admin can enforce “no cloud models” and “no writes outside
workspace” fleet-wide; an auditor can replay a session without seeing secrets.

### 4.18 Plugins and SDK

- wasmtime host; plugins declare capabilities in a signed manifest.
- Extension points: command, palette action, status widget, block renderer,
  theme, completion source, agent adapter, workflow step.
- No ambient filesystem/network; all host calls go through the broker.
- Resource limits (CPU/memory/time) and crash isolation.
- Registry: signed packages, version constraints, revocation.
- SDKs: Rust (native), TypeScript/Python (JSON-RPC), CLI/headless, IDE bridge.

Acceptance: a malicious plugin cannot read files or open sockets without a
grant; a crashed plugin does not crash the terminal; uninstall removes state.

### 4.19 Security workbench

- Engagement workspace: scope, authorization note, dates, rules of engagement.
- Scope guard: every host/URL/command checked against scope; out-of-scope
  requires explicit break-glass with audit.
- Evidence: command, output, timestamp, operator, host, hash; append-only;
  export with chain-of-custody.
- Findings: severity, evidence links, CVSS/MITRE, remediation, report templates.
- Integration: scanners, notes, screenshots, PCAP/forensics viewers (via plugins).
- Collaboration: read-only observer, incident room, approvals.
- SIEM export; signed report; redaction profiles.

Acceptance: an out-of-scope target is blocked before network I/O; evidence
tampering is detectable; reports contain reproducible commands and hashes.

### 4.20 Notifications, accessibility and i18n

- Notifications: OSC 9/777, command completion, agent states, approvals;
  desktop notifications; tab badges with priority; do-not-disturb.
- Accessibility: screen-reader mode (semantic block text), high contrast,
  reduced motion, keyboard-only navigation, font scaling, focus indicators.
- i18n: UI strings externalized; RTL layout for chrome; CJK ambiguous width;
  locale-aware dates; translated docs.
- Themes: import/export, light/dark auto, 256/truecolor, contrast checks.

---

## 5. UX flows

### 5.1 First run

```text
z ui
 ├─ detect OS/shell; offer to install shell integration (preview diff)
 ├─ import from iTerm2/Ghostty/Windows Terminal/Warp/Tabby (optional)
 ├─ choose theme, font, profile (beginner/developer/security)
 ├─ `z tour`: 5 interactive steps (run a command, split, search, block, agent)
 └─ open a real shell; show “F2 palette · F4 AI · F11 search”
```

### 5.2 Daily developer flow

1. Open workspace; panes restore.
2. Run `cargo test`; block shows header, timer, live output.
3. Search output with F11; copy a failure.
4. Pin the failing block to the agent context.
5. Ask the agent to fix; review diff; accept/rollback.
6. Commit via palette; block links to the commit.

### 5.3 Agent approval flow

```text
Agent wants: write src/lib.rs + run cargo test
┌─ Approval required ──────────────────────────────────────────┐
│ Agent: claude-code        Risk: medium      Cost: $0.04      │
│ Tool: filesystem.write    Scope: ./src/lib.rs                │
│ Policy: agent-dev allows workspace writes; exec needs review │
│ Preview: 3 files, +42 −7                                     │
│ [Approve once] [Approve for session] [Edit] [Deny]           │
└──────────────────────────────────────────────────────────────┘
```

After approval: diff review, checkpoint, audit entry, badge cleared.

### 5.4 Beginner flow

- `z do "find why my tests fail"` → intent preview → suggested commands →
  explain output → offer fix → show diff → apply with undo.
- Every dangerous action shows a plain-English warning and a safe alternative.

### 5.5 Incident/security flow

- Create engagement → set scope → run tools → capture evidence → findings →
  report; share read-only session with reviewer; export signed bundle.

### 5.6 Team flow

- Share workflow/notebook; teammate imports; approval roles; auditor observes;
  fleet policy enforces model/network limits.

---

## 6. Keymap design

Terminals cannot distinguish `Ctrl+Shift+<letter>` from `Ctrl+<letter>` in the
general case. Use function keys and a leader:

| Key | Action |
|---|---|
| F2 | command palette |
| F3 | editor |
| F4 | copilot/agent panel |
| F5 | system monitor |
| F6 | LAN chat |
| F7 | new tab |
| F8 | split pane |
| F9 | close pane |
| F10 | quit |
| F11 | search |
| F12 | copy mode |
| Alt+1..9 | select tab |
| Alt+←/→ | previous/next tab |
| Alt+O | next pane |
| Alt+V / Alt+H | dashboard / home |
| Shift+PgUp/PgDn | scroll |
| Ctrl+Space | leader (then `b` blocks, `a` agents, `w` workspace, `s` search, `c` copy, `p` palette, `?` help) |

Everything is rebindable; the leader is optional and disabled by default in
favor of direct keys.

---

## 7. Performance engineering

### 7.1 Budgets

| Layer | Budget |
|---|---|
| PTY read → parser | ≤2 ms per 16 KiB chunk |
| Parser → frame | ≤8 ms p95 |
| Input → PTY write | ≤2 ms |
| Frame render | ≤16.6 ms at 60 FPS |
| Block record | ≤1 ms per block (async persistence) |
| Search 100k lines | ≤50 ms |
| Context retrieval | ≤100 ms local |
| Session attach replay | ≤500 ms for 10k lines |

### 7.2 Techniques

- Zero-copy reads where possible; reuse buffers.
- Batch PTY writes; coalesce frames; damage-only rendering.
- Async scrollback compression (zstd) off the hot path.
- SQLite WAL + prepared statements; no DB calls on the render thread.
- Bounded channels with backpressure; slow clients get keyframes.
- Profile with `perf`/`cargo flamegraph`; track regressions in CI.

### 7.3 Benchmark suite

- `vtebench` throughput; DOOM-fire FPS; large log replay; 4-pane stress;
  100k-line search; startup/latency harness; memory soak.
- Publish hardware, OS, build flags, methodology and p50/p95.
- CI gate: >10% regression fails.

---

## 8. Security and threat model

### 8.1 Trust boundaries

```text
untrusted terminal output (VT/OSC)  → parser (no execution)
untrusted links/files              → confirmation + policy
agent/model output                → advice only
agent tool call                   → MCP/ACP bridge → policy → approval → broker
plugin                            → wasm sandbox → capability host calls
remote host                       → SSH host key + policy
web client                        → token + RBAC + TLS
```

### 8.2 Threats and mitigations

| Threat | Mitigation |
|---|---|
| Malicious OSC/CSI crashes or spoofs UI | strict parser, limits, golden/fuzz tests, no execution |
| OSC 52 clipboard exfiltration | opt-in, size cap, no read, per-app allowlist |
| Hyperlink phishing | show target, confirmation, scheme allowlist |
| Secret leakage to model | gateway redaction, context preview, local-only mode |
| Agent writes outside workspace | policy + Landlock/seccomp when available, approvals |
| Agent tool-call replay | single-use nonce/TTL approval tokens |
| Malicious plugin | wasm sandbox, capabilities, signed manifests, limits |
| Supply-chain update | SHA-256 + signatures, staged rollout, rollback |
| Audit tampering | hash chain + signatures + external export |
| SSH MITM | host-key verification, no auto-accept |
| Web exposure | loopback default, read-only tokens, TLS, RBAC |
| Prompt injection | treat model output as untrusted; tool calls gated |
| Path traversal in scans | no symlink following, canonicalize, bounds |

### 8.3 Sandbox roadmap

Current: `no_new_privs`, non-dumpable, `PDEATHSIG`, rlimits, umask. Next:

1. **Landlock** filesystem rules from policy scopes (read/write/exec).
2. **seccomp** deny-list for network/socket syscalls when `network: none`.
3. **cgroup v2** CPU/memory/pids for agent/tool runs.
4. **Network namespace** for `network: none` when privileges allow.
5. macOS Seatbelt profile; Windows Job Object + restricted token.
6. Report the actual achieved level per action; fail closed if required level
   is unavailable.

---

## 9. Testing and quality

- **Unit:** parser, blocks, policy, context ranking, redaction, config.
- **Golden:** VT/OSC screen snapshots per sequence; block rendering.
- **Integration:** PTY round-trip, daemon attach/detach, SSH, MCP, agents,
  checkpoints, workflow runs.
- **Fuzzing:** VT/OSC parser; config/YAML; MCP frames; plugin wasm.
- **Property:** search/copy round-trips; block state machine; policy invariants.
- **Load:** 1 GB output, 100k blocks, 4 panes, 10 agents, memory soak.
- **Cross-platform:** Linux, macOS, Windows CI; ConPTY tests.
- **Security:** secret redaction, path traversal, OSC injection, approval replay,
  plugin escape, host-key mismatch.
- **Agent evals:** scripted prompts across models; tool-call correctness; cost;
  diff quality; regression suite.
- **Migration:** import fixtures from iTerm2/Ghostty/Warp/Windows Terminal.

---

## 10. Telemetry and privacy

- Off by default; explicit opt-in; local-only metrics by default.
- Never collect prompts, command output, file contents, secrets or clipboard.
- Aggregate counters (feature usage, latency, crash signature) only.
- Per-project opt-out; enterprise policy can disable.
- A `z privacy` command shows exactly what would be sent.

---

## 11. Packaging and release

- Build targets: Linux x64/arm64, macOS universal, Windows x64/arm64.
- Formats: tar.gz, deb/rpm, Homebrew, winget, MSI, DMG, scoop.
- Signed artifacts + checksums; auto-update from signed manifest; staged rollout;
  rollback.
- Channels: stable, beta, nightly; `z upgrade --channel`.
- Migration: side-by-side install, import, uninstall preserving user data.
- Crash reporting opt-in with local preview.

---

## 12. Delivery plan

### Phase 0 — Foundation (weeks 1–2)

- Extract `z-vt` from `tui`; define `z-session` protocol; SQLite schema.
- Shell integration scripts for bash/zsh/fish/pwsh/nushell.
- Block lifecycle + basic UI; copy/search/hyperlinks.
- Config/keybinding schema + migration.

### Phase 1 — Daily driver (weeks 3–6)

- Session daemon + attach/detach; restore; workspaces/layouts.
- GPU renderer spike; benchmark harness; packaging/import/onboarding.
- Notifications/progress; accessibility baseline.

### Phase 2 — Agentic (weeks 7–12)

- Agent supervisor + adapters (Claude Code, Codex, Gemini, OpenCode, Aider).
- Context index + `@` picker; approval broker/MCP proxy.
- Diff review + checkpoints; model router; workflows/notebooks MVP.

### Phase 3 — Remote/team (months 4–6)

- SSH domains, durable sessions, remote agent, web client.
- Team sync, SSO/SCIM/RBAC, audit export, fleet policy.
- Plugin host + registry.

### Phase 4 — Moats (months 6–12)

- Security workbench, signed ledger, time travel, incident room, air-gapped AI.
- Independent security audit; SOC 2 readiness; signed releases.

### Team shape

- 2 renderer/runtime engineers
- 2 session/remote engineers
- 1 shell/integration engineer
- 2 agent/context engineers
- 1 security/policy engineer
- 1 UX/design
- 1 QA/automation
- 1 developer relations/docs

---

## 13. Acceptance criteria by epic

| Epic | Done when |
|---|---|
| Shell integration | Five shells, prompt jump, exit code, cwd, select output; existing prompts still work |
| Blocks | 100k blocks searchable, share redacted, survive restart |
| Copy/search | 100k-line regex <50 ms; Unicode round-trip; links safe |
| Sessions | UI crash/restart keeps processes; two clients attach |
| Config | Every action rebindable; invalid config fails with line number |
| GPU | 60 FPS at 10 MB/s; p95 latency <16 ms; CPU fallback |
| Agent host | Three agents parallel; approval from dashboard; audited |
| Context | Deterministic pack; no secret egress; 100k files indexed |
| Approval | Deny by default; single-use tokens; replay rejected |
| Checkpoints | Byte-identical rollback; concurrent edits serialized |
| Model router | Budget enforced; fallback <2 s; per-agent usage |
| SSH/durable | Network drop, reconnect, process still running |
| Team/enterprise | Fleet policy enforced; auditor replay; SIEM export |
| Plugin | Malicious plugin cannot escape capabilities |
| Security workbench | Out-of-scope blocked pre-network; evidence tamper-evident |

---

## 14. Open decisions

1. **GPU renderer:** build on wgpu/glyphon vs fork Ghostty/WezTerm components vs
   use a web renderer. Recommendation: wgpu + glyphon for control; keep TUI.
2. **License:** BUSL vs Apache-2.0/MIT client. Recommendation: open client/SDK,
   commercial enterprise server; Warp’s open client raises the bar.
3. **Agent protocol:** MCP-first, ACP adapter later; do not invent a new
   proprietary tool protocol.
4. **Cloud sync:** local-first + E2EE optional; do not require an account.
5. **Block storage:** SQLite vs embedded KV; recommendation: SQLite for
   searchability + separate compressed output store.
6. **Web client:** xterm.js vs custom canvas; recommendation: start with
   xterm.js for speed, replace hot paths later.
7. **Plugin ABI:** WASM (wasmtime) vs WASI preview 2; recommendation: wasmtime
   with a narrow host ABI and capability manifest.

---

## 15. Innovation backlog (after the basics)

- **Command provenance graph:** command → files → tests → commit → PR.
- **Policy simulator:** test agent plans against policy before running.
- **Signed evidence mode:** every block/report export carries a verifiable
  signature and chain-of-custody.
- **Context pins:** pin blocks/files to an agent; visible token budget.
- **Time-travel terminal:** semantic replay of a session with diffs.
- **Workspace snapshots:** full environment + agent state, portable.
- **Read-only auditor seat:** live observer with secret redaction.
- **Air-gapped mode:** local models, no egress, signed model registry.
- **Incident room:** shared session, annotations, approvals, postmortem.
- **Universal agent adapter:** MCP/ACP/CLI/remote agents behind one UI.
- **Intent bar:** natural language → command plan → risk preview → run.
- **Explain & undo:** explain any block and revert its effects where possible.
- **Fleet agent runs:** schedule/queue agents across machines with policy.
- **Benchmark leaderboard:** reproducible, community-submitted results.

---

## 16. What not to build

- A full IDE/LSP from scratch before blocks/sessions/agents are excellent.
- A proprietary cloud sync service before local workflows are excellent.
- A foundation model.
- A native mobile app before a web client.
- A plugin runtime before the session/block/config contracts are stable.
- “Fastest” or “maximum sandbox” marketing without published evidence.
- A custom agent protocol when MCP/ACP already exist.

---

## 17. Example files

Target-schema examples live in [`docs/examples/`](examples/):

- [`zentrion.toml`](examples/zentrion.toml) — full configuration
- [`workspace.yaml`](examples/workspace.yaml) — tabs/panes/layout/restore
- [`workflow.yaml`](examples/workflow.yaml) — parameterized workflow with approval
- [`agents/claude-code.yaml`](examples/agents/claude-code.yaml) — agent adapter
- [`policy.yaml`](examples/policy.yaml) — agent profiles and network rules

These are design examples, not configurations the current build validates yet.

## 18. Source notes

See [Competitive roadmap §17](COMPETITIVE-ROADMAP.md#17-source-notes) for the
market sources. This blueprint adds no external claims; protocol and schema
designs are original to Zentrion.
