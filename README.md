<div align="center">

```
███████╗███████╗███╗   ██╗████████╗██████╗ ██╗ ██████╗ ███╗   ██╗
╚══███╔╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██║██╔═══██╗████╗  ██║
  ███╔╝ █████╗  ██╔██╗ ██║   ██║   ██████╔╝██║██║   ██║██╔██╗ ██║
 ███╔╝  ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║██║   ██║██║╚██╗██║
███████╗███████╗██║ ╚████║   ██║   ██║  ██║██║╚██████╔╝██║ ╚████║
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                         T E R M I N A L
```

**A fast, local-first terminal for software development, AI work and authorized security testing.**

*Built with ❤️ by [Zentrion Technologies](https://zentriontechnologies.com)*

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-orange.svg?style=flat-square)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-brightgreen?style=flat-square&logo=linux)](releases/README.md)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows)](releases/README.md)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-silver?style=flat-square&logo=apple)](releases/README.md)
[![Powered by Rust](https://img.shields.io/badge/Powered%20by-Rust-orange?style=flat-square&logo=rust)](Cargo.toml)

</div>

---

ZENTRION TERMINAL is a shell-first terminal multiplexer with a policy broker,
audited tool manager, AI gateway and security-analysis engines built on top of
the same runtime. It does not replace your shell — it gives every shell a real
PTY, tabs, splits, and a local control plane.

## ⚡ What actually works

- **Real terminal, not a dashboard mock.** Every pane is a PTY running your
  shell through a `vt100` screen emulator. Full-screen programs, colours,
  cursor addressing, Unicode and resize all work.
- **Tabs and panes.** Up to four panes per tab, unlimited tabs. Each pane has
  its own process, history and scrollback (10,000 lines).
- **Durable sessions + command blocks.** `z session create` owns a PTY in a
  per-user daemon; attach, detach, or `z session attach` from another terminal.
  Shell integration emits OSC 133 marks, so commands become blocks with cwd,
  exit code, duration and output hash, searchable with `z blocks search`.
- **Workspaces and restore plans.** YAML tabs/panes/layouts with
  `never|layout|layout+cwd|full` restore; commands only auto-run with explicit
  opt-in. `z workspace restore --dry-run` shows the plan first.
- **Context engine.** `z context index` builds an incremental SQLite FTS5 index
  (git-aware, secret-excluding). `z context pack "query"` produces a
  deterministic, token-budgeted, redacted context pack with citations.
- **Checkpoints and rollback.** `z checkpoint create` snapshots the worktree
  content-addressed (optionally Ed25519-signed); `z checkpoint diff` shows
  hunks; `z checkpoint restore` returns files byte-for-byte and removes files
  added since the snapshot.
- **Workflows with approvals.** `z workflow run wf.yaml` executes
  run/approve/parallel/conditional/HTTP/artifact steps with timeouts, secret
  handles and audit records. HTTP is off unless allowlisted.
- **Security engagements.** `z engagement create` records authorization and
  scope; `z engagement run <id> <cmd> --target <host>` blocks out-of-scope
  commands before execution and records a signed evidence chain; reports are
  redacted and Ed25519-signed.
- **Agent host + MCP proxy.** `z agent run claude-code` supervises any adapted
  CLI agent; `z mcp serve` exposes policy-gated filesystem/process tools with
  approvals and single-use tokens. `z agent approvals` is the approval inbox.
- **Layered TOML config.** `z config show|validate|import|keys` with strict
  errors (file:line), profiles, named actions and importers for Windows
  Terminal, Ghostty and iTerm2.
- **Command palette.** `F2` opens a palette that either runs a shell command in
  the focused pane or performs an internal action (`:theme`, `:split`, `:view`,
  `:e`, `:ai`, `:quit`).
- **Built-in editor.** `F3` opens a real text editor (`Ctrl+S` save,
  `Ctrl+O` open) or `:e <path>` from the palette.
- **AI copilot.** `F4` opens a sidebar backed by the gateway. It redacts
  credentials/PII before outbound calls and never executes anything.
- **Live system monitor.** `F5` shows CPU, memory and the top processes from
  `sysinfo`.
- **Encrypted LAN chat.** `F6` starts AES-256-GCM peer-to-peer chat with UDP
  discovery and a shared passphrase. No account, no server, no telemetry.
- **Themes.** `z theme set dracula` persists a theme to your config; the UI
  loads it on the next start. Seven built-in themes.
- **Policy-brokered execution.** `z run` and `z code` go through identity,
  policy, capability, risk and audit. There is no “AI fast path”.
- **Tool registry.** Curated Kali-style bundles plus an explicit opt-in
  `--os-package` fallback to apt/brew/winget/choco.
- **Security scanning.** `z security scan .` walks a local tree and reports
  real credential matches and risky code patterns with file/line evidence.
  `z security secrets`, `z security sast`, `z cloud scan` and `z scan` cover
  more surfaces.
- **MCP client.** `z mcp connect --allow <command>` performs the JSON-RPC
  handshake and lists tools. The server process is policy-gated like any other
  brokered program.
- **Local IPC daemon + SDK.** `z daemon start` exposes policy-brokered
  execution over loopback for SDK clients. Set `ZENTRION_DAEMON_TOKEN` to
  require a shared token (`z daemon stop` / `z lockdown` stops it).
- **Verified updates.** `z upgrade` checks a manifest, verifies SHA-256,
  replaces the binary atomically and can roll back.

### Honest limits

- The sandbox is resource/privilege hardening (`no_new_privs`, rlimits,
  non-dumpable, umask, parent-death signal), **not** Landlock/seccomp
  filesystem confinement. `z platform` reports `resource-limits`.
- **TUI keybindings are only partially rebindable.** `z config keys` validates
  and prints the keymap, but the ratatui app still handles most keys directly.
- **Agent runs are foreground.** `z agent run` owns the agent PTY in-process;
  closing the CLI ends the agent. Agent state derived from screen patterns is
  labelled approximate.
- **Sessions are Unix-only.** The daemon/client use a Unix socket; the Windows
  named-pipe transport is not implemented. Raw scrollback is not persisted
  across a daemon restart (blocks are).
- **No GPU renderer, web client, SSH domains, plugin runtime or team control
  plane yet.** The design for them is in the blueprint, not in this binary.
- **Checkpoint accept is file-level.** Hunks are displayed, but there is no
  "accept this hunk only" operation.
- **No performance numbers are claimed.** No benchmark harness has been run.
- Plugins are validated (WASM header, manifest, SHA-256) but not executed;
  there is no embedded WASM runtime yet.
- AI research is model-synthesized. It does not crawl the web by default, and
  it is instructed not to invent citations.
- Cloud commands perform static IaC review; they do not call AWS/GCP/Azure
  APIs and there is no hosted “cloud sync” service.
- Enterprise sync requires your own control plane via
  `ZENTRION_ENTERPRISE_URL`.

See [Implementation status](docs/IMPLEMENTATION-STATUS.md) for the full,
test-backed matrix and known limitations.

## 📥 Install

### Build from source (all platforms)

Requires Rust 1.75+ (tested with current stable) and a C toolchain:

```sh
git clone https://github.com/zentrion/terminal.git
cd terminal
cargo build --release
install -m 755 target/release/z ~/.local/bin/z   # or copy to a PATH directory
z ui
```

### Linux release archive

A real Linux x64 archive is produced locally by:

```sh
./scripts/package.sh
# dist/zentrion-linux-x64.tar.gz + .sha256 + .json
```

### Installer scripts

`releases/install.sh` (Unix) and `releases/install.ps1` (Windows) build from
source. They respect `ZENTRION_SOURCE_DIR` if you already have a checkout:

```sh
# Unix
ZENTRION_SOURCE_DIR="$PWD" bash releases/install.sh

# Windows PowerShell
$env:ZENTRION_SOURCE_DIR = "$PWD"; powershell -ExecutionPolicy Bypass -File .\releases\install.ps1
```

macOS and Windows artifacts are not built in this environment; build from source
instead. See [Releases & Installers](releases/README.md).

## 🚀 Quick Start

```sh
z ui
```

**Keys**

| Key | Action |
|---|---|
| `F2` | Command palette |
| `F3` | Mini IDE / editor |
| `F4` | AI copilot sidebar |
| `F5` | System monitor |
| `F6` | LAN chat |
| `F7` | New tab |
| `F8` | Split pane (max 4) |
| `F9` | Close pane; a one-pane tab closes when another tab exists |
| `F10` | Quit |
| `Alt+V` | Toggle terminal / dashboard |
| `Alt+H` | Dashboard home |
| `Alt+1..9` | Switch terminal tab (or dashboard view while in a dashboard) |
| `Alt+O` | Focus next pane |
| `Alt+←/→` | Previous/next tab |
| `Alt+P` | Cycle proficiency hints |
| `Shift+PgUp/PgDn` | Scroll terminal history |
| Mouse wheel | Scroll history (or forward to full-screen apps that enable mouse) |
| `Shift+Home/End` | Jump to top/bottom of history |
| `Ctrl+S` / `Ctrl+O` | Save / open inside the editor |
| `Tab` / `Shift+Tab` | Next/previous dashboard view |
| `1..0` | Jump to a dashboard view |

> The terminal does not steal `Ctrl+P`, `Ctrl+Q` or `Ctrl+D` from your shell:
> ordinary control keys go to the running program.

## 🧠 AI provider setup

The copilot, `z ai ask`, `z ai auto` and research views use the gateway.

**Local (Ollama, default):**
```sh
export ZENTRION_AI_PROVIDER=ollama
export ZENTRION_AI_MODEL=qwen2.5-coder:7b
```

**OpenAI:**
```sh
export ZENTRION_AI_PROVIDER=openai
export OPENAI_API_KEY="sk-..."
export ZENTRION_AI_MODEL=gpt-4o-mini
```

**Qwen / DashScope-compatible:**
```sh
export ZENTRION_AI_PROVIDER=qwen
export DASHSCOPE_API_KEY="..."
```

**Any OpenAI-compatible endpoint:**
```sh
export ZENTRION_AI_PROVIDER=openai-compatible
export ZENTRION_AI_BASE_URL=http://127.0.0.1:8080/v1
```

Credentials and PII are redacted by the gateway before any outbound request.

## 🔐 Security model

```text
caller -> identity -> policy -> capability -> risk/approval -> broker -> audit
```

- Deny-by-default policy: workspace read/write only, no network, no process
  spawning, no secrets, no admin until a project policy grants it.
- `z code allow` writes an explicit project allowlist for the detected
  toolchain (cargo, npm, go, python, make, git). Review it before committing.
- Network probes (`z network dns|ports|ping|http`) require the target to be in
  `network.allow` or an explicit `--allow` for that one request.
- Audit log is a SHA-256 hash chain; `z audit verify` detects tampering.
- Secrets live in an AES-256-GCM vault with a per-install key file (`0600`),
  not in config or environment dumps.
- Tool installs are checksum/trust-gated; the OS package-manager fallback is
  never implicit.

## 🛠 Common commands

```sh
z doctor                    # offline health check
z status                    # runtime, project, policy, audit
z setup                     # create durable local storage
z init . --name myproject   # scaffold .zentrion/
z code status               # detect the toolchain and commands
z code test                 # run through the broker
z code allow                # allow the detected toolchain in project policy
z security scan .           # secrets + code + dependency scan
z security posture          # policy + audit + latest scan
z scan .                    # native engine scan
z finding list              # findings from the latest scan
z report latest             # markdown report
z network dns example.com --allow
z network ports example.com 1-1024 --allow
z cloud scan .              # static IaC review
z bundle list               # curated tool bundles
z install nmap              # verified install from the registry
z run <tool> [args]         # brokered execution
z mcp connect --allow npx -y @modelcontextprotocol/server-filesystem /tmp
z agent profiles
z agent run "plan a safe review of this repo"
z theme set cyberpunk
z daemon start
z upgrade check
```

## 📚 Documentation

- [Getting Started](docs/GETTING_STARTED.md)
- [Terminal & UI](docs/terminal.md)
- [Architecture](docs/architecture/overview.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Tools](docs/tools/README.md)
- [Competitive roadmap](docs/COMPETITIVE-ROADMAP.md) — what to build next to lead the market
- [Implementation blueprint](docs/IMPLEMENTATION-BLUEPRINT.md) — deep architecture, protocols, schemas and delivery plan
- [Documentation index](docs/DOCUMENTATION_INDEX.md)

## 🧪 Build & test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## 🏢 About

ZENTRION TERMINAL is a product of **Zentrion Technologies**. Learn more at
[zentriontechnologies.com](https://zentriontechnologies.com).

## 📄 License

Business Source License 1.1 (BUSL-1.1). See [LICENSE](LICENSE).
