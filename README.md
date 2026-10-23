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

# Zentrion Terminal
### The Category-Leading, Pure-Rust Local-First Agentic Terminal

**Ultra-fast terminal multiplexer with policy-brokered AI agents, deep SecOps workflows, durable sessions, and zero Electron latency.**

*Engineered by [Zentrion Technologies](https://zentriontechnologies.com)*

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-orange.svg?style=flat-square)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-brightgreen?style=flat-square&logo=linux)](releases/README.md)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows)](releases/README.md)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-silver?style=flat-square&logo=apple)](releases/README.md)
[![Powered by Rust](https://img.shields.io/badge/Powered%20by-Rust-orange?style=flat-square&logo=rust)](Cargo.toml)
[![Tests: Passing](https://img.shields.io/badge/Tests-60%20Integration%20Passing-success?style=flat-square)](tests/cli_integration.rs)

</div>

---

## 🌟 Why Zentrion Terminal?

Modern terminal emulators force developers and security engineers to compromise: either accept resource-heavy, laggy Electron wrappers, or use bare-bones terminal windows with no native AI context, no command auditing, and fragile session lifecycles.

**Zentrion Terminal** redefines the terminal experience. Built 100% in pure Rust, it combines:
- **Zero-Latency Native Execution:** Real OS PTYs (`portable-pty`), sub-millisecond screen search, and high-throughput VT100 parsing capable of rendering massive log dumps without UI stutter.
- **Autonomous Terminal AI Agent:** Full terminal screen buffer awareness, automatic error code diagnostics (`z ai fix`), 1-click execution fixes with human-in-the-loop approval, and real-time SSE token streaming (`z models ask --stream`).
- **Native Multiplexing & Durable Sessions:** Multi-pane splits, tabs, named workspaces, and a Unix daemon architecture that preserves PTY processes across terminal restarts.
- **Enterprise-Grade Threat & SecOps Workflow:** Built-in security cheat sheets, payload lookups (XSS, SQLi, CSRF), automated security header checks, scope enforcement, and Ed25519-signed evidence chains.
- **Web Observer with Live SSE Streaming:** Real-time browser viewing with full 16/256/truecolor ANSI terminal rendering, blinking cursor, and command history.

---

## ⚡ Core Capabilities & Architecture

| Feature | Zentrion Terminal Architecture |
|---|---|
| **Pure Native Performance** | 100% Rust memory safety, zero DOM/web latency, sub-millisecond FTS search, and high-throughput log streaming. |
| **Native PTY & Shell Integration** | Full OS PTYs supporting interactive tools (`htop`, `vim`, `nano`, `ssh`, Python debuggers). Authoritative OSC 133 command blocks capture cwd, exit code, duration, and output hash. |
| **Multi-Pane & Workspaces** | Up to 4 split panes per tab, unlimited tabs, vi-style copy mode (`F12`), and YAML-based workspace layouts with selective restore policies (`never`, `layout`, `layout+cwd`, `full`). |
| **Autonomous AI Diagnostics** | `z ai fix` inspects recent failed command blocks, identifies root causes, and proposes 1-click execution fixes with human approval. `z ai explain` clarifies syntax and flags. |
| **Streaming Model Router** | Multi-provider router (Ollama, OpenAI, Anthropic, Gemini, Groq) with daily budget reservations, fallback routing, prompt credential redaction, response caching, and SSE token streaming (`--stream`). |
| **Live Agent Dashboard & MCP** | TUI live dashboard (`Alt+A`) polling `z-agents::Supervisor` runs, history, and approval broker requests. Native Model Context Protocol (MCP) server (`z mcp serve`) with single-use approval tokens. |
| **SecOps & Scope Enforcement** | Pre-execution scope guards block unauthorized commands before spawn; Ed25519 signed audit trail guarantees non-repudiation. |
| **Real-Time Web Observer** | Loopback HTTP server (`z web serve`) with SSE push updates (`/api/session/{id}/stream`), high-fidelity ANSI color parsing, and token-based read/write access. |
| **WASM Plugin Sandbox** | Wasmtime plugin host (`z plugin run`) with strict memory/fuel caps and zero unauthorized network or filesystem access. |

---

## 🚀 Quick Start

### 1. Launch the Interactive Terminal UI (TUI)
```sh
z ui
```

### 2. Autonomous Error Fix & Explain
When a terminal command fails with a non-zero exit code:
```sh
# Analyze the last failed command and propose a fix
z ai fix

# Review and execute the proposed fix with human-in-the-loop approval
z ai fix --approve

# Explain any complex command, pipeline, or error
z ai explain "iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
```

### 3. Stream AI Model Completions
```sh
# Ask with real-time SSE token streaming
z models ask "Explain the difference between TCP SYN and ACK scan" --stream
```

### 4. Serve the Web Observer
```sh
# Start loopback web observer with live SSE streaming & ANSI rendering
z web serve --allow-input
```

---

## ⌨️ TUI Keyboard Shortcuts

All 26 keybindings dispatch cleanly through `z-config::Keymap`:

| Key | Context | Action |
|---|---|---|
| `F2` | Global | Command palette (`:theme`, `:split`, `:view`, `:e`, `:ai`, `:quit`) |
| `F3` | Global | Built-in text editor (`Ctrl+S` save, `Ctrl+O` open) |
| `F4` | Global | AI copilot sidebar (credential-redacted, advisory only) |
| `F5` | Global | Live system resource monitor (CPU, RAM, top processes) |
| `F6` | Global | Encrypted LAN peer-to-peer chat (AES-256-GCM, zero servers) |
| `F7` | Terminal | Create new terminal tab |
| `F8` | Terminal | Split active pane horizontally/vertically (up to 4 panes) |
| `F9` | Terminal | Close active pane / tab |
| `F10` | Global | Quit Zentrion Terminal |
| `F11` | Terminal | Search live session and SQLite command block store; rerun commands |
| `F12` | Terminal | Vi-style copy mode (`hjkl`, `w/b`, `/` search, `v` select, `y` yank) |
| `Alt+A` | Global | Agent approval inbox (review, approve `a`, or deny `d` actions) |
| `Alt+V` | Global | Toggle between terminal and dashboard views |
| `Alt+H` | Global | Return to dashboard home |
| `Alt+O` | Terminal | Focus next pane |
| `Alt+1..9` | Global | Select tab `1..9` (or dashboard view) |
| `Alt+← / →` | Terminal | Select previous / next tab |
| `Shift+PgUp/Dn` | Terminal | Scroll terminal history buffer |

---

## 📥 Installation

### Option A: Build from Source (Recommended for Developers)

Requires Rust 1.75+ and a standard C toolchain:

```sh
git clone https://github.com/Sanjay-Program/ZENTRION-TERMINAL.git
cd ZENTRION-TERMINAL
cargo build --release
install -m 755 target/release/z ~/.local/bin/z   # Or place in your $PATH
z --version
```

### Option B: Automated Platform Installer

```sh
# Linux & macOS
ZENTRION_SOURCE_DIR="$PWD" bash releases/install.sh

# Windows (PowerShell)
$env:ZENTRION_SOURCE_DIR = "$PWD"; powershell -ExecutionPolicy Bypass -File .\releases\install.ps1
```

---

## 🧠 AI Provider Configuration

Zentrion supports local-first and enterprise cloud LLMs with strict prompt credential redaction:

```sh
# Local Ollama (Default, 100% offline)
export ZENTRION_AI_PROVIDER=ollama
export ZENTRION_AI_MODEL=qwen2.5-coder:7b

# OpenAI
export ZENTRION_AI_PROVIDER=openai
export OPENAI_API_KEY="sk-..."
export ZENTRION_AI_MODEL=gpt-4o-mini

# Anthropic Claude
export ZENTRION_AI_PROVIDER=anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
export ZENTRION_AI_MODEL=claude-3-5-sonnet-20241022

# Any OpenAI-compatible local endpoint (vLLM, LocalAI)
export ZENTRION_AI_PROVIDER=openai-compatible
export ZENTRION_AI_BASE_URL="http://127.0.0.1:8080/v1"
```

---

## 🛡 Security Architecture & Governance

```text
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ User / Agent │ ──> │ Policy Engine│ ──> │ Risk Guard & │ ──> │ Audited Host │
│  Invocation  │     │ (Allowlists) │     │ Approval     │     │ Execution    │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                 │                     │
                                                 ▼                     ▼
                                          ┌──────────────┐      ┌──────────────┐
                                          │ Human-in-the-│      │ Ed25519 Hash │
                                          │ Loop Inbox   │      │ Chain Ledger │
                                          └──────────────┘      └──────────────┘
```

1. **Deny-by-Default Policy:** Workspace read/write only. Network access, process spawning, and secrets require explicit policy grants (`z policy`).
2. **Pre-Execution Scope Guard:** `z engagement run` verifies target CIDRs, IPs, and hostnames before executing any command; out-of-scope attempts are blocked and logged.
3. **Cryptographic Non-Repudiation:** Audit events and checkpoints are hashed via SHA-256 and signed with local Ed25519 keys (`z audit key`, `z audit verify`).
4. **Hard Daily Budget Ledger:** Model invocations reserve estimated maximum tokens upfront before sending HTTP requests, preventing accidental runaway cloud expenses.

---

## 🛠 Command Reference

```sh
# Diagnostics & Status
z doctor                    # Offline health check
z status                    # Runtime, project, policy, and audit status
z config show               # Inspect effective layered configuration

# Terminal Sessions & Multiplexing
z session list              # List daemon-managed sessions
z session create --title dev# Create a durable PTY session
z session attach <id>       # Attach to a running session
z workspace save mywork     # Snapshot current tabs and pane layouts
z workspace restore mywork  # Recreate layout with restore verification

# AI Agent & Diagnostics
z ai fix                    # Analyze terminal failure and propose fix
z ai fix --approve          # Execute proposed fix with human approval
z ai explain <cmd>          # Explain command flags or error codes
z models ask "prompt" --stream # Real-time streaming model completion

# SecOps & Penetration Testing Cheat Sheets & Payloads
z security cheatsheet xss   # Built-in cheat sheets (XSS, SQLi, CSRF, SSRF, LFI, Recon)
z security payload sqli     # Curated injection test vectors and polyglots
z security headers <url>    # Automated HTTP security header grading (A+ to F)
z security scan .           # Detect hardcoded credentials and SAST patterns
z engagement create scope   # Register authorized penetration testing scope
z engagement run <id> <cmd> # Run command with strict scope validation

# Cloud & Microservice Mesh Telemetry
z cloud telemetry --sidecar envoy # Envoy/Istio sidecar traffic telemetry
z cloud anomaly --sidecar istio   # Dual-engine microservice anomaly detection

# Policy Governance & Safeguards
z policy simulate           # Replay policy against historic audit traffic
z policy push --approve     # Deploy policy with human-in-the-loop approval

# Remote & Collaboration
z remote exec <host> <cmd>  # Strict host-key SSH command execution
z web serve --allow-input   # Start web terminal observer with SSE streaming
```

---

## 🧪 Testing & Verification

Every subsystem is verified with automated tests:

```sh
# Run all workspace unit tests
cargo test --workspace

# Run complete CLI end-to-end integration suite (60 tests)
cargo test -p z-integration-tests --test cli_integration

# Verify tree-wide clippy lints
cargo clippy --workspace --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

---

## 📄 License & Organization

Zentrion Terminal is released under the **Business Source License 1.1 (BUSL-1.1)**. See [LICENSE](LICENSE) for details.

Engineered with precision by **Zentrion Technologies** · [zentriontechnologies.com](https://zentriontechnologies.com).
