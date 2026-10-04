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

**The world's #1 terminal. A lightweight, fully modifiable, universal developer + AI + cybersecurity runtime that performs everything.**  
Nothing — human, AI, plugin, IDE, or CI — touches the OS without an explicit, policy-checked, audited capability.

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-orange.svg?style=flat-square)](LICENSE)
[![Platform: Linux x64](https://img.shields.io/badge/Linux-x64%20Download-brightgreen?style=flat-square&logo=linux)](releases/DOWNLOAD_GUIDE.md)
[![Platform: Windows x64](https://img.shields.io/badge/Windows-x64%20Download-blue?style=flat-square&logo=windows)](releases/DOWNLOAD_GUIDE.md)
[![Platform: macOS Universal](https://img.shields.io/badge/macOS-Universal%20Download-silver?style=flat-square&logo=apple)](releases/DOWNLOAD_GUIDE.md)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange?style=flat-square&logo=rust)](Cargo.toml)
[![Version](https://img.shields.io/badge/Version-0.1.0-purple?style=flat-square)](CHANGELOG.md)
[![Security: Policy-Enforced](https://img.shields.io/badge/Security-Policy--Enforced-red?style=flat-square)](SECURITY.md)

</div>

---

## Table of Contents

- [What is ZENTRION TERMINAL?](#what-is-zentrion-terminal)
- [The Core Principle](#the-core-principle)
- [Download](#-download)
- [Install](#-install)
  - [Linux (Archive)](#option-1--linux-from-release-archive-recommended)
  - [Build from Source](#option-2--build-from-source-all-platforms)
  - [Windows](#option-3--windows)
  - [macOS](#option-4--macos)
  - [Uninstall](#uninstall)
- [Quick Start](#-quick-start)
- [AI Provider Setup](#-ai-provider-setup)
- [All Commands — Complete Reference](#-all-commands--complete-reference)
- [Security Architecture](#-security-architecture)
  - [Policy System](#1-policy-system)
  - [Capability System](#2-capability-system)
  - [Identity System](#3-identity-system)
  - [Execution Broker](#4-execution-broker)
  - [Audit System](#5-audit-system)
  - [Sandbox](#6-sandbox)
  - [Secrets Management](#7-secrets-management)
- [AI Integration & Architecture](#-ai-integration--architecture)
  - [AI Runtime](#ai-runtime-z-ai)
  - [AI Gateway](#ai-gateway)
  - [Agent Runtime](#agent-runtime)
  - [MCP Architecture](#mcp-model-context-protocol)
  - [AI Supply Chain & BOM](#ai-supply-chain--bom)
- [Tool System](#-tool-system)
  - [Tool Categories](#tool-categories)
  - [Tool Lifecycle](#tool-lifecycle)
- [Shell & Terminal Integration](#-shell--terminal-integration)
  - [PowerShell](#powershell-windows)
  - [WSL](#wsl-windows-subsystem-for-linux)
  - [Git Integration](#git-integration)
  - [Kali Linux Tools](#kali-linux-tools-security-toolkit)
- [Native Engines](#-native-engines)
- [Plugin System](#-plugin-system)
- [Project System](#-project-system)
- [Platform Support](#-platform-support)
- [System Architecture](#-system-architecture)
- [Roadmap](#-roadmap)
- [Building & Development](#-building--development)
- [SDK & API](#-sdk--api)
- [Documentation](#-documentation)
- [License](#-license)
- [Security Reporting](#-security-reporting)

---

## What is ZENTRION TERMINAL?

ZENTRION TERMINAL is the official terminal, runtime, and AI execution platform built by **Zentrion Technologies**. It serves as the single, unified control layer for:

- **Developers** — backend, frontend, mobile, data, DevOps
- **Security professionals** — authorized pen testing, red teaming, defensive work
- **AI/ML engineers** — local or cloud AI with policy enforcement
- **AI agents** — autonomous workflows that still need human-level accountability
- **MCP-based applications** — tools that use the Model Context Protocol
- **CI/CD systems** — automated pipelines with the same security as interactive use
- **Enterprise environments** — central policy, fleet management, audit compliance

It replaces the need for WSL (when not wanted), Docker (for most dev tasks), Kali Linux as a separate OS (security tools run on-demand, verified), and uncontrolled AI agents.

---

## The Core Principle

> **AI must not directly control the operating system by default.**

Every caller — human, AI, IDE, CI, plugin — passes through the same enforced pipeline:

```
Caller (Human / AI / IDE / Plugin / CI / MCP)
         │
         ▼
  ┌──────────────────────────────────────────┐
  │            ZENTRION INTERFACE            │
  └──────────────────────────────────────────┘
         │
         ▼
  ┌──────────────────────────────────────────┐
  │         ZENTRION RUNTIME                 │
  │  ┌──────────┬──────────┬──────────────┐  │
  │  │ Identity │  Policy  │  Execution   │  │
  │  └──────────┴──────────┴──────────────┘  │
  └──────────────────────────────────────────┘
         │
         ▼
  ┌──────────────────────────────────────────┐
  │          CAPABILITY SYSTEM               │
  │  (short-lived, scoped, single-use grants) │
  └──────────────────────────────────────────┘
         │
         ▼
  ┌──────────────────────────────────────────┐
  │           SECURITY LAYER                 │
  │  ┌────────┬──────────┬─────────────────┐ │
  │  │   FS   │ Network  │    Process      │ │
  │  └────────┴──────────┴─────────────────┘ │
  └──────────────────────────────────────────┘
         │
         ▼
  ┌──────────────────────────────────────────┐
  │             SANDBOX                      │
  │  Linux: landlock+seccomp+cgroups v2      │
  │  macOS: Seatbelt/sandbox-exec            │
  │  Windows: Job Objects + optional WSL2    │
  └──────────────────────────────────────────┘
         │
         ▼
  ┌──────────────────────────────────────────┐
  │          HOST ABSTRACTION                │
  │  ┌──────────┬──────────┬──────────────┐  │
  │  │ Windows  │  macOS   │    Linux     │  │
  │  └──────────┴──────────┴──────────────┘  │
  └──────────────────────────────────────────┘
```

Security is enforced in **code**, not by trusting a model to behave. A fully prompt-injected AI model can only issue requests that the policy engine, capability system, and sandbox still have to approve and constrain.

---

## 📥 Download

Full release manifest: [`releases/releases.json`](releases/releases.json)  
Install guide: [`releases/DOWNLOAD_GUIDE.md`](releases/DOWNLOAD_GUIDE.md)

| Platform | Download | SHA-256 |
|---|---|---|
| Linux x86_64 | [`zentrion-linux-x64.tar.gz`](releases/zentrion-linux-x64.tar.gz) | `625c8711a80e6d01fe2542be5ab09cd0e10e9093761552c8a9837d01633699ca` |
| macOS universal | [`zentrion-macos-universal.tar.gz`](releases/zentrion-macos-universal.tar.gz) | `938179d18b0793d47fdb0f00b5b544f64c7761ac6872f85057acd3086bb98b90` |
| Windows x64 | [`Zentrion-Windows-x64.msi`](releases/Zentrion-Windows-x64.msi) | `e8b7b7fa115bdbb549cce67f94b5affd3be80c7862938c96d78525df618ae40d` |

### Linux

```sh
base="https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases"
curl -LO "$base/zentrion-linux-x64.tar.gz"
curl -LO "$base/zentrion-linux-x64.tar.gz.sha256"
sha256sum -c zentrion-linux-x64.tar.gz.sha256
tar -xzf zentrion-linux-x64.tar.gz
install -Dm755 z "$HOME/.local/bin/z"
z doctor
```

### macOS

```sh
base="https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases"
curl -LO "$base/zentrion-macos-universal.tar.gz"
curl -LO "$base/zentrion-macos-universal.tar.gz.sha256"
shasum -a 256 -c zentrion-macos-universal.tar.gz.sha256
tar -xzf zentrion-macos-universal.tar.gz
install -m755 z /usr/local/bin/z
z doctor
```

### Windows

```powershell
$base = "https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases"
Invoke-WebRequest "$base/Zentrion-Windows-x64.msi" -OutFile "Zentrion-Windows-x64.msi"
Invoke-WebRequest "$base/Zentrion-Windows-x64.msi.sha256" -OutFile "Zentrion-Windows-x64.msi.sha256"

$expected = (Get-Content Zentrion-Windows-x64.msi.sha256).Split(" ")[0].ToUpperInvariant()
$actual = (Get-FileHash Zentrion-Windows-x64.msi -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw "Checksum failed: $actual" }

Start-Process -Wait -FilePath msiexec.exe -ArgumentList "/i Zentrion-Windows-x64.msi /qb"
z doctor
```

---

## 🔧 Install

### Option 1 — Linux from Release Archive (Recommended)

```sh
# 1. Download (see above)

# 2. Install — no root required, installs to ~/.local/bin/z by default
scripts/install.sh --archive zentrion-linux-x64.tar.gz \
  --sha256 625c8711a80e6d01fe2542be5ab09cd0e10e9093761552c8a9837d01633699ca

# 3. Add to PATH if not already
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
# For zsh:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
# For fish:
fish_add_path ~/.local/bin

# 4. Verify installation
z doctor
```

**Custom install prefix:**
```sh
scripts/install.sh --archive zentrion-linux-x64.tar.gz --prefix /usr/local
```

### Option 2 — Build from Source (All Platforms)

**Requirements:** Rust 1.75+ ([rustup.rs](https://rustup.rs))

```sh
# Clone
git clone https://github.com/Sanjay-Program/ZENTRION-TERMINAL.git
cd ZENTRION-TERMINAL

# Build release binary
scripts/build.sh release

# Install
scripts/install.sh

# Add to PATH (Linux/macOS)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

### Option 3 — Windows

```powershell
$base = "https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases"
Invoke-WebRequest "$base/Zentrion-Windows-x64.msi" -OutFile "Zentrion-Windows-x64.msi"
Invoke-WebRequest "$base/Zentrion-Windows-x64.msi.sha256" -OutFile "Zentrion-Windows-x64.msi.sha256"

$expected = (Get-Content Zentrion-Windows-x64.msi.sha256).Split(" ")[0].ToUpperInvariant()
$actual = (Get-FileHash Zentrion-Windows-x64.msi -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw "Checksum failed: $actual" }

# Install locally (No admin required, installs to %LOCALAPPDATA%\Zentrion)
Start-Process -Wait -FilePath msiexec.exe -ArgumentList "/i Zentrion-Windows-x64.msi /qb"

# Then verify:
z doctor
```

**Supported:** Windows 10 21H2+, Windows 11, x64 and ARM64  
**Shells:** PowerShell 7 (primary), PowerShell 5.1, CMD, Windows Terminal  
**Install location:** `%LOCALAPPDATA%\Zentrion\bin\z.exe` (no admin required)

### Option 4 — macOS

```sh
base="https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases"
curl -LO "$base/zentrion-macos-universal.tar.gz"
curl -LO "$base/zentrion-macos-universal.tar.gz.sha256"
shasum -a 256 -c zentrion-macos-universal.tar.gz.sha256

# Install locally
./scripts/install.sh --archive zentrion-macos-universal.tar.gz

# Verify
z doctor
```

**Supported:** macOS Ventura+, Intel (x86_64) and Apple Silicon (arm64)

### Uninstall

```sh
scripts/uninstall.sh
# Removes application files only; config, audit, tools, memory and sessions remain.
```

---

## ⚡ Quick Start

```sh
# Health check — read-only, no network calls
z doctor

# Show runtime status
z status

# Initialize and inspect durable local storage
z setup
z storage show
z storage policy

# Choose an adaptable workflow profile
z profile list
z profile apply developer
z profile apply ai-developer

# Show native platform capabilities
z platform

# Create a new project (scaffolds .zentrion/ with all manifests)
z init my-project
cd my-project

# Search the tool registry (fully offline)
z search security
z search nmap
z search --category networking

# Explore curated development/security bundles
z bundle list
z bundle plan kali-top10
z bundle plan devsecops
z bundle plan security-lab

# Inspect a tool before installing
z info nmap

# Preview install without changing anything
z install nmap --dry-run

# Install a tool (SHA-256 verified before anything is written)
z install nmap

# List installed tools
z list
z list --outdated      # only tools with newer versions available

# Run a tool through the security broker
z run nmap -- -sV 127.0.0.1

# Run a tool from the tool store
z run nmap -- --version

# See where a tool is installed
z which nmap

# Check tool for corruption
z verify nmap

# Update tools
z update              # all tools
z update nmap         # one tool

# Roll back to previous version
z rollback nmap

# Remove a tool
z remove nmap

# Scan a target (security analysis)
z scan .
z scan --profile web https://example.com
z scan --profile network 192.168.1.0/24
z scan --profile code ./src/

# View scan findings
z finding list

# View latest report
z report latest

# AI analysis of last scan
z ai analyze

# Launch the operator dashboard
z ui

# Audit log
z audit tail          # last 20 events
z audit tail 50       # last 50 events
z audit verify        # verify the tamper-evident hash chain

# Emergency stop
z lockdown
```

---

## AI Provider Setup

Zentrion defaults to a local Ollama-compatible workflow. You can switch to
OpenAI, Qwen/DashScope-compatible APIs, or any OpenAI-compatible endpoint by
environment variable. Secrets stay outside project files.

### Local Ollama or Qwen through Ollama

```sh
ollama pull qwen2.5-coder:7b
export ZENTRION_AI_PROVIDER=ollama
export ZENTRION_AI_BASE_URL=http://localhost:11434
export ZENTRION_AI_MODEL=qwen2.5-coder:7b
```

### Qwen/DashScope-compatible API

```sh
export ZENTRION_AI_PROVIDER=qwen
export DASHSCOPE_API_KEY="sk-..."
export ZENTRION_AI_MODEL=qwen3-coder-plus
```

### OpenAI

```sh
export ZENTRION_AI_PROVIDER=openai
export OPENAI_API_KEY="sk-..."
export ZENTRION_AI_MODEL=gpt-4.1-mini
```

### Any OpenAI-Compatible Endpoint

Use this for LM Studio, llama.cpp servers exposing `/v1/chat/completions`,
OpenRouter, self-hosted gateways, or enterprise proxies.

```sh
export ZENTRION_AI_PROVIDER=openai-compatible
export ZENTRION_AI_PROVIDER_NAME=local-qwen
export ZENTRION_AI_BASE_URL=http://127.0.0.1:8080/v1
export ZENTRION_AI_API_KEY=local
export ZENTRION_AI_MODEL=qwen-local
```

Agent runs use the same gateway and still pass through redaction, policy and
tool guardrails. Model choice does not grant filesystem, network or process
permissions.

---

## 📋 All Commands — Complete Reference

### Runtime & Health

| Command | Description |
|---------|-------------|
| `z` | Print banner and common commands |
| `z version` | Show version, platform, architecture, build type |
| `z version --json` | Machine-readable JSON output |
| `z doctor` | Health check: OS, config, project, policy, PATH, data dir (offline, zero network calls) |
| `z doctor --json` | JSON health report |
| `z status` | Runtime, project, policy, audit status |
| `z status --json` | Machine-readable status |
| `z setup` | Initialize local durable storage and show first-run next steps |
| `z storage show` | Show config, data, cache, tools, audit, memory and session paths |
| `z storage init` | Create missing durable storage directories |
| `z storage doctor` | Check storage path existence and writability |
| `z storage policy` | Explain what survives upgrade/uninstall |
| `z profile list` | Show adaptable user profiles |
| `z profile show <name>` | Show recommended commands and docs for a profile |
| `z profile apply <name>` | Initialize storage and print first commands for a profile |
| `z platform` | Report native platform capabilities and sandbox levels |
| `z sbom` | Emit a runtime SBOM-like JSON summary |

### Configuration

| Command | Description |
|---------|-------------|
| `z config` | Show all configuration |
| `z config get` | Get all config values |
| `z config get log_level` | Get a specific key |
| `z config get telemetry_enabled` | Get telemetry status |
| `z config set log_level debug` | Set log level (trace/debug/info/warn/error) |
| `z config set telemetry_enabled true` | Enable telemetry (off by default) |
| `z config path` | Show config directory path |

### Project Management

| Command | Description |
|---------|-------------|
| `z init` | Scaffold a project in the current directory |
| `z init my-project` | Scaffold a project in a new directory |
| `z init my-project --name custom-name` | Scaffold with a custom name |
| `z init --json` | JSON output |
| `z project` | Show current project info |
| `z project --check` | Validate project manifests |
| `z project --json` | Machine-readable project info |

`z init` creates `.zentrion/` with these files:

```
.zentrion/
├── project.yaml       # Project name, version, metadata
├── policy.yaml        # Security rules (deny-by-default)
├── tools.yaml         # Tool declarations and requirements
├── ai.yaml            # AI provider/model config and permissions
├── environment.yaml   # Environment profiles and variables
└── secrets.yaml       # Secret handles and metadata (never values)
```

### Policy

| Command | Description |
|---------|-------------|
| `z policy` | Validate the effective policy |
| `z policy validate` | Validate and show result |
| `z policy show` | Show the full effective merged policy (YAML) |
| `z policy test <action> <resource>` | Test a specific action/resource against policy |
| `z policy test fs.read ./src/** --json` | JSON output of policy decision |

**Policy decisions returned:** `ALLOW`, `DENY`, `REQUIRE_APPROVAL`  
**Risk levels:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### Execution

| Command | Description |
|---------|-------------|
| `z run <program> [args...]` | Run a program through the security broker (no shell) |
| `z run nmap -- -sV 127.0.0.1` | Run a registered tool |
| `z run python -- script.py` | Run any permitted binary |
| `z run <program> --approve` | Confirm a HIGH/CRITICAL risk action explicitly |
| `z run <program> --json` | JSON execution result |

`z run` **never invokes a shell**. Arguments are passed as a structured array directly to the binary — shell metacharacters are inert:

```sh
z run echo 'hello; echo PWNED'   # prints the literal string. No injection.
z run bash -- -c 'echo safe'     # only if bash is in policy's process.spawn
```

### Audit

| Command | Description |
|---------|-------------|
| `z audit` | Verify the audit chain |
| `z audit verify` | Verify SHA-256 hash chain (detects tampering) |
| `z audit tail` | Show last 20 events |
| `z audit tail 50` | Show last N events |
| `z audit --json` | Machine-readable output |

Each audit event records: `timestamp`, `actor`, `action`, `resource`, `decision`, `risk level`, `result`.

### Tool Management

| Command | Description |
|---------|-------------|
| `z search <query>` | Search the tool registry (offline) |
| `z search security` | Search by keyword |
| `z search --category networking` | Filter by category |
| `z search --json` | JSON output |
| `z bundle list` | Show curated workflow bundles |
| `z bundle show <name>` | Inspect a bundle |
| `z bundle plan <name>` | Print dry-run install commands for a bundle |
| `z info <tool>` | Show tool details, permissions, platforms |
| `z info nmap --version 7.94` | Specific version |
| `z install <tool>` | Install a tool (checksum verified) |
| `z install <tool> --version ^7.94` | Install specific version |
| `z install <tool> --dry-run` | Preview without installing |
| `z install <tool> --offline` | Use cache only, no network |
| `z install <tool> --approve` | Confirm risky permissions |
| `z list` | List all available tools |
| `z list --installed` | List only installed tools |
| `z list --outdated` | List tools with updates available |
| `z remove <tool>` | Remove a tool |
| `z uninstall <tool>` | Alias for remove |
| `z update` | Update all tools |
| `z update <tool>` | Update one tool |
| `z update <tool> --approve` | Update with approval for risky changes |
| `z rollback <tool>` | Roll back to previous version |
| `z use <tool>@<version>` | Select active version of an installed tool |
| `z verify <tool>` | Check tool for corruption or missing files |
| `z which <tool>` | Show where a tool is installed |
| `z compatibility <tool>` | Show per-platform support matrix for a tool |

### Cache

| Command | Description |
|---------|-------------|
| `z cache` | Show cache info |
| `z cache list` | List cached artifacts |
| `z cache clean` | Remove cached artifacts |

### Native Engines

| Command | Description |
|---------|-------------|
| `z engine` | List native engines |
| `z engine list` | List all engines with status |
| `z engine info <name>` | Show engine details and operations |
| `z engine doctor` | Health check for all engines |
| `z engine --json` | JSON output |

Native engines available (no external tools needed):
- `dns` — DNS resolver (A, AAAA, MX, TXT, NS, CNAME, PTR, SOA, SRV records)
- `http` — HTTP/HTTPS client
- `tls` — TLS certificate inspection
- `process` — Process inspection and management
- `filesystem` — File system operations and analysis

### Security Scanning

| Command | Description |
|---------|-------------|
| `z scan <target>` | Run a security scan |
| `z scan .` | Scan current directory |
| `z scan --profile minimal .` | Minimal scan |
| `z scan --profile standard .` | Standard scan (default) |
| `z scan --profile web <url>` | Web application scan |
| `z scan --profile network <cidr>` | Network scan |
| `z scan --profile system .` | System scan |
| `z scan --profile code ./src/` | Code analysis scan |
| `z scan --profile dependency .` | Dependency vulnerability scan |
| `z scan --json` | JSON report output |
| `z finding list` | List findings from the last scan |
| `z finding --json` | JSON findings |
| `z asset list` | Show assets discovered in last scan |
| `z report latest` | Render latest scan report |
| `z report --json` | JSON report |

### AI Commands

| Command | Description |
|---------|-------------|
| `z ai analyze` | AI analysis of the most recent scan |
| `z ai privacy` | Show AI privacy status (what goes where) |
| `z ai status` | Show which AI tier is active (cloud/local/none) |
| `ZENTRION_AI_PROVIDER=ollama` | Use local Ollama-compatible provider |
| `ZENTRION_AI_PROVIDER=qwen` | Use Qwen/DashScope-compatible API |
| `ZENTRION_AI_PROVIDER=openai-compatible` | Use custom `/v1/chat/completions` endpoint |
| `z ai bom` | AI Bill of Materials — all AI components in the project |
| `z ai bom --diff` | Show AI component changes since last commit |
| `z ai bom --check-policy` | Fail if AI components violate policy |
| `z ai run` | Start an interactive AI session (Phase 3) |

### Secrets

| Command | Description |
|---------|-------------|
| `z secrets set <name>` | Store a secret (prompts for value, stored in OS keyring) |
| `z secrets list` | List secret names and metadata (never values) |
| `z secrets get <name>` | Retrieve a secret (requires approval) |
| `z secrets delete <name>` | Delete a secret |
| `z secrets rotate <name>` | Rotate a secret (grace period invalidation) |
| `z secrets detect ./` | Scan files for accidentally committed secrets |

### Agents (Phase 3)

| Command | Description |
|---------|-------------|
| `z agent list` | List active and recent agents |
| `z agent inspect <id>` | Show agent state, capabilities, memory |
| `z agent kill <id>` | Immediately terminate an agent |
| `z agent kill --all` | Kill all agents |
| `z lockdown` | Emergency stop — kills all agents, revokes all live capabilities |

### Documentation

| Command | Description |
|---------|-------------|
| `z docs` | Open documentation index |
| `z docs <topic>` | Search bundled docs |
| `z docs security` | Open security docs |
| `z docs --json` | JSON doc index |
| `z support` | Show support and troubleshooting entry points |
| `z commands` | Searchable index of all commands |
| `z commands <query>` | Filter commands by keyword |

### Global Flags

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--json` | All commands | Machine-readable JSON output |
| `--project <path>` | All commands | Use this directory as the project root |
| `--help` | All commands | Show help |
| `--version` | Root command | Show version |

---

## 🛡️ Security Architecture

### 1. Policy System

Declarative YAML, versioned, deny-by-default. Every resource access must be explicitly allowed.

```yaml
# .zentrion/policy.yaml
apiVersion: zentrion.policy/v1
kind: Policy
metadata:
  name: my-project

defaults:
  mode: deny           # deny-by-default: everything not listed is blocked

filesystem:
  read:
    - "./src/**"
    - "./tests/**"
  write:
    - "./src/**"
  delete: []           # empty = deny delete

network:
  allow:
    - "api.example.com:443"
    - "registry.npmjs.org:443"
  listen: []           # no listening sockets

secrets:
  read: false
  write: false

system:
  admin: false

process:
  spawn:
    - "name:python"
    - "name:npm"
    - "name:node"

ai:
  models:
    allow:
      - "provider:openai/model:gpt-4o-mini"
      - "provider:local/model:llama3.1-8b"
  send_secrets: false
  max_tokens_per_day: 200000

agents:
  - name: refactor-agent
    capabilities:
      filesystem:
        read: ["./src/**", "./tests/**"]
        write: ["./src/**"]
      network:
        allow: []
      secrets:
        read: false
      system:
        admin: false
    resources:
      cpu: 30%
      memory: 2GB
      runtime: 10m
      network: restricted
      max_tool_calls: 100
```

**Policy precedence** (lowest → highest, can only narrow, never widen):
1. Built-in default (deny-all except workspace read/write)
2. User policy (`~/.zentrion/policy.yaml`)
3. Project policy (`.zentrion/policy.yaml`)
4. Enterprise overlay (Phase 5, can only restrict further)

**Policy decisions:**
```sh
z policy test process.spawn nmap        # → ALLOW / DENY / REQUIRE_APPROVAL
z policy test net.connect api.openai.com:443
z policy test fs.write /etc/passwd
```

### 2. Capability System

Every granted action produces a **short-lived, single-use capability token** — not a persistent permission:

```
Request → Policy Allow → Capability Grant {
  id: cap_<uuid>
  actor: user:sanjay
  action: process.spawn
  resource: nmap
  scope: name:nmap
  granted_at: <timestamp>
  expires_at: <timestamp + TTL>
  single_use: true
  revoked: false
}
```

- Capabilities are **in-memory only** — they don't survive process exit
- `z lockdown` immediately revokes all live capabilities
- No capability = no execution, regardless of policy layer

### 3. Identity System

Every request carries a named, typed actor:

| Actor Type | ID Format | Created by |
|-----------|-----------|-----------|
| Local user | `user:<username>` | OS identity |
| AI agent | `agt_<random>` | Agent runtime |
| Plugin | `plugin_<name>` | Plugin loader |
| MCP server | `mcp_<name>` | MCP gateway |
| CI system | `ci_<id>` | CI integration |

### 4. Execution Broker

The single choke point through which all host effects pass:

```
Caller
  │ ExecRequest { actor, action, resource, reason, ttl }
  ▼
Execution Broker
  ├─ 1. Authenticate actor (z-identity)
  ├─ 2. Evaluate policy (z-policy) → ALLOW/DENY/REQUIRE_APPROVAL
  ├─ 3. Check/issue capability (z-capability)
  ├─ 4. Assess risk (LOW/MEDIUM/HIGH/CRITICAL)
  │     HIGH/CRITICAL → require --approve flag
  ├─ 5. Create sandbox context (z-sandbox, risk-scaled)
  ├─ 6. Execute in sandbox (z-process/fs/network)
  ├─ 7. Write hash-chained audit event (z-audit)
  └─ ExecResult { status, output, exit_code, risk, audit_id, duration_ms }
```

**Exit codes:**
- `0` — success
- `1` — runtime error
- `2` — policy denied
- `3` — approval required (re-run with `--approve`)

### 5. Audit System

Append-only, SHA-256 hash-chained, tamper-evident log stored locally:

```
Event N: { ts, actor, action, resource, decision, risk, result, prev_hash }
          └─── SHA-256 ──────────────────────────────────────────────────┘
                                         ↓
Event N+1: { ..., prev_hash: hash(Event N) }
```

- `z audit verify` detects any modification to any past event
- `z audit tail` shows the most recent events in human-readable form
- Prompts are **not** stored by default (opt-in, local only)
- Every AI provider call, secret access, tool install, and policy change is audited

### 6. Sandbox

Per-OS native isolation, honest about what each platform can guarantee:

| Guarantee | Linux | macOS | Windows |
|-----------|-------|-------|---------|
| Filesystem confinement | **Landlock** — strong | **Seatbelt/sandbox-exec** — strong | ACLs on workspace dir — partial |
| Network confinement | **netns/cgroup + nftables** | sandbox-exec network deny | Windows Firewall per-app — best-effort |
| Process restrictions | **seccomp** syscall filter | sandbox-exec process limits | Job Objects — no syscall filter |
| Resource limits (cpu/mem) | **cgroups v2** — strong | rlimits + taskpolicy — moderate | Job Objects — good |
| Env isolation (secrets) | Strong | Strong | Strong |
| Untrusted binary isolation | **Strong** | Moderate | **Weak** |

**Sandbox profiles:**

| Profile | Used for | Isolation level |
|---------|----------|-----------------|
| `default` | Everyday shell commands | Minimal overhead |
| `tool` | Installed tools via `z run` | Scoped to declared permissions |
| `agent` | AI agent execution | Cgroups + landlock + seccomp |
| `quarantine` | First run of new binaries | Maximum isolation |

**Fallback behavior:**

| Risk level | Linux | macOS | Windows native | Windows + WSL2 |
|-----------|-------|-------|---------------|----------------|
| LOW | Native | Native | Native | Native |
| MEDIUM | Native | Native | JobObject + caps | Native in WSL |
| HIGH | Native | Native | Requires consent or WSL2 | Native in WSL |
| CRITICAL | Native | Native | Requires WSL2 or explicit opt-out | Native in WSL |

**Escape detection:** Linux seccomp SIGSYS logs unexpected syscalls → kill + audit CRITICAL. All platforms: daemon pipe / secrets path access by child process → deny + audit + incident report.

### 7. Secrets Management

```sh
# Store a secret (prompts for value — never echoed, stored in OS keyring)
z secrets set db_password
z secrets set openai_api_key

# List handles (names only, never values)
z secrets list

# Retrieve (requires explicit approval, terminal-only output)
z secrets get db_password

# Inject into a process (opt-in, documented risk)
z run myapp --env db_password

# Rotate with grace period
z secrets rotate db_password

# Scan for accidentally committed secrets (regex + entropy analysis)
z secrets detect ./
z secrets detect ./src/

# Delete
z secrets delete old_token
```

**Storage backends by platform:**
- **Linux:** Secret Service API (gnome-keyring / KWallet)
- **macOS:** macOS Keychain
- **Windows:** DPAPI / Windows Credential Manager
- **Fallback:** Encrypted file (age-style, key from passphrase) with loud warning

Secret values are:
- ✅ Stored in OS keyring (encrypted at rest)
- ✅ Accessible only by handle name in policy
- ✅ Redacted in all logs, errors, and AI context
- ❌ Never placed in environment by default
- ❌ Never sent to AI models unless explicitly allowed per-handle in policy
- ❌ Never stored in project files (only metadata handles)

---

## 🤖 AI Integration & Architecture

### AI Runtime (z-ai)

Full provider abstraction — swap models without changing any other code:

```
z-ai
├─ ProviderAdapter trait (OpenAI, Anthropic, Gemini, OpenAI-compatible, Local)
├─ ModelRegistry (local + remote catalogs, capabilities, pricing)
├─ Gateway (see AI Gateway below)
├─ Session/Context manager (conversation state, token budgets)
└─ LocalInferenceAdapter (llama.cpp / Ollama-compatible)
```

**Supported providers:**

| Provider | Type | Notes |
|----------|------|-------|
| OpenAI | Cloud BYOK | GPT-4o, GPT-4o-mini, o1, o3 |
| Anthropic | Cloud BYOK | Claude 3.5 Sonnet, Haiku, Opus |
| Google Gemini | Cloud BYOK | Gemini 1.5 Pro, Flash |
| Any OpenAI-compatible | Cloud/Local | LM Studio, vLLM, Groq, etc. |
| llama.cpp server | Local | Any GGUF model |
| Ollama | Local | Any Ollama model |

**BYOK (Bring Your Own Key):** API keys never touch Zentrion servers. They go directly from your OS keyring to the provider endpoint. No Zentrion man-in-the-middle.

**Local AI hardware detection:**
- CPU cores, RAM
- GPU: CUDA, ROCm, Metal via vendor APIs
- VRAM detection for model sizing
- NPU detection (best-effort)
- Recommends: largest model fitting in free VRAM − 20% headroom

**Degradation ladder:**
```
Full cloud BYOK
  ↓ (if API key not set / provider unreachable)
Local model (llama.cpp / Ollama)
  ↓ (if no local model)
No AI (terminal still fully functional)
```

`z ai status` reports which rung is active and why.

**Model abstraction:**
```
ModelRef = provider/model-id
ModelInfo {
  id, name, provider
  context_window: usize
  modalities: [text, vision, audio]
  function_calling: bool
  local: bool
  license, cost_tier
}
```

**Provider interface:**
```rust
trait Provider {
    fn id(&self) -> ProviderId;
    fn models(&self) -> Vec<ModelInfo>;
    fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse>;
    fn stream(&self, req: CompletionRequest) -> BoxStream<Result<StreamChunk>>;
    fn tools(&self) -> ToolSchemaSupport;
    fn health(&self) -> Health;   // reachable, auth valid, quota
}
```

### AI Gateway

Every AI request passes through the Gateway before reaching any provider:

```
Application / Agent / CLI
        │ prompt + tools
        ▼
Zentrion AI Gateway
 ├─ policy check         (which providers/models are allowed; per-project)
 ├─ context budget       (token limits, cost budget enforcement)
 ├─ sensitive data detection
 │   ├─ secrets: registered handles + pattern detection (AWS keys, tokens, privkeys)
 │   ├─ PII: emails, phone numbers, IDs (heuristic, configurable)
 │   └─ source code: visible in z ai status, auditable; enterprise can block
 ├─ redaction / blocking (replace with handles or refuse to send)
 ├─ provider egress      (BYOK direct — no Zentrion servers in the path)
 ├─ output validation    (tool-call schema, size, format)
 └─ audit               (what was sent to whom — redacted record stored locally)
        │
        ▼
Provider ──▶ response ──▶ validation ──▶ caller
```

**Gateway does NOT claim:**
- Perfect prompt-injection detection (this is a structural mitigation, not a detection game)
- Model output as authoritative (tool calls from models must pass through the broker like human commands)

**Tool-call validation:** Every `ToolCall` from a model is checked against: tool existence, parameter schema, actor capability, risk level, and approval requirement — the same broker path as human commands.

**Gateway logs store:** model, token counts, cost, redaction counts, decision outcomes. Prompts are **not** persisted by default.

### Agent Runtime

Autonomous AI agents that run within the same security boundary as human users:

```
User intent
   → Agent created (identity, policy, capabilities, limits, TTL)
   → Model plans (ProposedAction[])
   → for each action:
       Gateway validates
         → Policy check
         → Capability check
         → Risk assessment
         → [auto-allow | approval-queue | denied]
   → Sandbox executes tool (or rejects)
   → Result fed back to model
   → loop until: done | time limit | resource limit | too many denials | user stops
   → audit summary written, agent terminated, capabilities revoked
```

**Agent identity:**
```
AgentIdentity {
  id: agt_<random>           # new id every time — no zombie privilege
  name: "refactor-agent"
  project_id, user_id
  model: ModelRef
  provider: ProviderId
  policy_ref, capabilities: Capability[]
  created_at, expires_at     # hard TTL — cannot be extended by the agent
  status: active|paused|done|killed|expired
  resources: {
    cpu_pct: 30,
    mem_mb: 2048,
    runtime: "10m",
    net_mode: "restricted",
    max_tool_calls: 100
  }
}
```

**Lifecycle:** `created → active → (paused | done | killed | expired) → audited → capabilities revoked`

A killed agent **cannot be resumed**. New agent = new identity. No zombie privilege.

**Approval flow:**
- HIGH/CRITICAL actions → approval queue
- `z status` shows pending approvals
- Timeout = deny, agent pauses (state preserved)
- `z agent kill <id>` for immediate termination

**Memory:**
- Session memory: conversation + tool results, size-capped, local only
- Persistent memory: opt-in, project-scoped, inspectable via `z agent inspect`
- No shared memory between agents by default
- Persistent memory never sent to providers except as explicit user action

**Agents cannot spawn other agents (v1)** — no privilege amplification.

### MCP (Model Context Protocol)

First-class support for MCP servers, with the same security guarantees as everything else:

```
AI / Agent / Application
       |
 MCP Gateway (z-mcp)
       |
 Server Identity + Trust metadata
       |
 Policy + Capability (same broker path — no special privileges)
       |
 MCP Tool execution
```

**MCP server registration:**
```yaml
apiVersion: zentrion.mcp/v1
kind: MCPServer
metadata:
  name: github-mcp
  version: 1.4.0
  transport: stdio              # stdio | sse | streamable-http
  command: ["npx", "@modelcontextprotocol/server-github"]
  publisher:
    id: pub_anthropic
    key: minisign-fingerprint
trust:
  level: community              # community | verified | first-party
  verified_at: 2026-09-12
permissions:
  - {tool: "create_issue", action: net.connect, resource: "host:api.github.com:443"}
  - {tool: "search",       action: net.connect, resource: "host:api.github.com:443"}
```

**Trust levels:**
- `first-party` — published by Zentrion, signed by our key
- `verified` — publisher identity + review passed (future)
- `community` — registered but unreviewed; quarantine sandbox profile by default

**MCP security rules:**
- Unregistered server → refused entirely
- New server requires: manifest + permission declaration + explicit user consent + integrity verification
- Version update that adds new permissions → re-triggers consent (no silent escalation)
- `z mcp trust <name> --revoke` kills the server process, removes registration, revokes capabilities immediately
- stdio servers run as sandboxed child processes with no fs/network beyond declared permissions

### AI Supply Chain & BOM

`z ai bom` generates a complete, machine-readable inventory of every AI component in your project:

```json
{
  "bomVersion": "1.0",
  "generatedAt": "2026-10-03T10:00:00Z",
  "project": "my-app",
  "components": [
    {"type": "model",        "name": "gpt-4o-mini",    "provider": "openai",       "local": false},
    {"type": "model",        "name": "llama3.1-8b",    "provider": "local/ollama", "local": true},
    {"type": "agent",        "name": "refactor-agent", "id": "agt_9f2c",           "capabilities": ["fs.read:./**"]},
    {"type": "mcp-server",   "name": "github-mcp",     "version": "1.4.0",         "trust": "community"},
    {"type": "tool",         "name": "nmap",            "version": "7.95",          "source": "upstream"},
    {"type": "dataset",      "name": "support-tickets", "location": "./data/",      "containsPII": true},
    {"type": "external-api", "name": "openai",          "endpoint": "https://api.openai.com", "dataSent": "code+prompts"},
    {"type": "plugin",       "name": "docker-helper",   "version": "1.2.0",         "permissions": ["fs.read:./**"]},
    {"type": "policy",       "name": "project",         "hash": "sha256:..."},
    {"type": "secret-handle","name": "db_password",     "store": "os-keyring",      "everSharedWithAI": false}
  ]
}
```

**Uses:**
- `z ai bom --diff` — shows AI component changes since last commit (for code review)
- `z ai bom --check-policy` — CI gate: fails if a component violates policy (e.g., cloud model in a local-only project)
- Compliance: export for audit; feeds supply-chain graph analysis

---

## 🔨 Tool System

Tools are **never bundled by default**. The base install ships zero security tools and zero AI models. Everything is installed on demand, verified, and sandboxed.

### Tool Categories

| Category | Examples |
|----------|---------|
| **Development** | git, python, node, npm, cargo, go, docker, kubectl |
| **Security** | nmap, masscan, nikto, sqlmap, burpsuite, metasploit |
| **Networking** | curl, wget, netcat, tcpdump, wireshark |
| **OSINT** | theHarvester, recon-ng, shodan-cli |
| **Web Security** | gobuster, ffuf, nuclei, wfuzz |
| **Forensics** | volatility, autopsy, sleuthkit |
| **Cloud** | awscli, gcloud, azurecli, terraform |
| **DevOps** | ansible, helm, packer, vault |
| **Data** | jq, yq, sqlite3, psql |
| **AI/ML** | ollama, llamacpp, huggingface-cli |
| **Mobile Security** | apktool, frida, jadx |
| **Privacy** | tor, proxychains |
| **Research** | wireshark, zaproxy, openssl |

### Tool Manifest Schema

```yaml
apiVersion: zentrion.tool/v1
kind: Tool
metadata:
  name: nmap
  version: "7.95"
  description: Network exploration tool and security scanner
  license: NPSL
  categories: [networking, security, osint]
  homepage: https://nmap.org

platforms: [linux, macos, windows]
architectures: [x64, arm64]

permissions:
  network: true
  filesystem: workspace          # none | workspace | home | system
  process: true
  raw_sockets: true              # triggers HIGH risk + requires --approve

source:
  type: upstream                 # upstream | mirror | build-from-source
  url: https://nmap.org/dist/nmap-7.95.tar.bz2
  method: package-manager        # package-manager | binary | source-build | script

integrity:
  checksum: sha256:<hash>        # per artifact — verified before write
  signature: minigpg:<sig>       # optional publisher signature
  provenance: upstream-release   # upstream-release | reproducible-build | ci-verified

dependencies:
  - {name: libpcap, provided_by: system}

risk:
  level: HIGH                    # LOW | MEDIUM | HIGH | CRITICAL
  network: outbound
  notes: "raw socket scanning requires elevated privileges on some systems"

lifecycle:
  install_behavior: standalone-binary
  uninstall: remove-binary
  update_channel: stable
```

### Tool Lifecycle

```
install → download (with retry/fallback) → verify checksum → verify signature (if present)
        → quarantine sandbox first run → policy check → capability grant → store
        → active → (update | rollback | remove)
```

**Source methods:**

| Method | Description | Security |
|--------|-------------|---------|
| `package-manager` | apt/dnf/brew/winget | Trusted system channel; Zentrion records what was installed |
| `binary` | Prebuilt binary from URL | Checksum + signature verify; quarantine on first run |
| `source-build` | Build from source in sandbox | Build in restricted sandbox; checksum of result pinned |
| `script` | Vendor install script | Script pinned by checksum, reviewed metadata; **never executed unsigned** |

**Authorization note:** Security tools are for authorized testing and defensive work. Zentrion does not ship default workflows targeting systems you don't own.

---

## 🖥️ Shell & Terminal Integration

### PowerShell (Windows)

```powershell
# z runs natively in PowerShell 7 and PowerShell 5.1
z doctor
z install git
z run git -- status

# Tab completion registration (no profile injection without consent)
z config set shell.completions powershell

# z adds completions to PSModulePath — you must consent first
```

**Supported:** PowerShell 7 (primary), Windows PowerShell 5.1, CMD  
**Recommended:** Windows Terminal + PowerShell 7

### WSL (Windows Subsystem for Linux)

Zentrion detects WSL2 and uses it as a **strong isolation path** when available:

```sh
# z doctor reports WSL2 presence, distro list, and systemd status
z doctor

# Use WSL for strong isolation with Linux tooling on Windows
z env use wsl:Ubuntu-22.04

# Run Linux tools (nmap etc.) inside WSL for proper sandbox
z run nmap -- -sV target

# WSL paths are recognized
# \\wsl$\Ubuntu-22.04\home\user\project
```

**WSL rules:**
- Zentrion **never auto-installs WSL** — it detects presence and offers the command
- If WSL2 absent: Windows-native path continues (reduced sandbox levels — see §10.4)
- Filesystem bridge: `\\wsl$\` paths recognized; cross-OS file access performance warning shown
- `z env use wsl:<distro>` runs tool execution inside WSL for proper Linux sandboxing

**Without WSL, Windows handles:**
- HIGH risk → requires explicit consent
- CRITICAL risk → requires WSL2 or explicit typed opt-out

### Git Integration

Git is treated as a normal tool — installed on-demand, run through the broker:

```sh
# Install git (verified)
z install git

# Configure git to run through the broker
z run git -- config --global user.name "Your Name"
z run git -- config --global user.email "you@example.com"

# Normal git operations (through broker = audited)
z run git -- clone https://github.com/org/repo
z run git -- add .
z run git -- commit -m "feat: add feature"
z run git -- push origin main

# Git must be in policy's process.spawn list:
# .zentrion/policy.yaml
# process:
#   spawn:
#     - "name:git"
```

### Kali Linux Tools (Security Toolkit)

ZENTRION TERMINAL replaces Kali Linux as a separate OS. Security tools run on-demand, verified, sandboxed, on your existing OS:

```sh
# Search available security tools
z search security
z search --category security
z search kali

# Network reconnaissance
z install nmap && z run nmap -- -sV -sC target
z install masscan && z run masscan -- --rate 1000 192.168.0.0/24
z install rustscan && z run rustscan -- -a target

# Web security
z install nikto && z run nikto -- -h https://target.com
z install gobuster && z run gobuster -- dir -u https://target.com -w wordlist.txt
z install ffuf && z run ffuf -- -w wordlist.txt -u https://target.com/FUZZ
z install nuclei && z run nuclei -- -u target.com
z install sqlmap && z run sqlmap -- -u "https://target.com?id=1" --approve

# OSINT
z install theharvester && z run theharvester -- -d domain.com -b all
z install amass && z run amass -- enum -d target.com

# Exploitation (HIGH/CRITICAL risk — requires --approve)
z install metasploit --approve && z run msfconsole --approve

# Password tools
z install hashcat && z run hashcat -- -a 0 -m 1000 hash.txt wordlist.txt
z install john && z run john -- --wordlist=wordlist.txt hashes.txt

# Forensics
z install volatility3 && z run vol -- -f memory.dmp windows.pslist
z install sleuthkit && z run tsk_recover -- -e -i raw disk.img output/

# Wireless (requires raw_sockets — HIGH risk)
z install aircrack-ng --approve
z run aircrack-ng -- -a2 -b <bssid> -w wordlist.txt capture.cap --approve

# SSL/TLS analysis
z install testssl && z run testssl -- https://target.com
z install sslyze && z run sslyze -- target.com

# Policy for security work (example):
# .zentrion/policy.yaml
# process:
#   spawn:
#     - "name:nmap"
#     - "name:nikto"
# network:
#   allow:
#     - "target.example.com:*"
```

**Key difference from Kali:** All these tools are:
1. Installed on demand from the verified registry (not bundled)
2. SHA-256 verified before write
3. Run through the security broker (audited)
4. Sandboxed according to their risk profile
5. Logged in the tamper-evident audit chain

You get **Kali's tool library** with **enterprise-grade access controls and audit logging**.

---

## ⚙️ Native Engines

Built-in, zero-dependency engines for common operations — no external tools needed:

### DNS Engine
```sh
# All standard record types
z engine info dns
z scan --profile network target.com       # uses native DNS

# Supports: A, AAAA, MX, TXT, NS, CNAME, PTR, SOA, SRV
```

### HTTP Engine
```sh
z engine info http
# TLS/HTTPS, HTTP/1.1, HTTP/2, request/response inspection
```

### TLS Engine
```sh
z engine info tls
# Certificate chain inspection, cipher suite analysis, expiry checks
```

### Process Engine
```sh
z engine info process
# Process listing, inspection, resource monitoring
```

### Filesystem Engine
```sh
z engine info filesystem
# File metadata, permissions analysis, content inspection
```

```sh
# List all engines with native status
z engine list

# Full engine health check
z engine doctor
z engine doctor --json

# SBOM including native capabilities
z sbom
```

---

## 🔌 Plugin System

Extend Zentrion with new commands, tool adapters, AI providers, security scanners, and IDE integrations:

**Plugin types:**
- `cli` — adds new `z <command>` subcommands
- `tool` — new tool adapters (custom install logic)
- `ai` — new AI provider adapters
- `agent` — new agent types
- `security` — new scanner engines
- `mcp` — MCP server registration
- `ide` — IDE extension (separate repos, Phase 4+)

**Plugin manifest:**
```yaml
apiVersion: zentrion.plugin/v1
kind: Plugin
metadata:
  name: docker-helper
  version: 1.2.0
  api_compat: ">=0.3.0 <0.9.0"
  publisher:
    id: pub_dockerhelper_co
    key: minisign-pubkey-fingerprint
  license: Apache-2.0

permissions:
  - {action: fs.read,    resource: "path:./**"}
  - {action: net.connect, resource: "host:registry-1.docker.io:443"}
  - {action: proc.spawn, resource: "name:docker"}

type: cli
entry:
  runtime: native              # native | wasm | script
  artifact: plugin-linux-x64.tar.zst
  integrity: {checksum: sha256:..., signature: minisign:...}
```

**Plugin execution isolation:**
| Runtime | Isolation |
|---------|-----------|
| `wasm` | WASI sandbox — preferred for third-party plugins |
| `native` | Separate process over authenticated IPC, under granted capabilities only |
| `script` | Interpreted in sandbox profile `plugin` |

In-process plugins are **not allowed** (crash/isolation risk).

**Plugin lifecycle:**
```
install → verify(integrity) → declare permissions → user consent → grant caps
        → register → active → (update | disable | uninstall)
```
Version updates requesting new permissions re-trigger consent. No silent escalation.

---

## 📁 Project System

Every Zentrion project is a directory with a `.zentrion/` folder:

```sh
z init my-app               # create project
cd my-app
z project                   # show project info
z project --check           # validate all manifests
```

**Generated files:**
```yaml
# .zentrion/project.yaml
apiVersion: zentrion.project/v1
kind: Project
metadata:
  name: my-app
  version: "0.1.0"
  description: "My project"
```

```yaml
# .zentrion/ai.yaml
ai:
  providers:
    - id: local
      type: ollama
      endpoint: "http://localhost:11434"
  models:
    default: "local/llama3.1-8b"
  cost_budget:
    tokens_per_day: 200000
    usd_per_month: 10.00
```

```yaml
# .zentrion/environment.yaml
environments:
  dev:
    vars:
      NODE_ENV: development
      LOG_LEVEL: debug
  prod:
    vars:
      NODE_ENV: production
```

```yaml
# .zentrion/tools.yaml
tools:
  require:
    - name: python
      version: ">=3.11"
    - name: node
      version: ">=20"
  allow:
    - nmap
    - git
```

```yaml
# .zentrion/secrets.yaml (handles only — never values)
secrets:
  - name: db_password
    scope: project
    created: 2026-10-03
    rotation: 90d
    allowed_to_ai: false
  - name: openai_api_key
    scope: project
    allowed_to_ai: false
```

---

## 💻 Platform Support

### Current — Phase 1

| Target | Built | Tested | Sandbox |
|--------|-------|--------|---------|
| **Linux x86_64** | ✅ | ✅ | landlock + seccomp + cgroups v2 |
| Linux arm64 | ❌ | ❌ | — |
| macOS x86_64 | ❌ | ❌ | — |
| macOS arm64 | ❌ | ❌ | — |
| Windows x64 | ❌ | ❌ | — |
| Windows arm64 | ❌ | ❌ | — |

### Planned — Phase 2

All platforms will reach full feature parity by Phase 3. Linux is the reference platform.

### Install Locations

| Purpose | Windows | macOS | Linux |
|---------|---------|-------|-------|
| Binary | `%LOCALAPPDATA%\Zentrion\bin\z.exe` | `/usr/local/bin/z` | `~/.local/bin/z` |
| Config | `%APPDATA%\Zentrion` | `~/.config/zentrion` | `~/.config/zentrion` |
| Data/Audit | `%LOCALAPPDATA%\Zentrion` | `~/Library/Application Support/Zentrion` | `~/.local/share/zentrion` |
| Cache | `%LOCALAPPDATA%\Zentrion\Cache` | `~/Library/Caches/Zentrion` | `~/.cache/zentrion` |
| Secrets | DPAPI / Credential Manager | macOS Keychain | Secret Service |

No elevated install required for per-user mode (the default). System-wide install is optional and explicit.

### Packaging

| Platform | Packages |
|----------|----------|
| Linux | tar.gz, .deb, .rpm, AUR, Nix flake |
| macOS | .pkg, Homebrew cask, tar.gz |
| Windows | .zip, MSI, winget, Scoop |

---

## 🏗️ System Architecture

```
L1 ZENTRION CORE       host detection, lifecycle, IPC, config, identity,
                       capability+policy interfaces, process/fs/net abstraction,
                       secure-storage interface, logging, audit, errors
L2 DEVELOPER RUNTIME   projects, environments, language runtimes, deps, tools,
                       manifests, reproducibility
L3 SECURITY RUNTIME    policy engine, sandbox adapters, restrictions, secrets,
                       audit, threat detection, scanning orchestration
L4 AI RUNTIME          provider/model abstraction, AI gateway, local AI,
                       routing, context, tool-calling, AI policy/security
L5 AGENT RUNTIME       agent identity/lifecycle, planning loop, approvals,
                       resource limits, termination
L6 ECOSYSTEM           SDK, registry client, plugin system, tool/agent/MCP/model registries
L7 CLOUD/ENTERPRISE    accounts, teams, fleet, central policy/audit — FUTURE Phase 5+
```

### 26 Core Components

| Component | Layer | Purpose |
|-----------|-------|---------|
| `z-core` | 1 | Lifecycle, IPC, error model, plugin host API |
| `z-config` | 1 | Layered config resolution |
| `z-identity` | 1 | Who is calling (user/agent/plugin/mcp/ci) |
| `z-capability` | 1 | Grant/check/revoke/expiry of capabilities |
| `z-policy` | 1 | Declarative rules + evaluation engine |
| `z-exec` (broker) | 1 | Single choke point for host effects |
| `z-process` | 1 | Spawn/kill/inspect abstraction |
| `z-filesystem` | 1 | Path/permission abstraction, VFS scoping |
| `z-network` | 1 | Connect/listen policy enforcement |
| `z-sandbox` | 1/3 | Per-OS isolation adapters |
| `z-secrets` | 1/3 | OS-keystore-backed secret store |
| `z-audit` | 1/3 | Hash-chained event log |
| `z-telemetry` | 1 | Opt-in only, explicitly off by default |
| `z-cli` | UI | The terminal UX (`z` binary) |
| `z-runtime` | 2 | Projects/environments/tools lifecycle |
| `z-project` | 2 | `.zentrion/` manifest management |
| `z-env` | 2 | Environment profiles |
| `z-tool` | 2 | Tool install/verify/inventory |
| `z-registry` | 6 | Verified package fetch (client) |
| `z-plugin` | 6 | Manifest + permission-gated plugins |
| `z-update` | 1 | Signed self-update |
| `z-ai` | 4 | Provider/model abstraction + gateway |
| `z-agent` | 5 | Agent runtime |
| `z-mcp` | 4/6 | MCP gateway |
| `z-security` | 3 | Scanner orchestration (delegates to tools) |
| `z-sdk` | 6 | Language SDKs (Phase 4) |

### Codebase Structure

```
ZENTRION-TERMINAL/
├── cli/            # z binary — CLI commands, all user interaction
│   └── src/
│       ├── main.rs           # Entry point, command dispatch (clap)
│       ├── commands.rs       # Core commands (version/doctor/status/init/run/audit/policy)
│       ├── tools_cmd.rs      # Tool management commands
│       ├── phase3_cmd.rs     # Engine/scan/finding/report/sbom/ai commands
│       ├── native_engines.rs # Native engine wrappers
│       ├── docs_cmd.rs       # Documentation commands
│       └── context.rs        # Runtime initialization, policy resolution
├── core/           # z-core — config, host detection, errors, fs utils
├── policy/         # z-policy — YAML policy parser + evaluation engine
├── capability/     # z-capability — capability store, grant/check/revoke
├── exec/           # z-exec — execution broker (the security choke point)
├── audit/          # z-audit — hash-chained audit log
├── identity/       # z-identity — actor identity, local user detection
├── registry/       # z-registry — tool registry client
├── native/         # z-native — native engines (DNS, HTTP, TLS, process, fs)
├── nativetool/     # z-nativetool — native tool adapters
├── package/        # z-package — download, verify, extract
├── projects/       # z-projects — .zentrion/ scaffolding and validation
├── catalog/        # z-catalog — tool catalog and metadata
├── compat/         # z-compat — cross-platform compatibility helpers
├── version/        # z-version — version resolution and comparison
├── docs/           # Full documentation (77 specification files)
├── scripts/        # Build, install, package, test scripts
├── dist/           # Release artifacts (Linux x64 binary + checksums)
├── schemas/        # JSON Schema definitions (single source of truth for all manifests)
├── tests/          # Integration and CLI tests
└── .github/        # CI workflows (build + test on Linux, macOS, Windows)
```

---

## 🗺️ Roadmap

| Phase | Status | Scope |
|-------|--------|-------|
| **Phase 0 — Architecture** | ✅ Done | Full specification (77 docs, all schemas, ADRs) |
| **Phase 1-14 — ZENTRION TERMINAL** | ✅ Done | z-core, CLI, policy engine + capability store, execution broker, audit hash-chain, project scaffolding, CI on 3 OS, native engines, sandbox (Linux landlock+seccomp), macOS/Windows abstractions, AI Gateway, Agent Runtime, Tool System, Package Registry, Plugins, MCP, TUI, DevSec (SAST/SBOM), Secrets Vault (OS Keyring), Enterprise Cloud Fleet Sync, Safe Monolithic Tools, AI-BOM Supply Chain, OTA Updates, and IPC SDK Daemon. |
| **Phase 15 — Continuous Hardening** | 🔜 Future | Enterprise telemetry scaling, managed AI expansion, persistent multi-agent orchestration. |

**Cost:** Phases 0–14 are **FREE** (local dev, OSS CI, no paid services required).

---

## 🔨 Building & Development

```sh
# Clone
git clone https://github.com/Sanjay-Program/ZENTRION-TERMINAL.git
cd ZENTRION-TERMINAL

# Build debug binary
scripts/build.sh

# Build release binary (optimized)
scripts/build.sh release

# Run all tests
scripts/test.sh

# Run linter (clippy + fmt check)
scripts/lint.sh

# Format code
scripts/format.sh

# Package a release tarball + SHA-256 checksum + JSON manifest
scripts/package.sh
# Output: dist/zentrion-linux-x64.tar.gz
#         dist/zentrion-linux-x64.tar.gz.sha256
#         dist/zentrion-linux-x64.json

# Build tool index
scripts/build-tool-index.py

# Check for accidentally committed secrets
scripts/check-no-secrets.sh
```

**Requirements:**
- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Linux: build-essential, pkg-config, libssl-dev, libdbus-1-dev (for Secret Service)
- macOS: Xcode Command Line Tools
- Windows: Visual Studio Build Tools (MSVC) or LLVM

**CI:** GitHub Actions builds and tests on `ubuntu-latest`, `macos-latest`, `windows-latest`.

---

## 📦 SDK & API

Language SDKs ship in Phase 4. All SDKs are **clients of the runtime over local IPC** — security decisions stay in the runtime. No per-language bypass.

```typescript
// TypeScript (Phase 4)
import { Zentrion } from "@zentrion/sdk";

const z = new Zentrion();
await z.status();
await z.tools().install("nmap");

const result = await z.exec({
  actor: z.whoami(),
  action: "process.spawn",
  resource: "nmap",
  reason: "security scan"
});

const agent = await z.agents.create({
  name: "refactor-agent",
  model: "openai/gpt-4o-mini",
  policy: "project",
  resources: { cpu: "30%", memory: "2GB", runtime: "10m" }
});

await z.audit.tail(20);
```

```python
# Python (Phase 4)
from zentrion import Zentrion

z = Zentrion()
z.tools().install("nmap")
report = z.scan("./src")
z.ai.run("analyze this scan", context=report)
```

**Planned SDK languages:** TypeScript, Python (v1), Go, Rust, C++, Java (later)

All SDKs use JSON Schema types generated from `schemas/` (single source of truth).

---

## 📚 Documentation

77 specification documents in `docs/`:

### Core Architecture
| Document | Description |
|----------|-------------|
| [01-VISION.md](docs/01-VISION.md) | Product vision and principles |
| [02-REQUIREMENTS.md](docs/02-REQUIREMENTS.md) | Detailed requirements |
| [03-SYSTEM-ARCHITECTURE.md](docs/03-SYSTEM-ARCHITECTURE.md) | 26-component architecture |
| [04-CORE-RUNTIME.md](docs/04-CORE-RUNTIME.md) | Core runtime design |
| [05-CLI-SPEC.md](docs/05-CLI-SPEC.md) | CLI specification |
| [STORAGE.md](docs/STORAGE.md) | Durable local storage paths and retention |

### Security
| Document | Description |
|----------|-------------|
| [06-SECURITY-ARCHITECTURE.md](docs/06-SECURITY-ARCHITECTURE.md) | Security layers |
| [07-THREAT-MODEL.md](docs/07-THREAT-MODEL.md) | Threat model and mitigations |
| [08-CAPABILITY-MODEL.md](docs/08-CAPABILITY-MODEL.md) | Capability system design |
| [09-POLICY-SPEC.md](docs/09-POLICY-SPEC.md) | Policy YAML specification |
| [10-SANDBOX-SPEC.md](docs/10-SANDBOX-SPEC.md) | Sandbox per-OS spec |
| [24-SECRETS.md](docs/24-SECRETS.md) | Secrets management |
| [25-AUDIT.md](docs/25-AUDIT.md) | Audit system |

### Platform
| Document | Description |
|----------|-------------|
| [11-CROSS-PLATFORM.md](docs/11-CROSS-PLATFORM.md) | Build matrix, PAL |
| [12-WINDOWS.md](docs/12-WINDOWS.md) | Windows architecture |
| [13-MACOS.md](docs/13-MACOS.md) | macOS architecture |
| [14-LINUX.md](docs/14-LINUX.md) | Linux architecture |

### AI & Agents
| Document | Description |
|----------|-------------|
| [18-AI-RUNTIME.md](docs/18-AI-RUNTIME.md) | AI provider abstraction |
| [19-AI-GATEWAY.md](docs/19-AI-GATEWAY.md) | AI security gateway |
| [20-AGENT-RUNTIME.md](docs/20-AGENT-RUNTIME.md) | Agent execution loop |
| [21-MCP-ARCHITECTURE.md](docs/21-MCP-ARCHITECTURE.md) | MCP integration |
| [22-AI-BOM.md](docs/22-AI-BOM.md) | AI Bill of Materials |
| [23-AI-SUPPLY-CHAIN.md](docs/23-AI-SUPPLY-CHAIN.md) | AI supply chain analysis |

### Tools & Ecosystem
| Document | Description |
|----------|-------------|
| [15-TOOL-SYSTEM.md](docs/15-TOOL-SYSTEM.md) | Tool system design |
| [16-PLUGIN-SYSTEM.md](docs/16-PLUGIN-SYSTEM.md) | Plugin architecture |
| [17-REGISTRY.md](docs/17-REGISTRY.md) | Tool registry |
| [27-PROJECT-SYSTEM.md](docs/27-PROJECT-SYSTEM.md) | Project scaffolding |
| [28-SDK.md](docs/28-SDK.md) | SDK design |
| [29-API-SPEC.md](docs/29-API-SPEC.md) | API specification |
| [35-ROADMAP.md](docs/35-ROADMAP.md) | Development roadmap |

### User Guides
| Document | Description |
|----------|-------------|
| [QUICKSTART.md](docs/QUICKSTART.md) | Get running in 5 minutes |
| [CLI.md](docs/CLI.md) | CLI command reference |
| [INSTALLATION.md](docs/INSTALLATION.md) | Platform-specific install |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Contributing guide |
| [RELEASE_READINESS.md](docs/RELEASE_READINESS.md) | Current release status |
| [PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) | Platform support matrix |
| [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Security model summary |
| [DOCUMENTATION_INDEX.md](docs/DOCUMENTATION_INDEX.md) | Full index (all 77 docs) |

---

## ⚠️ Known Limitations (Phase 1)

- **No signature verification** — artifact integrity is enforced (SHA-256 before write) but authenticity (publisher signing) is not yet implemented. A tool may set `signature_required: true` to fail closed.
- **No sandbox** — policy and capabilities authorize actions but do not confine a process once running. **Do not run untrusted binaries in Phase 1.**
- **No secrets storage** — Phase 2. Never enter sensitive values.
- **No AI/agents/MCP** — architecture fully specified and implemented in skeleton; Phase 3 ships the full runtime.
- **No concurrency lock** — atomic rename narrows the window but is not a full lock.
- **No zip/zstd extraction** — only `.tar.gz` supported.
- **Remote registry transport** — off by default; requires `--features http` at compile time.
- **Linux x86_64 only** — Windows and macOS code is written and CI-configured but not yet built or tested.
- **Single in-process broker** — capabilities are in-memory and do not survive exit.

---

## 🔒 License

**Business Source License 1.1 (BUSL-1.1)** © 2026 Zentrion Technologies

> ✅ You may **freely use** ZENTRION TERMINAL for personal, educational, research, or internal business purposes.  
> ❌ You may **NOT** copy, modify, sublicense, sell, or redistribute the source code or any derivative works without explicit written permission from Zentrion Technologies.  
> 📅 The license converts to **Apache-2.0** on **2030-10-03**.

See [LICENSE](LICENSE) for full terms.  
Commercial licensing inquiries: legal@zentriontechnologies.com

---

## 🔐 Security Reporting

To report a security vulnerability, **do NOT open a public GitHub issue**.

See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## 🌐 Links

| Resource | URL |
|----------|-----|
| Company Website | zentriontechnologies.com |
| Product Page | zentriontechnologies.com/terminal |
| Download | zentriontechnologies.com/terminal/download |
| Docs | zentriontechnologies.com/terminal/docs |
| GitHub | github.com/Sanjay-Program/ZENTRION-TERMINAL |

---

<div align="center">

**ZENTRION TERMINAL** — Built by Zentrion Technologies  
© 2026 All rights reserved · [License](LICENSE) · [Security](SECURITY.md) · [Docs](docs/)

</div>
