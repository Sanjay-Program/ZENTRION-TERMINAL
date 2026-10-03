<div align="center">

<img src="https://img.shields.io/badge/ZENTRION-TERMINAL-0d1117?style=for-the-badge&labelColor=0d1117&color=00d4ff" alt="ZENTRION TERMINAL"/>

# ZENTRION TERMINAL

**A secure, AI-native, cross-platform terminal and runtime.**  
Built for developers, security teams, and AI-powered workflows.  
No WSL. No Docker. No VM. No cloud account required.

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-orange.svg?style=flat-square)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20x64-brightgreen?style=flat-square)](docs/PLATFORM_SUPPORT.md)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue?style=flat-square)](CHANGELOG.md)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange?style=flat-square&logo=rust)](Cargo.toml)
[![Security](https://img.shields.io/badge/Security-Policy--Enforced-red?style=flat-square)](SECURITY.md)

[**Download**](#-download) • [**Install**](#-install) • [**Quick Start**](#-quick-start) • [**Docs**](docs/) • [**Security**](#-security-model)

</div>

---

## What is ZENTRION TERMINAL?

ZENTRION TERMINAL is the official secure terminal and runtime by **Zentrion Technologies**.

Every command — whether from a human, an AI, a plugin, or a CI pipeline — passes through the same enforced path:

```
Caller → Identity → Policy → Capability → Risk Check → Execution → Audit
```

Security is enforced in **code**, not by hoping a model behaves correctly.

### ✅ What it is
- A **local-first runtime** with policy, capability and audit controls built in
- A **secure terminal** for everyday shell use, developer and security workflows
- A **tool manager** for native and community tools — with verified, checksum-confirmed installs
- A **JSON-friendly control plane** for CI, automation, and AI clients
- A clean, fast launch: download → install → open → type

### ❌ What it is NOT
- Not a shell wrapper around the OS
- Not a hidden layer that silently installs WSL, Docker, or a VM
- Not a cloud-only service
- Not "everything runs everywhere" — tool compatibility is explicit and honest

---

## 📥 Download

### Linux x86_64 (Current Release)

| File | SHA-256 |
|------|---------|
| [`zentrion-linux-x64.tar.gz`](dist/zentrion-linux-x64.tar.gz) | `325ebcb36115976c5c4de30a093181c9c12623fd675febfa1da2072a49d9c442` |

```sh
# Download and verify
wget https://github.com/Sanjay-Program/ZENTRION-TERMINAL/releases/download/v0.1.0/zentrion-linux-x64.tar.gz
wget https://github.com/Sanjay-Program/ZENTRION-TERMINAL/releases/download/v0.1.0/zentrion-linux-x64.tar.gz.sha256

sha256sum -c zentrion-linux-x64.tar.gz.sha256
```

> **macOS and Windows** — code paths are written and behind platform traits; CI is configured but **not yet built or tested**. Coming in a future release.

---

## 🔧 Install

### Option 1 — From a release archive (recommended)

```sh
# 1. Download the archive (see Download section above)

# 2. Install — no root required, installs to ~/.local/bin/z
scripts/install.sh --archive zentrion-linux-x64.tar.gz \
  --sha256 325ebcb36115976c5c4de30a093181c9c12623fd675febfa1da2072a49d9c442

# 3. Add to PATH (if not already)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 4. Verify
z doctor
```

### Option 2 — Build from source

```sh
# Requirements: Rust 1.75+ (https://rustup.rs)
git clone https://github.com/Sanjay-Program/ZENTRION-TERMINAL.git
cd ZENTRION-TERMINAL

# Build release binary
scripts/build.sh release

# Install to ~/.local/bin/z
scripts/install.sh

# Add to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Option 3 — Custom prefix

```sh
scripts/install.sh --archive zentrion-linux-x64.tar.gz --prefix /usr/local
```

### Uninstall

```sh
scripts/uninstall.sh
```

---

## ⚡ Quick Start

```sh
z doctor                       # health check — fully offline
z platform                     # show native capabilities

z init my-project              # create a project with secure default policy
cd my-project

z search security              # search the tool registry (offline)
z info nmap                    # see metadata, permissions, compatibility

z install nmap --dry-run       # preview: what, from where, at what risk
z install nmap                 # install with checksum verification

z list                         # show installed tools
z run nmap -- --version        # run through the security broker

z verify nmap                  # health check
z update                       # update all tools
z rollback nmap                # revert to previous version
z remove nmap                  # uninstall

z audit tail                   # recent security-relevant events
z audit verify                 # verify the tamper-evident audit hash chain
```

### 🔐 Tools are NOT auto-permitted

Installing a tool does **not** let it run. You must explicitly allow it in your project policy first:

```yaml
# .zentrion/policy.yaml
tools:
  allow:
    - "nmap"
```

Until then, `z run nmap` exits with code 2 and explains why. This is by design.

### Shell-injection is impossible by design

`z run` never invokes a shell — arguments are passed as a structured array directly to the target binary:

```sh
z run echo 'hello; echo PWNED'   # prints the literal text. No injection.
```

---

## 🏗️ How it works

Before anything executes, the broker enforces **5 sequential layers**:

| Layer | What it does |
|-------|-------------|
| **Identity** | Every request carries a named actor (user, agent, plugin, CI) |
| **Policy** | Declarative, deny-by-default YAML rules must explicitly ALLOW the action |
| **Capability** | A short-lived, single-use grant scoped to the exact action and resource |
| **Risk** | HIGH/CRITICAL actions require explicit `--approve` — no silent escalation |
| **Audit** | Every outcome is appended to a SHA-256 hash-chained, tamper-evident log |

---

## 🛡️ Security Model

| Layer | Phase 1 Status |
|-------|---------------|
| Identity | ✅ Local user identity; agent/plugin/MCP types defined |
| Policy | ✅ Full parser, strict validation, glob scopes, deny-by-default, layer merge |
| Capability | ✅ In-memory store with expiry, revocation, scope + actor checks |
| Risk & Approval | ✅ HIGH/CRITICAL gate; no silent approval |
| Execution Broker | ✅ Single choke point for all process execution |
| Audit | ✅ Append-only, hash-chained, tamper-evident, verifiable |
| Sandbox | 🔜 Phase 2 |
| Secrets | 🔜 Phase 2 — values never stored anywhere currently |

> ⚠️ **Phase 1 note:** No sandbox is active. Policy and capabilities authorize actions, but do not confine a process once running. **Do not run untrusted binaries with Phase 1.**

See the full [Security Model](docs/SECURITY_MODEL.md) and [Threat Model](docs/07-THREAT-MODEL.md).

---

## 🖥️ Platform Support

| Target | Built | Tested |
|--------|-------|--------|
| **Linux x86_64** | ✅ Yes | ✅ Yes |
| Linux arm64 | ❌ | ❌ |
| macOS x86_64 / arm64 | ❌ (code written) | ❌ |
| Windows x86_64 / arm64 | ❌ (code written) | ❌ |

See [Platform Support](docs/PLATFORM_SUPPORT.md) for details.

---

## 📁 Project Structure

```
ZENTRION-TERMINAL/
├── cli/            # Command-line interface (`z` binary)
├── core/           # Core runtime types and traits
├── policy/         # Policy parser and enforcement
├── capability/     # Capability store (grants, revocation)
├── exec/           # Execution broker (the security choke point)
├── audit/          # Tamper-evident audit log
├── identity/       # Actor identity types
├── registry/       # Tool registry (offline-first)
├── native/         # Native platform engines (DNS, HTTP, TLS, fs)
├── nativetool/     # Native tool adapters
├── package/        # Package download, verify, extract
├── projects/       # Project workspace management
├── compat/         # Cross-platform compatibility layer
├── version/        # Version resolution
├── catalog/        # Tool catalog and metadata
├── docs/           # Full documentation (77 files)
├── scripts/        # Build, install, package, test scripts
├── dist/           # Release artifacts (binaries + checksums)
└── schemas/        # YAML/JSON schema definitions
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | Get running in 5 minutes |
| [CLI Reference](docs/CLI.md) | All `z` commands |
| [Installation Guide](docs/INSTALLATION.md) | Platform-specific install |
| [Security Model](docs/SECURITY_MODEL.md) | How security layers work |
| [Policy Spec](docs/09-POLICY-SPEC.md) | Writing policy.yaml |
| [Tool System](docs/15-TOOL-SYSTEM.md) | Managing tools |
| [Development Guide](docs/DEVELOPMENT.md) | Contributing to the project |
| [Release Readiness](docs/RELEASE_READINESS.md) | Current release status |
| [Documentation Index](docs/DOCUMENTATION_INDEX.md) | All 77 docs |

---

## 🔨 Building

```sh
# Build release binary
scripts/build.sh release

# Build debug binary
scripts/build.sh

# Run tests
scripts/test.sh

# Run linter
scripts/lint.sh

# Format code
scripts/format.sh

# Package a release tarball + checksum
scripts/package.sh
# Output: dist/zentrion-linux-x64.tar.gz + .sha256 + .json
```

---

## ⚠️ Known Limitations

- **No signature verification** — artifact *integrity* is enforced (SHA-256 before writing), but *authenticity* is not. A tool may set `signature_required: true` to fail closed.
- **No sandbox** — policy decides whether a tool runs; nothing confines it once running. A permitted tool has your full user privileges.
- **No secrets storage** — arrives in Phase 2. Never enter sensitive values.
- **No concurrency lock** around store mutations — atomic rename narrows the window but is not a full lock.
- **zip/zstd archives** — refused explicitly; only `.tar.gz` supported.
- **Remote registry** — off by default, requires `--features http` at compile time.

---

## 🔒 License

**Business Source License 1.1 (BUSL-1.1)** © 2026 Zentrion Technologies

> You may **freely use** ZENTRION TERMINAL.  
> You may **NOT** copy, modify, sublicense, sell, or redistribute the source code or any derivative works without explicit written permission from Zentrion Technologies.  
> The license converts to **Apache-2.0** on **2030-10-03**.

See [LICENSE](LICENSE) for full terms.  
For commercial licensing: legal@zentriontechnologies.com

---

## 🔐 Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).  
Do **not** open a public GitHub issue for security vulnerabilities.

---

## 🌐 Links

| Resource | URL |
|----------|-----|
| Company Website | zentriontechnologies.com |
| Product Page | zentriontechnologies.com/terminal |
| Download | zentriontechnologies.com/terminal/download |
| Documentation | zentriontechnologies.com/terminal/docs |

---

<div align="center">

Built by **Zentrion Technologies** · © 2026 All rights reserved

</div>
