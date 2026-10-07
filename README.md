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

**The world's #1 Next-Generation Terminal. A lightweight, universal developer, AI, and cybersecurity runtime that performs everything.**  

*Built with ❤️ by [Zentrion Technologies](https://zentriontechnologies.com)*

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-orange.svg?style=flat-square)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-brightgreen?style=flat-square&logo=linux)](releases/README.md)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows)](releases/README.md)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-silver?style=flat-square&logo=apple)](releases/README.md)
[![Powered by Rust](https://img.shields.io/badge/Powered%20by-Rust-orange?style=flat-square&logo=rust)](Cargo.toml)

</div>

---

> 🚀 **The Ultimate Shell Replacement**  
> We combined the speed of `tmux`, the smarts of `Warp` and `GitHub Copilot`, the isolation of `Docker`, and the toolchain of `Kali Linux` into a single, massively fast Rust binary. No subscriptions, no telemetry, just raw terminal power.

## ⚡ What is ZENTRION TERMINAL?

ZENTRION TERMINAL is the flagship terminal, runtime, and AI execution platform developed by **[Zentrion Technologies](https://zentriontechnologies.com)**. 

We built ZENTRION to be the absolute best terminal in the world, completely redefining what a command line can do. It serves as a single, unified control layer that replaces your fragmented workflows—no more jumping between `WSL`, `Docker`, `Warp`, `tmux`, or `Kali Linux` VMs. Whether you are a Backend Developer, a Cybersecurity Professional, a DevOps Engineer, or a beginner—ZENTRION TERMINAL provides a secure environment where every action is mapped to an intent, audited, and strictly confined by policies.

### 🌟 Why Choose ZENTRION? (Features)
*   💻 **Built-in Mini IDE (New!):** Never leave the terminal to open VS Code again. Press `Alt+E` to slide out the native Code Editor pane, complete with AI auto-complete overlays.
*   ☁️ **Enterprise Cloud Sync (New!):** Run `z cloud login` and `z cloud sync` to instantly synchronize your themes, keybindings, and P2P chat history across Mac, Windows, and Linux.
*   🎨 **Custom Dynamic Theming (New!):** Type `z theme apply cyberpunk` or `z theme apply dracula` to instantly reskin the entire interface.
*   🧠 **Context-Aware AI Copilot:** A Warp-style AI assistant built directly into the UI (press `Alt+C`). It reads your terminal errors, explains them, and writes the fix.
*   💬 **Zero-Config P2P LAN Chat:** Collaborate with developers on the same Wi-Fi instantly. Press `0` in the UI to send AES-256-GCM encrypted messages peer-to-peer. No internet, no servers, no Slack needed.
*   🔍 **Agentic Deep Research:** Press `9` and type a complex topic. Our background agents will scrape the web, synthesize answers, and drop a markdown report into your workspace.
*   🖥️ **Built-in System Monitor:** Press `Alt+S` anywhere to overlay a beautiful, real-time `htop`-style dashboard monitoring CPU, Memory, and top running processes.
*   🛠️ **Universal Package Manager:** Need a tool? Type `z install nmap` or `z install chrome`. Zentrion pulls from its own audited cybersecurity registry or falls back to your OS package manager (`apt`, `brew`, `winget`).
*   ⌨️ **Desktop-Style Keybindings:** Say goodbye to complicated Linux shortcuts. ZENTRION uses familiar bindings: `Alt+E` for Editor, `Ctrl+P` for Command Palette, `Ctrl+Q` to Quit, etc.

## 📥 1-Click Universal Download

Zentrion Technologies provides seamless installers for all major Operating Systems. You do not need to install complex dependencies; our scripts handle everything.

### Linux & macOS
Run this single command in your terminal to install natively:
```bash
curl -sSL https://raw.githubusercontent.com/zentrion/terminal/main/releases/install.sh | bash
```

### Windows (10/11)
Open PowerShell as Administrator and run:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/zentrion/terminal/main/releases/install.ps1'))
```

> **Having trouble?** Read the detailed [Releases & Installer Guide](releases/README.md).

## 🚀 Quick Start & Shortcuts

Launch the Next-Gen UI by running:
```sh
z-cli ui
```

**Global Desktop-Style Shortcuts:**
*   `Alt+S` - Toggle Live System Monitor
*   `Alt+E` - Toggle Built-in Mini IDE (Code Editor)
*   `Ctrl+P` - Toggle Command Palette
*   `Alt+C` - Toggle AI Copilot
*   `0` - Open Secure P2P LAN Chat
*   `9` - Open Deep Research Engine
*   `Ctrl+Q` - Quit

## 🧠 AI Provider Setup

Zentrion defaults to a local, privacy-first Ollama-compatible workflow for the AI Copilot and Deep Research engine. You can easily switch to OpenAI or other cloud providers using environment variables.

**Local (Ollama/Qwen):**
```sh
export ZENTRION_AI_PROVIDER=ollama
export ZENTRION_AI_MODEL=qwen2.5-coder:7b
```

**Cloud (OpenAI):**
```sh
export ZENTRION_AI_PROVIDER=openai
export OPENAI_API_KEY="sk-..."
```

## 📚 Comprehensive Documentation

Zentrion Technologies believes in crystal-clear documentation. Dive into the world's most capable terminal runtime:

* 🆕 [**Getting Started Guide (For Beginners)**](docs/GETTING_STARTED.md) - The ultimate guide for absolute beginners and non-computer users.
* 📖 [**The 1000 Commands Reference**](docs/1000-COMMANDS-REFERENCE.md) - Massive dictionary of workflows (Dev, DevOps, Cybersecurity, AI).
* 🖥️ [**Terminal & UI Overview**](docs/terminal.md) - Master the UI layout and shortcuts.
* 🗺️ [**Documentation Index**](docs/DOCUMENTATION_INDEX.md) - Full site map and architecture deep dives.

## 🤝 Building & Contributing

To build ZENTRION TERMINAL from source, ensure you have Rust 1.75+ installed:

```sh
git clone https://github.com/zentrion/terminal.git
cd terminal
cargo build --release
```

## 🏢 About Zentrion Technologies

ZENTRION TERMINAL is a proud product of **Zentrion Technologies**. Discover more about our mission to secure the future of AI computation and developer tools at [zentriontechnologies.com](https://zentriontechnologies.com).

## 📄 License

This software is licensed under the **Business Source License 1.1 (BUSL-1.1)**. See the [LICENSE](LICENSE) file for details.
