# ZENTRION TERMINAL - Enterprise Edition Installers

Welcome to the ZENTRION deployment directory. We provide hardened, automated scripts to make downloading, compiling, and configuring ZENTRION as seamless and secure as possible across all major operating systems.

## 🐧 Linux & 🍏 macOS (Universal Enterprise Installer)

This installer is designed to work out-of-the-box on macOS and virtually all Linux distributions (Ubuntu, Debian, Fedora, CentOS, Arch, Alpine, etc.). 

**What this script does securely:**
1. Automatically detects your OS and installs the correct C-compiler toolchains (`build-essential`, `gcc`, `base-devel`, or `xcode-select`).
2. Downloads the Rust compiler via the official `rustup` channel if missing.
3. Clones the ZENTRION Enterprise core and compiles it natively for maximum speed on your architecture.
4. Generates your local `~/.zentrion` vaults and aggressively locks the permissions to `chmod 700` to prevent cross-user access.
5. Injects the binary into your PATH (`.bashrc` or `.zshrc`).

**To deploy ZENTRION natively, run this single command:**

```bash
curl -sSL https://raw.githubusercontent.com/zentrion/terminal/main/releases/install.sh | bash
```

## 🪟 Windows (Native Installer)

This script installs ZENTRION natively on Windows 10 and 11. 

**What this script does securely:**
1. Ensures the Rust toolchain is installed via `rustup-init.exe`.
2. Clones the repository and compiles the executable.
3. Generates the `~/.zentrion` vault and applies strict Windows ACL rules (Access Control Lists) ensuring only your specific user account has `FullControl`.

**To deploy ZENTRION natively, open PowerShell as Administrator and run:**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/zentrion/terminal/main/releases/install.ps1'))
```

## Post-Installation

Once the installation is complete, completely close and reopen your terminal (or PowerShell window) to refresh your environment paths. Then, launch the Next-Gen UI:

```sh
z-cli ui
```

### Essential First Steps:
*   **Sign in to Cloud Sync:** Run `z cloud login` to authenticate your enterprise account and sync your environment.
*   **Apply a Theme:** Run `z theme apply cyberpunk` to reskin your terminal.
*   **Open the Editor:** Press `Alt+E` inside the UI to launch the built-in AI IDE pane.
