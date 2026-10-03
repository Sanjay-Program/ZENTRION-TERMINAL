# 11 — CROSS-PLATFORM ARCHITECTURE

## 11.1 Build matrix

| Target | Toolchain | Binary | Packaging | Installer | Update | Test env |
|---|---|---|---|---|---|---|
| Windows x64 | Rust (MSVC) | `.exe` PE | zip, MSI, winget manifest, Scoop | MSI / winget | signed MSI + in-app updater | GitHub Actions windows-latest + self-hosted Win10/11 |
| Windows ARM64 | Rust (MSVC aarch64) | `.exe` PE | zip, MSI | MSI | same | GH Actions arm64 runner (available) |
| macOS Intel | Rust (x86_64-apple-darwin) | Mach-O universal | `.pkg`, Homebrew cask, tar.gz | pkg installer | Sparkle-style signed updater / `z update` | GH Actions macos-13 |
| macOS ARM64 | Rust (aarch64-apple-darwin) | Mach-O universal2 | same | same | same | GH Actions macos-14 |
| Linux x64 | Rust (gnu) | ELF | tar.gz, .deb, .rpm, AUR, Nix flake | package managers + install script | `z update` + distro packages | GH Actions ubuntu-22.04/24.04 |
| Linux ARM64 | Rust (aarch64 gnu) | ELF | tar.gz, .deb, .rpm | same | same | GH Actions arm64 runner |

Single `z` binary; heavy features are lazy-loaded modules compiled in but
only initialized on demand (keeps startup fast and install small).

## 11.2 Platform abstraction layer (PAL)

```
HostAdapter {
  detect() → HostInfo            // os, arch, virt, shell, keyring, sandbox_caps
  fs() → FileSystemApi           // paths, permissions, watching
  process() → ProcessApi         // spawn (with rlimits/job objects), kill, inspect
  network() → NetworkApi         // dial/listen with hooks
  secure_storage() → SecureStore // keyring / DPAPI / Keychain / Secret Service
  sandbox() → SandboxApi         // platform-native adapters
  shell() → ShellApi             // pwsh/cmd/bash/zsh/fish integration
}
```

All platform-specific code lives in `host/<os>/`; no `#[cfg(windows)]` branches
outside that directory (enforced in review/CI lint).

## 11.3 Paths & conventions

| Purpose | Windows | macOS | Linux |
|---|---|---|---|
| binary | `%LOCALAPPDATA%\Zentrion\bin` | `/usr/local/bin` or `~/Applications/Zentrion` | `/usr/local/bin` or `~/.local/bin` |
| config | `%APPDATA%\Zentrion` | `~/.config/zentrion` | `~/.config/zentrion` |
| data/audit | `%LOCALAPPDATA%\Zentrion` | `~/Library/Application Support/Zentrion` | `~/.local/share/zentrion` |
| cache | `%LOCALAPPDATA%\Zentrion\Cache` | `~/Library/Caches/Zentrion` | `~/.cache/zentrion` |
| secrets | DPAPI / Windows Credential Manager | Keychain | Secret Service (gnome-keyring/KWallet) |

No elevated install required for per-user mode (default); system-wide install
optional and explicit.

## 11.4 Cross-platform rules
- UTF-8 everywhere; Windows-1252/UTF-16 handled at boundary only.
- Path handling: never assume `/`; case-sensitivity differences documented per feature (fs scopes use normalized comparison).
- No fork() reliance (Windows has no fork); process spawning via async subprocess APIs.
- Line endings and terminal escapes abstracted in UI layer.
- No assumption about systemd/launchd/Windows service — optional integrations only.

## 11.5 What is NOT promised
- Identical sandbox strength (see 10-SANDBOX-SPEC).
- Feature parity on day one: Linux is reference platform in Phase 1–2; Windows/macOS reach parity through Phase 3.
- NPU/GPU availability.
