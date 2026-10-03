# 12 — WINDOWS ARCHITECTURE

```
Zentrion CLI
   |
Zentrion Core
   |
Windows Host Adapter
   |            \
PowerShell/CMD   optional WSL2
Windows Terminal  └→ Zentrion Linux Environment
```

## Targets
Windows 10 21H2+, Windows 11, x64 and ARM64 (ARM64 emulation of x64 not relied
upon for core; native ARM64 build provided).

## Shells
- **PowerShell 7** (primary), Windows PowerShell 5.1 (supported), CMD (supported), Windows Terminal recommended.
- Shell integration: PSModulePath registration for `z` completions; no profile injection without consent.

## WSL — optional capability, never assumed
- `z doctor` detects WSL2 presence, distro list, and systemd status.
- If present: `z env use wsl:Ubuntu-22.04` runs tool execution inside WSL for strong isolation and Linux tooling (nmap, etc.).
- If absent: Windows-native path continues with reduced sandbox levels (see §10.4). Zentrion never auto-installs WSL; it offers the command and requires user action.
- Filesystem bridge: `\\wsl$\` / `\\wsl.localhost\` paths recognized; performance warning shown for cross-OS file access.

## Filesystem
- Project paths: normal NTFS paths; permission model via ACLs on the project directory when sandbox needs confinement.
- Long paths opt-in handled; UNC paths supported.
- Case-insensitivity: scope matching normalizes case on Windows.

## Process
- Spawn via `CreateProcess` with Job Objects (cpu/mem/pids/kill-on-close).
- Restricted token where feasible (drop privileges, deny UI token); not full seccomp equivalent — documented limitation.
- `proc.kill` kills the whole Job Object to avoid orphans.

## Networking
- Outbound via WinHTTP/crate TLS stack; no inbound listeners by default.
- Windows Firewall rules only created with explicit user consent and audited.

## Environment variables
- Clean env block for sandboxed children (inherit-list only).
- Secrets never placed in env by default; explicit opt-in per tool (documented risk).

## Permissions
- Runs as the invoking user. `sys.admin` capability triggers UAC elevation prompt for that single operation; elevation is never persistent.

## Install / uninstall / update / rollback
- Install: per-user MSI (no admin) or winget/manifest; adds binary dir to user PATH.
- Uninstall: removes binaries, data dir (with confirmation), revokes firewall rules, unregisters shell module.
- Update: signed MSI staged to `%LOCALAPPDATA%\Zentrion\update\`, verified (Authenticode + our minisign), applied on next start; rollback keeps previous version in `versions\` for instant revert.
- Code signing is a release requirement; unsigned builds refuse auto-update.
