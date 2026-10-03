# 14 — LINUX ARCHITECTURE

## Target distributions (initial)
Ubuntu 22.04/24.04 LTS, Debian 12+, Fedora 40+, Arch (rolling). Others via
tar.gz with documented prerequisites.

## Packaging
| Distro | Format | Location |
|---|---|---|
| Ubuntu/Debian | `.deb` (universe repo planned; direct download first) | `/usr/bin/z` or `~/.local/bin` |
| Fedora | `.rpm` (COPR planned) | same |
| Arch | AUR package | `/usr/bin/z` |
| Any | tar.gz + install script (verifiable checksum) | user-local |

## Filesystem
- Standard XDG paths; project dirs anywhere user-writable.
- Scoped fs access via **Landlock** ruleset per sandbox instance (kernel ≥ 5.13; on older kernels Zentrion reports reduced capability and adjusts risk ceiling).
- Overlay write workspace via bind mounts or plain temp dirs depending on kernel/container context.

## Process
- spawn via `posix_spawn`/`fork+exec` wrapper with rlimits and cgroup v2 placement when available.
- **Seccomp** default-deny syscall filter with allowlist (BPF) for sandboxed children — strongest layer; SIGSYS = kill + audit.
- pids cgroup to prevent fork bombs; memory.high/memory.max; cpu.max for quota.
- User namespaces (unprivileged userns) used where distro policy allows; fallback documented (Debian/Ubuntu restrictions handled in `z doctor`).

## Network
- Default: no listener; outbound only.
- Confinement: dedicated **network namespace + veth + nftables allowlist** for HIGH risk execution when privileges allow; seccomp-based `socket` restrictions as the unprivileged fallback.
- No modification of host firewall without explicit consent and audit.

## Sandbox summary (Linux = reference platform)
Landlock (fs) + seccomp (syscalls) + cgroup v2 (resources) + namespaces (net/mount) — strongest combination of the three platforms; still combined with broker-side capability enforcement (defense in depth).

## Shell & service management
- bash, zsh, fish supported (completions generated; no rc-file modification without consent).
- Optional systemd **user** unit only for explicit daemon mode (`z agent serve`); never auto-enabled; no root services.

## Service management / updates
- `z update` verifies minisign signature of release manifest + artifact hashes, stages binary, health-checks (`z doctor --quick`), rolls back on failure.
- Distro packages updated through the package manager; in-app update disabled when installed that way (detected via package ownership check) to avoid double-management.
