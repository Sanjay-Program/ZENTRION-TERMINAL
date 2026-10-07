# 13 — macOS ARCHITECTURE

## Targets
- macOS 13 Ventura+; Intel x64 and Apple Silicon arm64, shipped as universal2 binary.
- Apple Silicon is primary; Intel supported but not assumed identical (Rosetta not relied upon; native builds for both).

```
Zentrion CLI
   |
Zentrion Core
   |
macOS Host Adapter
   |          \
native exec    optional Linux VM (for Linux-only tooling)
 (Seatbelt)
```

## Execution model
- Native execution on both architectures; `z doctor` reports arch.
- Optional lightweight Linux VM (QEMU/libkrun/VT via virtualization.framework) for tools that only exist on Linux — offered, not installed by default.

## Sandbox
- Primary: **Seatbelt (`sandbox-exec`) profiles** generated per SandboxSpec — fs read/write confinement, network deny/allowlist.
- Documented limitation: `sandbox-exec` is deprecated by Apple but remains functional; treated as best-effort confinement with capability+policy enforcement in broker as the primary control.
- Resource limits: `posix_spawn` file rlimits, `taskpolicy` for CPU clipping; memory via rlimits (moderate strength — see matrix).
- **Optional VM path** offers strong isolation for HIGH/CRITICAL operations when the user enables it.

## Filesystem sharing
- Project dir is bind-visible to the Linux VM via virtiofs (when VM mode used); read/write mapped to policy scopes.
- Default native mode: no VM involvement.

## Networking
- Outbound only; Seatbelt network deny by default in sandbox profiles.
- No TUN/TAP manipulation; pf anchors only with explicit consent.

## Permissions (TCC)
- Terminal app permissions govern what Zentrion inherits (Files/Folders, Camera, Mic). Zentrion never requests TCC access beyond what a user-invoked feature needs.
- `device.access` capability maps to TCC prompts; Zentrion cannot and does not bypass TCC — documented.

## Keychain
- Secrets stored in login Keychain via Security framework; items named `zentrion.<project>.<handle>`.
- `secret.read` capability required; Keychain prompt may appear on first access (OS-level control, not Zentrion-controlled).

## Install / update / rollback
- `.pkg` (per-user or system), Homebrew cask, tar.gz.
- Signed + notarized (release requirement; unsigned builds refuse auto-update).
- Updates staged in `~/Library/Application Support/Zentrion/versions/`, health-checked, auto-rollback on failure.
