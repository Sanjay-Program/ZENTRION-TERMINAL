# The native runtime

Zentrion is one runtime that talks to three operating systems directly.
There is **no compatibility environment**: no WSL, no container, no VM, and no
shell dependency. Where a platform cannot do something, Zentrion says so
instead of faking it.

```
                 Human / AI / Agent / IDE / CI
                              |
                        Zentrion CLI + APIs
                              |
                       Zentrion Runtime
                +-------------+-------------+
                |             |             |
         Tool Manager     Native APIs    Security Engines
                |             |             |
        +-------+-------+     |      +------+------+
        |       |       |     |      |      |      |
      Policy Capability Audit |   DNS   HTTP   TLS*
        +-------+-------+     |      |      |      |
                |             |      +------+------+
         Native Execution -----+
                |
        +-------+-------+-----+
        |       |       |     |
      Windows  macOS  Linux  (all via OS APIs)
```

\* TLS inspection is defined but not implemented in Phase 2 — see below.

## Architecture in one sentence

Every subsystem is a trait with a per-platform implementation:

```
PlatformResolver   OS + arch + ABI  →  PlatformTarget
ProcessInspector   /proc on Linux, libproc on macOS*, Toolhelp32 on Windows*
FilesystemInspector std::fs (+ Unix mode bits) — genuinely native everywhere
DNS                OS resolver for A/AAAA; wire protocol for other types*
HTTP               interface only; transport is an opt-in build feature
TLS                interface only; no backend compiled in Phase 2
```

`*` = written and compiled only on its own target; **UNVERIFIED** here.

## What is actually implemented and tested

Verified on Linux x64 in this environment:

| Subsystem | Status |
|---|---|
| Platform resolution (OS + arch + ABI) | Implemented, tested |
| Process inspection (own user, via `/proc`) | Implemented, tested |
| Filesystem inspection + path safety | Implemented, tested |
| System info (CPU, memory, hostname) | Implemented, tested (Linux) |
| DNS A/AAAA via the OS resolver | Implemented, tested (offline-safe) |
| Sandbox level reporting | Implemented, tested (honest per-platform) |
| HTTP transport | Interface only — opt-in `http` feature |
| TLS inspection | Interface only — returns `Unsupported` |

## Honest platform matrix

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Platform resolution | verified | unverified | unverified |
| Process inspection | verified (`/proc`) | not implemented (needs libproc) | not implemented (needs Toolhelp32) |
| Filesystem inspection | verified | unverified | unverified |
| System memory info | verified (`/proc/meminfo`) | returns `None` | returns `None` |
| DNS A/AAAA | verified | unverified | unverified |
| Sandbox level reported | maximum | filesystem+network | resource-limits |

"Not implemented" means the trait returns `Unsupported` with a message. It does
**not** mean a silent fallback to parsing another tool's output.

## No hidden compatibility layer

`z platform` prints this, and it is true of the codebase:

```
Compatibility environments required: none
  WSL: no   Docker: no   VM: no
```

There is no code path that installs, starts, or requires any of them. A tool
whose manifest declares an `external_dependency` requires the user to opt in
explicitly; that is a warning, not automation.

## Reading order

- [windows.md](windows.md) — what is and is not implemented on Windows
- [macos.md](macos.md) — same for macOS
- [linux.md](linux.md) — the reference platform
- [tool-portability.md](tool-portability.md) — the compatibility levels
- [sandbox.md](sandbox.md) — isolation levels and what they really mean
- [runtime.md](runtime.md) — how execution is brokered
