# Linux

## Status

**This is the reference platform and the only one verified in Phase 2.**
Everything in the "verified" column was built and tested on Fedora x86_64 in
this environment.

## What is implemented and verified

| Area | Implementation | Status |
|---|---|---|
| Platform target | OS + arch + ABI (`gnu` / `musl`) | verified |
| Path resolution | XDG: `$XDG_CONFIG_HOME/zentrion`, `$XDG_DATA_HOME/zentrion`, `$XDG_CACHE_HOME/zentrion` | verified |
| OS version | `PRETTY_NAME` from `/etc/os-release` | verified |
| Executable detection | Unix permission bits | verified |
| Process inspection | Reads `/proc/<pid>/{comm,stat,exe,status}` directly | verified |
| Process listing | Enumerates `/proc`, filters numeric entries | verified |
| System memory | `MemTotal` / `MemAvailable` from `/proc/meminfo` | verified |
| DNS A/AAAA | OS resolver via `getaddrinfo` | verified |
| Sandbox level | `Maximum` (landlock + seccomp + cgroups + namespaces available) | reported honestly |
| Process execution | `std::process::Command`, direct, no shell | verified |

## ABI awareness

The platform resolver distinguishes `gnu` from `musl`. A GNU-linked artifact is
**not** selected for a musl host, and vice versa. This is enforced in
`PlatformArtifact::matches` and covered by tests.

## No shell dependency

Normal tool execution does not require `/bin/sh`, `bash`, or any other shell.
The process layer calls `Command::new(program).args(&args)`. Shell
metacharacters in arguments are inert:

```
$ z run echo 'a; echo PWNED'
a; echo PWNED          # one literal line; nothing else executed
```

## Sandbox level: what "maximum" means

`SandboxLevel::Maximum` reports that the *platform offers* Landlock (filesystem),
seccomp (syscalls), cgroup v2 (resources) and namespaces (network/mount).
It is a capability report. **The sandbox is not wired into the execution path
in Phase 2** — nothing is confined yet. Policy decides whether an action runs;
it does not confine a process that has been permitted. See
[sandbox.md](sandbox.md).

## Distribution notes

- Prefer portable artifacts where practical.
- glibc compatibility is not solved: an artifact built against a newer glibc
  than the host has is refused by the dynamic loader, not by Zentrion. The
  install record records the ABI so the cause is visible.
- ARM64 is first-class in the resolver; it is simply untested here.
