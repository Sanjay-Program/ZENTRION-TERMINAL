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
| DNS | OS resolver for A/AAAA; built-in wire client for CNAME/MX/TXT/NS/SOA/PTR | verified |
| Sandbox level | `resource-limits` (no_new_privs + rlimits + non-dumpable + umask + PDEATHSIG) | implemented and reported honestly |
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

## Sandbox level: what `resource-limits` means

Every brokered child receives:

- `PR_SET_NO_NEW_PRIVS` (no setuid escalation)
- `PR_SET_DUMPABLE=0` (no ptrace/core inspection of the child)
- `PR_SET_PDEATHSIG=SIGKILL` (child dies with the broker)
- `RLIMIT_CORE=0` and a CPU-time limit derived from the request timeout
- `umask(077)` so created files are private by default

There is **no** Landlock, seccomp, cgroup or namespace confinement yet. Policy
decides whether an action runs; it does not confine a permitted process. The
capability report therefore says `resource-limits`, not `maximum`. See
[sandbox.md](sandbox.md).

## Distribution notes

- Prefer portable artifacts where practical.
- glibc compatibility is not solved: an artifact built against a newer glibc
  than the host has is refused by the dynamic loader, not by Zentrion. The
  install record records the ABI so the cause is visible.
- ARM64 is first-class in the resolver; it is simply untested here.
