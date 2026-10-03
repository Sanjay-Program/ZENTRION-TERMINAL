# 10 — SANDBOX SPEC

## 10.1 Design principle
Sandbox is **platform-native adapters behind one interface**, never a
reimplementation. Where a platform can't guarantee something, we say so and
degrade the risk ceiling (fail-closed), we don't pretend.

## 10.2 Sandbox interface (language-agnostic)

```
SandboxSpec {
  profile:      "default" | "tool" | "agent" | "quarantine"
  fs:           {read: [paths], write: [paths], tmpfs: true}
  net:          {mode: "none"|"allowlist"|"full", hosts: [], ports: []}
  proc:         {max_children, allowed_binaries}
  resources:    {cpu_pct, mem_mb, pids, disk_mb, wall_time}
  env:          {inherit: [], deny: [SECRET_*, SSH_AUTH_SOCK, ...]}
  cwd:          path
  cleanup:      "auto"
  detect_escape: bool
}
SandboxHandle { spawn(spec, cmd) → ProcHandle; status(); kill(); cleanup() }
```

## 10.3 Per-OS capability matrix (honest)

| Guarantee | Linux | macOS | Windows |
|---|---|---|---|
| Filesystem read/write confinement | **landlock** — strong | **sandbox-exec / Seatbelt** — strong (deprecated but functional); app-sandbox limited for CLI tools | Partial (ACLs on workspace dir; **no robust per-process fs sandbox for arbitrary processes**) |
| Network confinement | **netns/cgroup + nftables**, or seccomp-based proxy | sandbox-exec network deny / pf anchors (best-effort) | Windows Firewall per-app rules (best-effort) |
| Process restrictions | **seccomp** filter (syscall deny), pids cgroup | sandbox-exec process limits; no seccomp-equivalent granularity | Job Objects (CPU/mem/pids), no syscall filter |
| Resource limits (cpu/mem/io) | cgroups v2 — strong | `posix_spawn` rlimits + `taskpolicy` (cpu), mem via rlimits — moderate | Job Objects — good |
| Wall-clock kill | strong | strong | strong |
| Env isolation (hide secrets) | strong (fresh env) | strong | strong (clean env block) |
| Full isolation of untrusted binaries | strong | moderate | **weak** |

**Honest limitation statement:** on Windows there is currently no built-in
mechanism with Linux-grade syscall/filesystem confinement for arbitrary child
processes. Zentrion's Windows strategy: rely on (a) broker-side capability
enforcement *before* spawn, (b) Job Objects for resources, (c) restricted
tokens where feasible, (d) **optional WSL2 as the strong-isolation path**, and
(e) deny-by-default: if the required isolation level isn't available, the
operation is refused unless the user explicitly opts out (see §10.6).

## 10.4 Fallback behavior table

| Required risk | Linux | macOS | Windows (native) | Windows (WSL2) |
|---|---|---|---|---|
| LOW | native | native | native | native |
| MEDIUM | native | native | JobObject+caps | native-in-WSL |
| HIGH | native | native | **requires consent or WSL2** | native-in-WSL |
| CRITICAL | native | native | **requires WSL2 or explicit typed opt-out** | native-in-WSL |

`z doctor` reports which levels are actually available on the current machine.

## 10.5 Temporary workspace & cleanup
- Sandboxed writes go to a per-execution overlay dir (Linux: overlay via tmpfs/bind; macOS: per-run temp dir; Windows: per-run temp dir with ACL).
- On exit: overlay is diffed → successful writes are applied to workspace if policy allows; temp dir removed.
- Orphaned sandbox: watchdog reaps after wall-time × 2.

## 10.6 Escape detection & response
- Linux: seccomp SIGSYS logs, unexpected syscall attempts → kill + audit CRITICAL.
- All platforms: child tries to open daemon pipe / secrets paths → deny + audit (paths are outside sandbox-visible set).
- On escape suspicion: kill process tree, revoke session capabilities, surface incident report.
- Response is *detection + containment*, not prevention guarantees; true isolation bugs at OS level are out of scope.
