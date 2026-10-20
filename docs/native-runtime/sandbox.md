# Sandbox levels

## Read this first

**The current build hardens processes but does not filesystem- or syscall-
confine them.** Every brokered child gets `no_new_privs`, non-dumpable,
`PDEATHSIG`, no core dumps, a CPU-time limit and `umask 077`. The tool manager
decides *whether* something may run; Landlock/seccomp-style confinement of
*how* it runs is not implemented. `z platform` reports `resource-limits`.

Do not run untrusted binaries and assume they are contained. They are not.

## Levels

| Level | Name | Meaning |
|---|---|---|
| 0 | none | normal process semantics |
| 1 | resource-limits | CPU/memory/process-count caps only |
| 2 | filesystem | level 1 + filesystem restrictions |
| 3 | filesystem+network | level 2 + network restrictions |
| 4 | strong | level 3 + syscall filtering |
| 5 | maximum | everything the platform offers |

Defined in `z_native::SandboxLevel`. Ordering is meaningful and used to compare
a requirement against what is available.

## Per-platform report

| Platform | Reported level | Basis | What is missing |
|---|---|---|---|
| Linux | `resource-limits` (1) | no_new_privs, non-dumpable, PDEATHSIG, rlimits, umask | Landlock, seccomp, cgroups, namespaces |
| macOS | `resource-limits` (1) | POSIX rlimits and process hygiene | Seatbelt profiles, syscall filtering |
| Windows | `none` (0) | no Job Object wiring yet | all confinement |

This is a capability report asserted by a test against the compile target so it
cannot drift from reality.

## Why not claim more

Landlock, seccomp and network namespaces are real Linux primitives, but wiring
them into a general-purpose terminal broker without breaking compilers, package
managers and interactive programs is a substantial project. Reporting a level
that is not applied would be worse than reporting the truth.

## Why Windows is lower

There is no supported Windows mechanism offering Linux-grade syscall and
filesystem confinement for an arbitrary child process. Rather than claim one,
Zentrion reports level 1. Options for raising it later (restricted tokens,
AppContainer, job-object restrictions) are real but partial, and would be
reported as their true level, not as "strong".

## What a stronger sandbox would add

1. A `SandboxProvider` trait with `create / configure / execute / terminate /
   destroy`.
2. `LinuxSandboxProvider`: Landlock ruleset from the policy's filesystem
   scopes, seccomp filter, cgroup v2 limits, network namespace for
   `network: none`.
3. `MacOSSandboxProvider`: generated Seatbelt profile.
4. `WindowsSandboxProvider`: Job Object limits plus a restricted token where
   it helps, reporting the level it actually achieves.
5. Broker integration: a request whose risk requires level *N* is refused when
   the platform cannot reach *N*, unless the user explicitly opts out.

## Relationship to policy

Policy and sandbox are complementary and neither replaces the other:

- **Policy** answers "is this actor allowed to do this to this resource?" and
  is enforced in the broker, before execution.
- **Sandbox** answers "what can this process actually reach once running?" and
  is enforced by the kernel.

A permitted process is currently unconfined at the filesystem/network level.
That is the principal security limitation and is stated as such in the security
review.
