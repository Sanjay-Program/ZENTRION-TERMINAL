# Sandbox levels

## Read this first

**Phase 2 does not confine processes.** The tool manager decides *whether*
something may run; it does not yet confine *how* it runs. `z platform` reports
the isolation the platform *offers*, not isolation that is currently applied.

Do not run untrusted binaries with Phase 2 and assume they are contained. They
are not.

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
| Linux | `maximum` (5) | Landlock + seccomp + cgroup v2 + namespaces | nothing platform-side |
| macOS | `filesystem+network` (3) | Seatbelt profiles + rlimits | no syscall filter |
| Windows | `resource-limits` (1) | Job Objects | no filesystem or syscall confinement for arbitrary children |

This is a capability probe, asserted by a test against the compile target so
the report cannot drift from reality.

## Why Windows is lower

There is no supported Windows mechanism offering Linux-grade syscall and
filesystem confinement for an arbitrary child process. Rather than claim one,
Zentrion reports level 1. Options for raising it later (restricted tokens,
AppContainer, job-object restrictions) are real but partial, and would be
reported as their true level, not as "strong".

## What Phase 3 will add

1. A `SandboxProvider` trait with `create / configure / execute / terminate /
   destroy`.
2. `LinuxSandboxProvider`: Landlock ruleset from the policy's filesystem
   scopes, seccomp filter, cgroup v2 limits, network namespace for
   `network: none`.
3. `MacOSSandboxProvider`: generated Seatbelt profile.
4. `WindowsSandboxProvider`: Job Object limits plus a restricted token where
   it helps, reporting the level it actually achieves.
5. Broker integration: a request whose risk requires level *N* is refused when
   the platform cannot reach *N*, unless the user explicitly opts out. That is
   the Phase 0 fail-closed rule, and it is not yet wired up.

## Relationship to policy

Policy and sandbox are complementary and neither replaces the other:

- **Policy** answers "is this actor allowed to do this to this resource?" and
  is enforced in the broker, before execution.
- **Sandbox** answers "what can this process actually reach once running?" and
  is enforced by the kernel.

A permitted process is currently unconfined. That is the principal security
limitation of Phase 2 and is stated as such in the security review.
