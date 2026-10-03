# 04 — CORE RUNTIME (L1)

## Responsibilities
Host detection, runtime lifecycle, IPC, configuration, identity,
capability/policy interfaces, process/filesystem/network abstraction,
secure-storage interface, logging, auditing, error handling.

## Startup sequence

```
z (invoked)
 └─ 1. host probe (OS/arch/virt/sandbox caps)          [cached ≤ 24h]
 └─ 2. config resolution (defaults→user→project→env)
 └─ 3. open local audit log (hash-chained)
 └─ 4. load identity (user profile, local keypair)
 └─ 5. initialize broker (policy engine + capability store)
 └─ 6. dispatch command
```

Nothing in steps 1–5 performs network I/O. No daemon unless a long-running
agent/AI session requires one (`z agent` starts it; it exits when sessions end).

## Identity model

Every actor has a typed identity:

```
Actor {
  id:            string        // stable: usr_xxxx | agt_xxxx | plg_xxxx | mcp_xxxx | ci_xxxx
  type:          user|agent|plugin|mcp|ci|ide
  parent_id:     string?       // agent → user; plugin → user
  project_id:    string?
  created_at, expires_at: ts
  policy_ref:    uri           // resolved policy document
  status:        active|suspended|revoked|expired
}
```

Delegation: an agent's capabilities are always **subsets** of its creator's
grants minus the agent's policy denials. Agents can never re-delegate beyond
their own scope (one level of delegation only in v1).

## IPC

- Local Unix domain socket (Linux/macOS) / named pipe (Windows).
- Mutual authentication via local keypair handshake + per-peer token.
- All IPC payloads are `ExecRequest`/`ExecResult` or management ops.
- IPC is **not** network-exposed. Remote access = Phase 5 cloud relay, explicitly designed later.
- Default socket permissions: user-only (0600 / ACL).

## Configuration layering (lowest → highest precedence)

1. built-in defaults
2. `~/.zentrion/config.yaml` (user)
3. `.zentrion/project.yaml` (project; most keys lock here)
4. environment variables `ZENTRION_*`
5. runtime `--flag` overrides (CLI only, never widen permissions)

Merges are additive for lists, replace for scalars; security lists (policy
paths, secrets) intersect-or-deny rather than union — see `09-POLICY-SPEC.md`.

## Error handling

```
ZenError {
  code:    "ZEN-POL-4031"      // area.severity-seq
  human:   "Zentrion blocked this AI agent from reading ~/.ssh"
  detail:  {...}               // machine-readable
  cause:   ZenError?
  audit_id?: string
}
```

Error areas: `CFG COR POL CAP EXE SBX SEC NET FS PR AI AGT MCP REG UPD AUD`
Severity: 0 debug … 5 fatal. Every error surfaced to a user must render
`human` plus "what was attempted / why blocked / options" (see 59 in spec §SECURITY-UX inside `06-SECURITY-ARCHITECTURE.md`).

## Failure philosophy (L1 must hold these)

| Failure | Behavior |
|---|---|
| policy engine unreachable | **deny all host effects**, commands that only read config still work |
| capability store corrupt | deny privileged ops; offer `z capability repair` from audit replay |
| audit write fails | operation is **aborted** for HIGH/CRITICAL risk; LOW proceeds with in-memory buffer + warning |
| config corrupt | refuse to start with repair instructions; never fall back to defaults silently |
| IPC auth fails | connection refused, event logged |

## What L1 deliberately does NOT do

- No AI logic, no tool installation, no project semantics (L2–L5).
- No network calls except z-update (signature-checked) and user-initiated fetches.
- No background services by default.
