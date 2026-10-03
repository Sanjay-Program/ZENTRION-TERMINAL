# 05 — CLI SPEC (`z`)

Design principle: **simple top, deep underneath.**

```
z install nmap     z init my-project    z secure .
z ai run           z agent list         z doctor
```

All commands accept `--json` (machine output for scripts/SDK/agents),
`--yes` (non-interactive where risk permits), `--project <path>`,
`--config <file>`.

## Command table

| Command | Purpose | Security notes |
|---|---|---|
| `z` | interactive shell/repl (TUI) | runs inside project policy |
| `z help [cmd]` | help | none |
| `z version [--json]` | versions of core/runtime/schemas | none |
| `z doctor` | health check: host probe, sandbox caps, config, registry reachability, AI status, update channel | read-only; makes 0 network calls unless `--network` |
| `z status` | running agents, active sessions, pending approvals, lockdown state | none |
| `z init [path]` | scaffold `.zentrion/` (project.yaml, policy.yaml, tools.yaml, ai.yaml, environment.yaml, secrets.yaml refs) | writes only under target path |
| `z env` | list/select environment profiles (`z env use dev`) | env activation re-evaluates policy |
| `z project` | show/validate project manifest (`z project check`) | none |
| `z install <tool\|plugin\|model>` | install from registry with verification; prompts on permission grants | HIGH: requires checksum/signature match; permission prompts |
| `z uninstall <name>` | remove + revoke its capabilities | revoke is immediate |
| `z update [core\|tools] [--check]` | self-update with signature verify + rollback | CRITICAL: staged, health-checked |
| `z search <query>` | search registry metadata (network, explicit) | network logged |
| `z run <tool> [args]` | run an installed tool under policy + sandbox | broker path |
| `z exec <cmd...>` | execute arbitrary command under current policy | MEDIUM+; sandbox by risk |
| `z secure <path>` | run security scan suite on path | read-only by default |
| `z policy` | `show / validate / test / edit` project+user policies | none (validate is offline) |
| `z permission` | grant/revoke/list capability grants (`z permission grant mcp filesystem.read ./data`) | HIGH: explicit consent |
| `z agent` | `list / new / inspect / kill / logs` | kill is always allowed |
| `z ai` | `status / run / chat / config / bom / models` | provider keys never displayed |
| `z model` | `list / add / remove` (local + remote catalog) | model download integrity-checked |
| `z mcp` | `list / add / remove / trust` server management | trust change requires consent |
| `z scan <path>` | alias of `z secure` with report flags | read-only |
| `z secrets` | `set/get/list/delete/rotate/detect` | get requires risk approval; never printed to AI context |
| `z audit` | `tail / show / verify / export` | verify checks hash chain |
| `z events` | human-friendly recent activity feed | derived from audit |
| `z lockdown [--network] [--duration 15m]` | kill-switch: agents stopped, caps revoked, optional egress block | always available, logged |
| `z config` | get/set user config (never policy bypass) | guarded keys require re-auth |

## Exit codes

0 ok · 1 usage · 2 denied-by-policy · 3 approval-rejected · 4 sandbox failure ·
5 integrity failure · 6 network/registry failure · 7 internal error ·
130 interrupted.

## Example outputs

`z doctor`
```
OS:        Linux 6.x (fedora) x64
Sandbox:   landlock=full  seccomp=full  cgroup=full  ns=user
Policy:    project(policy.yaml) valid, 4 grants, 0 conflicts
Secrets:   keyring available (Secret Service)
Registry:  reachable (cached metadata 2h old)
AI:        no provider configured (BYOK: z ai config)
Updates:   v0.1.0 = latest, signature ok
```

`z exec` denied:
```
✗ Zentrion blocked this command.
  What was attempted:  read /home/you/.ssh/id_ed25519
  Why blocked:         project policy denies filesystem.read outside workspace
  Policy:              .zentrion/policy.yaml (filesystem.read)
  Risk:                HIGH
  Options:             (1) add read scope to policy  (2) run with --approve  (3) cancel
  Audit:               ev_9f2c… recorded
```

Every error message follows this five-part pattern (see `06-SECURITY-ARCHITECTURE.md` §UX).

## Non-goals
No command silently widens permissions. No hidden flags bypass the broker
(an explicit, separately-authenticated `z capability repair` is the only
administrative path and it is audited).
