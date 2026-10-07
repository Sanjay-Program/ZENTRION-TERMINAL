# 08 — CAPABILITY MODEL

## 8.1 Concepts

A **capability** is a structured, non-forgeable reference to a permitted
(action, resource-scope) pair, held by an identity, with expiry, issued by the
capability service, checked by the Execution Broker on every request.

```
Capability {
  id:          string        // e.g. "cap_8f3a…"
  actor_id:    string        // usr_x | agt_x | plg_x | mcp_x | ci_x
  action:      string        // from taxonomy below
  resource:    string        // scope expression (path, host, pid-range, secret-handle)
  constraints: {max_ops?, max_bytes?, max_duration?, time_window?}
  issued_by:   string        // "policy:project" | "user-consent" | "enterprise"
  issued_at:   timestamp
  expires_at:  timestamp     // short-lived by default (5m–24h depending on risk)
  parent_cap:  string?       // delegation chain (agents inherit ⊆ parent)
  revocation:  "immediate" | "on-session-end" | "on-project-close"
  risk:        LOW|MEDIUM|HIGH|CRITICAL
  approval:    {required: bool, granted_by?: user_id, granted_at?: ts}
}
```

Non-cryptographic in Phase 0; in-memory opaque tokens held by the broker.
Cryptographic sealing (needed only if capabilities must survive restarts or
cross process boundaries) is a Phase 3 decision — **not** specified as a
security guarantee until implemented.

## 8.2 Action taxonomy

| Domain | Actions |
|---|---|
| filesystem | `fs.read` `fs.write` `fs.delete` `fs.execute` `fs.watch` |
| network | `net.connect` `net.listen` `net.dns` |
| process | `proc.spawn` `proc.kill` `proc.signal` `proc.inspect` |
| secrets | `secret.read` `secret.write` `secret.list` |
| tools | `tool.execute` `tool.install` |
| AI | `model.invoke` `model.stream` |
| MCP | `mcp.call` `mcp.register` |
| device | `device.access` (mic, camera, serial — CRITICAL) |
| containers/VMs | `container.run` `vm.run` (LATER) |
| system | `sys.admin` (privilege escalation — CRITICAL) |

## 8.3 Resource scopes

| Domain | Scope expression examples |
|---|---|
| filesystem | `path:./src/**`, `path:/etc/hosts` (absolute = HIGH) |
| network | `host:api.example.com:443`, `cidr:10.0.0.0/8`, `port:8080` |
| process | `child-of:self`, `pid:1234`, `name:nmap` |
| secrets | `secret:db_password` (handle, never value) |
| tools | `tool:nmap`, `tool:*` (wildcard = HIGH) |
| model | `model:gpt-4o`, `provider:openai` |
| mcp | `mcp:server-id/tool-name` |

Scope evaluation: longest-match wins; `**` recursive, `*` single segment.
Absolute paths outside `$HOME` and outside the project workspace are always
at least HIGH risk.

## 8.4 Lifecycle

```
requested → evaluated(policy) → issued → active → (used | expired | revoked) → audited
```

- **Request** comes only via the broker.
- **Issued** only after policy evaluation passes AND (for HIGH/CRITICAL) user approval.
- **Expiry defaults**: LOW 24h, MEDIUM 1h, HIGH 10m, CRITICAL single-use.
- **Revocation**: immediate; broker checks a revocation set before every use.
- **Delegation**: agent capabilities ⊆ creator's, minus agent policy denials. No re-delegation beyond one hop in v1.
- **Inheritance**: project-open grants a base set to the interactive user; agents get subsets.

## 8.5 Isolation semantics
Capabilities gate *authorization*; the sandbox enforces *confinement*. Both
must pass. A capability without a matching sandbox profile at required risk
level results in denial (fail-closed).

## 8.6 Example capability token (illustrative, non-cryptographic)

```json
{
  "id": "cap_9f2c81",
  "actor_id": "agt_refactor_01",
  "action": "fs.write",
  "resource": "path:./src/**",
  "constraints": {"max_ops": 200, "max_bytes": 10485760, "max_duration": "10m"},
  "issued_by": "policy:project",
  "issued_at": "2026-10-03T10:00:00Z",
  "expires_at": "2026-10-03T10:10:00Z",
  "parent_cap": "cap_user_base_3a",
  "revocation": "on-session-end",
  "risk": "MEDIUM",
  "approval": {"required": false}
}
```

```json
{
  "id": "cap_7b1d04",
  "actor_id": "agt_sec_scan_02",
  "action": "net.connect",
  "resource": "host:api.github.com:443",
  "constraints": {"max_ops": 50},
  "issued_by": "user-consent",
  "issued_at": "2026-10-03T10:02:11Z",
  "expires_at": "2026-10-03T10:12:11Z",
  "parent_cap": "cap_user_base_3a",
  "revocation": "immediate",
  "risk": "HIGH",
  "approval": {"required": true, "granted_by": "usr_sanjay", "granted_at": "2026-10-03T10:02:05Z"}
}
```
