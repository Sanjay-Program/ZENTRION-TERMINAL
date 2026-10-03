# How execution is brokered

## The invariant

Nothing reaches the operating system except through the execution broker.

```
Caller (CLI / tool / future AI)
        |
        v
   ExecRequest { actor, action, resource, reason }
        |
        v
  +---------------------------------------------+
  | 1. identity   — who is asking               |
  | 2. policy     — is it allowed, at what risk |
  | 3. capability — scoped, expiring, single-use|
  | 4. risk       — HIGH/CRITICAL needs approval|
  | 5. execute    — direct, no shell            |
  | 6. audit      — hash-chained event          |
  +---------------------------------------------+
        |
        v
   Native OS APIs
```

## Tool execution specifically

`z run <tool> -- <args>`:

1. Look up the tool in the store; fail if not installed.
2. Read the manifest to find the executable, or a native engine.
3. If a **native engine** is declared, run it in-process. No external binary,
   no shell, no artifact bytes.
4. Otherwise canonicalize the executable path *within the tool directory*
   (`canonical_within` refuses symlinks that resolve outside).
5. Build an `ExecRequest` with `action: "tool.execute"`, `resource: "tool:<name>"`.
6. The broker evaluates policy against the **tool name**, not the binary path —
   so a permitted tool cannot be swapped for a different binary.
7. A tool whose manifest declares `network: true` is **escalated to HIGH risk**
   and requires `--approve`. The manifest can only raise the bar, never lower it.
8. Arguments are passed as a structured array.
9. The outcome is audited.

## Why the tool name, not the path

If the policy resource were the binary path, an attacker who could influence
the path (a replaced artifact, a symlink) would be running something the policy
never approved. Keying on the tool name means the policy grants exactly the
tool the user has in mind.

## Argument handling

There is no `sh -c`, no `cmd /c`, no string concatenation, and no `eval`
anywhere in the process layer. One function builds a `Command` and passes
`.args(&args)`. Tests assert that `;`, `&&`, `$( )`, backticks, redirects,
newlines and quotes remain literal, with a line-count assertion proving no
second command ran.

## Environment hygiene

Child processes receive a controlled environment:

- `ZENTRION_SECRET` and `SSH_AUTH_SOCK` are **removed** unconditionally.
- Callers may add variables explicitly; they may not inherit secrets by default.

## Failure behaviour

| Failure | Behaviour |
|---|---|
| Policy engine error | deny |
| Policy denies | deny, exit code 2, audited |
| Approval required, not given | `approval_required`, audited, no execution |
| Capability check fails | deny |
| Executable missing | error with a reinstall suggestion |
| Process times out | killed, reported as `Timeout` |
| Audit write fails | the broker propagates the error rather than running unlogged |

## No shell, and no implicit network

The runtime works offline. Network transport is a compile-time feature
(`--features http`), off by default, and an install that needs it says so
rather than silently reaching out.
