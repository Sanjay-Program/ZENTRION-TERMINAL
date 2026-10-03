# 25 — AUDIT

## 25.1 Event schema

```json
{
  "id": "ev_9f2c81…",
  "ts": "2026-10-03T10:02:11.431Z",
  "actor": "agt_refactor_01",
  "actor_type": "agent",
  "action": "fs.write",
  "resource": "path:./src/main.rs",
  "project": "my-app",
  "policy": "project@sha256:abc…",
  "capability": "cap_8f3a",
  "result": "allowed",
  "risk": "MEDIUM",
  "platform": "linux-x64",
  "prev_hash": "sha256:…",
  "hash": "sha256:…"
}
```

## 25.2 Local audit
- Append-only, **hash-chained** (each event hashes the previous) → tamper-evident; `z audit verify` walks the chain.
- Stored at `~/.local/share/zentrion/audit/` (platform paths per 11); rotated daily, retained 90 days by default (configurable).
- Secrets are never in events; resources are handles/scopes, not content.
- For HIGH/CRITICAL operations, an audit-write failure aborts the operation (fail-closed); LOW ops continue with buffered events + warning.

## 25.3 Optional cloud audit (Phase 5, enterprise)
- Batched export, signed at origin, SIEM-friendly (JSONL). Off by default.
- Central retention policies apply; local copy always remains.

## 25.4 Privacy
- Events contain no file contents, no prompts, no secret values.
- Resource paths may be sensitive (e.g., `/home/x/bank-project`); user can configure path truncation. Export prompts show what leaves the machine.

## 25.5 Export & consumption
- `z audit export --since 24h --format jsonl` → file or stdout.
- `z events` renders human-readable feed.
- Integrity: chain verification + optional daily "anchor" hash written to a separate file the user can back up.

## 25.6 Honest limits
Hash chaining detects modification of a local log file but cannot prevent a
root attacker from rewriting the whole chain. For stronger guarantees, remote
anchoring is future work (enterprise).
