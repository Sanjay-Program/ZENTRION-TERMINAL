# 29 — API SPEC & VERSIONING

## 29.1 Version scheme
- **Runtime API version**: `v1`, `v2`… exposed via IPC handshake and `z version`.
- **Schema versions**: `zentrion.policy/v1`, `zentrion.tool/v1`, etc.
- **Registry API**: URL versioned (`/v1/...`).

## 29.2 Compatibility rules
- Backward compatible within a major version: additive fields only; unknown fields rejected by strict parsers (schema evolution via optional fields).
- Breaking changes = new major version; old version supported ≥ 12 months or until < 5% traffic (registry).
- Deprecation: fields/endpoints marked `deprecated: true` + `removal_version`; CLI warns.

## 29.3 Feature detection & negotiation
```
handshake: client sends {api_versions: ["v2","v1"], features: [...]}
runtime replies: {api_version: "v2", features: [...supported...]}
```
Clients degrade gracefully: if runtime lacks a feature, SDK surfaces clear error
rather than misbehaving. `z version --json` exposes the full capability set.

## 29.4 ExecRequest/ExecResult (canonical v1)

```jsonc
// request
{
  "actor": {"id": "agt_x", "type": "agent"},
  "action": "fs.write",
  "resource": "path:./src/**",
  "reason": "apply refactor patch",
  "constraints": {"max_bytes": 1048576},
  "ttl": "10m"
}
// result
{
  "status": "allowed|denied|approval_required|failed|timeout",
  "request_id": "req_...",
  "audit_id": "ev_...",
  "error": {"code": "ZEN-POL-4031", "human": "...", "detail": {...}},
  "output_ref": "stdout captured to cache://...",   // large outputs by reference
  "metrics": {"duration_ms": 812, "bytes_written": 4096}
}
```

## 29.5 Error model
Areas × severity (see 04). Stable code space documented in `schemas/errors.json`;
`human` message required; `detail` optional machine data.
