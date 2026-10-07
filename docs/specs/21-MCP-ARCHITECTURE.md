# 21 — MCP ARCHITECTURE

## 21.1 Position

```
AI / Agent / Application
        |
  MCP Gateway (z-mcp)
        |
  Server Identity + Trust metadata
        |
  Policy + Capability (same broker path)
        |
  MCP Tool execution
```

MCP is a first-class subsystem, but MCP tools get **no special privileges** —
each call is treated like any other tool request.

## 21.2 Server registration

```yaml
apiVersion: zentrion.mcp/v1
kind: MCPServer
metadata:
  name: github-mcp
  version: 1.4.0
  transport: stdio          # stdio | sse | streamable-http
  command: ["npx", "@modelcontextprotocol/server-github"]
  publisher:
    id: pub_anthropic
    key: minisign-fingerprint
trust:
  level: community          # community | verified | first-party
  verified_at: 2026-09-12
permissions:                # declared per tool
  - {tool: "create_issue", action: net.connect, resource: "host:api.github.com:443"}
  - {tool: "search", action: net.connect, resource: "host:api.github.com:443"}
```

Unregistered server → refused. New server requires: manifest, permission
declaration, explicit user consent, and integrity verification of its binary/package.

## 21.3 Execution flow
1. Model selects MCP tool → gateway validates tool name against registered allowlist.
2. Gateway maps tool → declared permission → broker request with server's actor identity (`mcp_<name>`).
3. Policy + capability + risk as usual. Denied = returned to model as error.
4. Response scanned for injection heuristics (raises risk for next call, best-effort).
5. Audit event per call.

## 21.4 Lifecycle, isolation, revocation
- stdio servers run as child processes of the daemon, sandboxed with no fs/network beyond declared permissions.
- `z mcp trust <name> --revoke` kills the server process, removes registration, revokes capabilities immediately.
- Server crash → marked degraded, calls fail closed; auto-restart only with user config.
- Version updates re-trigger consent if permissions changed.

## 21.5 Trust metadata levels
- **first-party**: published by Zentrion, signed by our key.
- **verified**: publisher identity + review passed (future).
- **community**: registered but unreviewed — surfaced clearly in UI; quarantine profile by default.
