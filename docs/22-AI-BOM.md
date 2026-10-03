# 22 — AI-BOM

## 22.1 Purpose
Machine-readable inventory of every AI/automation component active in a project
or machine — for audits, compliance, and supply-chain analysis.

Command: `z ai bom` (formats: `table`, `json`, `yaml`, `cyclonedx-ish json`).

## 22.2 Schema

```json
{
  "bomVersion": "1.0",
  "generatedAt": "2026-10-03T10:00:00Z",
  "project": "my-app",
  "components": [
    {"type": "model", "name": "gpt-4o-mini", "provider": "openai", "version": "2024-07-18", "local": false, "license": "commercial"},
    {"type": "model", "name": "llama3.1-8b", "provider": "local/ollama", "version": "q4_K_M", "local": true},
    {"type": "agent", "name": "refactor-agent", "id": "agt_9f2c", "model": "gpt-4o-mini", "policy": "project", "capabilities": ["fs.read:./**", "fs.write:./src/**"]},
    {"type": "mcp-server", "name": "github-mcp", "version": "1.4.0", "trust": "community", "tools": ["create_issue", "search"]},
    {"type": "tool", "name": "nmap", "version": "7.95", "source": "upstream", "checksum": "sha256:..."},
    {"type": "package", "name": "tokio", "version": "1.40", "ecosystem": "cargo"},
    {"type": "dataset", "name": "support-tickets", "location": "./data/tickets.csv", "containsPII": true},
    {"type": "external-api", "name": "openai", "endpoint": "https://api.openai.com", "dataSent": "code+prompts"},
    {"type": "plugin", "name": "docker-helper", "version": "1.2.0", "permissions": ["fs.read:./**"]},
    {"type": "policy", "name": "project", "hash": "sha256:..."},
    {"type": "secret-handle", "name": "db_password", "store": "os-keyring", "everSharedWithAI": false}
  ]
}
```

## 22.3 Generation
Assembled from: project manifests, agent registry, installed tool inventory,
package lockfiles, MCP registrations, gateway audit logs (which providers
actually received data). `z ai bom --diff` shows changes since last commit —
useful in code review for spotting a new MCP server or model appearing.

## 22.4 Uses
- CI gate: `z ai bom --check-policy` fails if a component violates policy (e.g., cloud model in local-only project).
- Compliance: export for review; feeds the supply-chain graph (23).
