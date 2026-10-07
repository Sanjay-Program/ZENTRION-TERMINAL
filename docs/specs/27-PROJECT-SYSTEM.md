# 27 — PROJECT SYSTEM

## 27.1 `z init` scaffold

```
my-project/
└── .zentrion/
    ├── project.yaml        # universal project manifest (28)
    ├── policy.yaml         # security policy (09)
    ├── tools.yaml          # tool pins for this project
    ├── ai.yaml             # AI config: providers, models, gateway rules
    ├── environment.yaml    # env profiles + dependency/runime pins
    └── secrets.yaml        # handles only — never values (24)
```

## 27.2 File purposes

| File | Purpose | Example keys |
|---|---|---|
| `project.yaml` | identity, languages, versions, platform requirements | name, version, languages, min_zentrion |
| `policy.yaml` | permission policy for humans/agents/tools/plugins in this project | filesystem, network, secrets, agents |
| `tools.yaml` | project-pinned tools | `nmap: "7.95"`, `trivy: "0.55"` |
| `ai.yaml` | AI defaults | provider: local/ollama, model, send_code: true, cost_budget |
| `environment.yaml` | env profiles | `dev: {python: "3.12", vars: {...}}`, `ci: {...}` |
| `secrets.yaml` | secret handles + rotation metadata | see 24 |

All schemas versioned (`apiVersion: zentrion.<kind>/v1`), validated by `z project check`.

## 27.3 Universal project manifest schema (project.yaml)

```yaml
apiVersion: zentrion.project/v1
kind: Project
metadata:
  name: my-app
  version: 0.1.0
  description: Example service
languages:
  - {name: rust, version: "1.82"}
  - {name: typescript, version: "5.6"}
tools:
  include: tools.yaml
ai:
  include: ai.yaml
agents:
  - name: refactor-agent
    policy_inline_or_ref: policy.yaml
mcp:
  servers: [github-mcp]
permissions:
  include: policy.yaml
secrets:
  include: secrets.yaml
security:
  policy: policy.yaml
environment:
  include: environment.yaml
platforms:
  required: [linux-x64, macos-arm64]
  optional: [windows-x64]
zentrion:
  min_version: "0.1.0"
```

## 27.4 Environment profiles (`z env use dev`)
Profiles activate: language runtime selection (delegates to existing version
managers if present — mise/asdf/nvm — or uses declared toolchains), env vars
(non-secret), and policy scope. Switching re-evaluates policy; secrets are
never placed in env by default.

## 27.5 Reproducibility
- Pinned tools + lockfile semantics in tools.yaml.
- `z project check` verifies versions are satisfiable and policy valid.
- Git-ignorable: `.zentrion/cache/` only; the manifest files belong in version control.
