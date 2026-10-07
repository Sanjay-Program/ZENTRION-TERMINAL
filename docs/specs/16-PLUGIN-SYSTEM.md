# 16 — PLUGIN SYSTEM

## 16.1 Plugin types
CLI plugin (commands), tool plugin, AI plugin (provider), agent plugin,
security plugin (scanner), MCP plugin, IDE plugin (separate repos, Phase 4+).

## 16.2 Plugin manifest

```yaml
apiVersion: zentrion.plugin/v1
kind: Plugin
metadata:
  name: docker-helper
  version: 1.2.0
  api_compat: ">=0.3.0 <0.9.0"     # zentrion plugin API range
  publisher:
    id: pub_dockerhelper_co
    key: minisign-pubkey-fingerprint
  license: Apache-2.0

permissions:                        # capability requests — user consents
  - {action: fs.read, resource: "path:./**"}
  - {action: net.connect, resource: "host:registry-1.docker.io:443"}
  - {action: proc.spawn, resource: "name:docker"}

type: cli                           # cli|tool|ai|agent|security|mcp|ide
entry:
  runtime: native                   # native|wasm|script
  artifact: plugin-linux-x64.tar.zst
  integrity: {checksum: sha256:..., signature: minisign:...}
```

## 16.3 Lifecycle
```
install → verify(integrity) → declare permissions → user consent → grant caps
        → register → active → (update | disable | uninstall)
```
- Install: integrity verified before unpacking; artifact unpacked read-only.
- Consent: permission list shown in plain language; later version requesting
  new permissions re-triggers consent (no silent escalation on update).
- Uninstall: capabilities revoked immediately, registration removed, audited.

## 16.4 Execution isolation
| Runtime | Isolation |
|---|---|
| `wasm` | WASI sandbox (limited caps; preferred for third-party plugins) |
| `native` | runs as a separate process, talks to the daemon over authenticated IPC, under its granted capabilities only — never in-process |
| `script` | interpreted in sandbox profile `plugin` |

In-process plugins are **not allowed** (crash/isolation risk).

## 16.5 Version & API compatibility
- Manifest declares SemVer range against the plugin API.
- Incompatible plugin → refuses to enable with clear message; no partial loading.
- Plugin updates are signed by the same publisher key (key rotation = explicit re-trust flow).

## 16.6 Audit
Install, consent, update, permission change, and every plugin-initiated broker
request produce audit events tagged with the plugin's actor id.
