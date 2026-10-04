# Runtime Architecture

The runtime layer owns platform detection, process execution, filesystem
access, host/environment discovery and the security path used by humans,
agents, plugins, SDKs and CI.

## Runtime Contract

Everything that can affect the host passes through the same sequence:

```text
caller
  -> identity
  -> policy
  -> capability
  -> risk/approval
  -> brokered execution
  -> sandbox / native engine / tool store
  -> audit
```

There is no separate "AI fast path". Agents and external AI providers request
actions through the same runtime surfaces as users.

## Core Surfaces

| Surface | Purpose |
|---|---|
| `z doctor` | Offline health check |
| `z status` | Runtime, project, policy and audit state |
| `z setup` | First-run setup for durable local storage |
| `z storage` | Storage paths, retention policy and health |
| `z run` | Brokered process/tool execution |
| `z bundle` | Curated development/security tool packs |
| `z scan` | Native security assessment |
| `z ai` | Gateway-mediated AI analysis |
| `z ui` | Operator dashboard for runtime, tools, agents and docs |
| SDK / daemon | Local IPC path for apps and IDE integrations |

## Platform Paths

| Platform | Config | Data |
|---|---|---|
| Linux | `$XDG_CONFIG_HOME/zentrion` | `$XDG_DATA_HOME/zentrion` |
| macOS | `~/Library/Application Support/Zentrion` | `~/Library/Application Support/Zentrion` |
| Windows | `%APPDATA%\Zentrion` | `%LOCALAPPDATA%\Zentrion` |

`ZENTRION_CONFIG_DIR` and `ZENTRION_DATA_DIR` override these paths for testing,
portable installs and packaging.

Durable user storage survives binary deletion, normal uninstall and upgrades.
That includes config, audit, installed tools, sessions, history, memory and scan
reports. Cache is disposable but still left in place unless the user explicitly
cleans it. Use `z storage show` and `z storage policy` for the exact paths and
retention contract.

## Ease-of-Use Flow

New users should be able to start with:

```sh
z doctor
z setup
z storage show
z status
z bundle list
z bundle plan web
z ui
```

Advanced users then add policy, provider configuration, SDK clients, MCP
servers or plugins without replacing the runtime security model.
