# Release Readiness

## What ships

- A Rust workspace whose binary is `z`.
- A real PTY terminal UI (`z ui`) with tabs, panes, editor, copilot, system
  monitor, LAN chat, research and dashboard views.
- A policy/capability/audit broker used by `z run`, `z code` and the IPC daemon.
- A verified tool store, curated bundles, scanners, MCP client, plugin
  validation, enterprise API client and verified updater.
- Documentation in this repository.

## Build and test

Exercised in this workspace:

```sh
cargo build --workspace
cargo test --workspace
cargo check --workspace --all-targets
./scripts/package.sh
```

The test suite covers CLI integration, tool lifecycle, the daemon over a real
socket, PTY round trips, P2P encryption/message delivery, MCP handshake,
vault encryption, update verification/rollback, policy behavior and the TUI
layout/editor.

## Platforms

| Platform | Status |
|---|---|
| Linux x64 | Built and tested here |
| Linux ARM64 | Code-compatible; not executed here |
| macOS | Source build expected to work; not executed here |
| Windows | Source build expected to work (ConPTY); not executed here |

Only the Linux archive is produced by `scripts/package.sh` in this workspace.
`releases/install.sh` and `releases/install.ps1` build from source.

## Installer status

- Source installers: implemented, corrected to install the `z` binary.
- Linux tar.gz: produced locally by `scripts/package.sh`.
- macOS DMG / Windows MSI: not implemented in this repository.
- Signing/notarization: not implemented.

## Known limitations

- Sandbox is `resource-limits` (no_new_privs, rlimits, non-dumpable, umask,
  PDEATHSIG). Landlock/seccomp/filesystem confinement is not implemented.
- Plugins are validated but not executed (no WASM runtime embedded).
- AI research is model-synthesized; no web crawler.
- Cloud is a static IaC reviewer; no provider API calls.
- Enterprise sync requires a user-provided control plane
  (`ZENTRION_ENTERPRISE_URL`).
- Updates require `ZENTRION_UPDATE_MANIFEST`; manifests are integrity-checked
  by SHA-256 but not signed yet.
- Release artifacts are not code-signed.

## Release checklist

- [x] workspace build
- [x] workspace tests
- [x] CLI integration tests
- [x] daemon integration tests
- [x] MCP handshake test
- [x] PTY terminal test
- [x] P2P encryption/message test
- [x] verified update/rollback test
- [x] local archive packaging script
- [x] source installers
- [ ] signed artifacts
- [ ] Windows/macOS artifacts built on those OSes
- [ ] Linux native packages
- [ ] code signing/notarization
