# Changelog

## Unreleased — terminal and security overhaul

### Terminal
- Added a real PTY-backed terminal engine (`portable-pty` + `vt100`) with
  colours, Unicode, resize and 10,000-line scrollback.
- Added tabs (up to unlimited), up to four panes per tab, pane focus, closing
  and a live tab bar.
- Added SGR mouse forwarding and wheel scrolling.
- Added bracketed paste handling (terminal, editor, palette, chat, copilot).
- Reworked keybindings to keys terminals can actually distinguish: F2–F10 and
  Alt combinations; ordinary `Ctrl` keys go to the shell.
- Fixed terminal restoration on error and panic.
- Added real commands in the palette (`:theme`, `:view`, `:e`, `:ai`, `:new`,
  `:split`, `:close`, `:quit`).
- Added a persistent theme system with seven themes.
- Added a real editor with load/save/save-as, Unicode-safe editing and line
  numbers.
- Added a gateway-backed AI copilot and research view.
- Added a live system monitor.
- Added encrypted P2P LAN chat with a real protocol (see below).

### Security
- Replaced the hard-coded vault master key with a per-install random key file
  (`0600`), atomic vault writes, and legacy-vault migration.
- Fixed an AI redaction regex that used unsupported backreferences and crashed
  the copilot.
- Added gateway redaction tests for AWS keys, private keys, GitHub tokens,
  JWTs, bearer headers and email addresses.
- Added brokered-child hardening: `no_new_privs`, non-dumpable, `PDEATHSIG`,
  `RLIMIT_CORE`, CPU-time limits and `umask 077`.
- Corrected the sandbox capability report from “maximum” to the true level
  (`resource-limits`).
- Made `process.spawn` policy matching exact rather than prefix-based.
- Gated bundled native tools (`z-curl`, `z-ping`, `z-sysinfo`) behind the
  project `tools.allow` list and network policy; `z-curl` no longer follows
  redirects.
- Made the OS package-manager fallback explicit (`z install --os-package`).
- Added optional shared-token authentication to the IPC daemon.
- Added real audit/exit behavior for denied daemon requests.

### Networking and protocols
- Rewrote P2P chat: length-prefixed AES-256-GCM frames, UDP discovery with
  port reuse, peer expiry, idle timeouts, replay-resistant nonces and a
  stretched passphrase KDF.
- Fixed MCP client runtime panic, added handshake, `tools/list`, timeouts and
  child cleanup.

### CLI
- Replaced fake success paths for `code`, `security`, `network`, `cloud`,
  `agent`, `do`, `theme`, `enterprise`, `upgrade`, `mcp`, `plugin`, `daemon`
  and `lockdown` with real or honest implementations.
- Added local filesystem scanning to `z scan`/`z security scan` with
  file/line evidence and secret masking.
- Added static IaC review (`z cloud scan`).
- Added dependency SBOMs (`z sbom --deps`) and project-derived AI BOMs.
- Added `z ai ask`, honest AI status/privacy, and real AI inventory.
- Added verified manifest-based updates with SHA-256, atomic install and
  rollback.
- Added secret name listing/deletion (`z config list-secrets`,
  `z config delete-secret`).
- Added daemon status/stop and token authentication.
- Corrected installers to install `z` (not `z-cli`), support local checkouts
  and verify the installed binary.

### Documentation and releases
- Rewrote README, getting-started, terminal, release and architecture docs to
  match actual behavior and limits.
- Removed fake release artifacts and added a real Linux x64 archive plus
  checksum produced by `scripts/package.sh`.
