# Changelog

## Unreleased — blueprint implementation

### Performance and CI
- Added the `z-bench` harness and a `Performance gate` CI job: VT parsing
  (policy-checked and raw), screen search, block insert/FTS search, durable
  audit append and CLI startup, with order-of-magnitude regression thresholds.
  Reference Linux release figures: ~16 MiB/s parsing, 0.6 ms screen search,
  ~5k blocks/s insert, ~5 ms FTS search, ~59k audit events/s, ~5 ms startup.
- Added a production release profile (thin LTO, one codegen unit, stripped
  symbols) and made `cargo clippy --workspace --all-targets -- -D warnings`
  clean tree-wide.

### Plugin runtime, packaging, DNS and audit signing
- Added a capability-gated wasmtime plugin host (`z plugin run`): only `log`,
  `clock`, `kv:read` and `kv:write` imports exist, fuel/linear-memory limits are
  enforced, output is bounded, unknown imports fail instantiation, and runs are
  audited. Per-plugin key/value state persists under the user data directory.
- Replaced the SHA-512 refusal and 512 MiB buffering cap in `z-package` with
  streaming SHA-256/SHA-512 over any artifact size.
- Added real `.tar.zst` extraction (zstd) and `.zip` extraction (stored +
  deflate, CRC-32 verified) to the two-phase, traversal/symlink/bomb-safe
  extractor; the tool installer now sniffs tar, tar.gz, tar.zst and zip.
- Added a built-in DNS wire-protocol client: A/AAAA/CNAME/MX/TXT/NS/SOA/PTR
  over UDP with TCP fallback, resolv.conf discovery, and hardened name
  compression parsing. `z dnsx --type MX|TXT|...` and reverse PTR lookups work
  without `dig`/`nslookup`; the phase-3 `dns.records`/`dns.reverse` operations
  are wired to it.
- Added opt-in Ed25519 signing to `z-audit`: `z audit key` creates a local key,
  new events are signed (the signature is excluded from the SHA-256 chain), and
  `z audit verify` checks signatures, missing keys and unsigned legacy logs.

### Terminal workspace, blocks and sessions
- Added `z-session`: a per-user Unix-socket daemon that owns PTYs, records
  command blocks, replays output by sequence number and survives UI detach.
- Added JSON-RPC + binary output framing, attach/detach, resize/signal/close,
  daemon status/shutdown and a blocking client that auto-spawns the daemon.
- Added generated shell integration for bash/zsh/fish/pwsh/nushell (bash
  exercised end-to-end) and block capture from OSC 133 marks; internal shell
  setup commands are filtered out.
- Added `z block`/`z session`/`z workspace` commands, YAML layouts and restore
  policies. Risky commands require `auto_run` or `--approve`.
- TUI sessions now install shell integration; `F11` opens a block/search
  overlay with rerun, and OSC 9;4 progress appears in the pane title.

### Configuration and context
- Added `z-config`: layered TOML, strict validation with file:line errors,
  profiles, named actions/keybinding validation, atomic writes with backup and
  importers for Windows Terminal, Ghostty, iTerm2 and Zentrion TOML.
- Added `z-context`: incremental SQLite FTS5 repository index (git-aware and
  secret-excluding), lexer-level symbols, search and deterministic,
  token-budgeted, redacted context packs with citations.

### Checkpoints, workflows and security
- Added `z-checkpoint`: content-addressed snapshots, blob dedupe, diff hunks,
  byte-verified full/file rollback, workspace locking, GC and Ed25519-signed
  manifests.
- Added `z-workflow`: validated YAML, params/secrets, conditions, approvals,
  parallel steps, policy-gated HTTP, artifacts, timeouts, retries, audit
  records and saved run history.
- Added `z-security`/`z engagement`: authorization and scope records, wildcard/
  CIDR/port scope checks, pre-execution scope blocking, break-glass, signed
  append-only evidence chain with hashed output, findings and signed
  redacted markdown/HTML reports.
- Added Ed25519 signing to `z-identity` for checkpoint/evidence/report exports.

### Notebooks
- Added `z-notebook`: shell/markdown/AI cells with parameters, previous-output
  interpolation, per-cell timeouts, output caps, secret redaction, audit
  records and JSON run history.
- Added `z notebook create|list|show|validate|run|runs|export`; AI cells run
  through the model router and honour budgets, while `--no-ai` fails them
  explicitly. Markdown/HTML exports include executed outputs.
- Added unit tests and a CLI integration test (parameterized shell + markdown,
  export, audit verification).

### Web observer
- Added `z-web` and `z web serve`: loopback-only HTTP observer with separate
  read and write tokens, session list, plain-text screen snapshots, optional
  input and an embedded no-ANSI page. Tokens are written to a `0600` file;
  non-loopback binds are refused. Tests cover auth scopes, snapshots and input.
- Not a full terminal renderer: no xterm.js/colors, WebSocket/SSE streaming or
  TLS; documented as an observer.

### Remote SSH and notifications
- Added `z-remote`: validated SSH destinations, system-OpenSSH execution,
  interactive remote shells as daemon-owned sessions, scp upload/download and
  detached local port forwarding. Host-key verification is always strict;
  dangerous extra options (`ProxyCommand`, `StrictHostKeyChecking=no`, …) are
  rejected. Tests use fake OpenSSH binaries and a CLI integration test.
- TUI OSC 9 notifications now show a footer banner and per-tab unread/failed
  badges; optional desktop notifications use `notify-send`/`osascript`.
- Accessibility: high-contrast palette, reduced-motion busy indicator, and
  ANSI-free `--plain` session/block output for screen readers and scripts.

### Model router and budgets
- Added `z-models`: built-in provider registry (Ollama, OpenAI, Anthropic,
  Gemini, OpenRouter, Groq, custom endpoints), model-reference resolution and
  policy routing (manual/local-only/local-first/cost/latency/quality).
- Added a durable daily usage ledger with hard pre-call reservations,
  per-agent budgets, per-session/task accounting and atomic, locked writes.
- Added ordered fallback, retries with jitter, persisted circuit breakers and
  an in-process response cache that refuses to cache prompts with detected
  secrets.
- Added OpenAI-compatible and Anthropic transports; credentials are read from
  the configured environment variable and never logged.
- Added `z models list|route|ask|usage|doctor` and an end-to-end mock-provider
  CLI test proving completion, costing and usage recording.

### Daemon-owned agents and approvals
- Moved the agent supervisor into the session daemon: `z agent run --detach`
  keeps running after the CLI exits; `z agent list/dashboard` reports live
  state; `z agent stop` terminates a run.
- Added `agent.start/list/get/input/queue/stop/resume/fork` JSON-RPC methods
  and streaming output polling.
- Added a TUI approval inbox (`Alt+A`) that lists pending requests with
  action/resource/risk/expiry and approves/denies with an audit event.

### Agents and MCP
- Added `z-agents`: adapter manifests for Claude Code, Codex, Gemini CLI,
  OpenCode, Aider and custom agents, built-in profiles, PTY supervisor with
  status/queue/trace/resume, approval broker with single-use tokens and audit,
  and a local MCP server exposing policy-gated filesystem/process tools.
- Added agent policy actions to `z-policy` (tool call, fs read/write/delete,
  exec, shell, network, secret read); deny by default.
- `z agent` now provides adapters/profiles/list/dashboard/run/resume/fork/
  approvals/approve/deny/trace; `z mcp serve` is the brokered MCP proxy.

### Fixes
- Fixed z-blocks compile errors and two recorder/store test failures.
- Fixed bash integration to pass `--rcfile` as a separate argument.
- Restored SIGPIPE defaults so piping into `head` does not panic.
- Added 51 end-to-end CLI tests including sessions, context, checkpoints,
  workflows and security scope blocking.
- Added [Implementation status](docs/IMPLEMENTATION-STATUS.md) with explicit
  partial and unimplemented areas.

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
