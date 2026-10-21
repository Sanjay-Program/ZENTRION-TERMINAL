# Implementation status

**Updated:** 2026-10-20  
**Companion to:** [Implementation Blueprint](IMPLEMENTATION-BLUEPRINT.md) and
[Competitive Roadmap](COMPETITIVE-ROADMAP.md)

This page reports what the current tree actually does. It is deliberately
conservative: a feature is **implemented** only when code is wired into `z` and
covered by tests; design text is never treated as shipped.

Legend: **implemented** · **partial** (working with a stated limit) ·
**not started**.

---

## 1. Subsystems

| Area | Status | Where | Evidence / limits |
|---|---|---|---|
| VT parsing, OSC policy, screen, search, selections, link detection | implemented | `z-vt` | Golden unit tests for OSC 133/7/9/9;4/52/1337, search, selections, link schemes. No execution from output. |
| Command blocks, SQLite/WAL store, FTS5, gzip output, redaction, sharing | implemented | `z-blocks` | Recorder state-machine tests, store round-trip, tamper detection, secret redaction tests. |
| PTY sessions, Unix socket daemon, JSON-RPC + binary frames, attach/detach, replay, block sink | implemented (Unix) | `z-session` | End-to-end daemon test; CLI integration test creates a bash session and asserts blocks/replay. Windows named pipe is not implemented. |
| Shell integration scripts (bash, zsh, fish, pwsh, nushell) | partial | `z-session/src/integration.rs` | Bash is exercised end-to-end. The other four scripts are generated and validated by manifest tests but the shells were unavailable in this environment. Bash compound/pipeline command text is best-effort because bash's DEBUG trap reports simple commands. |
| Workspaces, YAML layouts, restore policies | implemented | `z-session/src/workspace.rs` | Blueprint example parses; unit tests for validation and restore plans; `z workspace restore` spawns shells and only auto-runs commands with `auto_run`/`--approve`. Agent panes are reported, not auto-started. |
| Layered config, keybindings, profiles, importers | implemented | `z-config` | 21 unit tests: precedence, strict unknown-key errors with line numbers, atomic writes, backup, Windows Terminal/Ghostty/iTerm2 import. The TUI now dispatches bound F-key/Alt actions through this keymap; actions without a TUI implementation (copy mode, agent dashboard, workspace actions) still fall through. |
| Repository index, symbols, deterministic context packs | implemented | `z-context` | SQLite FTS5, git-aware walking, secret/binary exclusions, incremental reindex, budgeted packs, redaction. Symbols are lexer-level, not tree-sitter; embeddings are not implemented. |
| Content-addressed checkpoints, diff, rollback, GC | implemented | `z-checkpoint` | Blob dedupe, signed manifests (Ed25519), diff hunks, byte-verified full/file restore, deletion of added files, workspace lock, GC. Hunk-level *accept* is not implemented (view hunks, accept/restore per file). |
| Workflows (run/approve/parallel/if/http/artifact), vars, secrets, audit | implemented | `z-workflow` | 20 tests including timeout kill, denied approval, parallel, artifact traversal, audit records. No scheduler/daemon yet. |
| Notebooks (shell/markdown/AI cells, params, runs, exports) | implemented | `z-notebook` | 7 unit tests plus a CLI integration test: ordered cells, `${param}`/previous-output interpolation, timeouts, output caps, secret redaction, audit records, JSON run history and markdown/HTML export. AI cells use the model router; `--no-ai` fails them explicitly. No scheduling or collaborative editing. |
| Security engagements, scope guard, evidence chain, findings, signed reports | implemented | `z-security` | 21 tests: wildcard/CIDR/ports/out-of-scope, break-glass, pre-execution blocking, Ed25519 evidence chain, tamper detection, signed markdown/HTML. It does not bundle scanners; it governs commands you run. |
| Agent adapters, profiles, approval broker, supervisor, MCP server | implemented (daemon-owned) | `z-agents`, `z-session` | 21 unit tests plus a CLI integration test: the session daemon owns agent PTYs, so `z agent run --detach` survives CLI exit and `z agent list` reports live state. Approvals are single-use, audited, and can be resolved from the CLI or the TUI approval inbox (`Alt+A`). |
| TUI approval inbox | implemented | `tui` | `Alt+A` lists pending broker requests with action/resource/risk/expiry; `a`/`d` approve or deny and write the audit log. |
| Agent policy actions | implemented | `z-policy` | `agent.tool.call`, `agent.fs.*`, `agent.exec`, `agent.shell`, `agent.net`, `agent.secret.read`; deny by default. |
| TUI blocks, global search, rerun, OSC 9;4 progress | implemented (session-local + persisted search) | `tui` | Shell integration and blocks are wired into TUI sessions; `F11` searches both the live session and the persisted SQLite block store and can rerun a command. A full approval modal is still CLI-only. |
| Copy mode, vi motions, OSC 52 clipboard | implemented (line-based) | `tui/src/copy.rs` | Six unit tests for motions, inclusive Unicode-safe selections and search/wrap. `F12` opens copy mode, `v` selects, `y` yanks via OSC 52. Rectangular block selection is not implemented. |
| Hyperlink confirmation | implemented (copy mode) | `tui` | `o` detects a safe http/https/mailto link on the cursor line, shows the exact target, and opens it only on Enter/y using the OS opener. No auto-open and no shell. File links are detected by `z-vt` but are not opened from the TUI yet. |
| Desktop notifications, tab badges | implemented (optional desktop integration) | `tui` | OSC 9 shows a footer banner and a per-tab unread/failed badge; `ui.desktop_notifications = true` invokes `notify-send` (Linux) or `osascript` (macOS). No sound, focus detection or per-approval badges yet. |
| GPU renderer | not started | — | `z ui` remains ratatui; `ui.gpu` is a config field only. |
| Remote SSH execution, shells, transfers, forwarding | partial | `z-remote` | 12 unit tests plus a fake-OpenSSH CLI test. Strict host-key verification is always on; jump hosts, identity, port, scp upload/download and detached local port forwards are implemented. Remote shells run as daemon-owned command sessions. **Not implemented:** native SSH (uses system OpenSSH), durable remote daemons/sessions, SFTP protocol, web client. |
| Web observer / sharing | partial | `z-web`, `z web serve` | Loopback-only HTTP server with separate read-only and optional write tokens, session list, plain-text screen snapshots (500 ms polling), optional input and an embedded no-ANSI page. 2 unit tests plus an end-to-end CLI test. **Not implemented:** xterm.js/colors/cursor fidelity, WebSocket/SSE streaming, TLS, multi-user/RBAC/IPv6+proxy deployment. |
| Team sync, SSO/SCIM/RBAC, fleet policy | not started | — | Existing enterprise stubs are unrelated to the blueprint control plane. |
| wasm plugin host | implemented | `plugin` | 8 unit tests. wasmtime host with a tiny host ABI (`log`, `clock`, `kv:read`, `kv:write`), fuel and linear-memory limits, no filesystem/network/process/secret imports, persisted per-plugin KV and audit records. Unknown imports fail instantiation. |
| Model router (registry, cost/latency/quality/local-first, budgets, fallback, cache) | implemented | `z-models` | 24 unit tests plus an end-to-end mock-provider CLI test. Durable daily ledger with hard reservations, per-agent budgets, retries/fallback, persisted circuit breakers, prompt credential redaction before transport and secret-safe response caching. No streaming/cancellation or embeddings yet; the cache is process-local. |
| Landlock/seccomp/cgroup/network namespace | not started | — | Existing hardening is privilege/rlimit based. |
| Audit ledger Ed25519 signing | implemented (opt-in) | `z-audit`, `z audit key` | Hash chain unchanged (signature excluded). `z audit key` creates a local Ed25519 key; subsequent events carry `signature`/`signer`. `z audit verify` checks both the chain and signatures, reports missing keys and fails on a bad signature. Unsigned legacy logs still verify as unsigned. |
| Native DNS records | implemented | `z-native::dns` | Built-in wire-protocol client for A/AAAA/CNAME/MX/TXT/NS/SOA/PTR: UDP with TCP fallback on truncation, resolv.conf nameservers, compression-pointer loop/bounds checks, 10 offline packet/parser tests plus a local UDP end-to-end test. |
| Package hashing and extraction | implemented | `z-package` | Streaming SHA-256/SHA-512 (no size cap) and a two-phase, bounds-checked extractor for tar, tar.gz, tar.zst and zip (stored + deflate, CRC-32 verified). Zip refuses traversal, symlinks, encryption, multi-disk and ZIP64 instead of guessing. 54 crate tests. |
| Accessibility | partial | `tui`, CLI | `ui.high_contrast` uses a high-contrast palette; `ui.reduced_motion` suppresses the busy spinner; `z session replay --plain` and `z blocks show --plain` emit ANSI-free text; keyboard navigation exists. No semantic screen-reader mode or focus announcements. |
| i18n / RTL | not started | — | UI strings are English-only; no translation catalog or RTL layout. |
| Performance benchmarks (vtebench, DOOM-fire, 100k search) | not started | — | No benchmark harness or CI gate; no figures are claimed. |

---

## 2. Command surface added in this pass

```text
z session   list|create|attach|replay|blocks|input|resize|signal|close|status|stop|daemon
z workspace list|show|save|delete|restore [--dry-run|--approve|--restore policy]
z blocks    list|search|show|stats|verify|export|import|gc
z context   index|search|pack|symbols|status|clear
z checkpoint create|list|show|diff|restore|sign|verify|gc
z workflow  validate|run|list|show
z engagement create|list|show|scope-check|run|evidence|note|verify|finding|findings|report
z models    list|route|ask|usage|doctor
z remote    hosts|exec|shell|upload|download|forward|forwards|stop-forward|hostkey|doctor
z web       serve [--allow-input] [--bind 127.0.0.1:0] [--token-file PATH]
z notebook  create|list|show|validate|run|runs|export
z agent     adapters|profiles|list|dashboard|run|resume|fork|stop|approvals|approve|deny|trace
z mcp       serve --agent <id> --profile <profile> --workspace <dir>
z config    show|validate|paths|import|actions|keys|edit|init  (legacy get/set/secrets retained)
z plugin    load|inspect|list|run|capabilities
z audit     tail|verify|key
z ui        terminal with shell-integration blocks and F11 block/search overlay
```

All destructive or agentic paths are deny-by-default and audited:

- `z engagement run` checks scope **before** spawning the command; out-of-scope
  attempts are appended to the evidence chain as `denied` records.
- Workflow shell/agent steps produce audit events; approvals are explicit;
  HTTP requires `allow_http` plus a host allowlist.
- MCP tools run under an agent profile; write/delete/exec can require an
  approval that a separate `z agent approve <id>` process grants.
- Model calls reserve the maximum possible cost before contacting a provider;
  a hard budget rejection happens before network I/O and is audited.
- Checkpoint restore refuses a manifest whose Ed25519 signature is invalid.

---

## 3. Known limitations (not marketing copy)

1. **TUI keybindings are only partly rebindable.** Bound F-key and Alt+
   actions now dispatch through the loaded keymap (palette, tabs, panes,
   editor, copilot, monitor, chat, blocks/search, copy mode, quit, tab
   select/next/prev, pane next). Actions with no TUI implementation — agent
   dashboard, workspace save/open, font scaling — fall through or do nothing,
   so the “every action rebindable” criterion is not fully met.
2. **The TUI agent dashboard is still static.** Agents now run in the session
   daemon and the TUI has a working approval inbox, but the `Agents` dashboard
   page does not yet poll live runs. Use `z agent dashboard` for the live table.
3. **State detection is approximate.** Adapter manifests support `hooks` and
   `jsonl` modes, but the current detector only evaluates screen patterns for
   all modes; the UI labels this as approximate. Do not treat `waiting_input`
   as exact.
4. **Bash command capture is incomplete for compound commands** (pipelines,
   loops) because bash exposes only the currently executing simple command to
   its DEBUG trap. zsh/fish hooks are better but were not runnable here.
5. **Model streaming is not implemented.** `z models ask` waits for the full
   response; there is no token stream or cancellation. Response caching is
   process-local, embeddings are not implemented, and the built-in price table
   is static and should be verified against provider pricing.
6. **No scrollback persistence for raw session output.** Blocks are persisted
   to SQLite; a daemon restart loses the live screen and raw ring buffer.
7. **Checkpoint/hunk workflow is file-level.** Hunk diffs are displayed, but
   there is no “accept only this hunk” operation yet.
8. **Windows support is not complete.** The session daemon/client are Unix
   socket-only; the Windows named-pipe transport from the blueprint is absent.
9. **Security convenience is deliberate, not a scanner.** Target extraction
   from commands only recognizes URLs and IP literals; pass `--target` for
   hostnames. Break-glass is local and audited, not multi-party.
10. **Signing is local-key signing, and it is opt-in.** `z audit key` enables
    signatures for future events; it detects tampering by someone without the
    key, but a local attacker who can read the key can re-sign (both the audit
    key and checkpoint/evidence keys are stored `0600`). Logs created before a
    key exists remain unsigned and `z audit verify` says so.
11. **No claim of performance.** No benchmarks were run for this pass, so the
    blueprint's latency/FPS/RAM targets remain unverified.

---

## 4. Verification performed

```sh
cargo test --workspace       # all crate unit tests + workspace integration tests
cargo test -p z-integration-tests --test cli_integration
```

The CLI integration suite now covers config validation/import, context
indexing and packs, checkpoint rollback, workflow approval/parallel/audit,
security scope blocking, and a real bash session with block replay. Shell
integration for bash is additionally covered by
`z-session/tests/shell_integration.rs`.

Manual smoke checks during development also exercised `z mcp serve` with a
real JSON-RPC handshake and `z agent run` with a local adapter.

---

## 5. Recommended next work (highest leverage first)

1. TUI keybinding dispatch through `z-config::Keymap` for every action.
2. Agent supervisor inside the session daemon + TUI approval dashboard.
3. Copy mode and persisted FTS block search in the TUI.
4. Daemon-owned scrollback persistence and Windows transport.
5. Hunk-level checkpoint accept/reject.
6. Benchmark harness and CI regression gate.
7. TLS inspection backend (the native TLS module still reports `Unsupported`
   rather than fabricating a certificate chain) and an xterm.js/WebSocket web
   observer.
8. SSH domains, web observer tokens and the enterprise control plane.
