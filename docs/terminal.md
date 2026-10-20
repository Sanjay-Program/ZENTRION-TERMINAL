# Terminal

Zentrion is shell-first: the terminal is the product, and the dashboard is an
optional control surface around it.

## Launch

```sh
z ui
```

Each pane is a real pseudo-terminal running `$SHELL` (or `/bin/sh`). It renders
through a `vt100` screen buffer, so colours, cursor addressing, Unicode,
full-screen TUI programs and resizing work as expected. Scrollback is 10,000
lines per pane.

## Layout

- Header: version, theme, pane count, platform and working directory.
- Tab bar: one entry per tab; the focused pane decides the label.
- One to four panes per tab.
- Footer: the keys for the current mode.

## Keys

Terminals cannot distinguish `Ctrl+Shift+<letter>` from `Ctrl+<letter>`, so
Zentrion uses function keys and Alt combinations instead of stealing ordinary
control keys from your shell.

| Key | Action |
|---|---|
| `F2` | Command palette |
| `F3` | Mini IDE (`Ctrl+S` save, `Ctrl+O` open) |
| `F4` | AI copilot sidebar |
| `F5` | Live system monitor |
| `F6` | LAN chat |
| `F7` | New tab |
| `F8` | Split pane (up to four) |
| `F9` | Close focused pane; closes a one-pane tab if another tab exists |
| `F10` | Quit |
| `Alt+V` | Toggle terminal / last dashboard view |
| `Alt+H` | Dashboard home |
| `Alt+1..9` | Terminal: switch tab. Dashboard: jump to view |
| `Alt+O` | Focus next pane |
| `Alt+←/→` | Previous / next tab |
| `Alt+P` | Cycle beginner/professional/expert hints |
| `Shift+PgUp` / `Shift+PgDn` | Scroll history by ten lines |
| Mouse wheel | Scroll history; forwarded to apps that request mouse events |
| `Shift+Home` / `Shift+End` | Jump to top / bottom |
| `Tab` / `Shift+Tab` | Next / previous dashboard view |
| `1..0` | Jump to a dashboard view (dashboard, chat and research tabs) |
| `Esc` | Leave a dashboard/chat/research view or close an overlay |

Inside the terminal pane, all other keys — including `Ctrl+P`, `Ctrl+Q`,
`Ctrl+D`, `Ctrl+Z`, `Ctrl+C` — are sent to the running program.

## Command palette

`F2` opens the palette. Type either:

- a shell command (`z status`, `git status`, `cargo test`), which runs in the
  focused pane; or
- an internal action:
  - `:new`, `:split`, `:close`
  - `:theme <name>`
  - `:view <terminal|home|workflows|tools|agents|ai|security|storage|docs|research|chat>`
  - `:e <path>` (open in the editor)
  - `:ai <prompt>` (send to the copilot)
  - `:sysmon`, `:chat`, `:quit`

## Dashboard views

| View | Shows |
|---|---|
| Home | Runtime facts and key map |
| Workflows | Commands by role |
| Tools | Registry and bundle commands |
| Agents | Agent profiles and guardrails |
| AI | Provider setup |
| Security | Scan, findings, report and posture commands |
| Storage | Config/data paths and retention |
| Docs | Documentation map |
| Research | Model-synthesized research with saved reports |
| LAN Chat | Encrypted peer-to-peer chat |

## AI copilot

`F4` opens a sidebar. It uses `ZENTRION_AI_PROVIDER` (Ollama by default) and
`ZENTRION_AI_MODEL`. The gateway redacts credential patterns and PII before any
outbound call. The copilot proposes commands; it never executes them for you.

## Research

The Research view asks the configured model for a structured markdown report
and writes it under `<data>/research/`. Web crawling is not enabled, so the
report is model knowledge and should be verified. The prompt explicitly forbids
inventing citations.

## LAN chat

`F6` opens encrypted LAN chat:

- Set `ZENTRION_P2P_KEY` or type a shared passphrase when prompted.
- Peers on the same network announce over UDP 7777 and message over TCP 7778.
- Every announcement and message is AES-256-GCM encrypted with a key derived
  from the shared passphrase.
- There is no server, account or telemetry. Everyone with the passphrase can
  read and send; treat it as a group password.

Port overrides: `ZENTRION_P2P_PORT`, `ZENTRION_P2P_DISCOVERY_PORT`.

## Themes

```sh
z theme list
z theme set dracula
z theme reset
```

Themes: `zentrion`, `cyberpunk`, `dracula`, `gruvbox`, `nord`, `matrix`,
`solarized-dark`. The selection is stored in `config.yaml` and read by the UI
at startup. `ZENTRION_THEME` overrides it for one session.

## System requirements

A POSIX PTY (Linux/macOS) or ConPTY (Windows). If the shell cannot start, the
terminal pane shows the error instead of pretending to work.
