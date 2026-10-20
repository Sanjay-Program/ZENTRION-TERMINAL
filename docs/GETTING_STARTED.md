# Getting Started with ZENTRION TERMINAL

ZENTRION TERMINAL is a shell-first terminal for development, AI-assisted work
and authorized security testing. This guide gets you from zero to a working
terminal in a few minutes.

## 1. What makes it different?

A normal terminal emulator shows you a shell. ZENTRION adds a local control
plane around that shell:

- **Real terminal panes.** Tabs and splits, each with a live PTY and scrollback.
- **Policy-brokered execution.** Commands run through identity, policy,
  capability and audit. Dangerous actions are denied until your project policy
  explicitly allows them.
- **A local tool registry.** Verified installs and curated bundles; the OS
  package-manager fallback requires `--os-package`.
- **AI without a fast path.** The copilot can suggest commands, but host
  effects still go through the broker.
- **Local-first by design.** No telemetry, no account, no network calls from
  `z doctor`.

## 2. Install

Build from source:

```sh
git clone https://github.com/zentrion/terminal.git
cd terminal
cargo build --release
install -m 755 target/release/z ~/.local/bin/z
```

Or use the source-building installers in [`releases/`](../releases/README.md).
Linux x64 release archives can be produced with `./scripts/package.sh`.
macOS/Windows release artifacts are not built in this environment — build from
source on those platforms.

## 3. Your first five minutes

```sh
z setup          # create config/data directories
z doctor         # offline health check
z ui             # open the terminal
```

You start in a real shell. Type commands exactly as you would in any terminal.

### Keys

| Key | Action |
|---|---|
| `F2` | Command palette |
| `F3` | Mini IDE (`Ctrl+S` save, `Ctrl+O` open) |
| `F4` | AI copilot |
| `F5` | System monitor |
| `F6` | Encrypted LAN chat |
| `F7` | New tab |
| `F8` | Split pane |
| `F9` | Close pane/tab |
| `F10` | Quit |
| `Alt+V` | Toggle terminal / dashboard |
| `Alt+H` | Dashboard home |
| `Alt+1..9` | Switch tab (or dashboard view) |
| `Alt+O` | Next pane |
| `Shift+PgUp/PgDn` | Scroll terminal history |
| `Tab` / `Shift+Tab` | Next/previous dashboard view |

`Ctrl+P`, `Ctrl+Q`, `Ctrl+D` and friends are **not** stolen from the shell.

## 4. Everyday commands

```sh
z status                    # runtime, project, policy, audit
z code status               # detect the toolchain
z code test                 # run through the broker
z code allow                # explicitly allow the detected toolchain
z security scan .           # credentials + risky code + dependencies
z security posture          # policy + audit + latest scan
z scan .                    # native engine scan
z finding list
z report latest
z network dns example.com --allow
z cloud scan .              # static IaC review
z bundle list
z install nmap
z run nmap --version
```

If a brokered command is denied, the error names the policy field to change.
Inside a project, `z init` creates `.zentrion/` and `z code allow` grants the
detected compiler/test toolchain. Review the generated policy before committing.

## 5. AI setup

```sh
# Local Ollama (default)
export ZENTRION_AI_PROVIDER=ollama
export ZENTRION_AI_MODEL=qwen2.5-coder:7b

# Or OpenAI
export ZENTRION_AI_PROVIDER=openai
export OPENAI_API_KEY="sk-..."
```

Then use `F4` in the UI, or:

```sh
z ai ask "explain this error"
z ai status
z ai auto "plan a safe review of this repository"
```

The gateway redacts credentials and PII before outbound calls. AI output is
advice; it never executes commands.

## 6. LAN chat

```sh
export ZENTRION_P2P_KEY='a long shared passphrase'
z ui   # press F6
```

Share the passphrase out of band. Chat is AES-256-GCM encrypted, peer-to-peer,
with no server or account. Anyone with the passphrase can read and send.

## 7. Where to go next

- [Terminal and UI reference](terminal.md)
- [Security model](SECURITY_MODEL.md)
- [Tools and registry](tools/README.md)
- [Command reference](1000-COMMANDS-REFERENCE.md)
- [Documentation index](DOCUMENTATION_INDEX.md)

---
*Powered by [Zentrion Technologies](https://zentriontechnologies.com).*
