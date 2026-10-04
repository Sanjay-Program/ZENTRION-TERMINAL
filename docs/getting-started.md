# Getting Started

Zentrion is a native cross-platform terminal and runtime.

## Install

Download the artifact for your platform from
[`../releases/DOWNLOAD_GUIDE.md`](../releases/DOWNLOAD_GUIDE.md), verify the
SHA-256 checksum, then run:

```sh
z doctor
z version
z status
```

`z doctor` is offline and does not need an account.

## First 10 Minutes

```sh
# 1. Check the machine
z doctor
z status

# 2. Create or enter a project
z init my-project
cd my-project

# 3. Explore curated tools
z bundle list
z bundle plan kali-top10
z bundle plan devsecops

# 4. Preview and install one tool after review
z info nmap
z install nmap --dry-run
z install nmap --approve

# 5. Run through the broker
z run nmap -- --version

# 6. Open the dashboard
z ui
```

## AI Setup

Local Qwen/Ollama:

```sh
ollama pull qwen2.5-coder:7b
export ZENTRION_AI_PROVIDER=ollama
export ZENTRION_AI_BASE_URL=http://localhost:11434
export ZENTRION_AI_MODEL=qwen2.5-coder:7b
```

Qwen/DashScope-compatible API:

```sh
export ZENTRION_AI_PROVIDER=qwen
export DASHSCOPE_API_KEY="sk-..."
export ZENTRION_AI_MODEL=qwen3-coder-plus
```

Custom OpenAI-compatible endpoint:

```sh
export ZENTRION_AI_PROVIDER=openai-compatible
export ZENTRION_AI_BASE_URL=http://127.0.0.1:8080/v1
export ZENTRION_AI_API_KEY=local
```

## Daily Commands

| Goal | Command |
|---|---|
| Check health | `z doctor` |
| See policy/runtime state | `z status` |
| Find tools | `z search <term>` |
| Browse bundles | `z bundle list` |
| Preview a lab | `z bundle plan security-lab` |
| Run a brokered command | `z run <program> -- <args>` |
| Scan a project | `z scan .` |
| Open dashboard | `z ui` |

## Related docs

- [Terminal](terminal.md)
- [CLI](cli.md)
- [Installation](INSTALLATION.md)
- [AI](ai.md)
- [Agents](agents.md)
- [Tools](tools/README.md)
- [Release readiness](RELEASE_READINESS.md)
