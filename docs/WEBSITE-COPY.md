# Website Copy

## Hero

ZENTRION TERMINAL is a native cross-platform secure runtime for developer, security,
networking and AI workflows.

## Subheading

Install one lightweight terminal runtime and use unified tools across Windows, macOS and
Linux without WSL, Docker, a VM or a separate Kali install.

## Value propositions

- Native execution, not shell-based compatibility tricks.
- Policy, capability and audit controls built into the runtime.
- Tool compatibility is explicit and honest across OS and architecture.
- Local-first by default, with cloud features optional.
- Small base install; add tool packs only when needed.

## Suggested call to action

Download ZENTRION TERMINAL

Company website: zentriontechnologies.com

## Download Cards

Linux x86_64:

- File: `zentrion-linux-x64.tar.gz`
- SHA-256: `625c8711a80e6d01fe2542be5ab09cd0e10e9093761552c8a9837d01633699ca`
- Install: `sha256sum -c zentrion-linux-x64.tar.gz.sha256 && tar -xzf zentrion-linux-x64.tar.gz`

macOS Universal:

- File: `zentrion-macos-universal.tar.gz`
- SHA-256: `938179d18b0793d47fdb0f00b5b544f64c7761ac6872f85057acd3086bb98b90`
- Install: `shasum -a 256 -c zentrion-macos-universal.tar.gz.sha256 && tar -xzf zentrion-macos-universal.tar.gz`

Windows x64:

- File: `Zentrion-Windows-x64.msi`
- SHA-256: `e8b7b7fa115bdbb549cce67f94b5affd3be80c7862938c96d78525df618ae40d`
- Install: verify with `Get-FileHash`, then run `msiexec.exe /i Zentrion-Windows-x64.msi /qb`

Machine-readable release manifest: `releases/releases.json`.

## Product Pillars

- Developer terminal: projects, policies, native engines, SDK and daemon.
- Cybersecurity platform: curated Kali-style bundles, scans, findings, reports and audit.
- AI agent runtime: profiles, handoffs, guardrails, traces and controlled tool access.
- Multi-provider AI: local Ollama/Qwen, OpenAI, Qwen/DashScope and OpenAI-compatible endpoints.
- Secure automation: every host effect routes through identity, policy, capability and audit.

## First Run Copy

```sh
z doctor
z setup
z storage show
z status
z bundle list
z bundle plan devsecops
z ui
```

## AI Provider Copy

Use local models by default:

```sh
export ZENTRION_AI_PROVIDER=ollama
export ZENTRION_AI_MODEL=qwen2.5-coder:7b
```

Connect external APIs when needed:

```sh
export ZENTRION_AI_PROVIDER=qwen
export DASHSCOPE_API_KEY="sk-..."
```

Or point Zentrion at any OpenAI-compatible endpoint:

```sh
export ZENTRION_AI_PROVIDER=openai-compatible
export ZENTRION_AI_BASE_URL=http://127.0.0.1:8080/v1
```

## Suggested technical notes

- Works offline for basic runtime commands.
- Supports per-user install and uninstall.
- Verifies artifacts with checksums and a transactional install pipeline.
- Emits machine-readable JSON for automation and CI.
- Agent/tool actions remain policy-bound even when using external AI providers.
- Preserves user data across upgrades, binary deletion and normal uninstall.
