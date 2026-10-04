# Terminal

This page describes the normal shell-first experience.

## What this is

Zentrion should open to a usable terminal immediately. The shell remains the
shell; Zentrion commands are additive.

## Useful commands

- `z doctor`
- `z version`
- `z status`
- `z setup`
- `z storage show`
- `z profile list`
- `z bundle list`
- `z bundle plan web`
- `z search scanner`
- `z scan <target>`
- `z ai <args>`
- `z docs`
- `z ui`

## Interactive UI

`z ui` opens the terminal dashboard. It is still shell-first: the UI shows the
same primitives the CLI uses instead of inventing a separate control plane.

Views:

| View | Shows |
|---|---|
| Home | Runtime posture, broker status, policy and audit signals |
| Workflows | Developer, AI, security, DevSecOps, cloud, student and everything profiles |
| Tools | Curated Kali-style, web, recon, DevSecOps and lab bundles |
| Agents | Profiles, handoffs, tool allowlists and guardrails |
| AI | Local/API provider setup including Ollama, Qwen, OpenAI and compatible endpoints |
| Security | Policy, scan, findings, reports and audit commands |
| Storage | Durable data paths and retention policy |
| Docs | The documentation pages that explain each subsystem |

Keyboard:

- `Tab` switches views.
- `1` through `8` jump to a view.
- `/` opens the workflow command map.
- `q` exits.

## Adaptable Profiles

```sh
z profile list
z profile show developer
z profile apply everything
```

Profiles are recommendations, not privilege grants. They help normal users get
to useful commands faster while the runtime still enforces policy and audit.
