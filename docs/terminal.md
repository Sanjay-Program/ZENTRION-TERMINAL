# Terminal

This page describes the normal shell-first experience.

## What this is

Zentrion should open to a usable terminal immediately. The shell remains the
shell; Zentrion commands are additive.

## Useful commands

- `z doctor`
- `z version`
- `z status`
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
| Ops | Runtime posture, broker status, policy and audit signals |
| Tools | Curated Kali-style, web, recon, DevSecOps and lab bundles |
| Agents | Profiles, handoffs, tool allowlists and guardrails |
| Docs | The documentation pages that explain each subsystem |

Keyboard:

- `Tab` switches views.
- `1` through `4` jump to a view.
- `q` exits.
