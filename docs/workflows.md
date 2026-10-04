# Workflows

Workflows are the human-friendly layer over tools, projects, security, AI and
storage. They do not bypass policy; they help users find the right safe command
sequence for their role.

## Profiles

```sh
z profile list
z profile show developer
z profile apply ai-developer
z profile apply cybersecurity
z profile apply everything
```

Available profiles:

| Profile | Use when |
|---|---|
| `developer` | Build, test, run and inspect projects |
| `ai-developer` | Use local/API models and safe agents |
| `cybersecurity` | Run authorized assessment, findings and audit workflows |
| `devsecops` | SAST, secret scanning, SBOM and dependency review |
| `cloud` | Policy-first cloud, IaC and configuration review |
| `student` | Learn terminal, AI and security basics safely |
| `everything` | Full Zentrion command-center mode |

`z profile apply <name>` initializes durable storage and prints the commands
that profile should start with. It does not install tools or grant permissions
without further review.

## Daily Command Palette

```sh
z commands storage
z commands ai
z commands scan
z docs terminal
z ui
```

The interactive UI has profile, AI, tools, security, storage and docs views for
users who do not want to memorize commands.

## Related docs

- [CLI](cli.md)
- [Tools](tools.md)
- [Terminal](terminal.md)
- [Storage](STORAGE.md)
