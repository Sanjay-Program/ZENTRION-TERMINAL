# Privacy Model

## Local-first default

The implemented runtime is designed to work locally without requiring an
account for basic terminal use.

## What is intentionally local

- Command execution metadata
- Audit events
- Tool install state
- Project scaffolding
- Documentation sources bundled in the repository
- Sessions, command history and agent/project memory
- Scan reports and findings

## Local storage retention

Normal upgrades, binary replacement and uninstall preserve user data. This is
intentional: users should not lose audit logs, installed tools, sessions,
memory or project state because they upgraded or removed the executable.

Inspect paths and retention with:

```sh
z storage show
z storage policy
```

## What is not yet built

- A complete telemetry policy UI
- A cloud AI privacy boundary with provider-specific disclosures
- A centralized user account system

## User expectation

If a future feature transmits data externally, the user must see what is being
sent and why before it leaves the machine.
