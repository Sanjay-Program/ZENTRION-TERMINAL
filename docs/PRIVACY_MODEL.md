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

## What is not yet built

- A complete telemetry policy UI
- A cloud AI privacy boundary with provider-specific disclosures
- A centralized user account system

## User expectation

If a future feature transmits data externally, the user must see what is being
sent and why before it leaves the machine.
