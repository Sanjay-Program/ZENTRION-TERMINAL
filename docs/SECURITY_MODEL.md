# Security Model

This repository has two security layers in practice today:

1. The Phase 1 policy/capability/audit broker used for command execution.
2. The Phase 3 native engine/reporting surfaces used for findings and scans.

## Core principles

- Deny by default.
- Never invoke a shell when structured execution is available.
- Verify artifacts before use.
- Keep audit trails append-only and hash-chained where implemented.
- Be honest about what is and is not sandboxed.

## Current controls

- Policy parsing is strict.
- Tool execution requires policy allowance.
- Capability grants are scoped and short-lived in the execution path.
- Archive extraction refuses traversal and unsafe entries.
- Checksums are verified before install or activation.
- Tool installs are separated from tool execution permission.

## Not yet implemented here

- A true OS-level sandbox.
- Platform signing and notarization.
- Network packet filtering for tool execution.
- A complete secrets vault.

## Practical user guidance

Treat the repository as secure-by-design in the implemented paths, but do not
assume features are production-trusted until signing and platform installers
exist for the target OS.
