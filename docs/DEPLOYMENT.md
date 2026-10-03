# Deployment

Zentrion is designed to be transferred as a small, signed or checksum-verified
archive plus a per-user install. The same artifact can be used from GitHub
releases, a company download page, or an internal software catalog.

## What ships

- one `z` binary
- release metadata in JSON
- a checksum file for offline verification
- user-facing installation and quickstart docs

## Recommended release flow

1. Build a release archive with `scripts/package.sh`.
2. Publish the archive, checksum and JSON metadata together.
3. Let users verify the checksum before install.
4. Install per-user with `scripts/install.sh --archive <file> --sha256 <hash>`.

## What is deliberately not required

- root or administrator access
- WSL, Docker, Podman, VMware, VirtualBox or a Linux VM
- a separate package manager for the core runtime
- a cloud account for basic local use

## Website copy

Short version suitable for a product page:

> Zentrion is a native cross-platform secure runtime for developer, security,
> networking and AI workflows. It ships as a lightweight per-user install, runs
> on Windows, macOS and Linux, and keeps policy, capabilities and audit trails
> local by default.
