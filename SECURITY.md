# Security Policy

## Reporting

Report vulnerabilities privately to the maintainers. Do not open a public issue
with exploit details before a fix is available.

Include:
- affected version/commit,
- reproduction steps,
- impact,
- whether policy, the broker or the terminal renderer is involved.

## Supported versions

Only builds produced from the current `main` with a passing
`cargo test --workspace` are supported for security testing.

## Security properties implemented today

- Deny-by-default policy evaluated before execution.
- Capability issuance and audit (SHA-256 hash chain).
- Brokered children receive `no_new_privs`, non-dumpable, `PDEATHSIG`,
  `RLIMIT_CORE=0`, bounded CPU time and `umask 077`.
- Secrets are AES-256-GCM encrypted with a per-install key file (`0600`).
- AI provider requests are redacted before leaving the machine.
- P2P chat uses AES-256-GCM with a stretched shared passphrase, framed
  messages, idle timeouts and basic replay-age checks.
- Updates verify SHA-256 and replace binaries atomically on Unix.
- Installers build from source and verify the installed `z --version`.

## Known limitations

- No Landlock/seccomp/filesystem/network confinement for brokered children.
  `z platform` reports `resource-limits`.
- Update manifests are checksummed but not signed; code signing is absent.
- Plugins are validated, not executed.
- The IPC daemon is loopback-only; shared-token auth is optional
  (`ZENTRION_DAEMON_TOKEN`). Any local process that can read the token can
  issue requests.
- Cloud and enterprise integrations talk only to endpoints you configure; no
  hosted service is provided.

## Verification

Verify release archive checksums before installing. Checksums provide
integrity, not publisher authenticity.
