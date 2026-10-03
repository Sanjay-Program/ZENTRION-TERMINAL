# 24 — SECRETS

## 24.1 Requirements
- No plaintext secrets on disk by default.
- OS secure storage: Windows Credential Manager/DPAPI, macOS Keychain, Linux Secret Service (gnome-keyring/KWallet). Fallback when none available: encrypted file (age-style, key from passphrase) with a **loud warning** — never silently.
- Environment integration: opt-in injection of specific secrets into a process env (`z run --env SECRET_NAME`), documented risk.
- Detection: `z secrets detect` scans files for accidental committed secrets (regex + entropy, best-effort).
- Redaction: hard-coded scrubber in logs/audit/errors/AI context; cannot be disabled.
- Rotation support: `z secrets rotate <name>` marks old value for grace-period invalidation, tracks usage.
- Audit: every read/write logged (handle name only, never value).
- Least privilege: `secret.read` capability per handle; AI models never receive secret values unless a specific handle is explicitly allowed in policy (default: never).

## 24.2 Commands
```
z secrets set db_password          # prompts for value, stores in keyring
z secrets list                     # names + metadata only
z secrets get db_password          # requires approval per risk; prints to terminal only
z secrets delete db_password
z secrets rotate db_password
z secrets detect ./                # scan for leaks
```

## 24.3 Project file
`secrets.yaml` contains **only handles and metadata** (never values):
```yaml
secrets:
  - name: db_password
    scope: project
    created: 2026-10-03
    rotation: 90d
    allowed_to_ai: false
```

## 24.4 Threat notes
- Secret values live only in keyring and, transiently, in process memory of the requesting process.
- Memory scraping by local malware is out of scope (documented limitation); the defense is that secrets are not persisted in plaintext anywhere Zentrion controls.
