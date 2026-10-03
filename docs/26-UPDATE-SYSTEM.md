# 26 — UPDATE SYSTEM

## 26.1 Flow

```
release → build (reproducible) → sign (minisign) → publish (CDN)
   → client downloads manifest → verify signature + hashes
   → stage → health check → activate → (auto-rollback on failure)
```

## 26.2 What gets updated

| Artefact | Channel | Verification |
|---|---|---|
| zentrion core binary | stable / beta | minisign sig + sha256 + Authenticode/notarization |
| tools | on install/update | publisher sig + checksum |
| plugins | on install/update | publisher sig + checksum; permission diff → consent |
| models | manual download | size+hash published alongside model card |
| security policies (built-in defaults) | stable | signed; never auto-tightens without release note |
| revocation lists (bad checksums) | frequent | registry signature |

## 26.3 Update policy
- No auto-update by default; `z update --check` notifies, `z update` applies.
- Distro-managed installs defer to the package manager (detected).
- Updates are staged: current version kept; activation on next start after health check (`z doctor --quick`); failure → automatic rollback, audit event.

## 26.4 Rollback
`versions/` keeps last 3 releases. `z update rollback` restores previous,
verified against recorded hashes.

## 26.5 Release integrity requirements
- Releases built by CI from a tagged commit; provenance (commit + workflow) recorded in the manifest.
- Checksums published out-of-band (GitHub release page) in addition to the signed manifest, so registry compromise alone can't undetectably swap artifacts.
