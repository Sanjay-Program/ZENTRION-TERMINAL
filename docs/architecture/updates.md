# Updates Architecture

## Implemented flow

1. `ZENTRION_UPDATE_MANIFEST` points at a JSON manifest (local path, `file://`
   or HTTPS URL):
   ```json
   {"version":"1.2.0","url":"https://…/z","sha256":"<64 hex>","notes":"…"}
   ```
2. The engine compares the manifest version with the running version.
3. It downloads the artifact (HTTP(S) or local path), caps it at 200 MiB and
   verifies SHA-256 against the manifest.
4. On Unix it saves the current binary as `<exe>.old`, then atomically renames
   the staged binary into place and sets mode `0755`.
5. `z upgrade rollback` restores `<exe>.old`.

Plain HTTP is refused unless `ZENTRION_ALLOW_INSECURE_UPDATE=1`.

## Trust model

The SHA-256 digest protects against corrupt downloads. HTTPS protects the
manifest in transit. Manifests are **not signed yet**, so a compromised update
host remains in the trust path. Code signing and notarization are future work.

## Windows

Windows cannot replace a running executable. The verified artifact is staged as
`<exe>.new` for the installer to apply after the process exits; in-place
rollback is not supported there.
