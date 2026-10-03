# Release Readiness

## Installation

Zentrion currently ships as a Rust-built desktop/runtime toolchain with a
per-user installer script and a portable release archive. The release archive
contains the `z` binary, installation notes, quickstart notes, a checksum file
and JSON metadata.

## Platforms

Current tested platform coverage is honest and limited to what has been run in
this environment. See [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md).

## Architectures

Supported and tested claims are tied to the actual build/test matrix. The code
is written to distinguish OS, architecture and ABI, but only the exercised
targets should be treated as stable.

## Download channels

- GitHub Releases: planned release channel
- Company website: planned download entry point
- Local release archive: implemented by `scripts/package.sh`

## Installer status

- Per-user shell installer: implemented
- Portable tarball: implemented for Linux host packaging
- Windows GUI installer: planned
- macOS DMG installer: planned
- Linux native packages: planned

## CLI status

- `z version`: implemented
- `z doctor`: implemented
- `z update`: implemented for the current tool/runtime surface
- `z uninstall`: implemented at the tool/runtime level and via scripts
- `z config`: implemented
- `z project`: implemented
- `z tools`: implemented
- `z security`: implemented as a native engine/reporting surface
- `z ai`: implemented as a Phase 3 surface
- `z agent`: implemented as a command surface
- `z workflow`: planned as a higher-level composition layer
- `z ssh`: planned as a higher-level composition layer
- `z git`: planned as a higher-level composition layer
- `z docs`: planned for the app UI; documentation exists in-repo now

## Documentation status

The repository already contains detailed implementation reports and user docs.
The new release documents in this phase are the first attempt at a concise
public-facing navigation layer.

## Tool manager status

Tool install, verify, update, rollback and remove are implemented. Tool
compatibility is explicit and trust is not conflated with installation.

## Security status

Policy, capability, audit, checksum validation, archive extraction safety and
release artifact verification are implemented. Code signing, notarization and
platform package signing are not yet implemented in this repository.

## AI status

AI command surfaces and summaries exist, but provider integration, secret
storage and higher-level conversation handling are still incomplete.

## Testing

Validated in this workspace:

- `cargo test --workspace`
- `scripts/package.sh`
- install-from-archive smoke test

## Known limitations

- Windows/macOS installer artifacts are not yet built here.
- Code signing/notarization is not yet present.
- Website download pages are not implemented in this repository.
- The docs UI is not yet a shipped application feature.

## Known issues

- Release automation currently stops at packaged artifacts and GitHub upload
  placeholders.
- Public website metadata still needs a downstream consumer.

## Release checklist

- [x] package tarball
- [x] checksum file
- [x] JSON metadata
- [x] install smoke test
- [x] workspace tests
- [ ] signed artifacts
- [ ] Windows installer
- [ ] macOS installer
- [ ] Linux native package
- [ ] website download page
- [ ] documentation UI
