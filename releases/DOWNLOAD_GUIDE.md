# ZENTRION TERMINAL — Download & Installation Guide

## What is published

| Platform | Artifact | Status |
|---|---|---|
| Linux x86_64 | `zentrion-linux-x64.tar.gz` + `.sha256` | included; rebuild with `scripts/package.sh` |
| macOS | source build | not built here |
| Windows | source build | not built here |

The repository intentionally contains no mislabeled archives or placeholder
installers. Build the platform you need from source.

## Linux x86_64

```sh
# From this directory (releases/)
sha256sum -c zentrion-linux-x64.tar.gz.sha256
tar -xzf zentrion-linux-x64.tar.gz
install -m 755 zentrion-linux-x64/bin/z ~/.local/bin/z

z setup
z doctor
z ui
```

Rebuild from source with `./scripts/package.sh` (writes to `dist/`).

## Linux and macOS from source

```sh
ZENTRION_SOURCE_DIR="$PWD" bash releases/install.sh
```

## Windows 10/11 from source

```powershell
$env:ZENTRION_SOURCE_DIR = "$PWD"
powershell -ExecutionPolicy Bypass -File .\releases\install.ps1
```

Windows requires the Visual Studio C++ Build Tools and Git.

## Checksums

`scripts/package.sh` writes a SHA-256 checksum next to each archive. Verify it
before installing:

```sh
sha256sum -c zentrion-linux-x64.tar.gz.sha256
# or
shasum -a 256 -c zentrion-linux-x64.tar.gz.sha256
```

Checksums provide integrity, not authenticity. Code signing and notarization
are not implemented yet.
