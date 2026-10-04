# Installation

## Download verified release

Use the release manifest and platform guide:

- [`../releases/releases.json`](../releases/releases.json)
- [`../releases/DOWNLOAD_GUIDE.md`](../releases/DOWNLOAD_GUIDE.md)

Current downloadable artifacts:

| Platform | File | SHA-256 |
|---|---|---|
| Linux x86_64 | `zentrion-linux-x64.tar.gz` | `625c8711a80e6d01fe2542be5ab09cd0e10e9093761552c8a9837d01633699ca` |
| macOS universal | `zentrion-macos-universal.tar.gz` | `938179d18b0793d47fdb0f00b5b544f64c7761ac6872f85057acd3086bb98b90` |
| Windows x64 | `Zentrion-Windows-x64.msi` | `e8b7b7fa115bdbb549cce67f94b5affd3be80c7862938c96d78525df618ae40d` |

Verify checksums before installing.

## Build requirements

- Rust 1.75+ (stable), `cargo`
- No system libraries beyond the Rust standard toolchain
- No network access required to build (dependencies are vendored via the
  lockfile once fetched)

## Build

```sh
scripts/build.sh            # debug
scripts/build.sh release    # release
```

Or directly:

```sh
cargo build --workspace --release
# binary at target/release/z
```

## Install (per-user, no root)

```sh
scripts/install.sh                       # installs to ~/.local/bin/z
scripts/install.sh --prefix /opt/zentrion
```

The installer:

- copies only the `z` binary,
- never requires root or administrator privileges,
- does not modify your shell profile (it prints the line to add, if needed),
- optionally verifies an archive checksum with `--sha256 <hash>`,
- does not overwrite or remove existing user storage.

```sh
scripts/install.sh --archive zentrion-linux-x64.tar.gz --sha256 <hash>
```

## Uninstall

```sh
scripts/uninstall.sh
scripts/uninstall.sh --prefix /opt/zentrion
```

User data (configuration, audit log) is deliberately **left in place**. Remove
it manually if you want a full wipe:

- Linux: `~/.config/zentrion`, `~/.local/share/zentrion`, `~/.cache/zentrion`
- macOS: `~/Library/Application Support/Zentrion`, `~/Library/Caches/Zentrion`
- Windows: `%APPDATA%\Zentrion`, `%LOCALAPPDATA%\Zentrion`

Inspect the exact paths before or after uninstall:

```sh
z storage show
z storage policy
```

Durable storage is documented in [STORAGE.md](STORAGE.md).

## Platform notes

### Linux
Reference platform. Uses XDG paths:

| Purpose | Path |
|---|---|
| config | `$XDG_CONFIG_HOME/zentrion` (default `~/.config/zentrion`) |
| data (audit) | `$XDG_DATA_HOME/zentrion` (default `~/.local/share/zentrion`) |
| cache | `$XDG_CACHE_HOME/zentrion` (default `~/.cache/zentrion`) |

### macOS
Uses `~/Library/Application Support/Zentrion` for config and data, and
`~/Library/Caches/Zentrion` for cache. The OS-version probe reads
`/System/Library/CoreServices/SystemVersion.plist` on a best-effort basis.

### Windows
Uses `%APPDATA%\Zentrion` for config and `%LOCALAPPDATA%\Zentrion` for data.
Shell detection prefers `SHELL`, then falls back to `ComSpec`.

### Overrides (all platforms)
For testing and packaging, these environment variables override the defaults:

- `ZENTRION_CONFIG_DIR` — configuration directory
- `ZENTRION_DATA_DIR` — data directory (audit log lives at `<dir>/audit/events.jsonl`)
- `ZENTRION_CACHE_DIR` — cache directory for disposable local cache files
- `ZENTRION_LOG_LEVEL` — `trace|debug|info|warn|error`
- `ZENTRION_TELEMETRY` — only `true` or `1` enables it; anything else stays off

## Verify the installation

```sh
z version
z doctor
```

`z doctor` performs **no network calls** and never requires an account.
