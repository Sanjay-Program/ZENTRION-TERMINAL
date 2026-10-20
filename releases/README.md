# ZENTRION TERMINAL — Releases

ZENTRION is distributed as source plus a locally built, checksummed archive.
This repository does **not** contain prebuilt macOS or Windows binaries; they
must be built on the target platform.

## 🐧 Linux (x86_64)

A real archive is included in this directory:

- `zentrion-linux-x64.tar.gz`
- `zentrion-linux-x64.tar.gz.sha256`

To rebuild it from a checkout:

```sh
./scripts/package.sh
# dist/zentrion-linux-x64.tar.gz
# dist/zentrion-linux-x64.tar.gz.sha256
# dist/zentrion-linux-x64.json
```

Install from the archive:

```sh
sha256sum -c zentrion-linux-x64.tar.gz.sha256
tar -xzf zentrion-linux-x64.tar.gz
install -m 755 zentrion-linux-x64/bin/z ~/.local/bin/z
z setup
z ui
```

## 🐧🍏 Source installer (Linux & macOS)

```sh
bash releases/install.sh
# or, from an existing checkout:
ZENTRION_SOURCE_DIR="$PWD" bash releases/install.sh
```

The installer installs a C toolchain (unless `ZENTRION_SKIP_DEPS=1`), installs
Rust through rustup if needed, runs `cargo install --path cli --locked`, calls
`z setup`, and verifies `z --version`. It installs to `~/.cargo/bin`.

## 🪟 Windows (10/11)

```powershell
$env:ZENTRION_SOURCE_DIR = "$PWD"
powershell -ExecutionPolicy Bypass -File .\releases\install.ps1
```

The script requires Rust and Git, builds `z` from source, installs it to
`%USERPROFILE%\.cargo\bin`, and runs `z setup`. Build from source on Windows;
there is no MSI in this repository.

## Post-install

```sh
z doctor
z setup
z ui
```

- Themes: `z theme list`, `z theme set cyberpunk`
- AI: `export ZENTRION_AI_PROVIDER=ollama` (see README)
- Editor: `F3` in the UI
- Chat: `export ZENTRION_P2P_KEY='shared passphrase'`, then `F6`

## Verifying an archive

Every archive produced by `scripts/package.sh` has a sibling `.sha256` file.
There is no code signing or notarization yet; treat these as integrity
checksums, not publisher signatures.
