# Zentrion Terminal Downloads

This directory is the downloadable release surface for Windows, macOS and
Linux. Use `releases.json` as the machine-readable manifest for websites,
install pages and update checks.

Base URL:

```text
https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases
```

## Artifacts

| Platform | File | SHA-256 |
|---|---|---|
| Linux x86_64 | `zentrion-linux-x64.tar.gz` | `625c8711a80e6d01fe2542be5ab09cd0e10e9093761552c8a9837d01633699ca` |
| macOS universal | `zentrion-macos-universal.tar.gz` | `938179d18b0793d47fdb0f00b5b544f64c7761ac6872f85057acd3086bb98b90` |
| Windows x64 | `Zentrion-Windows-x64.msi` | `e8b7b7fa115bdbb549cce67f94b5affd3be80c7862938c96d78525df618ae40d` |

Always download the matching `.sha256` file and verify before installing.

## Linux x86_64

```sh
base="https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases"
curl -LO "$base/zentrion-linux-x64.tar.gz"
curl -LO "$base/zentrion-linux-x64.tar.gz.sha256"
sha256sum -c zentrion-linux-x64.tar.gz.sha256
tar -xzf zentrion-linux-x64.tar.gz
install -Dm755 z "$HOME/.local/bin/z"
z doctor
```

## macOS Apple Silicon and Intel

```sh
base="https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases"
curl -LO "$base/zentrion-macos-universal.tar.gz"
curl -LO "$base/zentrion-macos-universal.tar.gz.sha256"
shasum -a 256 -c zentrion-macos-universal.tar.gz.sha256
tar -xzf zentrion-macos-universal.tar.gz
install -m755 z /usr/local/bin/z
z doctor
```

## Windows x64

Run in PowerShell:

```powershell
$base = "https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases"
Invoke-WebRequest "$base/Zentrion-Windows-x64.msi" -OutFile "Zentrion-Windows-x64.msi"
Invoke-WebRequest "$base/Zentrion-Windows-x64.msi.sha256" -OutFile "Zentrion-Windows-x64.msi.sha256"

$expected = (Get-Content Zentrion-Windows-x64.msi.sha256).Split(" ")[0].ToUpperInvariant()
$actual = (Get-FileHash Zentrion-Windows-x64.msi -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw "Checksum failed: $actual" }

Start-Process -Wait -FilePath msiexec.exe -ArgumentList "/i Zentrion-Windows-x64.msi /qb"
z doctor
```

## First Run

```sh
z version
z doctor
z status
z bundle list
z ui
```

`z doctor` is offline by design. It should never require an account, API key or
network call.
