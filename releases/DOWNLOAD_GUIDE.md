# ZENTRION TERMINAL — Official Downloads & Installation Guide

Welcome to the ZENTRION TERMINAL releases page! This repository hosts the official, cryptographically verified binaries for all supported platforms.

You can link directly to these files from your website to allow users to download the terminal.

## Available Platforms

| OS / Architecture | File | SHA-256 Checksum |
|-------------------|------|------------------|
| **Linux (x86_64)** | `zentrion-linux-x64.tar.gz` | `zentrion-linux-x64.tar.gz.sha256` |
| **macOS (Universal)** | `zentrion-macos-universal.tar.gz` | `zentrion-macos-universal.tar.gz.sha256` |
| **Windows (x64)** | `Zentrion-Windows-x64.msi` | `Zentrion-Windows-x64.msi.sha256` |

---

## 📥 Linux Installation (x86_64)

**Download Links:**
* [Binary Archive (tar.gz)](https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/zentrion-linux-x64.tar.gz)
* [SHA-256 Checksum](https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/zentrion-linux-x64.tar.gz.sha256)

**Quick Install (Terminal):**
```bash
# 1. Download
wget https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/zentrion-linux-x64.tar.gz
wget https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/zentrion-linux-x64.tar.gz.sha256

# 2. Verify and extract
sha256sum -c zentrion-linux-x64.tar.gz.sha256
tar -xzf zentrion-linux-x64.tar.gz

# 3. Move to PATH
mv z ~/.local/bin/
z doctor
```

---

## 🍏 macOS Installation (Apple Silicon & Intel)

**Download Links:**
* [Universal Archive (tar.gz)](https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/zentrion-macos-universal.tar.gz)
* [SHA-256 Checksum](https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/zentrion-macos-universal.tar.gz.sha256)

**Quick Install (Terminal):**
```bash
# 1. Download
curl -LO https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/zentrion-macos-universal.tar.gz
curl -LO https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/zentrion-macos-universal.tar.gz.sha256

# 2. Verify and extract
shasum -a 256 -c zentrion-macos-universal.tar.gz.sha256
tar -xzf zentrion-macos-universal.tar.gz

# 3. Move to PATH
mv z /usr/local/bin/
z doctor
```

---

## 🪟 Windows Installation (x64 & ARM64)

**Download Links:**
* [Windows Installer (MSI)](https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/Zentrion-Windows-x64.msi)
* [SHA-256 Checksum](https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/Zentrion-Windows-x64.msi.sha256)

**Quick Install (PowerShell):**
```powershell
# 1. Download
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/Zentrion-Windows-x64.msi" -OutFile "Zentrion-Windows.msi"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Sanjay-Program/ZENTRION-TERMINAL/main/releases/Zentrion-Windows-x64.msi.sha256" -OutFile "Zentrion-Windows.msi.sha256"

# 2. Verify
$expected = Get-Content Zentrion-Windows.msi.sha256
$actual = (Get-FileHash Zentrion-Windows.msi -Algorithm SHA256).Hash
if ($actual -eq $expected.Split(' ')[0].ToUpper()) { echo "Checksum OK" } else { echo "Checksum FAILED" }

# 3. Install
Start-Process -Wait -FilePath msiexec.exe -ArgumentList "/i Zentrion-Windows.msi /qb"
```
