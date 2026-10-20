<#
.SYNOPSIS
ZENTRION TERMINAL source installer for Windows 10/11.

.DESCRIPTION
Uses an existing checkout (ZENTRION_SOURCE_DIR) or clones the repository,
builds `z` with cargo, installs it to %USERPROFILE%\.cargo\bin and initializes
local storage. No prebuilt binary is downloaded.
#>
$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "    ZENTRION TERMINAL: source installer (Windows)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Rust not found. Downloading rustup-init..." -ForegroundColor Yellow
    $rustupExe = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupExe
    Write-Host "[*] Running rustup (requires the Visual Studio C++ build tools)." -ForegroundColor Yellow
    Start-Process -FilePath $rustupExe -ArgumentList "-y" -Wait -NoNewWindow
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Git is required. Install Git for Windows and re-run." -ForegroundColor Red
    exit 1
}

$sourceDir = $env:ZENTRION_SOURCE_DIR
$cleanup = $null
if ($sourceDir) {
    if (-not (Test-Path (Join-Path $sourceDir "Cargo.toml"))) {
        Write-Host "[-] ZENTRION_SOURCE_DIR is not a checkout: $sourceDir" -ForegroundColor Red
        exit 1
    }
    $repoDir = $sourceDir
} else {
    $repoDir = Join-Path $env:TEMP ("zentrion-install-" + [guid]::NewGuid().ToString("N"))
    $cleanup = $repoDir
    Write-Host "[*] Cloning source into $repoDir..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/zentrion/terminal.git $repoDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Clone failed. Set ZENTRION_SOURCE_DIR to a checkout." -ForegroundColor Red
        exit 1
    }
}

Write-Host "[*] Building and installing..." -ForegroundColor Yellow
Push-Location $repoDir
cargo install --path cli --locked --force
Pop-Location

$z = Get-Command z -ErrorAction SilentlyContinue
if (-not $z) {
    Write-Host "[-] 'z' was not found on PATH. Add $env:USERPROFILE\.cargo\bin to PATH." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Initializing local storage..." -ForegroundColor Yellow
& z setup | Out-Null

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ("    Installed: " + (& z --version)) -ForegroundColor Green
Write-Host "    Run 'z ui' from a new PowerShell window to launch." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

if ($cleanup) { Remove-Item -Recurse -Force $cleanup }
