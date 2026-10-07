<#
.SYNOPSIS
ZENTRION Universal Windows Installer (Enterprise Edition)

.DESCRIPTION
This script installs ZENTRION TERMINAL on Windows 10/11 natively.
It ensures Rust is installed, clones the repo, compiles the binary, and sets strict ACL permissions.
#>

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "    ZENTRION TERMINAL: Enterprise Installer (Windows)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Check for Cargo/Rust
$cargoPath = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $cargoPath) {
    Write-Host "[*] Rust is not installed. Downloading rustup-init..." -ForegroundColor Yellow
    $rustupUrl = "https://win.rustup.rs/x86_64"
    $rustupExe = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupExe
    
    Write-Host "[*] Running Rust installer. Please follow the prompts (Requires VS C++ Build Tools)." -ForegroundColor Yellow
    Start-Process -FilePath $rustupExe -ArgumentList "-y" -Wait -NoNewWindow
    
    # Reload environment variables for the current session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
} else {
    Write-Host "[*] Rust is already installed." -ForegroundColor Green
}

# Check for Git
$gitPath = Get-Command git -ErrorAction SilentlyContinue
if ($null -eq $gitPath) {
    Write-Host "[-] Git is required but not found. Please install Git for Windows." -ForegroundColor Red
    exit 1
}

$repoDir = "$env:TEMP\zentrion-install"
if (Test-Path $repoDir) {
    Remove-Item -Recurse -Force $repoDir
}

Write-Host "[*] Downloading ZENTRION Enterprise Core..." -ForegroundColor Yellow
git clone https://github.com/zentrion/terminal.git $repoDir --quiet

Write-Host "[*] Compiling ZENTRION (This may take a few minutes)..." -ForegroundColor Yellow
Set-Location $repoDir
cargo install --path cli/ --locked --force

# Setup Config Directory Securely
Write-Host "[*] Initializing ZENTRION Secure Storage..." -ForegroundColor Yellow
$zentrionDir = "$env:USERPROFILE\.zentrion"
if (-Not (Test-Path "$zentrionDir\vault")) { New-Item -ItemType Directory -Force -Path "$zentrionDir\vault" | Out-Null }
if (-Not (Test-Path "$zentrionDir\audit")) { New-Item -ItemType Directory -Force -Path "$zentrionDir\audit" | Out-Null }

Write-Host "[+] Applying strict ACL security rules to Vault..." -ForegroundColor Green
$acl = Get-Acl $zentrionDir
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$env:USERNAME", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $zentrionDir $acl

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "    SUCCESS! ZENTRION Enterprise has been installed." -ForegroundColor Green
Write-Host "    Run 'z-cli ui' from a new PowerShell window to launch." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
