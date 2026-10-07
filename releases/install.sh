#!/usr/bin/env bash
set -e

# ZENTRION Universal Unix Installer (Enterprise Edition)
# Supports: Ubuntu/Debian, Fedora/CentOS/RHEL, Arch Linux, Alpine, and macOS

echo "============================================================"
echo "    ZENTRION TERMINAL: Enterprise Installer (Linux & macOS)"
echo "============================================================"

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "[*] Detected OS: $OS"
echo "[*] Detected Architecture: $ARCH"

# Install C Compiler toolchain based on OS
echo "[*] Checking OS-specific build toolchains..."
if [ "$OS" = "Linux" ]; then
    if command -v apt-get &> /dev/null; then
        echo "[*] Debian/Ubuntu detected. Ensuring build-essential is installed..."
        sudo apt-get update -qq && sudo apt-get install -y build-essential libssl-dev pkg-config -qq || true
    elif command -v dnf &> /dev/null; then
        echo "[*] Fedora/RHEL detected. Ensuring gcc is installed..."
        sudo dnf groupinstall -y "Development Tools" -q || true
        sudo dnf install -y openssl-devel pkgconf-pkg-config -q || true
    elif command -v pacman &> /dev/null; then
        echo "[*] Arch Linux detected. Ensuring base-devel is installed..."
        sudo pacman -Sy --needed --noconfirm base-devel openssl pkgconf || true
    fi
elif [ "$OS" = "Darwin" ]; then
    if ! xcode-select -p &> /dev/null; then
        echo "[*] macOS detected. Installing Command Line Tools..."
        xcode-select --install || true
        echo "[-] Please wait for Xcode tools to install, then re-run this script."
        exit 1
    fi
fi

# Install Rust Dependencies
if ! command -v cargo &> /dev/null; then
    echo "[*] Rust (cargo) is not installed. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "[*] Rust is already installed."
fi

# Clone Repository
REPO_DIR="/tmp/zentrion-install"
if [ -d "$REPO_DIR" ]; then
    rm -rf "$REPO_DIR"
fi

echo "[*] Downloading ZENTRION Enterprise Core..."
git clone https://github.com/zentrion/terminal.git "$REPO_DIR" --quiet

echo "[*] Compiling ZENTRION (This may take a few minutes)..."
cd "$REPO_DIR"
cargo install --path cli/ --locked --force

# Setup Config Directory Securely
echo "[*] Initializing ZENTRION Secure Storage..."
mkdir -p "$HOME/.zentrion/vault"
mkdir -p "$HOME/.zentrion/audit"
chmod 700 "$HOME/.zentrion"
chmod 700 "$HOME/.zentrion/vault"
chmod 700 "$HOME/.zentrion/audit"
echo "[+] Secure Vault initialized with strict 700 permissions."

# Ensure PATH is configured
if ! echo "$PATH" | grep -q "$HOME/.cargo/bin"; then
    echo "[*] Adding ~/.cargo/bin to your shell profile..."
    if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ] || [ -f "$HOME/.bashrc" ]; then
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$HOME/.bashrc"
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Verify Installation
if command -v z-cli &> /dev/null; then
    echo "============================================================"
    echo "    SUCCESS! ZENTRION Enterprise has been installed."
    echo "    Run 'z-cli ui' to launch the Next-Gen Terminal."
    echo "============================================================"
else
    echo "[-] Installation finished, but 'z-cli' could not be found."
    echo "[-] Please restart your terminal and try again."
fi
