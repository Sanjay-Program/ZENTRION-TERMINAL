#!/usr/bin/env bash
# ZENTRION TERMINAL source installer for Linux and macOS.
#
# Usage:
#   bash releases/install.sh
#   ZENTRION_SOURCE_DIR="$PWD" bash releases/install.sh
#   ZENTRION_SKIP_DEPS=1 bash releases/install.sh
#
# The installer clones (or uses) the source tree, builds `z` with cargo and
# installs it to ~/.cargo/bin. It never downloads prebuilt binaries.
set -euo pipefail

echo "============================================================"
echo "    ZENTRION TERMINAL: source installer (Linux & macOS)"
echo "============================================================"

OS="$(uname -s)"
ARCH="$(uname -m)"
echo "[*] Detected: $OS $ARCH"

install_deps() {
    case "$OS" in
        Linux)
            if command -v apt-get >/dev/null 2>&1; then
                echo "[*] Debian/Ubuntu: build-essential + pkg-config"
                sudo apt-get update -qq || true
                sudo apt-get install -y build-essential pkg-config libssl-dev -qq || true
            elif command -v dnf >/dev/null 2>&1; then
                echo "[*] Fedora/RHEL: gcc + pkg-config"
                sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config openssl-devel -q || true
            elif command -v pacman >/dev/null 2>&1; then
                echo "[*] Arch: base-devel + pkgconf"
                sudo pacman -Sy --needed --noconfirm base-devel pkgconf openssl || true
            else
                echo "[!] No known package manager; ensure a C toolchain is installed."
            fi
            ;;
        Darwin)
            if ! xcode-select -p >/dev/null 2>&1; then
                echo "[!] Xcode Command Line Tools are required."
                xcode-select --install || true
                echo "    Re-run this installer after the tools finish installing."
                exit 1
            fi
            ;;
        *)
            echo "[!] Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

if [ "${ZENTRION_SKIP_DEPS:-0}" != "1" ]; then
    install_deps
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "[*] Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
else
    echo "[*] Rust is already installed: $(cargo --version)"
fi

CLEANUP=""
if [ -n "${ZENTRION_SOURCE_DIR:-}" ]; then
    REPO_DIR="$ZENTRION_SOURCE_DIR"
    if [ ! -f "$REPO_DIR/Cargo.toml" ]; then
        echo "[-] ZENTRION_SOURCE_DIR does not look like a checkout: $REPO_DIR"
        exit 1
    fi
    echo "[*] Using existing source tree: $REPO_DIR"
else
    REPO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zentrion-install.XXXXXX")"
    CLEANUP="$REPO_DIR"
    echo "[*] Cloning source into $REPO_DIR..."
    if ! git clone --depth 1 https://github.com/zentrion/terminal.git "$REPO_DIR"; then
        echo "[-] Clone failed. Set ZENTRION_SOURCE_DIR to an existing checkout and re-run."
        rm -rf "$CLEANUP"
        exit 1
    fi
fi

echo "[*] Building and installing (this can take several minutes)..."
(cd "$REPO_DIR" && cargo install --path cli --locked --force)

if ! command -v z >/dev/null 2>&1; then
    echo "[-] 'z' was not found on PATH after install."
    echo "    Add \$HOME/.cargo/bin to PATH and restart your shell."
    [ -n "$CLEANUP" ] && rm -rf "$CLEANUP"
    exit 1
fi

echo "[*] Initializing local storage..."
z setup >/dev/null || true
chmod 700 "$HOME/.config/zentrion" 2>/dev/null || true
chmod 700 "$HOME/.local/share/zentrion" 2>/dev/null || true

VERSION="$(z --version 2>/dev/null | head -n1 || true)"
echo "============================================================"
echo "    Installed: $VERSION"
echo "    Run 'z ui' to launch the terminal."
echo "============================================================"

[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"
