#!/usr/bin/env sh
# Remove the Zentrion binary and bundled docs. Usage: scripts/uninstall.sh [--prefix DIR] [--purge]
set -eu
PREFIX="${HOME}/.local"
PURGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --purge) PURGE=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
BIN="${PREFIX}/bin/z"
SHARE="${PREFIX}/share/zentrion"
if [ -f "$BIN" ]; then
    rm -f "$BIN"
    echo "Removed $BIN"
else
    echo "No binary at $BIN"
fi
if [ -d "$SHARE" ]; then
    rm -rf "$SHARE"
    echo "Removed $SHARE"
fi
if [ "$PURGE" = "1" ]; then
    echo "Note: --purge removes application files only; user data (config, audit log)"
    echo "is left in place deliberately. Remove it manually if desired:"
    echo "  ~/.config/zentrion  ~/.local/share/zentrion"
fi
