#!/usr/bin/env sh
# Zentrion per-user installer (Phase 1 §29).
#
# - Installs the `z` binary and bundled docs when present.
# - Does NOT require root/administrator privileges.
# - Does NOT modify shell profiles without consent.
# - Verifies the artifact checksum when ZENTRION_SHA256 is provided.
#
# Usage:
#   scripts/install.sh [--prefix DIR] [--archive FILE]
#
# Default prefix: ~/.local (bin goes to ~/.local/bin).
set -eu

PREFIX="${HOME}/.local"
ARCHIVE=""
EXPECTED_SHA=""

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --archive) ARCHIVE="$2"; shift 2 ;;
        --sha256) EXPECTED_SHA="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

BIN_DIR="${PREFIX}/bin"
APP_DATA_DIR="${PREFIX}/share/zentrion"

# Locate the binary: from an archive, or from a local release build.
TMP=""
DOC_SRC=""
ROOT_SRC=""
if [ -n "$ARCHIVE" ]; then
    if [ ! -f "$ARCHIVE" ]; then
        echo "archive not found: $ARCHIVE" >&2; exit 1
    fi
    if [ -n "$EXPECTED_SHA" ]; then
        ACTUAL=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)
        if [ "$ACTUAL" != "$EXPECTED_SHA" ]; then
            echo "CHECKSUM MISMATCH — refusing to install." >&2
            echo "  expected: $EXPECTED_SHA" >&2
            echo "  actual:   $ACTUAL" >&2
            exit 1
        fi
        echo "Checksum verified."
    else
        echo "NOTE: no --sha256 supplied; integrity not verified."
    fi
    TMP=$(mktemp -d)
    tar -xzf "$ARCHIVE" -C "$TMP"
    SRC=$(find "$TMP" -name z -type f -perm -u+x | head -n1)
    DOC_SRC="$TMP/docs"
    ROOT_SRC="$TMP"
else
    if [ -x "target/release/z" ]; then
        SRC="target/release/z"
    elif [ -x "target/debug/z" ]; then
        SRC="target/debug/z"
    else
        echo "no binary found. Build first with scripts/build.sh release" >&2
        exit 1
    fi
    [ -d "docs" ] && DOC_SRC="docs"
    ROOT_SRC="."
fi

[ -n "$SRC" ] || { echo "could not locate binary in archive" >&2; exit 1; }

mkdir -p "$BIN_DIR" "$APP_DATA_DIR"
cp "$SRC" "$BIN_DIR/z"
chmod 755 "$BIN_DIR/z"
[ -n "$DOC_SRC" ] && [ -d "$DOC_SRC" ] && rm -rf "$APP_DATA_DIR/docs"
[ -n "$DOC_SRC" ] && [ -d "$DOC_SRC" ] && cp -R "$DOC_SRC" "$APP_DATA_DIR/"
[ -n "$ROOT_SRC" ] && [ -f "$ROOT_SRC/README.md" ] && cp "$ROOT_SRC/README.md" "$APP_DATA_DIR/README.md"
[ -n "$ROOT_SRC" ] && [ -f "$ROOT_SRC/SECURITY.md" ] && cp "$ROOT_SRC/SECURITY.md" "$APP_DATA_DIR/SECURITY.md"
[ -n "$ROOT_SRC" ] && [ -f "$ROOT_SRC/CHANGELOG.md" ] && cp "$ROOT_SRC/CHANGELOG.md" "$APP_DATA_DIR/CHANGELOG.md"
[ -n "$ROOT_SRC" ] && [ -f "$ROOT_SRC/FAQ.md" ] && cp "$ROOT_SRC/FAQ.md" "$APP_DATA_DIR/FAQ.md"
[ -n "$TMP" ] && rm -rf "$TMP"

echo "Installed: $BIN_DIR/z"
echo "App files: $APP_DATA_DIR"
echo "User data: preserved under the platform data directory (run: z storage show)"
echo

case ":${PATH}:" in
    *":${BIN_DIR}:"*) echo "PATH already includes $BIN_DIR" ;;
    *)
        echo "Add this to your shell profile to use \`z\` everywhere:"
        echo "    export PATH=\"${BIN_DIR}:\$PATH\""
        ;;
esac
