#!/usr/bin/env sh
# Format. Usage: scripts/format.sh [--check]
set -eu
if [ "${1:-}" = "--check" ]; then
    cargo fmt --all -- --check
else
    cargo fmt --all
fi
