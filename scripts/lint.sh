#!/usr/bin/env sh
# Lint. Usage: scripts/lint.sh
set -eu
cargo clippy --workspace --all-targets -- -D warnings
