#!/usr/bin/env sh
# Run the full test suite. Usage: scripts/test.sh
set -eu
cargo test --workspace
