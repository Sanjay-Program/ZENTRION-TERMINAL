#!/usr/bin/env sh
# Build Zentrion. Usage: scripts/build.sh [debug|release]
set -eu
PROFILE="${1:-debug}"
if [ "$PROFILE" = "release" ]; then
    cargo build --workspace --release
else
    cargo build --workspace
fi
echo "Built. Run: target/${PROFILE}/z"
