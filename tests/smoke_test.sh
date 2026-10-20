#!/usr/bin/env bash
# End-to-end CLI smoke test. Runs offline against a temporary config/data dir.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
Z_BIN="${Z_BIN:-$ROOT/target/debug/z}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/zentrion-smoke.XXXXXX")"
export ZENTRION_CONFIG_DIR="$TMP/config"
export ZENTRION_DATA_DIR="$TMP/data"
export ZENTRION_CACHE_DIR="$TMP/cache"
mkdir -p "$ZENTRION_CONFIG_DIR" "$ZENTRION_DATA_DIR" "$ZENTRION_CACHE_DIR"
cleanup() {
    if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

fail=0
check() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "PASS  $label"
    else
        echo "FAIL  $label"
        fail=1
    fi
}

expect_fail() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "FAIL  $label (unexpected success)"
        fail=1
    else
        echo "PASS  $label"
    fi
}

echo "ZENTRION smoke test"
check "version" "$Z_BIN" version
check "doctor (offline)" "$Z_BIN" doctor
check "status" "$Z_BIN" status
check "setup" "$Z_BIN" setup
check "theme list" "$Z_BIN" theme list
check "theme set dracula" "$Z_BIN" theme set dracula
check "security posture" "$Z_BIN" security posture
check "security scan" "$Z_BIN" security scan .
check "ai security status" "$Z_BIN" ai security status
check "ai bom" "$Z_BIN" ai bom
check "audit verify" "$Z_BIN" audit verify

expect_fail "unpermitted process is denied" "$Z_BIN" run whoami
check "allowlisted bundled tool" "$Z_BIN" run z-sysinfo

# The repo policy intentionally does not allow network probes.
expect_fail "network probe requires permission" "$Z_BIN" network dns localhost

# No update channel is configured in this checkout.
expect_fail "upgrade check without a manifest" "$Z_BIN" upgrade check

# Enterprise commands must not fabricate a login without a control plane.
expect_fail "enterprise login without a server" "$Z_BIN" enterprise login test-team

# Daemon: start, query, stop.
PORT=29319
"$Z_BIN" daemon start --port "$PORT" >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 1
check "daemon status" "$Z_BIN" daemon status --port "$PORT"
check "daemon stop" "$Z_BIN" daemon stop --port "$PORT"
sleep 0.5
if kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "FAIL  daemon exited"
    fail=1
else
    echo "PASS  daemon exited"
fi
unset DAEMON_PID

if [ "$fail" -ne 0 ]; then
    echo "SMOKE TEST FAILED"
    exit 1
fi
echo "ALL SMOKE CHECKS PASSED"
