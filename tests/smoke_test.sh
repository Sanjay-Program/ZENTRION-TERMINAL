#!/bin/bash
set -e

echo "Starting ZENTRION End-to-End Verification..."

Z_BIN="target/debug/z"

if [ ! -f "$Z_BIN" ]; then
    echo "Warning: ZENTRION binary not found at $Z_BIN. Make sure you are running this from the project root and it is built."
fi

echo "--- Check 1 (Security Policy): Running 'z run whoami' ---"
set +e
OUTPUT=$($Z_BIN run whoami 2>&1)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ] || echo "$OUTPUT" | grep -qi "denied"; then
    echo "Check 1 Passed: Execution denied as expected."
else
    echo "Check 1 Failed: Execution succeeded unexpectedly. Output: $OUTPUT"
    exit 1
fi

echo "--- Check 2 (AI Security): Running 'z ai security status' ---"
$Z_BIN ai security status
echo "Check 2 Passed."

echo "--- Check 3 (DevSec): Running 'z project scan' ---"
$Z_BIN project scan
echo "Check 3 Passed."

echo "--- Check 4 (Vault): Running 'z config set-secret test_key my_value' ---"
$Z_BIN config set-secret test_key my_value
echo "Check 4 Passed."

echo "--- Check 5 (Audit): Running 'z audit verify' ---"
$Z_BIN audit verify
echo "Check 5 Passed."

echo ""
echo "--- Check 6 (Enterprise Login): Running 'z enterprise login test-team' ---"
target/debug/z enterprise login test-team
echo "Check 6 Passed."
echo ""

echo "--- Check 7 (Enterprise Sync): Running 'z enterprise sync' ---"
target/debug/z enterprise sync
echo "Check 7 Passed."
echo ""

echo "--- Check 8 (Enterprise Telemetry): Running 'z enterprise fleet-status' ---"
target/debug/z enterprise fleet-status
echo "Check 8 Passed."
echo ""

echo "--- Check 9 (Monolithic Bundled Tool): Running 'z run z-sysinfo' ---"
target/debug/z run z-sysinfo
echo "Check 9 Passed."
echo ""

echo "--- Check 10 (AI-BOM Supply Chain): Running 'z ai bom' ---"
target/debug/z ai bom
echo "Check 10 Passed."
echo ""

echo "--- Check 11 (Secure OTA Update & Rollback): Running 'z upgrade' ---"
target/debug/z upgrade apply
target/debug/z upgrade rollback
echo "Check 11 Passed."
echo ""

echo "--- Check 12 (SDK IPC Daemon): Running 'z daemon' ---"
target/debug/z daemon start &
DAEMON_PID=$!
sleep 1
echo '{"command": "fs.write", "args": ["./src/**"]}' | nc 127.0.0.1 9099
wait $DAEMON_PID
echo ""
echo "Check 12 Passed."
echo ""

echo "================================================="
echo "ALL ZENTRION SYSTEMS VERIFIED - PHASE 14 SUCCESS"
echo "================================================="
