#!/usr/bin/env sh
# Fail if a high-confidence secret pattern appears in committed sources.
#
# This is a guardrail, not a substitute for review (see 30-TESTING). It is
# intentionally simple so it can be audited at a glance: patterns are built
# from fragments so the script cannot match its own source.
set -eu

# Build the patterns from fragments so this file does not contain the literal
# strings it searches for (avoids a self-match false positive).
P_PRIVKEY='PRIVATE'' KEY'
P_AWS='AKIA''[0-9A-Z]{16}'
P_GHP='ghp_''[A-Za-z0-9]{36}'
P_OAI='sk-''[A-Za-z0-9]{20,}'
P_PEM='-----''BEGIN'
PATTERNS="${P_PRIVKEY}|${P_AWS}|${P_GHP}|${P_OAI}|${P_PEM}"

if grep -rInE "$PATTERNS" \
    --include='*.rs' --include='*.toml' --include='*.yaml' --include='*.yml' \
    --include='*.json' --include='*.sh' \
    --exclude-dir=target --exclude-dir=.git . ; then
    echo "ERROR: possible secret material found in source. Review the matches above."
    exit 1
fi
echo "No high-confidence secret patterns found."
