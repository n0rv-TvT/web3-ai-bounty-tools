#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
SRC="${2:-}"

if [[ -z "$SRC" ]]; then
  if [[ -f "$ROOT/foundry.toml" ]]; then
    SRC=$(python3 - "$ROOT/foundry.toml" <<'PY'
import re,sys
text=open(sys.argv[1], errors='ignore').read()
m=re.search(r'^\s*src\s*=\s*["\']([^"\']+)', text, re.M)
print(m.group(1) if m else 'src')
PY
)
  elif ls "$ROOT"/hardhat.config.* >/dev/null 2>&1; then
    SRC="contracts"
  elif [[ -d "$ROOT/src" ]]; then
    SRC="src"
  else
    SRC="contracts"
  fi
fi

BASE="$ROOT/$SRC"
[[ -d "$BASE" ]] || BASE="$ROOT"

echo "# Web3 Enumeration"
echo
echo "root=$ROOT"
echo "src=$SRC"
echo

sol_files=$(find "$BASE" -type f -name '*.sol' \
  ! -path '*/node_modules/*' ! -path '*/lib/*' ! -path '*/out/*' ! -path '*/cache/*' \
  ! -path '*/test/*' ! -path '*/tests/*' ! -path '*/mocks/*' \
  ! -name '*.t.sol' ! -name '*Test*.sol' ! -name '*Exploit*.sol' 2>/dev/null | sort || true)

test_files=$(find "$ROOT" -type f \( -name '*.t.sol' -o -path '*/test/*.sol' -o -path '*/tests/*.sol' \) 2>/dev/null | sort || true)

echo "## Counts"
echo "solidity_files=$(printf '%s\n' "$sol_files" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "test_files=$(printf '%s\n' "$test_files" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "test_functions=$(printf '%s\n' "$test_files" | xargs -r grep -hE 'function[[:space:]]+test' 2>/dev/null | wc -l | tr -d ' ')"
echo "foundry_invariants=$(printf '%s\n' "$test_files" | xargs -r grep -hE 'function[[:space:]]+invariant_' 2>/dev/null | wc -l | tr -d ' ')"
echo "echidna_configs=$(find "$ROOT" -type f \( -name 'echidna*.yaml' -o -name 'echidna*.yml' \) 2>/dev/null | wc -l | tr -d ' ')"
echo "medusa_configs=$(find "$ROOT" -type f -name 'medusa*.json' 2>/dev/null | wc -l | tr -d ' ')"
echo "halmos_configs=$(find "$ROOT" -type f \( -name 'halmos*.toml' -o -name 'halmos*.json' \) 2>/dev/null | wc -l | tr -d ' ')"
echo

echo "## nSLOC"
printf '%s\n' "$sol_files" | xargs -r grep -hEv '^\s*(//|/\*|\*|$)' 2>/dev/null | wc -l | tr -d ' '
echo

echo "## Source Files"
printf '%s\n' "$sol_files" | sed '/^$/d'
echo
echo "## Test Files"
printf '%s\n' "$test_files" | sed '/^$/d'
