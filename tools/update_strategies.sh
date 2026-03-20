#!/bin/bash
# Regenerate strategy files from vanilla blockcheck2 scripts.
# Run this after updating the zapret2 git submodule.
#
# Usage: bash tools/update_strategies.sh

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DUMP="$SCRIPT_DIR/strategy-diff/dump_vanilla_real.sh"
OUT_DIR="$SCRIPT_DIR/../strategies"

if [ ! -f "$DUMP" ]; then
    echo "ERROR: $DUMP not found" >&2
    exit 1
fi

for proto in http tls12 tls13; do
    echo "Generating $proto..."
    bash "$DUMP" "$proto" 2>/dev/null | grep -v '^#\|^$\|^SKIPPED' > "$OUT_DIR/${proto}.txt"
    count=$(wc -l < "$OUT_DIR/${proto}.txt")
    echo "  $proto: $count strategies"
done

echo "Done. Files written to $OUT_DIR/"
