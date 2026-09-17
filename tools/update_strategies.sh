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

# QUIC. Ванильная фаза 90-quic.sh даёт 13 строк — у UDP мало рычагов. Сверху три
# источника, каждый назван:
#  * custom/list_quic.txt — рукописный список самого zapret2 (`--payload quic_initial`
#    через пробел приводится к `=`: разбор каталога режет строку по пробелам);
#  * фейк с repeats 5 и 10 перед ipfrag — ваниль берёт только FAKE_REPEATS=1;
#  * udplen — удлинение Initial, есть в zapret-antidpi.lua, но в blockcheck2 не
#    перебирается. Прирост не выше 64: Initial уже ~1250 байт, дальше MTU и
#    фрагментация самим ядром, а это уже другая страта (ipfrag).
LIST_QUIC="$SCRIPT_DIR/../reference/zapret2/blockcheck2.d/custom/list_quic.txt"
P=--payload=quic_initial
F=fake:blob=fake_default_quic
echo "Generating quic..."
{
    bash "$DUMP" quic 2>/dev/null | grep -v '^#\|^$\|^SKIPPED'
    grep -v '^#\|^$' "$LIST_QUIC" | sed 's/^--payload quic_initial /--payload=quic_initial /'
    for repeats in 5 10; do
        for pos in 8 16 32 64; do
            echo "$P --lua-desync=$F:repeats=$repeats --lua-desync=send:ipfrag:ipfrag_pos_udp=$pos --lua-desync=drop"
        done
    done
    for inc in 2 4 8 16 32 64; do
        echo "$P --lua-desync=udplen:increment=$inc"
    done
    for repeats in 1 5 10; do
        for inc in 2 16 64; do
            echo "$P --lua-desync=$F:repeats=$repeats --lua-desync=udplen:increment=$inc"
        done
    done
} | awk '!seen[$0]++' > "$OUT_DIR/quic.txt"
echo "  quic: $(wc -l < "$OUT_DIR/quic.txt") strategies"

echo "Done. Files written to $OUT_DIR/"
