#!/usr/bin/env bash
# Сколько пакетов в секунду настоящий скан гонит через NFQUEUE (#68).
# Запускается ВНУТРИ контейнера-стенда.
#
# Зачем: решение «одна очередь вместо восьми» упирается в вопрос, хватит ли
# однопоточному nfqws2 пропускной способности. Ответ зависит от того, какой
# поток пакетов мы вообще создаём. Замер даёт спрос, nfq-throughput-ab.sh — потолок.
#
# Метод: отдельная наблюдательная цепочка nft, которая считает ровно те пакеты,
# что уйдут в очередь, но сама ничего с ними не делает. Приоритеты выбраны так,
# чтобы встать перед боевыми (postnat 102, prenat -102).
#
# Почему не /proc/net/netfilter/nfnetlink_queue: там queue_total — мгновенная
# длина очереди, а id_sequence обнуляется вместе с очередью. Наши очереди
# создаются и исчезают на каждой стратегии, поэтому суммы по procfs скачут в минус.
set -uo pipefail

DOMAIN="${1:-rutracker.org}"
TIMEOUT="${2:-70}"
SAMPLES="${3:-40}"
BIN=/app/target/debug/blockcheckw

cleanup() {
    kill -INT "${PID:-0}" 2>/dev/null
    sleep 2
    pkill -9 -x blockcheckw 2>/dev/null
    pkill -9 -x nfqws2 2>/dev/null
    nft delete table inet obs 2>/dev/null
}
trap cleanup EXIT

pkill -9 -x nfqws2 2>/dev/null
pkill -9 -x blockcheckw 2>/dev/null
bash /app/tests/repro/setup-router.sh >/dev/null 2>&1

nft delete table inet obs 2>/dev/null
nft add table inet obs
nft add chain inet obs po '{ type filter hook postrouting priority 101; }'
nft add chain inet obs pr '{ type filter hook prerouting priority -103; }'
nft add rule inet obs po mark and 0x20000000 != 0 counter
nft add rule inet obs pr ct mark and 0x20000000 != 0 counter

cnt()     { nft list table inet obs | grep -oE 'packets [0-9]+' | awk '{s+=$2} END{print s+0}'; }
qdepth()  { awk '$1+0>=200 && $1+0<300 {if($3+0>m)m=$3+0} END{print m+0}' /proc/net/netfilter/nfnetlink_queue; }
qdrop()   { awk '$1+0>=200 && $1+0<300 {d+=$6; u+=$7} END{print d+u+0}' /proc/net/netfilter/nfnetlink_queue; }

echo "=== скан $DOMAIN, таймаут ${TIMEOUT}с ==="
"$BIN" --auto scan -d "$DOMAIN" --timeout "$TIMEOUT" >/tmp/scan-packet-rate.log 2>&1 &
PID=$!

for _ in $(seq 1 900); do
    [ "$(cnt)" != "0" ] && break
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.1
done

echo "сек   пакетов/с   глубина_очереди   потери"
prev=$(cnt); start=$prev; peak=0
for t in $(seq 1 "$SAMPLES"); do
    sleep 1
    kill -0 "$PID" 2>/dev/null || break
    cur=$(cnt); rate=$((cur-prev)); prev=$cur
    [ "$rate" -gt "$peak" ] && peak=$rate
    printf "  %-4s %-11s %-17s %s\n" "$t" "$rate" "$(qdepth)" "$(qdrop)"
done

echo
echo "пик: $peak пакетов/с, всего за замер: $((prev-start))"
echo "потолок одной очереди меряется через tests/repro/nfq-throughput-ab.sh"
