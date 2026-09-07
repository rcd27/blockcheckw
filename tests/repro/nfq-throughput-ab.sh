#!/usr/bin/env bash
# A/B по пропускной способности NFQUEUE для #68. Запускается ВНУТРИ контейнера.
#
#   8 процессов / 8 очередей   — как работает blockcheckw сегодня
#   1 процесс  / 1 очередь     — как он работал бы с --filter-mark
#
# Бинарь один и тот же в обоих вариантах, чтобы мерить архитектуру, а не версию.
#
# Требуется:
#   /tmp/z2/nfq2/nfqws2 + /tmp/z2/lua/*  — сборка zapret2 с --filter-mark (v1.0.5),
#                                          разворачивается git archive'ом, см.
#                                          docs/research/68-nfqws2-parallelism.md
#   python3, nc                          — генератор нагрузки
#
# ВАЖНО про интерпретацию: объёмная передача на loopback меряет НЕ ту нагрузку.
# Там работает GSO, в очередь приезжают суперсегменты по 57 КБ, стоимость разбора
# растёт с размером, и одна очередь проигрывает в 4 раза. Наш скан так не выглядит:
# он делает короткие соединения с мелкими пакетами. Разрыв на них — 1,2×.
set -uo pipefail

BIN=${BIN:-/tmp/z2/nfq2/nfqws2}
Z2=${Z2:-/tmp/z2}
N=8
SECS=${SECS:-10}
MB=${MB:-50}

LUA="--lua-init=@$Z2/lua/zapret-lib.lua --lua-init=@$Z2/lua/zapret-antidpi.lua"
COMMON="--uid=65534:65534 --fwmark=0x10000000 $LUA"
STRAT="--payload=tls_client_hello --lua-desync=tcpseg:pos=0,1"

for need in "$BIN" "$Z2/lua/zapret-lib.lua"; do
    [ -e "$need" ] || { echo "нет $need — см. docs/research/68-nfqws2-parallelism.md" >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "нужен python3" >&2; exit 1; }

# Живые nfqws2, без зомби. PID 1 в контейнере — sleep infinity, сирот он не
# пожинает, поэтому pgrep насчитывает лишнее и purge крутится вхолостую.
live_nfqws() {
    ps -eo stat=,comm= 2>/dev/null | awk '$2=="nfqws2" && $1 !~ /^Z/' | wc -l
}

purge() {
    for _ in $(seq 1 10); do
        pkill -9 -x nfqws2 2>/dev/null
        pkill -9 -x nc 2>/dev/null
        sleep 0.3
        [ "$(live_nfqws)" = "0" ] && break
    done
    nft delete table inet abexp 2>/dev/null
}

# Пакеты считаем nft-счётчиком: queue_total в procfs — это мгновенная длина
# очереди, а не накопительный счётчик, дельта по нему всегда нулевая.
nftcount() {
    nft list chain inet abexp out 2>/dev/null | grep -oE 'packets [0-9]+' | awk '{s+=$2} END{print s+0}'
}
qdrop() {
    awk '$1+0>=200 && $1+0<210 {d+=$6; u+=$7} END{print d+u+0}' /proc/net/netfilter/nfnetlink_queue
}

rules() {  # $1 = many|one
    nft add table inet abexp
    nft add chain inet abexp out '{ type filter hook output priority 100; }'
    for i in $(seq 0 $((N-1))); do
        local q
        if [ "$1" = many ]; then q=$((200+i)); else q=200; fi
        nft add rule inet abexp out ip daddr 127.0.0.1 tcp dport $((9001+i)) \
            meta mark set $((i+1)) counter queue num "$q"
    done
}

listeners() {  # $1 = many|one
    if [ "$1" = many ]; then
        for i in $(seq 0 $((N-1))); do
            $BIN $COMMON --qnum=$((200+i)) --filter-mark=$((i+1))/0xFFFF $STRAT >/dev/null 2>&1 &
        done
    else
        local args=""
        for i in $(seq 0 $((N-1))); do
            [ -n "$args" ] && args="$args --new"
            args="$args --filter-mark=$((i+1))/0xFFFF $STRAT"
        done
        # shellcheck disable=SC2086
        $BIN $COMMON --qnum=200 $args >/dev/null 2>&1 &
    fi
    sleep 1.5
}

# ── Генератор коротких соединений ───────────────────────────────────────────
cat > /tmp/bcw-conn.py <<'PY'
import socket, sys, threading, time

PORTS = [9001 + i for i in range(8)]

def server():
    def one(p):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", p)); s.listen(256)
        while True:
            try:
                c, _ = s.accept(); c.recv(256); c.sendall(b"ok\n"); c.close()
            except OSError:
                return
    for p in PORTS:
        threading.Thread(target=one, args=(p,), daemon=True).start()
    threading.Event().wait()

def client(per_port, seconds):
    done = [0] * len(PORTS)
    stop = time.time() + seconds
    def worker(idx, p):
        n = 0
        while time.time() < stop:
            try:
                c = socket.create_connection(("127.0.0.1", p), timeout=3)
                c.sendall(b"x" * 64); c.recv(64); c.close(); n += 1
            except OSError:
                pass
        done[idx] += n
    ts = []
    for i, p in enumerate(PORTS):
        for _ in range(per_port):
            t = threading.Thread(target=worker, args=(i, p)); t.start(); ts.append(t)
    t0 = time.time()
    for t in ts:
        t.join()
    print(f"{sum(done)} {time.time() - t0:.2f}")

if sys.argv[1] == "server":
    server()
else:
    client(int(sys.argv[2]), int(sys.argv[3]))
PY

# ── Вариант 1: короткие соединения (наш профиль нагрузки) ───────────────────
run_conn() {
    local name="$1" mode="$2" conc="$3"
    purge
    rules "$mode"
    listeners "$mode"
    local live c0 d0 c1 d1 conns el
    live=$(live_nfqws); c0=$(nftcount); d0=$(qdrop)
    read -r conns el <<<"$(python3 /tmp/bcw-conn.py client "$conc" "$SECS")"
    c1=$(nftcount); d1=$(qdrop)
    printf "  %-26s проц=%-2s потоков=%-4s %7d соед/с %8d пак/с  потерь=%s\n" \
        "$name" "$live" "$((conc*N))" \
        "$(awk -v c="$conns" -v e="$el" 'BEGIN{printf "%d", c/e}')" \
        "$(awk -v p="$((c1-c0))" -v e="$el" 'BEGIN{printf "%d", p/e}')" \
        "$((d1-d0))"
    purge
}

# ── Вариант 2: объём (для сравнения; меряет не нашу нагрузку) ───────────────
run_bulk() {
    local name="$1" mode="$2"
    purge
    rules "$mode"
    listeners "$mode"
    local live; live=$(live_nfqws)
    rm -f /tmp/bcw-got.*
    for i in $(seq 0 $((N-1))); do nc -l -p $((9001+i)) > /tmp/bcw-got.$i 2>/dev/null & done
    sleep 0.7
    local c0 s pids=() e c1
    c0=$(nftcount); s=$(date +%s%N)
    for i in $(seq 0 $((N-1))); do
        ( nc -N 127.0.0.1 $((9001+i)) < /tmp/bcw-payload.bin >/dev/null 2>&1 ) & pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
    e=$(date +%s%N); sleep 0.4; c1=$(nftcount)
    local ms=$(( (e-s)/1000000 )) pk=$((c1-c0))
    printf "  %-26s проц=%-2s %6d мс  %8d сегм/с\n" \
        "$name" "$live" "$ms" "$(( ms>0 ? pk*1000/ms : 0 ))"
    purge
}

ip link set lo mtu 1500 2>/dev/null
pkill -9 -f "bcw-conn.py server" 2>/dev/null; sleep 0.3
python3 /tmp/bcw-conn.py server & SRV=$!
trap 'kill $SRV 2>/dev/null; purge' EXIT
sleep 1

echo "== короткие соединения (профиль нагрузки скана), ${SECS}с на вариант =="
for c in 1 4 16; do
    echo "-- по $c потоков на порт --"
    run_conn "8 процессов / 8 очередей" many "$c"
    run_conn "1 процесс / 1 очередь"    one  "$c"
done

if [ "${WITH_BULK:-0}" = "1" ]; then
    [ -f /tmp/bcw-payload.bin ] || head -c $((MB*1024*1024)) /dev/zero > /tmp/bcw-payload.bin
    echo
    echo "== объёмная передача ${MB} МБ × $N (НЕ наша нагрузка: GSO даёт суперсегменты) =="
    run_bulk "8 процессов / 8 очередей" many
    run_bulk "1 процесс / 1 очередь"    one
fi
