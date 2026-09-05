#!/usr/bin/env bash
# Один эксперимент по issue #66. Запускается ВНУТРИ контейнера-стенда.
#
#   run-case.sh <имя> <триггер> [домен] [доп. флаги scan]
#
# триггер:
#   none        дать доработать до конца (E1)
#   table       SIGINT сразу как появилась наша таблица, до цепочек wp_* (E3)
#   workers     SIGINT после того, как появились цепочки wp_* (E2)
#   double      как workers, но два SIGINT подряд (E4)
#   sigterm     SIGTERM вместо SIGINT после появления цепочек wp_*
#
# Артефакты складывает в /app/target/repro66/<имя>/:
#   before.nft / after.nft  нормализованные снимки fw4
#   fw4.diff                их дифф — пустой файл означает «fw4 не пострадал»
#   monitor.log             трасса nft monitor: что и в каком порядке произошло
#   run.log                 stdout+stderr бинаря
#   verdict.txt            итог
set -uo pipefail

NAME="${1:?имя кейса}"
TRIGGER="${2:?триггер}"
DOMAIN="${3:-rutracker.org}"
EXTRA="${4:-}"
BIN=/app/target/debug/blockcheckw
OUT="/app/target/repro66/$NAME"
rm -rf "$OUT"; mkdir -p "$OUT"

# Уцелевший с прошлого кейса blockcheckw делает вердикт бессмысленным дважды:
# новый процесс встаёт на instance lock и НИЧЕГО не делает, а триггер тем
# временем срабатывает на таблице, которую держит старый. Получается зелёный
# «fw4 цела», который не проверил ни строчки кода. Убираем до подготовки стенда.
for p in $(pgrep -x blockcheckw); do kill -9 "$p" 2>/dev/null; done
sleep 0.5
if pgrep -x blockcheckw >/dev/null; then
    echo "СТЕНД НЕ ГОТОВ: не удалось снять предыдущий blockcheckw" >&2
    exit 1
fi

# Снимок fw4 без счётчиков и handle — иначе дифф всегда красный.
snapshot() {
    nft list table inet fw4 2>/dev/null \
        | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/g; s/ # handle [0-9]+//g; s/[[:space:]]+$//'
}

echo "=== [$NAME] подготовка стенда ==="
bash /app/tests/repro/setup-router.sh >/dev/null
snapshot > "$OUT/before.nft"
echo "fw4 до прогона: $(wc -l < "$OUT/before.nft") строк"

# Чёрный ящик: полная трасса событий ruleset.
nft monitor > "$OUT/monitor.log" 2>&1 &
MON=$!
sleep 0.3

echo "=== [$NAME] запуск blockcheckw scan -d $DOMAIN $EXTRA ==="
"$BIN" --auto scan -d "$DOMAIN" $EXTRA > "$OUT/run.log" 2>&1 &
PID=$!

wait_for() {  # предикат, таймаут в десятых секунды
    local pred="$1" limit="$2" i=0
    while [ $i -lt "$limit" ]; do
        eval "$pred" >/dev/null 2>&1 && return 0
        kill -0 "$PID" 2>/dev/null || return 1
        sleep 0.1; i=$((i+1))
    done
    return 1
}

TRIGGERED=нет
[ "$TRIGGER" = none ] && TRIGGERED="не требуется"

case "$TRIGGER" in
    none)
        wait "$PID"; RC=$?
        ;;
    table)
        if wait_for 'nft list table inet blockcheckw' 600; then
            echo "триггер: таблица появилась, шлю SIGINT немедленно" | tee -a "$OUT/verdict.txt"
            TRIGGERED=да
            kill -INT "$PID"
        else
            echo "триггер НЕ сработал: таблица blockcheckw не появилась" | tee -a "$OUT/verdict.txt"
        fi
        wait "$PID"; RC=$?
        ;;
    sigterm)
        if wait_for 'nft list table inet blockcheckw | grep -q "chain wp_"' 600; then
            echo "триггер: цепочки wp_* на месте, шлю SIGTERM" | tee -a "$OUT/verdict.txt"
            TRIGGERED=да
            kill -TERM "$PID"
        else
            echo "триггер НЕ сработал" | tee -a "$OUT/verdict.txt"
        fi
        wait "$PID"; RC=$?
        ;;
    workers|double)
        if wait_for 'nft list table inet blockcheckw | grep -q "chain wp_"' 600; then
            echo "триггер: цепочки wp_* на месте, шлю SIGINT" | tee -a "$OUT/verdict.txt"
            TRIGGERED=да
            kill -INT "$PID"
            if [ "$TRIGGER" = double ]; then
                sleep 0.2
                echo "шлю второй SIGINT (путь emergency_cleanup_sync)" | tee -a "$OUT/verdict.txt"
                kill -INT "$PID" 2>/dev/null || true
            fi
        else
            echo "триггер НЕ сработал: цепочки wp_* не появились" | tee -a "$OUT/verdict.txt"
        fi
        wait "$PID"; RC=$?
        ;;
esac

sleep 1
kill "$MON" 2>/dev/null; wait "$MON" 2>/dev/null

snapshot > "$OUT/after.nft"
diff -u "$OUT/before.nft" "$OUT/after.nft" > "$OUT/fw4.diff"
DIFF_RC=$?

{
    echo "exit code бинаря: ${RC:-?}"
    echo "fw4 после прогона: $(wc -l < "$OUT/after.nft") строк"
    if [ ! -s "$OUT/after.nft" ]; then
        echo "ВЕРДИКТ: fw4 УНИЧТОЖЕНА"
    elif [ $DIFF_RC -ne 0 ]; then
        echo "ВЕРДИКТ: fw4 ИЗМЕНЕНА (см. fw4.diff)"
    else
        echo "ВЕРДИКТ: fw4 цела"
    fi
    echo "чужая zapret: $(nft list table inet zapret >/dev/null 2>&1 && echo на месте || echo ОТСУТСТВУЕТ)"
    echo "наша blockcheckw: $(nft list table inet blockcheckw >/dev/null 2>&1 && echo 'ОСТАЛАСЬ (мусор)' || echo убрана)"
    # nft monitor НЕ печатает литерал "flush ruleset" — флэш виден как каскад
    # delete chain/table по чужим таблицам. Считать литерал бесполезно: на
    # заведомо сломанном коде он давал 0, пока fw4 сносило подчистую.
    echo "снос fw4 в трассе (delete chain/table inet fw4): $(grep -cE '^delete (chain|table) inet fw4' "$OUT/monitor.log" 2>/dev/null)"
    echo "ошибок 'No such file or directory' в логе: $(grep -c 'No such file or directory' "$OUT/run.log" 2>/dev/null)"
    # Гонка «cleanup снёс таблицу, а пайплайн ещё пишет в неё»: любой add chain
    # ПОСЛЕ delete table нашей таблицы — это простыня ENOENT из #66.
    # В контейнере окно между сносом и exit короче одного батча, поэтому здесь
    # обычно 0 даже на сломанном коде; на медленном mipsel туда попадает батч.
    echo "add chain после сноса нашей таблицы: $(awk '/^delete table inet blockcheckw/{d=1;next} d&&/^add chain inet blockcheckw/{n++} END{print n+0}' "$OUT/monitor.log" 2>/dev/null)"
    echo "батчей, упавших в снесённую таблицу: $(grep -c 'nft batch add failed' "$OUT/run.log" 2>/dev/null)"
    echo "триггер сработал: $TRIGGERED"
    # Зелёный вердикт засчитывается только если прогон реально состоялся.
    if grep -q 'waiting for another blockcheckw instance' "$OUT/run.log" 2>/dev/null; then
        echo "ВЕРДИКТ НЕДЕЙСТВИТЕЛЕН: прогон простоял на instance lock"
    elif [ "$TRIGGERED" = нет ]; then
        echo "ВЕРДИКТ НЕДЕЙСТВИТЕЛЕН: триггер не сработал, код прерывания не проверен"
    fi
} | tee -a "$OUT/verdict.txt"
