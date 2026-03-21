# Blockcheck Wrapper

Быстрая обёртка над [blockcheck2](https://github.com/bol-van/zapret2) для параллельного поиска стратегий обхода DPI.

> **Статус: WIP** — работает, но активно дорабатывается.

## Зачем

Ванильный `blockcheck2.sh` прогоняет стратегии **последовательно** — одну за другой. На TLS 1.2 (~8600 стратегий) это
занимает **~90 минут**.

blockcheckw запускает их **параллельно** и находит рабочие стратегии за **~2 минуты** при 1024 воркерах (~150
стратегий/сек).

## Архитектура параллелизма

### Как это работает

Каждый воркер получает уникальный **fwmark** (SO_MARK на TCP-сокете). nftables использует **vmap** (hash map) для
маршрутизации пакетов в нужный экземпляр nfqws2 за O(1):

```
Worker 0: fwmark=0x20000001 → nfqws2 qnum=200
Worker 1: fwmark=0x20000002 → nfqws2 qnum=201
...
Worker N: fwmark=0x200000XX → nfqws2 qnum=200+N
```

Поток пакетов:

```
reqwest SYN (mark=0x20000001)
  → postnat: mark vmap → jump wp_200
    → wp_200: ct mark set | queue num 200 → nfqws2 десинхронизирует
      → nfqws2 реинжектит с mark=DESYNC_MARK
        → predefrag: DESYNC_MARK → notrack

SYN/ACK (incoming)
  → prenat: ct mark vmap → jump wi_200
    → wi_200: queue num 200 → nfqws2 определяет TTL (autottl)
```

### Что НЕ делает curl

В отличие от ванильного blockcheck2, blockcheckw **не использует curl**. HTTP-запросы выполняются in-process через
`hyper` + `tokio-rustls` + `socket2`:

- **socket2** — создаёт TCP-сокет, ставит `SO_MARK` **до** `connect()` (SYN уже помечен)
- **tokio-rustls** — TLS handshake с контролем версии (TLS 1.2 only / TLS 1.3 only)
- **hyper** — HTTP/1.1 запрос поверх TLS-стрима

Это убирает ~600 fork+exec процессов curl за скан, и даёт полный контроль над сокетом.

### Сильные стороны

- **Скорость**: 100-150x ускорение по сравнению с последовательным blockcheck2
- **Масштабируемость**: vmap(map для более "старых" nftbales) dispatch — O(1) lookup, 512 воркеров работают так же
  быстро как 8 (по nftables overhead)
- **Нет TIME_WAIT проблемы**: fwmark-маршрутизация не привязана к фиксированным портам, эфемерные порты переиспользуются
  ядром
- **autottl работает**: prenat vmap перехватывает SYN/ACK для определения TTL сервера
- **Памяти мало**: основной потребитель — nfqws2 процессы (~2-4MB каждый). 64 воркера ≈ 200MB, 512 ≈ 1.5GB

### Слабые стороны и ограничения

- **TLS fingerprint отличается от curl**: rustls генерирует другой ClientHello (cipher suites, extensions), чем
  curl/OpenSSL. DPI может реагировать по-разному — покрытие эталона ~71%, а не 100%
- **Нужен root**: SO_MARK, nftables, NFQUEUE требуют привилегий
- **nfqws2 — отдельные процессы**: каждый воркер спавнит nfqws2 (fork+exec). Это ~100ms overhead на стратегию. Для
  роутеров с медленным CPU/storage это bottleneck
- **Батчевая модель**: стратегии обрабатываются батчами по W штук. Последний батч может недоиспользовать воркеры
- **RAM линейно растёт с воркерами**: на роутере с 256MB RAM максимум ~64 воркера

### Выбор числа воркеров

```shell
# Автоматический подбор (30 сек на каждый уровень, реальный корпус стратегий):
blockcheckw benchmark
```

```shell
# Быстрый прогон:
blockcheckw benchmark -t 15
```

```shell
# С ограничением по воркерам (для роутеров):
blockcheckw benchmark -t 20 -M 64
```

## Использование

```shell
# Скан всех протоколов:
blockcheckw scan -d rutracker.org
```

```shell
# Только TLS 1.2, 256 воркеров:
blockcheckw -w 256 scan -d rutracker.org -p tls12
```

## Check: найти лучшую стратегию

Двухфазная проверка стратегий из vanilla-отчёта с реальным data transfer:

```shell
# Базовый запуск (все стратегии, 3 прохода верификации):
blockcheckw check --from-file report_vanilla.txt -d rutracker.org
```

```shell
# Early stop после 10 рабочих, 5 проходов верификации, JSON в файл:
blockcheckw check --from-file report_vanilla.txt --take 10 --passes 5 -o result.json
```

```shell
# Без верификации (одиночный проход, как scan):
blockcheckw check --from-file report_vanilla.txt --passes 1
```

**Фаза 1 (отсев):** последовательный GET-запрос на каждую стратегию. Любой HTTP-ответ = стратегия работает (
timeout/reset = DPI блокирует, HTTP 400 = fakes дошли до сервера, redirect на чужой домен = заглушка провайдера).

**Фаза 2 (верификация):** каждая рабочая стратегия проверяется `--passes` раз. Считается `success_rate`, медианная
латентность, stability verdict. Финальный ранг: `stability × 0.6 + rank_score × 0.4`. Лучшая стратегия выводится как *
*BEST**.

## Совместимость с работающим zapret2

Если на системе уже запущен zapret2, blockcheckw автоматически обнаружит конфликт (nfqws2 процессы, nft-таблицы с queue
правилами на порт 443) и предложит временно остановить сервис.

**Поддерживаемые init-системы:** systemd (`systemctl`), OpenWrt/sysv (`/etc/init.d/zapret2`).

Поведение:

- **Сервис найден** — `service stop` перед сканом, `service start` после (автоматически, включая Ctrl+C)
- **Сервис не найден** (ручной запуск) — kill nfqws2 по PID + drop nft-таблиц, предупреждение о ручном восстановлении
- **Crash** — юзер перезапускает zapret2 самостоятельно (`systemctl start zapret2`)

## Обновить стратегии

Стратегии генерируются из ванильных скриптов blockcheck2 (git submodule):

```shell
git submodule update --remote reference/zapret2
bash tools/update_strategies.sh
```

## Зависимости

- nfqws2 (из zapret2, `/opt/zapret2/`)
- nftables

## Благодарности

Проект основан на [zapret2](https://github.com/bol-van/zapret2) — оригинальном инструменте обхода DPI от bol-van. Все
стратегии и логика их генерации взяты из blockcheck2.
