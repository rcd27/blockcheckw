# Blockcheck Wrapper

Быстрая обёртка над [blockcheck2](https://github.com/bol-van/zapret2) для параллельного поиска стратегий обхода DPI.

> **Статус: WIP** — работает, но активно дорабатывается.

## Зачем

Ванильный `blockcheck2.sh` прогоняет стратегии **последовательно** — одну за другой. На TLS 1.2 (~8600 стратегий) это занимает **~90 минут**.

blockcheckw запускает их **параллельно** и находит рабочие стратегии за **~1 минуту** при 512 воркерах (~150 стратегий/сек).

## Архитектура параллелизма

### Как это работает

Каждый воркер получает уникальный **fwmark** (SO_MARK на TCP-сокете). nftables использует **vmap** (hash map) для маршрутизации пакетов в нужный экземпляр nfqws2 за O(1):

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

В отличие от ванильного blockcheck2, blockcheckw **не использует curl**. HTTP-запросы выполняются in-process через `hyper` + `tokio-rustls` + `socket2`:

- **socket2** — создаёт TCP-сокет, ставит `SO_MARK` **до** `connect()` (SYN уже помечен)
- **tokio-rustls** — TLS handshake с контролем версии (TLS 1.2 only / TLS 1.3 only)
- **hyper** — HTTP/1.1 запрос поверх TLS-стрима

Это убирает ~600 fork+exec процессов curl за скан, и даёт полный контроль над сокетом.

### Сильные стороны

- **Скорость**: 100-150x ускорение по сравнению с последовательным blockcheck2
- **Масштабируемость**: vmap dispatch — O(1) lookup, 512 воркеров работают так же быстро как 8 (по nftables overhead)
- **Нет TIME_WAIT проблемы**: fwmark-маршрутизация не привязана к фиксированным портам, эфемерные порты переиспользуются ядром
- **autottl работает**: prenat vmap перехватывает SYN/ACK для определения TTL сервера
- **Памяти мало**: основной потребитель — nfqws2 процессы (~2-4MB каждый). 64 воркера ≈ 200MB, 512 ≈ 1.5GB

### Слабые стороны и ограничения

- **TLS fingerprint отличается от curl**: rustls генерирует другой ClientHello (cipher suites, extensions), чем curl/OpenSSL. DPI может реагировать по-разному — покрытие эталона ~71%, а не 100%
- **Нужен root**: SO_MARK, nftables, NFQUEUE требуют привилегий
- **nfqws2 — отдельные процессы**: каждый воркер спавнит nfqws2 (fork+exec). Это ~100ms overhead на стратегию. Для роутеров с медленным CPU/storage это bottleneck
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
// FIXME:
```shell
# Сохранить стратегии в файл:
blockcheckw -w 128 scan -d rutracker.org -o strategies.txt
```

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

Проект основан на [zapret2](https://github.com/bol-van/zapret2) — оригинальном инструменте обхода DPI от bol-van. Все стратегии и логика их генерации взяты из blockcheck2.
