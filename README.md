# Blockcheck Wrapper

[![CI](https://github.com/rcd27/blockcheckw/actions/workflows/ci.yml/badge.svg)](https://github.com/rcd27/blockcheckw/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/rcd27/blockcheckw)](https://github.com/rcd27/blockcheckw/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Быстрая обёртка над [blockcheck2](https://github.com/bol-van/zapret2) для параллельного поиска стратегий обхода DPI.

## Зачем

|                        | blockcheck2.sh        | blockcheckw                        |
|------------------------|-----------------------|------------------------------------|
| Скорость               | ~90 мин (TLS 1.2)     | ~2 мин (1024 воркера)              |
| Параллельность         | нет (последовательно) | vmap dispatch, O(1) lookup         |
| Пропускная способность | ~1 стратегия/сек      | ~150 стратегий/сек                 |
| Язык                   | Bash + curl           | Rust (compiled binary)             |
| TLS fingerprint        | curl/OpenSSL          | rustls                             |
| Установка              | часть zapret2         | отдельный бинарь, install.sh       |

> Задача ускорения подбора может быть также решена путём отброса заведомо нерабочих стратегий, с помощью флагов типа
> --no-{strategy}(сокращением пространства имён стратегий). blockcheckw пошёл путём брут-форса, упор только в RAM

## Как пользоваться

[Quickstart](./docs/QUICKSTART.md) — установка, использование, решение проблем.

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
- **Памяти мало**: основной потребитель — nfqws2 процессы (~2-4MB каждый). 64 воркера ≈ 200MB, 1024 ≈ 1.5GB
- **Удалённый скан**: флаг `--via` позволяет сканировать через удалённый шлюз

### Слабые стороны и ограничения

- **TLS fingerprint отличается от curl**: rustls генерирует другой ClientHello (cipher suites, extensions), чем
  curl/OpenSSL. DPI может реагировать по-разному — покрытие эталона ~71%, а не 100%
- **Нужен root**: SO_MARK, nftables, NFQUEUE требуют привилегий
- **nfqws2 — отдельные процессы**: каждый воркер спавнит nfqws2 (fork+exec). Это ~100ms overhead на стратегию. Для
  роутеров с медленным CPU/storage это bottleneck
- **Батчевая модель**: стратегии обрабатываются батчами по W штук. Последний батч может недоиспользовать воркеры
- **RAM линейно растёт с воркерами**: на роутере с 256MB RAM максимум ~64 воркера

## Благодарности

Проект основан на [zapret2](https://github.com/bol-van/zapret2) — оригинальном инструменте обхода DPI от bol-van. Все
стратегии и логика их генерации взяты из blockcheck2.
