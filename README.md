# Blockcheck Wrapper

**blockcheckw** — параллельный сканер стратегий обхода DPI. Переписан с `bash` на `Rust`.
Оригинальный `blockcheck2.sh` проверяет стратегии последовательно — одну за другой.
`blockcheckw` запускает их параллельно, изолируя воркеры через выделенные диапазоны портов.

## Как это работает

Каждый воркер получает изолированный слот:
- Уникальный диапазон source-портов (sport) для curl `--local-port`
- Персональное nftables-правило, матчащее только его sport-диапазон
- Свой экземпляр nfqws2 на выделенной NFQUEUE

Это позволяет запускать десятки стратегий одновременно без конфликтов.

### Pipeline команды scan

```
ISP detect → DNS resolve (+ spoofing check) → Conflict check → Baseline → Generate strategies → Run parallel → Verify → Rank → Summary
```

1. **ISP detect** — определяет провайдера через `curl ipinfo.io` (IP, ASN, город). Отображается как фиксированная строка под progress bar на протяжении всего сканирования
2. **DNS resolve** — резолвит домен с учётом `--dns` режима (см. ниже). В режиме `auto` автоматически обнаруживает DNS spoofing и переключается на DoH
3. **Conflict check** — обнаруживает работающие процессы nfqws2 и nft-таблицы с queue-правилами на порт 443 (см. [Детекция конфликтов](#детекция-конфликтов))
4. **Baseline** — проверяет каждый протокол без bypass (curl с `--connect-to` для привязки к резолвленному IP), определяет заблокированные
5. **Generate** — генерирует все стратегии для заблокированных протоколов (2449 HTTP / 9828 TLS1.3 / 19644 TLS1.2)
6. **Run parallel** — прогоняет стратегии параллельно через worker pool (быстрый скан, таймаут 1s). Каждый curl-запрос использует `--connect-to` для привязки к резолвленному IP
7. **Verify** — перепроверяет найденные стратегии N раз с увеличенным таймаутом (3s), отсеивает нестабильные (false positives из-за сетевого джиттера)
8. **Ranking** — ранжирует стратегии по 4 измерениям (совместимость, простота, универсальность, производительность), выводит топ-N со звёздами и пояснениями

## Сборка

```shell
cargo build --release
```

Кросс-компиляция и деплой для роутера (aarch64 + OpenWrt/musl):
```shell
cargo build --release --target aarch64-unknown-linux-musl &&
scp target/aarch64-unknown-linux-musl/release/blockcheckw root@router:/tmp/
```

## Тесты

### Unit-тесты
```shell
cargo test --lib
```

### Бенчмарк: автоопределение оптимального числа воркеров

```shell
blockcheckw benchmark
```

Автоматически тестирует степени двойки (1, 2, 4, ...) до `CPU * 16` и выдаёт готовую рекомендацию:

```
=== blockcheckw benchmark ===
domain=rutracker.org  protocol=HTTP  strategies=64  max_workers=128

 Workers  Elapsed(s)  Throughput  Speedup  Errors
 -------  ----------  ----------  -------  ------
      1*        8.85       0.9/s     1.0x       0
       2       36.80       1.7/s     1.9x       0
       4       19.50       3.3/s     3.7x       0
       8       10.40       6.2/s     6.9x       0
      16        6.10      10.5/s    11.7x       0
      32        3.50      18.3/s    20.3x       0
      64        2.40      27.1/s    30.1x       0
     128        2.80      22.7/s    25.2x       0
  * baseline probe: 8 strategies (I/O-bound, throughput stable)

Recommended: blockcheckw -w 64
```

**Как читать таблицу:**

| Колонка      | Значение                                                       |
|:-------------|:---------------------------------------------------------------|
| `Workers`    | Число параллельных воркеров в этом прогоне                     |
| `Elapsed(s)` | Время выполнения прогона в секундах                            |
| `Throughput` | Стратегий в секунду — основная метрика                         |
| `Speedup`    | Ускорение относительно baseline (worker=1)                     |
| `Errors`     | Инфраструктурные ошибки (nftables/nfqws2), не путать с FAILED  |
| `1*`         | Probe-прогон: 8 стратегий вместо полного набора для быстрого baseline. Нагрузка I/O-bound, throughput не зависит от количества стратегий |

**Алгоритм выбора оптимума:**
1. Отбросить точки с ошибками (errors > 0)
2. Найти максимальный throughput
3. Порог = 90% от максимума
4. Выбрать минимальное число воркеров, достигающее порога

**Флаги:**

| Флаг | Описание | По умолчанию |
|:-----|:---------|:-------------|
| `-s N` / `--strategies N` | Количество фейковых стратегий для прогона | 64 |
| `-M N` / `--max-workers N` | Верхняя граница поиска воркеров | CPU * 16 |
| `--raw` | Только таблица без рекомендации (для скриптов) | off |

**Примеры:**

```shell
# Быстрый тест на слабом железе
blockcheckw benchmark -s 16 -M 16

# Полный тест с расширенным диапазоном
blockcheckw benchmark -s 128 -M 256

# Для парсинга скриптом
blockcheckw benchmark --raw
```

## Запуск

### Scan — поиск рабочих стратегий

```shell
blockcheckw scan
```

По умолчанию сканирует `rutracker.org` по всем трём протоколам (HTTP, TLS1.2, TLS1.3).
Количество воркеров задаётся глобальным флагом `-w`.

```
=== DNS resolve ===
  dns mode: auto
  rutracker.org → 104.21.32.39, 172.67.182.196 (via system)
  ✓ DNS spoofing check: clean

=== Baseline (without bypass) ===
  ✗ HTTP: BLOCKED (UNAVAILABLE code=28)
  ✗ HTTPS/TLS1.2: BLOCKED (UNAVAILABLE code=28)
  ✓ HTTPS/TLS1.3: available without bypass

Blocked protocols: HTTP, HTTPS/TLS1.2

=== Scanning HTTP ===
  generated 2449 strategies, workers=64
  completed: 2449 | success: 149 | failed: 2300 | errors: 0 | 86.4s (28.4 strat/sec)

=== Verifying HTTP ===
  149 candidates, 3 passes, timeout=3s
  verify pass 1/3
  verify pass 2/3
  verify pass 3/3
  verified: 8/149 strategies (3/3 passes each)

=== Summary for rutracker.org ===
  ✓ HTTPS/TLS1.3: working without bypass
  ✓ HTTP: 8 working strategies found
=== Top strategies for HTTP (5 of 8) ===
  #1  ★★★ nfqws2 --payload=http_req --lua-desync=http_unixeol
          (universal)
  #2  ★★★ nfqws2 --payload=http_req --lua-desync=multisplit:pos=method+2
          (universal)
  #3  ★★☆ nfqws2 --payload=http_req --lua-desync=fake:blob=fake_default_http:ip_autottl=-4,3-20:repeats=1
  #4  ★★☆ nfqws2 --payload=http_req --lua-desync=hostfakesplit:ip_ttl=6:repeats=1
          (TTL-dependent (hop count specific))
  #5  ★☆☆ nfqws2 --payload=http_req --lua-desync=fake:blob=fake_default_http:tcp_md5:repeats=1 --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5
          (tcp fooling, may fail on some networks, multi-stage, complex)
  ... and 3 more (use --top 0 to show all)
  ✗ HTTPS/TLS1.2: no working strategies found
```

#### DNS и `--connect-to`

По умолчанию curl делает собственный DNS-резолв, что приводит к проблемам:
- Если DNS отравлен, curl идёт на IP заглушки, а nftables ловит трафик на правильном IP — мимо
- Даже без poisoning, DNS-ответы могут отличаться от того, что резолвил blockcheckw

Решение: blockcheckw резолвит домен один раз и передаёт IP в каждый curl через `--connect-to domain::ip:`.
Это гарантирует, что curl, nftables и nfqws2 работают с одним и тем же IP.

**DNS режимы** (`--dns`):

| Режим    | Поведение |
|:---------|:----------|
| `auto`   | System DNS + проверка на spoofing (сравнивает результаты system DNS и DoH для известных заблокированных доменов). Если spoofing обнаружен — автоматически переключается на DoH |
| `system` | Только system DNS (`getent` / `nslookup`), без проверки на spoofing |
| `doh`    | Только DNS-over-HTTPS (Cloudflare, Google, Quad9) |

**DoH резолвер** автоматически перебирает серверы (Cloudflare → Google → Quad9) и использует первый доступный. Запросы идут через Cloudflare JSON API (`application/dns-json`).

**Spoofing detection** резолвит 3 домена (`rutracker.org`, `pornhub.com`, `torproject.org`) через system DNS и DoH, сравнивает результаты. Если IP различаются или все домены резолвятся в один IP (captive portal) — сигнализирует spoofing.

#### Детекция конфликтов

Если на устройстве уже работает продакшн-инстанс nfqws2 (например, через zapret2), его nft-правила перехватывают тот же трафик на портах 80/443. Когда blockcheckw добавляет свои правила, пакеты проходят через **две** NFQUEUE — продакшн и тестовую. Двойная модификация ломает TLS handshake, и все стратегии возвращают таймаут (code=28).

blockcheckw автоматически детектирует конфликты перед сканированием:
- Работающие процессы nfqws2 (`pgrep`)
- nft-таблицы (кроме собственной и `fw4`) с queue-правилами на порт 443

При обнаружении конфликтов выводится интерактивный промпт:

```
WARNING conflicting DPI bypass detected:
  ! running nfqws2 processes found
  ! nft table 'inet zapret2' has queue rules intercepting port 443

  Kill nfqws2 and drop conflicting nft tables to proceed? [Y/n]
```

- **Y** / Enter — убивает nfqws2, удаляет конфликтующие nft-таблицы, продолжает сканирование
- **n** — прерывает с кодом 1

> **Примечание:** после завершения blockcheckw продакшн-сервис нужно перезапустить вручную (например, `service zapret2 restart`).

#### Как работает верификация

Быстрый скан (таймаут 1s) может давать false positives — стратегии, которые «сработали» случайно из-за сетевого джиттера. Верификация перепроверяет каждого кандидата:

- Прогоняет **только найденные стратегии** (не все 2449) — это быстро
- Каждая стратегия проверяется **N раз** (по умолчанию 3)
- Таймаут увеличен до **3 секунд** (vs 1s при скане) — строже
- В Summary попадают только стратегии, прошедшие **все N проверок**

#### Ranking стратегий

**Killer feature, которой нет в vanilla blockcheck2.sh.** Вместо вываливания сотен стратегий без пояснений, blockcheckw ранжирует результаты по качеству и показывает топ-N с пояснениями.

Каждая стратегия оценивается по 4 измерениям (0–100 баллов каждое):

| Измерение | Вес | Что оценивает |
|:----------|:---:|:--------------|
| **Compatibility** | 40% | Без fooling (100) > autottl (70) > fixed TTL (50) > tcp fooling (20) |
| **Simplicity** | 25% | 1 desync action (100) > 2 actions (70) > multi-stage (40) > complex (20) |
| **Universality** | 20% | Без TTL-зависимости (100) > autottl (60) > fixed ip_ttl (30) |
| **Performance** | 15% | Без overhead (100) > repeats 2–20 (70) > high repeats/multi-stage (40/20) |

Итоговый score = взвешенная сумма → звёзды:
- ★★★ = score ≥ 75 (работает везде, минимум сложности)
- ★★☆ = score ≥ 45 (работает, но с оговорками)
- ★☆☆ = score < 45 (последний resort)

Текстовые теги поясняют слабые стороны: `universal`, `TTL-dependent`, `tcp fooling`, `multi-stage, complex`, `high packet overhead`.

По умолчанию показывается топ-5. `--top 0` — полный список без обрезки.

С `--verbose` видно детали по каждой стратегии:
```
  ✓ nfqws2 --payload=http_req --lua-desync=fake:ip_ttl=4: 3/3
  ✗ nfqws2 --payload=http_req --lua-desync=fake:ip_ttl=1: 1/3
```

**Флаги:**

| Флаг | Описание | По умолчанию |
|:-----|:---------|:-------------|
| `-d` / `--domain` | Домен для проверки | `rutracker.org` |
| `-p` / `--protocols` | Протоколы через запятую: `http`, `tls12`, `tls13` | `http,tls12,tls13` |
| `--dns MODE` | DNS режим: `auto`, `system`, `doh` | `auto` |
| `--verify-passes N` | Количество проверочных прогонов (0 = пропустить) | `3` |
| `--verify-min N` | Минимум успешных прогонов для верификации | `= verify-passes` |
| `--verify-timeout T` | Таймаут curl при верификации (секунды) | `3` |
| `--top N` | Показать топ-N ранжированных стратегий (0 = все) | `5` |
| `--verbose` | Показать результат по каждой стратегии | off |

**Примеры:**

```shell
# Только HTTP с 64 воркерами
blockcheckw -w 64 scan -p http

# Конкретный домен, только TLS
blockcheckw -w 32 scan -d example.com -p tls12,tls13

# Все протоколы (по умолчанию)
blockcheckw -w 64 scan

# Принудительный DoH (в сетях с отравленным DNS)
blockcheckw -w 64 scan --dns doh

# System DNS без spoofing check
blockcheckw -w 64 scan --dns system

# Без верификации (как раньше)
blockcheckw -w 64 scan --verify-passes 0

# Мягкая верификация: 2 из 3 достаточно
blockcheckw -w 64 scan --verify-min 2

# Топ-3 лучших стратегии
blockcheckw -w 64 scan --top 3

# Все стратегии без обрезки (vanilla-стиль)
blockcheckw -w 64 scan --top 0

# 5 проходов, подробный вывод
blockcheckw -w 64 scan --verify-passes 5 --verbose
```

## Производительность

Результаты нагрузочного теста — 1000 стратегий, NanoPi R3S:

| Workers | Время | Throughput | Ускорение |
|--------:|------:|-----------:|----------:|
| 1       | ~17m  |  ~1.0/sec  |     1.0x  |
| **64**  |**46.7s**|**21.4/sec**| **~21x** |

Масштабирование почти линейное до 64 воркеров. 0 ошибок.

### Тестовый стенд

- **Роутер**: FriendlyElec NanoPi R3S
- **CPU**: 4x ARM Cortex-A53
- **RAM**: 2 GB
- **OS**: OpenWrt 25.12, kernel 6.12
- **Бинарник**: статически слинкованный `aarch64-unknown-linux-musl`, ~4.9 MB

## Зависимости

- Rust (edition 2021)
- tokio (async runtime)
- regex (парсинг ISP info)
- nfqws2 в `/opt/zapret2/`
- nftables
- curl

## Обновить git submodule

```shell
git submodule update --remote reference/zapret2
```
