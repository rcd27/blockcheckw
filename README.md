# Blockcheck Wrapper

Быстрая обёртка над [blockcheck2](https://github.com/bol-van/zapret2) для параллельного поиска стратегий обхода DPI.

> **Статус: WIP** — работает, но активно дорабатывается.

## Зачем

Ванильный `blockcheck2.sh` прогоняет стратегии **последовательно** — одну за другой. На TLS 1.2 это занимает **~90 минут
**.

blockcheckw запускает их **параллельно** и находит рабочие стратегии за **~15 минут** — в 6 раз
быстрее.

### Чем отличается от blockcheck2

|                                | blockcheck2    | blockcheckw                      |
|:-------------------------------|:---------------|:---------------------------------|
| Скорость (TLS 1.2, 64 воркера) | ~90 мин        | **~15 мин**                      |
| Ранжирование                   | плоский список | **топ-N с приоритетами**         |

### Честные оговорки

- Параллелизм использует `--local-port` для изоляции воркеров. Из-за TCP TIME_WAIT мы можем **терять ~30% стратегий** по
  сравнению с ванилой. Отталкиваемся от гипотезы, что для пользователя это не критично
- Стратегии генерируются из **ванильных скриптов blockcheck2** (git submodule). blockcheckw — обёртка, а не замена.

## Быстрый старт

```shell
# Собрать
cargo build --release

# Сканировать (требует root)
sudo ./target/release/blockcheckw -w 64 scan

# Только TLS 1.2
sudo ./target/release/blockcheckw -w 64 scan -p tls12

# Прогнать ванильный отчёт через наш pipeline
sudo ./target/release/blockcheckw -w 64 scan --from-file vanilla_results.txt
```

## Как это работает

```
DNS resolve → Spoofing check → Conflict check → Baseline → Parallel scan → Rank → Report
```

1. **DNS resolve** — резолвит домен, проверяет на DNS spoofing, при необходимости переключается на DoH
2. **Conflict check** — находит и убивает чужие nfqws2 / nft-таблицы, чтобы не мешали скану
3. **Baseline** — проверяет, какие протоколы заблокированы (без bypass)
4. **Parallel scan** — прогоняет все стратегии параллельно (64 воркера, таймаут 2с)
5. **Rank** — ранжирует найденные стратегии по производительности и простоте
6. **Report** — выводит топ-N и сохраняет `report_vanilla.txt` в совместимом формате

### Ранжирование

Все стратегии в результатах **уже проверены на вашем железе и провайдере** — они работают. Ранжирование отвечает на
вопрос: какую развернуть на роутере?

| Критерий               | Вес | Логика                                                                      |
|:-----------------------|:---:|:----------------------------------------------------------------------------|
| **Производительность** | 50% | Меньше пакетов = меньше нагрузка на роутер. `repeats=1` лучше `repeats=260` |
| **Простота**           | 50% | Меньше компонентов = надёжнее. 1 desync action лучше 3 actions + pktmod     |

Звёзды: ★★★ (score >= 80) → ★★☆ (>= 50) → ★☆☆ (< 50).

### Формат отчёта

blockcheckw генерирует `report_vanilla.txt` в формате, совместимом с vanilla blockcheck2:

```
* SUMMARY
curl_test_https_tls12 ipv4 rutracker.org : nfqws2 --payload=tls_client_hello --lua-desync=...
```

Можно скормить ванильный отчёт обратно: `--from-file vanilla_results.txt`.

## Флаги

| Флаг                   | Описание                                                | По умолчанию    |
|:-----------------------|:--------------------------------------------------------|:----------------|
| `-w N`                 | Число параллельных воркеров                             | `8`             |
| `-d` / `--domain`      | Домен для проверки                                      | `rutracker.org` |
| `-p` / `--protocols`   | Протоколы: `http,tls12,tls13`                           | все три         |
| `--dns MODE`           | DNS: `auto`, `system`, `doh`                            | `auto`          |
| `--from-file PATH`     | Загрузить стратегии из файла вместо встроенного корпуса | —               |
| `--top N`              | Показать топ-N (0 = все)                                | `5`             |
| `-o` / `--output FILE` | Сохранить стратегии в файл                              | —               |
| `--timeout N`          | Общий таймаут скана (сек, 0 = без лимита)               | `0`             |

## Сборка

```shell
cargo build --release
```

Кросс-компиляция для роутера (aarch64 + OpenWrt):

```shell
cargo build --release --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/blockcheckw root@router:/tmp/
```

## Shell completions

```shell
# Установить (авто-определяет шелл)
blockcheckw completions --install

# Или вручную
blockcheckw completions bash > ~/.local/share/bash-completion/completions/blockcheckw
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
- curl

## Благодарности

Проект основан на [zapret2](https://github.com/bol-van/zapret2) — оригинальном инструменте обхода DPI от bol-van. Все
стратегии и логика их генерации взяты из blockcheck2. 
