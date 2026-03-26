# Quickstart: blockcheckw

## TL;DR

```bash
# 1. Найти оптимальное число воркеров
blockcheckw benchmark

# 2. Сканировать → проверить лучшие стратегии (pipe)
blockcheckw -w 256 scan -d rutracker.org | blockcheckw check -d rutracker.org --take 10
```

Pipe работает между любыми командами: `scan`, `universal`, `check`.
Все параметры (`-w`, `-d`, `-p`, `--dns`) запоминаются между запусками — достаточно указать один раз.

---

## Требования

- Linux (x86_64, arm64, роутеры на mips/mipsel/arm/ppc/riscv64 — тоже поддерживаются)
- **root**-доступ (нужен для nftables и SO_MARK)
- Установленный [zapret2](https://github.com/bol-van/zapret2) — нужен бинарь `nfqws2`
  (обычно лежит в `/opt/zapret2/nfqws2`).
  **Важно**: ставьте из [релиза](https://github.com/bol-van/zapret2/releases/latest),
  а не через `git clone` — в клоне нет прекомпилированных бинарников
- `nftables` в системе (`nft` в PATH)

## Установка

### Вариант 1: скрипт (рекомендуется)

Скрипт сам определит архитектуру, скачает нужный бинарь из GitHub Releases и проверит
контрольную сумму:

```bash
curl -fsSL https://raw.githubusercontent.com/rcd27/blockcheckw/main/scripts/install.sh | sudo bash
```

Или скачайте скрипт и запустите вручную:

```bash
wget https://raw.githubusercontent.com/rcd27/blockcheckw/main/scripts/install.sh &&
chmod +x install.sh &&
sudo ./install.sh
```

По умолчанию ставится в `/usr/local/bin/blockcheckw`. Можно изменить:

```bash
sudo INSTALL_DIR=/opt/zapret2 ./install.sh
```

### Вариант 2: вручную

1. Откройте [страницу релизов](https://github.com/rcd27/blockcheckw/releases/latest)
2. Скачайте архив под вашу архитектуру (узнать: `uname -m`)
3. Распакуйте и переместите:

```bash
tar xzf blockcheckw-linux-x86_64.tar.gz
sudo mv blockcheckw /usr/local/bin/
sudo chmod +x /usr/local/bin/blockcheckw
```

### Проверка

```bash
blockcheckw --version
```

## Использование

> blockcheckw автоматически поднимает привилегии (sudo) при запуске.

### Глобальные флаги

Эти флаги указываются **перед** именем команды:

| Флаг | Описание |
|------|----------|
| `-w, --workers <N>` | Число параллельных воркеров (1–2048, по умолчанию 8) |
| `--auto` | Автоподтверждение всех промптов (для скриптов) |
| `--via <IP>` | Сканирование через удалённый шлюз (например, Tailscale IP роутера) |

```bash
# Пример: скан через роутер с 512 воркерами
blockcheckw -w 512 --via 100.64.0.2 scan -d rutracker.org
```

### 1. Подбор числа воркеров (benchmark)

Первым делом узнайте, сколько воркеров тянет ваша система:

```bash
blockcheckw benchmark
```

Быстрый прогон (15 секунд на уровень вместо 30):

```bash
blockcheckw benchmark -t 15
```

На роутере с ограниченной памятью:

```bash
blockcheckw benchmark -t 20 -M 64
```

Benchmark автоматически остановится, если памяти не хватает на следующий уровень.
Рекомендованное число запоминается — при следующем запуске `-w` подхватится автоматически.

| Флаг | Описание |
|------|----------|
| `-t, --time <SEC>` | Секунд на уровень (по умолчанию 30, минимум 5) |
| `-M, --max-workers <N>` | Максимум воркеров для теста |
| `-d, --domain <DOMAIN>` | Домен для теста (по умолчанию `rutracker.org`) |
| `-p, --protocol <PROTO>` | Протокол: `http`, `tls12`, `tls13` (по умолчанию `tls12`) |
| `--raw` | Только таблица, без рекомендации (для скриптов) |

### 2. Сканирование — найти рабочие стратегии (scan)

```bash
blockcheckw -w 256 scan -d rutracker.org
```

Это запустит поиск по всем протоколам (HTTP, TLS 1.2, TLS 1.3).

```bash
# Только TLS 1.2:
blockcheckw -w 256 scan -d rutracker.org -p tls12

# С таймаутом 300 секунд:
blockcheckw -w 256 scan -d rutracker.org --timeout 300

# Показать top-10 стратегий вместо top-5:
blockcheckw -w 256 scan -d rutracker.org --top 10

# Кастомные стратегии из файла (вместо встроенного корпуса):
blockcheckw -w 256 scan -d rutracker.org --from-file my_strategies.txt
```

Pipe в check (scan → проверка с data transfer):

```bash
blockcheckw -w 256 scan -d rutracker.org | blockcheckw check -d rutracker.org --take 10
```

Результат сохраняется в файл (JSON + vanilla report) автоматически.

| Флаг | Описание |
|------|----------|
| `-d, --domain <DOMAIN>` | Домен (по умолчанию `rutracker.org`) |
| `-p, --protocols <LIST>` | Протоколы через запятую: `http,tls12,tls13` (по умолчанию все) |
| `--dns <MODE>` | DNS: `auto`, `system`, `doh` (по умолчанию `auto`) |
| `--timeout <SEC>` | Общий таймаут в секундах (0 = без лимита) |
| `--top <N>` | Показать top N стратегий на протокол (0 = все, по умолчанию 5) |
| `-o, --output <FILE>` | Сохранить в указанный файл |
| `--from-file <FILE>` | Загрузить стратегии из файла вместо встроенных |

### 3. Проверка стратегий (check)

Верификация с реальным data transfer (32KB+). Стратегии сортируются по простоте автоматически.

Автоматически детектирует 16KB DPI cap — когда DPI пропускает TLS handshake, но обрывает
соединение после ~16KB данных. Такая стратегия грузит страницу, но ломает видео/скачивание.
check это ловит и помечает стратегию как FAIL.

```bash
# Из pipe (рекомендуется):
blockcheckw -w 256 scan -d rutracker.org | blockcheckw check -d rutracker.org --take 10

# Из файла:
blockcheckw check --from-file 2026-03-22_18-02_report_vanilla.txt -d rutracker.org

# 5 проходов верификации, взять 10 лучших:
blockcheckw check --from-file report_vanilla.txt --take 10 --passes 5
```

**Как работает check:**

- Каждая стратегия проверяется `--passes` раз с реальным GET-запросом (data transfer)
- Если первый проход FAIL — стратегия сразу отбрасывается (early-exit)
- Только стратегии с 100% success rate попадают в результат
- `--take N` останавливает проверку после N верифицированных стратегий на протокол

| Флаг | Описание |
|------|----------|
| `--from-file <FILE>` | Vanilla report или JSON (читает stdin если pipe) |
| `-d, --domain <DOMAIN>` | Домен (по умолчанию `rutracker.org`) |
| `--dns <MODE>` | DNS: `auto`, `system`, `doh` (по умолчанию `auto`) |
| `--timeout <SEC>` | Таймаут на стратегию в секундах (по умолчанию 6, макс 60) |
| `--take <N>` | Остановиться после N верифицированных на протокол (0 = все) |
| `--passes <N>` | Проходов верификации (по умолчанию 3, макс 100) |
| `-o, --output <FILE>` | Сохранить JSON-отчёт в файл |

### 4. Универсальные стратегии (universal)

Найти стратегии, работающие сразу на нескольких заблокированных доменах:

```bash
# Подготовить список доменов:
cat > blocked.txt << 'EOF'
rutracker.org
livejournal.com
linkedin.com
EOF

# Найти универсальные стратегии (сэмпл из 5 доменов):
blockcheckw -w 512 universal --domain-list blocked.txt --sample 5

# Pipe в check для верификации:
blockcheckw -w 512 universal --domain-list blocked.txt --sample 5 | blockcheckw check -d rutracker.org --take 10
```

Стратегии ранжируются по покрытию — сколько доменов из сэмпла они обходят.

| Флаг | Описание |
|------|----------|
| `--domain-list <FILE>` | Файл с доменами (один на строку, пустые строки и `#` игнорируются) |
| `-p, --protocols <LIST>` | Протоколы через запятую (по умолчанию `tls12`) |
| `--dns <MODE>` | DNS: `auto`, `system`, `doh` (по умолчанию `auto`) |
| `--sample <N>` | Сколько доменов тестировать из списка (по умолчанию 10) |
| `-o, --output <FILE>` | Сохранить JSON-отчёт в файл |

### 5. Диагностика доступности (status)

Standalone проверка: открывается домен или нет, и если нет — почему.
Не привязан к стратегиям или zapret2. Просто диагностика.

```bash
blockcheckw status --domain-list blocked.txt
```

Для каждого домена: DNS → TCP connect → TLS/HTTP. По результатам — тип блокировки:
- **available** — домен доступен
- **SNI blocked** — TCP проходит, TLS нет. DPI блокирует по SNI. zapret может обойти
- **IP blocked** — TCP не проходит. Нужен VPN
- **DNS failed** — не резолвится

```
=== Status summary ===
  available: 824/1096 | SNI blocked: 135 | IP blocked: 55 | elapsed: 25.9s
  135 SNI-blocked domains can be bypassed with zapret2
  55 IP-blocked domains require VPN
```

1000+ доменов за ~30 секунд. JSON-отчёт сохраняется автоматически.

| Флаг | Описание |
|------|----------|
| `--domain-list <FILE>` | Файл с доменами (один на строку, `#` — комментарий) |
| `--dns <MODE>` | DNS: `auto`, `system`, `doh` (по умолчанию `auto`) |
| `--timeout <SEC>` | Таймаут на домен в секундах (по умолчанию 6) |
| `-o, --output <FILE>` | Сохранить JSON-отчёт в файл |

## Если zapret2 уже запущен

blockcheckw автоматически обнаружит работающий zapret2 (nfqws2 процессы, nft-таблицы с
queue правилами на порт 443) и предложит временно остановить сервис.

**Поддерживаемые init-системы:** systemd (`systemctl`), OpenWrt/sysv (`/etc/init.d/zapret2`).

Поведение:

- **Сервис найден** — `service stop` перед сканом, `service start` после (автоматически,
  включая Ctrl+C)
- **Сервис не найден** (ручной запуск) — kill nfqws2 по PID + drop nft-таблиц,
  предупреждение о ручном восстановлении
- **Crash** — перезапустите zapret2 вручную (`systemctl start zapret2`)

## Shell completions

```bash
# Установить автодополнение для текущего шелла:
sudo blockcheckw completions --install
```

```bash
# Или вручную для bash:
blockcheckw completions bash >> ~/.bashrc
```

## Решение проблем

**`Permission denied`** — запустите через `sudo`.

**`nfqws2 not found`** — убедитесь, что zapret2 установлен и `nfqws2` доступен
(по умолчанию `/opt/zapret2/nfqws2`).

**`nft: command not found`** — установите nftables:

```bash
# Debian/Ubuntu
apt install nftables
```

```bash
# OpenWrt
opkg install nftables
```

**Скан зависает** — попробуйте уменьшить число воркеров (`-w 16`) или использовать DNS over
HTTPS (`--dns doh`).

**Пакеты дропаются / стратегии ложно проваливаются при большом числе воркеров** — ядро
может не справляться с нагрузкой на NFQUEUE и conntrack. Проверьте и увеличьте лимиты:

```bash
# Длина очереди NFQUEUE (по умолчанию 1024 — мало для 256+ воркеров)
sysctl -w net.netfilter.nf_conntrack_max=131072
sysctl -w net.netfilter.nf_queue_maxlen=65536
```

Чтобы сохранить после перезагрузки:

```bash
echo "net.netfilter.nf_conntrack_max=131072" >> /etc/sysctl.conf
echo "net.netfilter.nf_queue_maxlen=65536" >> /etc/sysctl.conf
sysctl -p
```

## Ссылки

- [zapret2](https://github.com/bol-van/zapret2) — оригинальный проект
- [Релизы blockcheckw](https://github.com/rcd27/blockcheckw/releases)
