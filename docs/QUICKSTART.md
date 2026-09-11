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
- Установленный [zapret2](https://github.com/bol-van/zapret2) версии **v1.0.5 или новее** —
  нужен бинарь `nfqws2` (обычно лежит в `/opt/zapret2/nfqws2`). Версия важна: с v1.0.5 в
  `nfqws2` появился `--filter-mark`, на котором держится весь параллелизм blockcheckw.
  На более старой сборке blockcheckw откажется стартовать (`exit code 6`,
  сообщение "nfqws2 does not support --filter-mark: requires build >= v1.0.5") —
  обновите zapret2 из [релиза](https://github.com/bol-van/zapret2/releases/latest).
  **Важно**: ставьте именно из релиза, а не через `git clone` — в клоне нет
  прекомпилированных бинарников
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

### Обновление

```bash
blockcheckw --upgrade
```

`--version` проверяет GitHub на наличие новой версии и подсказывает `--upgrade` если есть.
`--upgrade` скачивает и устанавливает последний релиз через `install.sh`.

## Использование

> blockcheckw автоматически поднимает привилегии (sudo) при запуске.

### Глобальные флаги

Эти флаги указываются **перед** именем команды:

| Флаг                          | Описание                                                                                   |
|-------------------------------|--------------------------------------------------------------------------------------------|
| `-w, --workers <N>`           | Число параллельных воркеров (1–1024 по умолчанию; см. ниже про потолок)                    |
| `--profiles-per-instance <N>` | Сколько стратегий держать в одном `nfqws2` одновременно (по умолчанию 1024, потолок 65535) |
| `-V, --version`               | Текущая версия + проверка обновлений на GitHub                                             |
| `--upgrade`                   | Обновление до последнего релиза                                                            |
| `--auto`                      | Автоподтверждение всех промптов (для скриптов)                                             |
| `--via <IP>`                  | Сканирование через удалённый шлюз (например, Tailscale IP роутера)                         |

`--workers` не может превышать `--profiles-per-instance`: план из K профилей не может
обслужить больше K проб в полёте одновременно. По умолчанию `--profiles-per-instance` —
1024, поэтому по умолчанию воркеров тоже не больше 1024. Флаг `--workers` формально
принимает значения до 2048, но чтобы реально использовать больше 1024, поднимите
`--profiles-per-instance` (потолок — 65535):

```bash
# Пример: скан через роутер с 512 воркерами
blockcheckw -w 512 --via 100.64.0.2 scan -d rutracker.org

# Пример: 2048 воркеров — нужно поднять и потолок профилей
blockcheckw --profiles-per-instance 2048 -w 2048 scan -d rutracker.org
```

**Важно**: `--workers` запоминается между запусками (см. TL;DR выше), а
`--profiles-per-instance` — нет. Если вы когда-то запускали с `-w`, большим
1024, без `--profiles-per-instance`, следующий запуск ЛЮБОЙ команды (включая
`check`, которой воркеры не нужны) откажет с `exit code 2` и сообщением про
превышение потолка. Лечится либо повторным `--profiles-per-instance N`,
либо перезаданием `-w` на значение не больше 1024.

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

| Флаг                     | Описание                                                  |
|--------------------------|-----------------------------------------------------------|
| `-t, --time <SEC>`       | Секунд на уровень (по умолчанию 30, минимум 5)            |
| `-M, --max-workers <N>`  | Максимум воркеров для теста                               |
| `-d, --domain <DOMAIN>`  | Домен для теста (по умолчанию `rutracker.org`)            |
| `-p, --protocol <PROTO>` | Протокол: `http`, `tls12`, `tls13` (по умолчанию `tls12`) |
| `--raw`                  | Только таблица, без рекомендации (для скриптов)           |

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

# Уточнить IP-блокировку через прокси (syn_blocked vs host_dead):
# scan идёт напрямую, прокси используется ТОЛЬКО для проверки живости IP-blocked хоста.
blockcheckw -w 256 scan -d rr3---sn-x.googlevideo.com --alive-via socks5://127.0.0.1:1080
```

Вывод `block_type` (см. [README](../README.md#классификация-блокировки-block_type)):
`not_blocked` / `throttled` / `sni_blocked` / `ip_blocked` / `syn_blocked` / `host_dead` / `dns_failed`.
Плюс отдельный флаг `dns_spoofed: bool` (system-DNS отравлен; ортогонален `block_type`).
Без `--alive-via` прямой SYN-дроп остаётся `ip_blocked`; с ним уточняется в
`syn_blocked` (хост жив через прокси) либо `host_dead`.

Pipe в check (scan → проверка с data transfer):

```bash
blockcheckw -w 256 scan -d rutracker.org | blockcheckw check -d rutracker.org --take 10
```

Результат сохраняется в файл (JSON + vanilla report) автоматически.

| Флаг                     | Описание                                                                                                    |
|--------------------------|-------------------------------------------------------------------------------------------------------------|
| `-d, --domain <DOMAIN>`  | Домен (по умолчанию `rutracker.org`)                                                                        |
| `-p, --protocols <LIST>` | Протоколы через запятую: `http,tls12,tls13` (по умолчанию все)                                              |
| `--dns <MODE>`           | DNS: `auto`, `system`, `doh` (по умолчанию `auto`)                                                          |
| `--timeout <SEC>`        | Общий таймаут в секундах (0 = без лимита)                                                                   |
| `--top <N>`              | Показать top N стратегий на протокол (0 = все, по умолчанию 5)                                              |
| `-o, --output <FILE>`    | Сохранить в указанный файл                                                                                  |
| `--from-file <FILE>`     | Загрузить стратегии из файла вместо встроенных                                                              |
| `--alive-via <PROXY>`    | Прокси ТОЛЬКО для проверки живости IP-blocked хоста (не маршрутизирует скан) → `syn_blocked` vs `host_dead` |

### 3. Проверка стратегий (check)

`check` мерит **две оси** и не сливает их в один ответ:

- **главная** — провёл ли десинк нас через DPI. Это и есть поле `working`: байты цели
  потекли, разговор не прервали, содержимое не разошлось с эталоном;
- **побочная** — подлинный ли ресурс вернулся. Это круг судеб `admits`: `Good` /
  `Grinding` / `Mirage` / `Trap` / `Dead` (подробности —
  [README](../README.md#судьба-цели-observed-и-admits)). Порядок выдачи задаёт судьба,
  простота — тай-брейкер при прочих равных.

**Неустановленная подлинность вердикта о канале не отменяет.** `working: false` ставится
только при положительном свидетельстве против: байтов не было, разговор прервали
(сброс или TLS-алерт посреди передачи), либо содержимое с эталоном **разошлось**
(`admits: ["Mirage"]`). Без `--reference-via` круг судеб честно остаётся широким, а
стратегия, проведшая байты через DPI, всё равно считается рабочей.

**`Good` объявляется только при `--reference-via`.** Без чистого egress для эталона
«байты текут» и «ресурс тот самый» неразличимы, и check честно оставляет круг из трёх
судеб — но на `working` это не влияет.

```bash
# Из pipe (рекомендуется), с эталоном через чистый egress:
blockcheckw -w 256 scan -d rutracker.org | blockcheckw check -d rutracker.org --take 10 --reference-via socks5://127.0.0.1:1080

# Из файла:
blockcheckw check --from-file 2026-03-22_18-02_report_vanilla.txt -d rutracker.org
```

**Как работает check:**

- Каждый прогон делает пробу без десинка (контроль) и судит её ТОЙ ЖЕ мерой, что и
  стратегии. Если контроль сам прошёл, в отчёте стоит `inconclusive: true` — домен на
  этой линии не режется, и о стратегиях прогон не говорит ничего
- `observed: "Unobserved"` — это недосмотр check, а не приговор домену
- `--take N` останавливает проверку после N прошедших стратегий на протокол
- Проба идёт не в корень, а по `--probe-path` (умолчание `/robots.txt`): главный вердикт
  от пути не зависит, а сверке с эталоном детерминированный путь нужен — он не редиректит
  и не гуляет в объёме. Нет `robots.txt` — сервер отдаст `404`, и это полноценная проба:
  эталон получит тот же `404` и сойдётся. Отката на `/` нет намеренно; корень
  запрашивается явно — `--probe-path /`

| Флаг                          | Описание                                                                   |
|-------------------------------|-----------------------------------------------------------------------------|
| `--from-file <FILE>`          | Vanilla report или JSON (читает stdin если pipe)                            |
| `-d, --domain <DOMAIN>`       | Домен (по умолчанию `rutracker.org`)                                        |
| `--dns <MODE>`                | DNS: `auto`, `system`, `doh` (по умолчанию `auto`)                          |
| `--timeout <SEC>`             | Таймаут на стратегию в секундах (по умолчанию 6, макс 60)                   |
| `--take <N>`                  | Остановиться после N верифицированных на протокол (0 = все)                 |
| `--reference-via <ENDPOINT>`  | Чистый egress для эталона ответа. Без него `Good` не объявляется            |
| `--probe-path <PATH>`         | Путь пробы (по умолчанию `/robots.txt`). Отката на `/` нет: `404` — полноценная проба |
| `--passes <N>`                | **устарел**, игнорируется — вердикт больше не булев, голосовать не по чему  |
| `-o, --output <FILE>`         | Сохранить JSON-отчёт в файл                                                 |

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

| Флаг                     | Описание                                                           |
|--------------------------|--------------------------------------------------------------------|
| `--domain-list <FILE>`   | Файл с доменами (один на строку, пустые строки и `#` игнорируются) |
| `-p, --protocols <LIST>` | Протоколы через запятую (по умолчанию `tls12`)                     |
| `--dns <MODE>`           | DNS: `auto`, `system`, `doh` (по умолчанию `auto`)                 |
| `--sample <N>`           | Сколько доменов тестировать из списка (по умолчанию 10)            |
| `-o, --output <FILE>`    | Сохранить JSON-отчёт в файл                                        |

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

| Флаг                   | Описание                                            |
|------------------------|-----------------------------------------------------|
| `--domain-list <FILE>` | Файл с доменами (один на строку, `#` — комментарий) |
| `--dns <MODE>`         | DNS: `auto`, `system`, `doh` (по умолчанию `auto`)  |
| `--timeout <SEC>`      | Таймаут на домен в секундах (по умолчанию 6)        |
| `-o, --output <FILE>`  | Сохранить JSON-отчёт в файл                         |

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

**`nfqws2 does not support --filter-mark: requires build >= v1.0.5`** (выход с
кодом 6, при "Checking prerequisites") — установленный `nfqws2` старее v1.0.5.
Обновите zapret2 до v1.0.5 или новее из
[релиза](https://github.com/bol-van/zapret2/releases/latest) — см.
[Требования](#требования).

**`--workers N exceeds --profiles-per-instance ...`** (выход с кодом 2) —
`--workers` запомнился из прошлого запуска большим, чем текущий потолок
`--profiles-per-instance` (по умолчанию 1024); это может произойти на ЛЮБОЙ
команде, включая `check`. Либо поднимите `--profiles-per-instance` до нужного
значения, либо перезадайте `-w` числом не больше 1024.

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
