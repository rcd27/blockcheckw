# Quickstart: blockcheckw

## TL;DR
// FIXME
```bash
# Всё в одну строку: benchmark → scan → check
blockcheckw benchmark | xargs -I{} blockcheckw -w {} scan -d rutracker.org | blockcheckw check -d rutracker.org --take 10
```

Или по шагам:

```bash
# 1. Найти оптимальное число воркеров
blockcheckw benchmark

# 2. Сканировать (подставить число из benchmark)
blockcheckw -w 1024 scan -d rutracker.org

# 3. Проверить найденные стратегии (pipe из scan)
blockcheckw -w 1024 scan -d rutracker.org | blockcheckw check -d rutracker.org --take 10
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

### 2. Сканирование — найти рабочие стратегии

```bash
blockcheckw -w 256 scan -d rutracker.org
```

Это запустит поиск по всем протоколам (HTTP, TLS 1.2, TLS 1.3).

```bash
# Только TLS 1.2:
blockcheckw -w 256 scan -d rutracker.org -p tls12
```

Pipe в check (scan → проверка с data transfer):

```bash
blockcheckw -w 256 scan -d rutracker.org | blockcheckw check -d rutracker.org --take 10
```

Результат всегда сохраняется в файл (JSON + vanilla report), даже при pipe.

### 3. Проверка стратегий (check)

Верификация с реальным data transfer. Стратегии сортируются по простоте автоматически.

```bash
# Из pipe (рекомендуется):
blockcheckw -w 256 scan -d rutracker.org | blockcheckw check -d rutracker.org --take 10

# Из файла:
blockcheckw check --from-file report_vanilla.txt -d rutracker.org

# 5 проходов верификации:
blockcheckw check --from-file report_vanilla.txt --take 10 --passes 5
```

**Как работает check:**

Каждая стратегия проверяется `--passes` раз с реальным GET-запросом (data transfer).
Если первый проход FAIL — стратегия сразу отбрасывается (early-exit).
Только стратегии с 100% success rate попадают в результат.
`--take N` останавливает проверку после N верифицированных стратегий на протокол.

### 4. Универсальные стратегии (universal)

Найти стратегии, работающие на нескольких доменах:

```bash
blockcheckw -w 1024 universal --domain-list blocked.txt --sample 5 | blockcheckw check -d rutracker.org --take 10
```

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
