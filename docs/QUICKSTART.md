# Quickstart: blockcheckw

## Требования

- Linux (x86_64, arm64, роутеры на mips/mipsel/arm/ppc/riscv64 — тоже поддерживаются)
- **root**-доступ (нужен для nftables и SO_MARK)
- Установленный [zapret2](https://github.com/bol-van/zapret2) — нужен бинарь `nfqws2`
  (обычно лежит в `/opt/zapret2/nfqws2`)
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

> Все команды нужно запускать от **root** (`sudo`).

### 1. Сканирование — найти рабочие стратегии

```bash
sudo blockcheckw scan -d rutracker.org
```

Это запустит поиск по всем протоколам (HTTP, TLS 1.2, TLS 1.3). По умолчанию используется
8 воркеров.

Больше воркеров = быстрее (но больше RAM):

```bash
# Для VPS/десктопа с запасом RAM:
sudo blockcheckw -w 256 scan -d rutracker.org

# Только TLS 1.2:
sudo blockcheckw -w 256 scan -d rutracker.org -p tls12
```

Сохранить результат в файл:

```bash
sudo blockcheckw -w 256 scan -d rutracker.org -o report.txt
```

### 2. Подбор числа воркеров (benchmark)

Не знаете, сколько воркеров поставить? benchmark подберёт оптимальное значение:

```bash
sudo blockcheckw benchmark
```

Быстрый прогон (15 секунд на уровень вместо 30):

```bash
sudo blockcheckw benchmark -t 15
```

На роутере с ограниченной памятью:

```bash
sudo blockcheckw benchmark -t 20 -M 64
```

### 3. Проверка стратегий (check)

Двухфазная проверка стратегий из vanilla-отчёта с реальным data transfer.

```bash
# Базовый запуск (все стратегии, 3 прохода верификации):
sudo blockcheckw check --from-file report_vanilla.txt -d rutracker.org
```

```bash
# Early stop после 10 рабочих, 5 проходов верификации, JSON в файл:
sudo blockcheckw check --from-file report_vanilla.txt --take 10 --passes 5 -o result.json
```

```bash
# Без верификации (одиночный проход, как scan):
sudo blockcheckw check --from-file report_vanilla.txt --passes 1
```

**Как работает check:**

- **Фаза 1 (отсев):** GET-запрос на каждую стратегию. HTTP-ответ = стратегия работает
  (timeout/reset = DPI блокирует, HTTP 400 = fakes дошли до сервера, redirect на чужой
  домен = заглушка провайдера).
- **Фаза 2 (верификация):** каждая рабочая стратегия проверяется `--passes` раз.
  Считается `success_rate`, медианная латентность, stability verdict. Финальный ранг:
  `stability × 0.6 + rank_score × 0.4`. Лучшая стратегия выводится как **BEST**.

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

**`Permission denied` / `Operation not permitted`** — запускайте через `sudo`.

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
