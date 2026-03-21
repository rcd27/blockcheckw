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

На роутере с ограниченной памятью:

```bash
sudo blockcheckw benchmark -t 20 -M 64
```

### 3. Проверка стратегий из ванильного blockcheck2

Если у вас уже есть отчёт от оригинального `blockcheck2.sh`, можно проверить стратегии
оттуда с верификацией:

```bash
sudo blockcheckw check --from-file report_vanilla.txt -d rutracker.org
```

Остановиться после 10 рабочих, 5 проходов верификации:

```bash
sudo blockcheckw check --from-file report_vanilla.txt --take 10 --passes 5
```

## Если zapret2 уже запущен

blockcheckw автоматически обнаружит работающий zapret2 и предложит его остановить на время
скана. После завершения (или Ctrl+C) сервис будет перезапущен.

## Памятка по RAM

| Воркеры | Примерное потребление |
|---------|----------------------|
| 8       | ~30 MB               |
| 64      | ~200 MB              |
| 256     | ~750 MB              |
| 512     | ~1.5 GB              |
| 1024    | ~3 GB                |

На роутере с 256 MB RAM используйте не более 64 воркеров.

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

## Ссылки

- [zapret2](https://github.com/bol-van/zapret2) — оригинальный проект
- [Релизы blockcheckw](https://github.com/rcd27/blockcheckw/releases)
