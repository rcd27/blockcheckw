#!/bin/sh
# blockcheckw installer
# Определяет архитектуру, скачивает бинарь из GitHub Releases, проверяет SHA256.
#
# Использование:
#   curl -fsSL https://raw.githubusercontent.com/rcd27/blockcheckw/main/install.sh | sudo bash
#
# Переменные окружения:
#   INSTALL_DIR  — каталог установки (по умолчанию /usr/local/bin)
#   VERSION      — версия для установки (по умолчанию latest)

set -eu

REPO="rcd27/blockcheckw"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

die() { printf '\033[1;31mОшибка:\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$1"; }

# --- Проверка зависимостей ---

command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || \
    die "Нужен curl или wget"

command -v sha256sum >/dev/null 2>&1 || \
    die "Нужен sha256sum (coreutils)"

command -v tar >/dev/null 2>&1 || \
    die "Нужен tar"

# --- Определение архитектуры ---

detect_arch() {
    machine=$(uname -m)
    case "$machine" in
        x86_64|amd64)           echo "x86_64"  ;;
        i?86|i586|i686)         echo "x86"      ;;
        aarch64|arm64)          echo "arm64"    ;;
        armv7*|armv6*|arm*)     echo "arm"      ;;
        mips64*)                echo "mips64"   ;;
        mipsel*|mipsle*)        echo "mipsel"   ;;
        mips*)                  echo "mips"     ;;
        ppc|powerpc)            echo "ppc"      ;;
        riscv64*)               echo "riscv64"  ;;
        *)  die "Неизвестная архитектура: $machine. Поддерживаются: x86_64, x86, arm64, arm, mips, mipsel, mips64, ppc, riscv64" ;;
    esac
}

ARCH=$(detect_arch)
info "Архитектура: $ARCH"

# --- Определение версии ---

if [ "$VERSION" = "latest" ]; then
    info "Определяю последнюю версию..."
    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    else
        VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    fi
    [ -n "$VERSION" ] || die "Не удалось определить последнюю версию. Проверьте доступ к api.github.com"
fi

info "Версия: $VERSION"

# --- Скачивание ---

TARBALL="blockcheckw-linux-${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

download() {
    url="$1"; dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fSL --retry 3 -o "$dest" "$url"
    else
        wget -q -O "$dest" "$url"
    fi
}

info "Скачиваю ${TARBALL}..."
download "${BASE_URL}/${TARBALL}" "${TMPDIR}/${TARBALL}" || \
    die "Не удалось скачать ${TARBALL}. Проверьте, что релиз ${VERSION} существует: ${BASE_URL}"

info "Скачиваю контрольные суммы..."
download "${BASE_URL}/SHA256SUMS.txt" "${TMPDIR}/SHA256SUMS.txt" || \
    die "Не удалось скачать SHA256SUMS.txt"

# --- Проверка контрольной суммы ---

info "Проверяю SHA256..."
cd "$TMPDIR"
grep "$TARBALL" SHA256SUMS.txt | sha256sum -c --quiet - || \
    die "Контрольная сумма не совпала! Файл мог быть повреждён при скачивании."

# --- Установка ---

info "Распаковываю..."
tar xzf "$TARBALL"

[ -f blockcheckw ] || die "Бинарь не найден в архиве"

mkdir -p "$INSTALL_DIR"
mv blockcheckw "${INSTALL_DIR}/blockcheckw"
chmod +x "${INSTALL_DIR}/blockcheckw"

info "Установлено: ${INSTALL_DIR}/blockcheckw"

# --- Проверка ---

if "${INSTALL_DIR}/blockcheckw" --version >/dev/null 2>&1; then
    ver=$("${INSTALL_DIR}/blockcheckw" --version)
    printf '\033[1;32mГотово!\033[0m %s\n' "$ver"
else
    info "Бинарь установлен, но не запускается (возможно, другая архитектура?)"
    exit 1
fi

# --- Подсказка ---

case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) printf '\n\033[1;33mВнимание:\033[0m %s не в PATH. Добавьте:\n  export PATH="%s:$PATH"\n' "$INSTALL_DIR" "$INSTALL_DIR" ;;
esac

printf '\nСледующий шаг:\n  sudo blockcheckw scan -d rutracker.org\n\n'
