#!/usr/bin/env bash
# Dev-контейнер: blockcheckw + nfqws2 + nftables, живёт постоянно.
# Исходники монтируются с хоста — правка кода не требует пересборки образа.
# Использование:
#   ./scripts/dev-container.sh build          сборка образа (docker/integration.Dockerfile)
#   ./scripts/dev-container.sh up             поднять контейнер bcw-dev
#   ./scripts/dev-container.sh shell          bash внутри контейнера
#   ./scripts/dev-container.sh run <args...>  cargo run -- <args> внутри контейнера
#   ./scripts/dev-container.sh down           остановить и удалить контейнер
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE=blockcheckw-integration
NAME=bcw-dev

case "${1:-}" in
    build)
        if [ ! -f reference/zapret2/nfq2/Makefile ]; then
            echo "==> Инициализирую сабмодуль reference/zapret2..."
            git submodule update --init reference/zapret2
        fi
        docker build -f docker/integration.Dockerfile -t "$IMAGE" .
        ;;
    up)
        # nfqws2 нужен nfnetlink_queue; грузим на хосте, если ещё не загружен
        if ! grep -q nfnetlink_queue /proc/modules; then
            sudo modprobe nfnetlink_queue nft_queue
        fi
        docker rm -f "$NAME" >/dev/null 2>&1 || true
        docker run -d --privileged --name "$NAME" \
            -v "$PWD":/app \
            -v bcw-dev-target:/app/target \
            --entrypoint sleep "$IMAGE" infinity
        echo "✓ Контейнер $NAME запущен. Дальше: shell | run <args>"
        ;;
    shell)
        docker exec -it "$NAME" bash
        ;;
    run)
        shift
        docker exec "$NAME" cargo run --quiet --bin blockcheckw -- "$@"
        ;;
    down)
        docker rm -f "$NAME"
        ;;
    *)
        echo "usage: $0 {build|up|shell|run <args...>|down}" >&2
        exit 1
        ;;
esac
