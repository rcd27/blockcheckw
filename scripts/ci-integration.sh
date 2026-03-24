#!/usr/bin/env bash
# Запуск интеграционных тестов в Docker-контейнере с --privileged.
# Требует: Docker, sudo (для modprobe).
# Использование: sudo ./scripts/ci-integration.sh
set -euo pipefail

echo "=== Loading kernel modules ==="
modprobe nfnetlink_queue 2>/dev/null || true
modprobe nf_tables       2>/dev/null || true
modprobe nft_queue       2>/dev/null || true

echo "=== Building Docker image ==="
docker build -f docker/integration.Dockerfile -t blockcheckw-integration .

echo "=== Running e2e_infra tests ==="
docker run --rm --privileged blockcheckw-integration --test e2e_infra -- --nocapture

echo "=== Running parallel_benchmark tests ==="
docker run --rm --privileged blockcheckw-integration --test parallel_benchmark -- --nocapture || {
    echo "WARNING: parallel_benchmark failed (may be flaky due to network access)"
}

echo ""
echo "✓ Integration tests complete"
