#!/usr/bin/env bash
# Локальная проверка — аналог GitHub CI.
# Запускай перед коммитом: ./ci-local.sh
set -euo pipefail

echo "=== cargo fmt --check ==="
cargo fmt --check

echo "=== cargo test --lib ==="
cargo test --lib

echo "=== cargo clippy ==="
cargo clippy -- -D warnings

echo ""
echo "✓ Все проверки пройдены"
