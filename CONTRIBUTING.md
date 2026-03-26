# Contributing

## Баги и предложения

[Issues](https://github.com/rcd27/blockcheckw/issues) — версия, архитектура (`uname -m`), команда, лог ошибки.

## Pull Requests

1. Fork, ветка от `main`
2. `./scripts/ci-local.sh` — должно быть зелёное
3. Conventional Commits: `fix:`, `feat:`, `feat(scope)!:`
4. Не используйте 64-bit-only API (`AtomicU64`) — проект собирается под 9 архитектур

Подробнее — [DEV.md](./docs/DEV.md).
