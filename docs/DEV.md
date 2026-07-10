# Разработка blockcheckw

## Локальная проверка перед коммитом

```bash
../scripts/ci-local.sh
```

Скрипт воспроизводит GitHub CI локально. Если прошёл — на CI пройдёт тоже.

### Что проверяется

| Проверка                   | `cargo build` | CI | `./scripts/ci-local.sh` |
|----------------------------|:-------------:|:--:|:-----------------------:|
| Компиляция                 |       +       | +  |        +        |
| `cargo fmt --check`        |       —       | +  |        +        |
| `cargo test --lib`         |       —       | +  |        +        |
| `cargo clippy -D warnings` |       —       | +  |        +        |

`cargo build --release` проверяет **только** компиляцию. Код может собираться, но падать на CI из-за clippy warnings или
неотформатированного кода.

## Dev-контейнер

Запуск `blockcheckw` локально требует root, nftables и собранный nfqws2. Чтобы не засорять хост — dev-контейнер
со всеми зависимостями (тот же образ, что в CI):

```bash
./scripts/dev-container.sh build   # образ: nfqws2 + nftables + rust toolchain
./scripts/dev-container.sh up      # долгоживущий контейнер bcw-dev (--privileged)
./scripts/dev-container.sh run scan -d cloudflare.com   # cargo run -- <args> внутри
./scripts/dev-container.sh shell   # bash внутри контейнера
./scripts/dev-container.sh down
```

Исходники монтируются с хоста: правишь код — `run` пересобирает инкрементально, образ пересобирать не нужно.
Первая сборка внутри контейнера небыстрая (свой `target/` в docker volume).

## Флоу коммита

1. Пишешь код
2. `./scripts/ci-local.sh` — убеждаешься, что всё зелёное
3. `git add` + `git commit` с conventional commit message
4. `git push`

## Conventional Commits

Release-please автоматически генерирует CHANGELOG.md и поднимает версию на основании коммитов:

| Префикс         | Что делает                  | Пример                                    |
|-----------------|-----------------------------|-------------------------------------------|
| `fix:`          | patch bump (0.1.9 → 0.1.10) | `fix: корректный timeout при DNS resolve` |
| `feat:`         | minor bump (0.1.9 → 0.2.0)  | `feat: добавлен autottl detection`        |
| `feat(scope)!:` | major bump (0.1.9 → 1.0.0)  | `feat(core)!: новый формат конфига`       |
| `chore:`        | без bump, без CHANGELOG     | `chore: обновлены зависимости`            |
| `docs:`         | без bump, без CHANGELOG     | `docs: обновлён README`                   |

**Важно:** `!` ставится **после** scope: `feat(core)!:`, а не `feat!(core):`.

## Релизный пайплайн

```
push в main
  └─ CI: fmt → test → clippy
  └─ Release Please: парсит коммиты
       └─ создаёт PR с CHANGELOG.md + version bump в Cargo.toml
            └─ мерж PR → GitHub Release + tag
                 └─ билд бинарей для всех архитектур
                      └─ upload .tar.gz + SHA256SUMS в релиз
```

### Целевые архитектуры

| Архитектура | Target                         | Toolchain | UPX |
|-------------|--------------------------------|-----------|-----|
| x86_64      | x86_64-unknown-linux-musl      | stable    | +   |
| x86         | i586-unknown-linux-musl        | stable    | +   |
| arm64       | aarch64-unknown-linux-musl     | stable    | +   |
| arm         | arm-unknown-linux-musleabi     | stable    | +   |
| mips        | mips-unknown-linux-musl        | nightly   | +   |
| mipsel      | mipsel-unknown-linux-musl      | nightly   | +   |
| mips64      | mips64-unknown-linux-muslabi64 | nightly   | —   |
| ppc         | powerpc-unknown-linux-musl     | nightly   | +   |
| riscv64     | riscv64gc-unknown-linux-musl   | nightly   | +   |
