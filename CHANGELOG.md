# Changelog

## [0.3.1](https://github.com/rcd27/blockcheckw/compare/v0.3.0...v0.3.1) (2026-03-21)


### Features

* **docs:** QUICKSTART.md, версия утилиты ([efaad40](https://github.com/rcd27/blockcheckw/commit/efaad40420835e9a19b15d09a4e7fc512fae0b58))


### Bug Fixes

* **docs:** разделение readme и quickstart ([df9f568](https://github.com/rcd27/blockcheckw/commit/df9f5689418e4543d288a5fc80fa5140ba1cf986))
* **fp:** вынос сайд-эффекта ([fa9374b](https://github.com/rcd27/blockcheckw/commit/fa9374b259a82132e788f0c0c00e67a0eaaf1b5e))
* **performance:** ненужные копирования строк между воркерами ([a0ad7d9](https://github.com/rcd27/blockcheckw/commit/a0ad7d9b1c22c3fed2a54f5bd43c3cea62ce30dc))

## [0.3.0](https://github.com/rcd27/blockcheckw/compare/v0.2.2...v0.3.0) (2026-03-21)


### ⚠ BREAKING CHANGES

* авто-определение `nobody uid/gid`, убран хардкод
* panic hook без timeout мог уводить роутеры в reboot
* **nfqws2:** killall nfqws2 заменён на sertvice stop/start (systemd / init.d), fallback без сервиса + gracefull exit с восстановлением

### Features

* **error-prone:** валидация CLI аргументов ([f9fd623](https://github.com/rcd27/blockcheckw/commit/f9fd623c1bbce0d81724d7fa6e579733117b073a))
* **error-prone:** проверка жизни nfqws2 при старте, если упал, то отображаем это соответственно, без магических sleep(100) ([c04ea7c](https://github.com/rcd27/blockcheckw/commit/c04ea7caec73a69fdbede83afeac24189ad4c655))
* **error-prone:** проверка на наличие запущенного процесса `blockcheckw` ([0e43a7a](https://github.com/rcd27/blockcheckw/commit/0e43a7a3c7c3084884f7756de27926086501ceb1))
* **nfqws2:** killall nfqws2 заменён на sertvice stop/start (systemd / init.d), fallback без сервиса + gracefull exit с восстановлением ([55647e0](https://github.com/rcd27/blockcheckw/commit/55647e0c3eff847d5c17fe82f2ef4e697bf0bf7d))
* **ux:** check_prerequisites на наличие необходимого окружения ([e9a7c07](https://github.com/rcd27/blockcheckw/commit/e9a7c07bd103f0ae760b16f2135ac33ca8f243e2))
* **ux:** добавлена обработка повторного CTRL+C для force quit ([d4e907c](https://github.com/rcd27/blockcheckw/commit/d4e907c26f25222a00c82cfd60aefe309b667225))


### Bug Fixes

* **core:** дублирование RegEx вызовов ([0dfc1fb](https://github.com/rcd27/blockcheckw/commit/0dfc1fb499c671122debe97a38214a151b1e41e5))
* **core:** обработка "неудачного" setrlimit, chowm ([4a914cc](https://github.com/rcd27/blockcheckw/commit/4a914cc4dbe9c77b8f0dafc4f7f8aca2ee01cf83))
* **dns:** кэширование DNS ([9c8bfa4](https://github.com/rcd27/blockcheckw/commit/9c8bfa4ebf5445669ce5f3c761417468113889bd))
* panic hook без timeout мог уводить роутеры в reboot ([a1f98f5](https://github.com/rcd27/blockcheckw/commit/a1f98f58485c3ab82e1e4687d181256bc354c7d8))
* авто-определение `nobody uid/gid`, убран хардкод ([d8daf8d](https://github.com/rcd27/blockcheckw/commit/d8daf8d21655d4ddf91bde16c65ce607bd70e1de))

## [0.2.2](https://github.com/rcd27/blockcheckw/compare/v0.2.1...v0.2.2) (2026-03-21)


### Bug Fixes

* **ci-cd:** прикрепление бинарей к релизу ([0f39318](https://github.com/rcd27/blockcheckw/commit/0f393184d4096518fde3f44c54b93c0167014445))
* **multiplatform:** AtomicU64 -&gt; AtomicUSize для поддержки 32-битных платформ ([c86204f](https://github.com/rcd27/blockcheckw/commit/c86204f450e3092bea6845f8e1a34ddcf77e3c4c))

## [0.2.1](https://github.com/rcd27/blockcheckw/compare/v0.2.0...v0.2.1) (2026-03-21)


### Bug Fixes

* **check:** немного свой пайплайн для CHECK, отличающийся от SCAN ([0122d9d](https://github.com/rcd27/blockcheckw/commit/0122d9d109e35df2b64509d590de3c4d5f7356dd))
* **ci-cd:** локальная проверка CI ([21a3856](https://github.com/rcd27/blockcheckw/commit/21a385673a4d9e2f5de8ef05450e35e046f66fa5))

## [0.2.0](https://github.com/rcd27/blockcheckw/compare/v0.1.9...v0.2.0) (2026-03-21)


### ⚠ BREAKING CHANGES

* **check:** добавлен entry-point в приложение, проверка vanilla списков "рабочих" стратегий на предмет РЕАЛЬНОЙ передачи данных

### Features

* **check:** добавлен entry-point в приложение, проверка vanilla списков "рабочих" стратегий на предмет РЕАЛЬНОЙ передачи данных ([9c877da](https://github.com/rcd27/blockcheckw/commit/9c877da8352caaaba5c58fb12a5982be5ff38968))
* **completions:** добавление автокомплит зависимостей ([b696430](https://github.com/rcd27/blockcheckw/commit/b69643083fc663588f67458234cbcbfb160c80be))
* **completions:** реализация CLI completions ([84732e0](https://github.com/rcd27/blockcheckw/commit/84732e076a47a8b75f7c3759974973bca826d0a2))
* **completions:** увеличено кол-во портов для воркера ([0969b45](https://github.com/rcd27/blockcheckw/commit/0969b45dae774f8c9f2fd1a58af333b15fe9209e))
* **completions:** цветная схема для completeioins ([f0b5be9](https://github.com/rcd27/blockcheckw/commit/f0b5be999bbeb9ed6fa5709895aa9b2bc09847fd))
* data-transfer проверка на реальную передачу данных, а не просто HANDSHAKE ([c1cca73](https://github.com/rcd27/blockcheckw/commit/c1cca73f5de41d050e74937fcc6e941d307098bc))
* **report:** blockcheckw_report.txt по окончании прогона ([d2b260c](https://github.com/rcd27/blockcheckw/commit/d2b260cd205e1c7a159bd2e365f6eb6cff1a73cb))
* **test:** тестовый режим прогона blockcheckw ([c643c83](https://github.com/rcd27/blockcheckw/commit/c643c83c2de245405a8cba43d783c04e515725a1))


### Bug Fixes

* **ranking:** переделана система ранжирования, теперь производительность + простота ([57f6e4a](https://github.com/rcd27/blockcheckw/commit/57f6e4a999d9fa4c39898abc7d1e41049068fda6))
* **scan:** verify и data-scan убраны из pipeline, как ломающие нахождение стратегий: TIME_WAIT на порту приводил к false negative ([7ac478e](https://github.com/rcd27/blockcheckw/commit/7ac478ee89054a2dd8293abb8bcab6043eae8f92))
* **strategies:** оптимизация генерации стратегий, приведение к vanilla-style ([868fe6b](https://github.com/rcd27/blockcheckw/commit/868fe6b6e3dd27d9257e5f86416ca05e59e09442))
* **strategy:** генерация стратегий tls12 1:1 с ваниллой ([e776fb8](https://github.com/rcd27/blockcheckw/commit/e776fb8be4421ba767a359c0f2d71748278a6c08))
* **ui:** более информативный progress-bar ([0ea9a80](https://github.com/rcd27/blockcheckw/commit/0ea9a809bb9037aeee9f2d39069c30d4f7c81e77))

## [0.1.9](https://github.com/greynet-systems/blockcheckw/compare/v0.1.8...v0.1.9) (2026-03-10)


### Bug Fixes

* **ci/cd:** замена зеркал для musl-тулчейнов ([224ed7d](https://github.com/greynet-systems/blockcheckw/commit/224ed7d0d79222ad12cf3792001e60a561fddca7))

## [0.1.8](https://github.com/greynet-systems/blockcheckw/compare/v0.1.7...v0.1.8) (2026-03-10)


### Bug Fixes

* **ci/cd:** ошибка скачивания musl-toolchain ([5dc0ef3](https://github.com/greynet-systems/blockcheckw/commit/5dc0ef3efe468deb49e71b330aaa854fc41a68a8))

## [0.1.7](https://github.com/greynet-systems/blockcheckw/compare/v0.1.6...v0.1.7) (2026-03-10)


### Bug Fixes

* **ci/cd:** вынос отдельного билда `build-musl-cross` для ppc, riscv64 платформ ([17f3d2f](https://github.com/greynet-systems/blockcheckw/commit/17f3d2f35cca59c0ae7621206448d2a608f3ea13))

## [0.1.6](https://github.com/greynet-systems/blockcheckw/compare/v0.1.5...v0.1.6) (2026-03-10)


### Bug Fixes

* **ci/cd:** переход обратно к cross-билду, разделённому на две части ([48dca73](https://github.com/greynet-systems/blockcheckw/commit/48dca7303a359a2c6dc93da9a3bc9db456f8138e))

## [0.1.5](https://github.com/greynet-systems/blockcheckw/compare/v0.1.4...v0.1.5) (2026-03-10)


### Bug Fixes

* **ci/cd:** отказ от Cross.toml, добавление build-no-docker для двух платформ ([c4cb004](https://github.com/greynet-systems/blockcheckw/commit/c4cb004dd031dcf52b9804f78e93509e90da9ca9))

## [0.1.4](https://github.com/greynet-systems/blockcheckw/compare/v0.1.3...v0.1.4) (2026-03-10)


### Bug Fixes

* **ci/cd:** build-std - это булевый флаг ([dfd46ef](https://github.com/greynet-systems/blockcheckw/commit/dfd46ef26d8191ea82b17a22bf8a7079447f02a8))

## [0.1.3](https://github.com/greynet-systems/blockcheckw/compare/v0.1.2...v0.1.3) (2026-03-10)


### Bug Fixes

* **ci/cd:** добавление `nightly` тулчейна для архитектур без дефолтного std ([e40871e](https://github.com/greynet-systems/blockcheckw/commit/e40871ea9eb31eff711f111743032e69241ba3f7))

## [0.1.2](https://github.com/greynet-systems/blockcheckw/compare/v0.1.1...v0.1.2) (2026-03-10)


### Features

* **benchmark:** US-benchmark ([1f0ecad](https://github.com/greynet-systems/blockcheckw/commit/1f0ecadd636552c63defcc4ade0e8f2fa492157b))
* **benchmark:** вынос бэнчмарка в отдельное место ([a837277](https://github.com/greynet-systems/blockcheckw/commit/a837277728310e42091e31f47ce582a1889b4b21))
* **benchmark:** нагрузочный тест для определения оптимального количества воркеров ([2976cc6](https://github.com/greynet-systems/blockcheckw/commit/2976cc6c36a78436ebb1984f4f109270f808016f))
* **doh:** проверка DNS spoofing перед прогоном + верификация(дополнительные прогоны) для найденных стратегий ([739479a](https://github.com/greynet-systems/blockcheckw/commit/739479aae82ae730b460ef04f4dd917fe7824801))
* **panic:** graceful откат nft таблиц, если что-то пошло не так ([89408a3](https://github.com/greynet-systems/blockcheckw/commit/89408a3c640ba6278a871c33a9d9f86178ae815c))
* **port:** базовое решение портировано из прототипа ([2382843](https://github.com/greynet-systems/blockcheckw/commit/23828437f61be3cfd797a5d6e8c90d3e561ed6a2))
* **rank:** оценка стратегий после верификации ([41d1740](https://github.com/greynet-systems/blockcheckw/commit/41d1740c0c7b8e09b11abc0fd541973eef438695))
* **runner:** ProgressBar для отображения состояния проверки ([dbe8444](https://github.com/greynet-systems/blockcheckw/commit/dbe8444b9bc6e2da441271a46093f3dfd9c0dbcc))
* **scan:** запуск сканирования, prod режим ([b1357b1](https://github.com/greynet-systems/blockcheckw/commit/b1357b1eaa0d49380a8a0d98ec93b0a7d5619a70))
* **scan:** симпатичный вывод с цветами и прочей мишурой ([5b88a26](https://github.com/greynet-systems/blockcheckw/commit/5b88a26bac261fbb496b681bb4d824220391552f))
* **strategy:** генерация стратегий ([4a65dc6](https://github.com/greynet-systems/blockcheckw/commit/4a65dc69821517fcee564ede2ce8ddb7adc1bde3))
* **ui:** абстракция для UI ([12da7bf](https://github.com/greynet-systems/blockcheckw/commit/12da7bf405b9b112c097ef0fb544fde756ac12e0))


### Bug Fixes

* **ci/cd:** изменение workflow для корректной сборки бинарей ([494f8fb](https://github.com/greynet-systems/blockcheckw/commit/494f8fb85d835e63e836028ef99a96d2264d3c1b))
* **ci/cd:** конфиг-файлы release-please ([fd1cfff](https://github.com/greynet-systems/blockcheckw/commit/fd1cfffbae7fd3f82184b18672152c8c29652929))
* **feat:** ISP парсинг ([f67183a](https://github.com/greynet-systems/blockcheckw/commit/f67183a2d9bdb57aba6fbc3d66495e3734c6034e))
* **ui:** info-bar с данными по ISP ([a7e8d33](https://github.com/greynet-systems/blockcheckw/commit/a7e8d332b3fd7a72060082b6e08a7b910fde681e))
* **ui:** разделитель между vanilla output и прогресс баром ([2fb4941](https://github.com/greynet-systems/blockcheckw/commit/2fb4941e5e0ead655793bac0cf2b87d1c40eaa99))

## [0.1.1](https://github.com/greynet-systems/blockcheckw/compare/blockcheckw-v0.1.0...blockcheckw-v0.1.1) (2026-03-10)


### Features

* **benchmark:** US-benchmark ([1f0ecad](https://github.com/greynet-systems/blockcheckw/commit/1f0ecadd636552c63defcc4ade0e8f2fa492157b))
* **benchmark:** вынос бэнчмарка в отдельное место ([a837277](https://github.com/greynet-systems/blockcheckw/commit/a837277728310e42091e31f47ce582a1889b4b21))
* **benchmark:** нагрузочный тест для определения оптимального количества воркеров ([2976cc6](https://github.com/greynet-systems/blockcheckw/commit/2976cc6c36a78436ebb1984f4f109270f808016f))
* **doh:** проверка DNS spoofing перед прогоном + верификация(дополнительные прогоны) для найденных стратегий ([739479a](https://github.com/greynet-systems/blockcheckw/commit/739479aae82ae730b460ef04f4dd917fe7824801))
* **panic:** graceful откат nft таблиц, если что-то пошло не так ([89408a3](https://github.com/greynet-systems/blockcheckw/commit/89408a3c640ba6278a871c33a9d9f86178ae815c))
* **port:** базовое решение портировано из прототипа ([2382843](https://github.com/greynet-systems/blockcheckw/commit/23828437f61be3cfd797a5d6e8c90d3e561ed6a2))
* **rank:** оценка стратегий после верификации ([41d1740](https://github.com/greynet-systems/blockcheckw/commit/41d1740c0c7b8e09b11abc0fd541973eef438695))
* **runner:** ProgressBar для отображения состояния проверки ([dbe8444](https://github.com/greynet-systems/blockcheckw/commit/dbe8444b9bc6e2da441271a46093f3dfd9c0dbcc))
* **scan:** запуск сканирования, prod режим ([b1357b1](https://github.com/greynet-systems/blockcheckw/commit/b1357b1eaa0d49380a8a0d98ec93b0a7d5619a70))
* **scan:** симпатичный вывод с цветами и прочей мишурой ([5b88a26](https://github.com/greynet-systems/blockcheckw/commit/5b88a26bac261fbb496b681bb4d824220391552f))
* **strategy:** генерация стратегий ([4a65dc6](https://github.com/greynet-systems/blockcheckw/commit/4a65dc69821517fcee564ede2ce8ddb7adc1bde3))
* **ui:** абстракция для UI ([12da7bf](https://github.com/greynet-systems/blockcheckw/commit/12da7bf405b9b112c097ef0fb544fde756ac12e0))


### Bug Fixes

* **ci/cd:** конфиг-файлы release-please ([fd1cfff](https://github.com/greynet-systems/blockcheckw/commit/fd1cfffbae7fd3f82184b18672152c8c29652929))
* **feat:** ISP парсинг ([f67183a](https://github.com/greynet-systems/blockcheckw/commit/f67183a2d9bdb57aba6fbc3d66495e3734c6034e))
* **ui:** info-bar с данными по ISP ([a7e8d33](https://github.com/greynet-systems/blockcheckw/commit/a7e8d332b3fd7a72060082b6e08a7b910fde681e))
* **ui:** разделитель между vanilla output и прогресс баром ([2fb4941](https://github.com/greynet-systems/blockcheckw/commit/2fb4941e5e0ead655793bac0cf2b87d1c40eaa99))
