# Changelog

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
