//! Единственная точка общения с nft (issue #66).
//!
//! Операция описывается типом, а не строкой, и исполняется интерпретатором.
//! Из этого следуют два инварианта, которые держит компилятор, а не ревьюер:
//!
//! 1. **Батч адресован конкретной таблице.** Собрать батч можно только из
//!    [`OwnedTable`] (наша) или [`ForeignTable`] (чужая, и только предъявив
//!    [`UserConsent`]). Операции над рулесетом целиком не существует —
//!    `flush ruleset` тут просто нечем выразить.
//! 2. **Один батч — одна транзакция.** [`NftRun::run`] принимает один
//!    [`NftBatch`] и делает один `nft -f -`. `nft` применяет файл единой
//!    netlink-транзакцией: при ошибке откатывается всё. Разбиение на два
//!    вызова (`flush`, затем загрузка) — как раз то, что в #66 оставило
//!    роутер без правил, и здесь оно невыразимо.

use crate::error::BlockcheckError;
use crate::system::process::{run_process, run_process_stdin};

/// Имя бинаря живёт здесь, а не у вызывающих: снаружи модуля про nft знать
/// нечего.
pub const BINARY: &str = "nft";

const NFT_TIMEOUT_MS: u64 = 15_000;
const NFT_READ_TIMEOUT_MS: u64 = 5_000;

// ── Описание операции ────────────────────────────────────────────────────────

/// Набор nft-команд, применяемых одной транзакцией.
///
/// Поле приватное: снаружи модуля батч не собрать из произвольной строки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftBatch(Vec<String>);

impl NftBatch {
    fn new(lines: Vec<String>) -> Self {
        Self(lines)
    }

    /// Батч из произвольных строк — для модулей-соседей внутри `firewall/`
    /// (например, `nftables::apply_dispatch`). Остаётся `pub(crate)`, чтобы
    /// снаружи `firewall/` батч по-прежнему было не собрать.
    pub(crate) fn from_lines(lines: Vec<String>) -> Self {
        Self::new(lines)
    }

    /// Скрипт для `nft -f -`.
    pub fn script(&self) -> String {
        let mut s = self.0.join("\n");
        s.push('\n');
        s
    }

    /// Команды батча — для тестов и диагностики.
    pub fn lines(&self) -> &[String] {
        &self.0
    }

    /// Первая команда батча — для сообщений об ошибке.
    pub fn first_line(&self) -> &str {
        self.0
            .first()
            .map(String::as_str)
            .unwrap_or("(пустой батч)")
    }

    /// Склеить два батча в одну транзакцию.
    pub fn then(mut self, other: NftBatch) -> Self {
        self.0.extend(other.0);
        self
    }
}

// ── Наша таблица ─────────────────────────────────────────────────────────────

/// Хэндл таблицы, которой владеем мы.
///
/// Не `Clone`: хэндл один. [`drop_table`](OwnedTable::drop_table) потребляет
/// его, поэтому обратиться к снесённой таблице нельзя — это ошибка
/// компиляции, а не гонка в рантайме.
#[derive(Debug)]
pub struct OwnedTable {
    name: String,
}

impl OwnedTable {
    /// Создать таблицу. Единственный ПУБЛИЧНЫЙ способ получить хэндл — второй,
    /// [`OwnedTable::create_with`], виден только внутри крейта.
    pub async fn create<R: NftRun>(runner: &R, name: &str) -> Result<Self, BlockcheckError> {
        let table = OwnedTable {
            name: name.to_string(),
        };
        runner.run(table.create_batch()).await?;
        Ok(table)
    }

    /// Создать таблицу одной транзакцией вместе с `leading` (команды ДО
    /// `add table` — снос остатков прошлого прогона, БЕЗ чтения перед
    /// записью — см. doc-комментарий `nftables::prepare_table`, почему) и
    /// `trailing` (команды ПОСЛЕ — хуки и статические правила).
    ///
    /// Существует ради `nftables::prepare_table`: три отдельных `nft -f -`
    /// (снос, создание, хуки) нарушали бы заявленный модулем инвариант «один
    /// батч — одна транзакция» и на падении третьей транзакции оставляли бы
    /// голую таблицу без хуков в рулсете.
    pub(crate) async fn create_with<R: NftRun>(
        runner: &R,
        name: &str,
        leading: Vec<String>,
        trailing: Vec<String>,
    ) -> Result<Self, BlockcheckError> {
        let table = OwnedTable {
            name: name.to_string(),
        };
        let mut lines = leading;
        lines.push(format!("add table inet {name}"));
        lines.extend(trailing);
        runner.run(NftBatch::new(lines)).await?;
        Ok(table)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Метка для аварийных путей, где владение хэндлом недоступно.
    pub fn marker(&self) -> OwnedTableMarker {
        OwnedTableMarker {
            name: self.name.clone(),
        }
    }

    /// Снести таблицу, потребив хэндл.
    pub async fn drop_table<R: NftRun>(self, runner: &R) -> Result<(), BlockcheckError> {
        runner.run(self.marker().drop_batch()).await
    }

    fn create_batch(&self) -> NftBatch {
        NftBatch::new(vec![format!("add table inet {}", self.name)])
    }
}

/// Метка нашей таблицы для panic-хуков и обработчиков сигналов: там хэндла
/// нет, но снести можно только то, что мы сами создали, — метку выдаёт
/// [`OwnedTable::marker`], из строки её не сконструировать.
#[derive(Debug, Clone)]
pub struct OwnedTableMarker {
    name: String,
}

impl OwnedTableMarker {
    /// Метка таблицы, которую мы собираемся создать. Нужна обработчикам
    /// сигналов: они ставятся раньше, чем таблица появляется, а снести им
    /// можно ровно её — `drop_batch` другой команды не порождает.
    pub fn planned(name: &str) -> Self {
        OwnedTableMarker {
            name: name.to_string(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn drop_batch(&self) -> NftBatch {
        NftBatch::new(vec![format!("delete table inet {}", self.name)])
    }
}

// ── Чужие таблицы ────────────────────────────────────────────────────────────

/// Согласие пользователя на вмешательство в чужое состояние.
///
/// Выдаётся только там, где пользователя реально спросили (промпт или
/// `--auto`), и требуется для единственной операции над чужой таблицей.
#[derive(Debug)]
pub struct UserConsent(());

impl UserConsent {
    /// Вызывать только после явного подтверждения пользователем.
    pub fn granted() -> Self {
        UserConsent(())
    }
}

/// Чужая таблица, найденная детектором конфликтов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignTable {
    family: String,
    name: String,
}

impl ForeignTable {
    pub fn detected(family: impl Into<String>, name: impl Into<String>) -> Self {
        ForeignTable {
            family: family.into(),
            name: name.into(),
        }
    }

    pub fn family(&self) -> &str {
        &self.family
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Единственная операция над чужой таблицей — удалить, и только с согласия.
    /// Восстановление сюда сознательно не входит: сервис, который таблицу
    /// создал, поднимает её сам (`start` симметричен `stop`).
    pub fn delete_batch(&self, _consent: &UserConsent) -> NftBatch {
        NftBatch::new(vec![format!("delete table {} {}", self.family, self.name)])
    }
}

// ── Разбор вывода ────────────────────────────────────────────────────────────

/// Разобрать `nft list tables` в пары `(family, name)`.
fn parse_table_names(out: &str) -> Vec<(String, String)> {
    out.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next()? == "table").then_some(())?;
            let family = parts.next()?.to_string();
            let name = parts.next()?.to_string();
            Some((family, name))
        })
        .collect()
}

// ── Интерпретаторы ───────────────────────────────────────────────────────────

/// Асинхронный исполнитель — основной путь.
pub trait NftRun {
    /// Один батч — одна транзакция `nft -f -`.
    fn run(
        &self,
        batch: NftBatch,
    ) -> impl std::future::Future<Output = Result<(), BlockcheckError>> + Send;

    /// Чтение: имена существующих таблиц как `(family, name)`.
    fn table_names(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<(String, String)>, BlockcheckError>> + Send;

    /// Чтение: содержимое чужой таблицы (для детекта конфликтующих правил).
    fn dump_foreign(
        &self,
        table: &ForeignTable,
    ) -> impl std::future::Future<Output = Result<String, BlockcheckError>> + Send;
}

/// Синхронный исполнитель для panic-хуков, где async-рантайм может быть мёртв.
pub trait NftRunSync {
    fn run(&self, batch: NftBatch) -> Result<(), BlockcheckError>;
}

/// Настоящий nft: один батч — один `nft -f -`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNft;

impl NftRun for SystemNft {
    async fn run(&self, batch: NftBatch) -> Result<(), BlockcheckError> {
        let result =
            run_process_stdin(&["nft", "-f", "-"], &batch.script(), NFT_TIMEOUT_MS).await?;
        if result.exit_code != 0 {
            // stderr обязателен в ошибке: в #66 отказ восстановления печатался
            // без причины, и пользователь не знал, что остался без правил.
            return Err(BlockcheckError::Nftables {
                command: batch.first_line().to_string(),
                stderr: result.stderr,
            });
        }
        Ok(())
    }

    async fn table_names(&self) -> Result<Vec<(String, String)>, BlockcheckError> {
        let result = run_process(&["nft", "list", "tables"], NFT_READ_TIMEOUT_MS).await?;
        if result.exit_code != 0 {
            return Err(BlockcheckError::Nftables {
                command: "nft list tables".to_string(),
                stderr: result.stderr,
            });
        }
        Ok(parse_table_names(&result.stdout))
    }

    async fn dump_foreign(&self, table: &ForeignTable) -> Result<String, BlockcheckError> {
        let result = run_process(
            &["nft", "list", "table", table.family(), table.name()],
            NFT_READ_TIMEOUT_MS,
        )
        .await?;
        Ok(result.stdout)
    }
}

/// Тот же nft для аварийных путей: без tokio, без ожидания рантайма.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNftSync;

/// Сколько ждать nft в аварийном пути. Ограничение обязательно: panic-хук без
/// таймаута уводил роутеры в перезагрузку (a1f98f5).
const SYNC_TIMEOUT_MS: u64 = 3_000;
const SYNC_POLL_MS: u64 = 100;

impl NftRunSync for SystemNftSync {
    fn run(&self, batch: NftBatch) -> Result<(), BlockcheckError> {
        use std::io::{Read, Write};

        let mut child = std::process::Command::new(BINARY)
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| BlockcheckError::ProcessSpawn {
                reason: e.to_string(),
            })?;

        // stdin закрывается вместе с дропом — иначе nft ждёт EOF и мы упрёмся
        // в таймаут на пустом месте.
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(batch.script().as_bytes());
        }

        for _ in 0..(SYNC_TIMEOUT_MS / SYNC_POLL_MS) {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        return Ok(());
                    }
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stderr.take() {
                        let _ = pipe.read_to_string(&mut stderr);
                    }
                    return Err(BlockcheckError::Nftables {
                        command: batch.first_line().to_string(),
                        stderr,
                    });
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(SYNC_POLL_MS)),
                Err(e) => {
                    return Err(BlockcheckError::ProcessSpawn {
                        reason: e.to_string(),
                    })
                }
            }
        }

        let _ = child.kill();
        Err(BlockcheckError::ProcessTimeout {
            timeout_ms: SYNC_TIMEOUT_MS,
        })
    }
}

/// Есть ли работающий nft. Намеренно `list tables`, а не `list ruleset`:
/// нам нужен факт доступности, а не дамп чужих правил.
pub fn is_available_sync() -> bool {
    std::process::Command::new(BINARY)
        .args(["list", "tables"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Интерпретатор для тестов: записывает транзакции, ничего не выполняет.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct RecordingNft {
        transactions: Mutex<Vec<NftBatch>>,
    }

    impl RecordingNft {
        pub fn transactions(&self) -> Vec<NftBatch> {
            self.transactions.lock().unwrap().clone()
        }

        /// Все команды всех транзакций, подряд.
        pub fn commands(&self) -> Vec<String> {
            self.transactions()
                .iter()
                .flat_map(|b| b.lines().to_vec())
                .collect()
        }
    }

    impl NftRun for RecordingNft {
        async fn run(&self, batch: NftBatch) -> Result<(), BlockcheckError> {
            self.transactions.lock().unwrap().push(batch);
            Ok(())
        }

        async fn table_names(&self) -> Result<Vec<(String, String)>, BlockcheckError> {
            Ok(Vec::new())
        }

        async fn dump_foreign(&self, _t: &ForeignTable) -> Result<String, BlockcheckError> {
            Ok(String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::RecordingNft;

    #[tokio::test]
    async fn own_table_lifecycle_touches_only_our_table() {
        let nft = RecordingNft::default();

        let table = OwnedTable::create(&nft, "blockcheckw").await.unwrap();
        table.drop_table(&nft).await.unwrap();

        assert_eq!(
            nft.commands(),
            vec![
                "add table inet blockcheckw".to_string(),
                "delete table inet blockcheckw".to_string(),
            ],
        );
    }

    /// #66: полный цикл не смеет упомянуть ruleset ни разу.
    #[tokio::test]
    async fn lifecycle_never_mentions_ruleset() {
        let nft = RecordingNft::default();

        let table = OwnedTable::create(&nft, "blockcheckw").await.unwrap();
        let marker = table.marker();
        table.drop_table(&nft).await.unwrap();
        nft.run(marker.drop_batch()).await.unwrap();

        for cmd in nft.commands() {
            assert!(
                !cmd.contains("ruleset"),
                "команда трогает весь ruleset: {cmd}"
            );
        }
    }

    /// Каждый батч уходит одной транзакцией — не «сначала одно, потом другое».
    #[tokio::test]
    async fn each_batch_is_exactly_one_transaction() {
        let nft = RecordingNft::default();
        let table = OwnedTable::create(&nft, "blockcheckw").await.unwrap();

        let combined = table.marker().drop_batch().then(table.create_batch());
        nft.run(combined).await.unwrap();

        let txs = nft.transactions();
        assert_eq!(txs.len(), 2, "создание + объединённый батч");
        assert_eq!(
            txs[1].lines().len(),
            2,
            "две команды должны уехать одной транзакцией, а не двумя вызовами",
        );
    }

    #[tokio::test]
    async fn foreign_delete_targets_only_that_table() {
        let foreign = ForeignTable::detected("inet", "zapret");
        let batch = foreign.delete_batch(&UserConsent::granted());

        assert_eq!(batch.lines(), ["delete table inet zapret"]);
    }

    #[test]
    fn parses_table_list_into_family_and_name() {
        let out = "table ip filter\ntable inet fw4\ntable ip6 nat\n";
        assert_eq!(
            parse_table_names(out),
            vec![
                ("ip".to_string(), "filter".to_string()),
                ("inet".to_string(), "fw4".to_string()),
                ("ip6".to_string(), "nat".to_string()),
            ],
        );
    }

    #[test]
    fn ignores_lines_that_are_not_tables() {
        let out = "table inet fw4\n\nwarning: something\ntable\n";
        assert_eq!(
            parse_table_names(out),
            vec![("inet".to_string(), "fw4".to_string())],
        );
    }

    #[test]
    fn marker_carries_our_table_name() {
        let table = OwnedTable {
            name: "blockcheckw".to_string(),
        };
        assert_eq!(table.marker().name(), "blockcheckw");
    }
}
