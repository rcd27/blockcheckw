//! Снятие СВОИХ остатков при входе.
//!
//! Зачем это отдельно от разрешателя конфликтов (`cmd::handle_bypass_conflicts`): тот судит о
//! ЧУЖИХ трубах и во встроенном режиме выключен целиком — там nft-состоянием владеет
//! вызывающий, и трогать чужое нельзя. Но собственные остатки прошлого прогона чужими не
//! являются: их оставили мы, и убрать их — наша работа, а не работа того, кто нас позвал.
//!
//! Признак «свой» — ТРОЙНОЙ, и это важно. Одного `--qnum` мало: на той же очереди мог осесть
//! чужой движок, и убить его значило бы вмешаться в мир вызывающего ровно там, где мы обещали
//! не вмешиваться. Марка десинка (`--fwmark`) нашей раскладки вместе с номером очереди уже
//! достаточно узка: чужой `nfqws2` несёт свою.

use crate::firewall::nft::{NftRun, OwnedTableMarker};
use crate::firewall::nftables;

/// Признак нашего остатка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Имя нашей nft-таблицы — его задаёт вызывающий, и по нему таблица опознаётся точно.
    pub table: String,
    /// Боевая очередь этого прогона.
    pub qnum: u16,
    /// Марка десинка нашей раскладки — её не ставит никто другой.
    pub desync_mark: u32,
}

/// Что удалось снять при входе. Пустой отчёт — «остатков не было», и это тоже наблюдение:
/// продукту оно говорит, что прошлый прогон закончился чисто.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Pid'ы снятых движков.
    pub killed: Vec<i32>,
    /// Была ли снята наша таблица.
    pub table_dropped: bool,
}

impl SweepReport {
    pub fn is_empty(&self) -> bool {
        self.killed.is_empty() && !self.table_dropped
    }
}

/// Наш ли это движок — по его командной строке.
///
/// Чистая функция: она и проверяется тестами, а хождение в `/proc` остаётся тонким слоем
/// вокруг неё. Так проверяемо то, что решает (признак), а не то, что читает (файловая система).
pub fn is_ours(cmdline: &str, sig: &Signature) -> bool {
    // Сверка ТОКЕНАМИ, а не вхождением подстроки: `--qnum=2000` содержит `--qnum=200`, и
    // наивное `contains` сняло бы чужой движок, стоящий на соседней очереди.
    let qnum = format!("--qnum={}", sig.qnum);
    let fwmark = format!("--fwmark=0x{:08X}", sig.desync_mark);
    let mut queue_matches = false;
    let mut mark_matches = false;
    for token in cmdline.split_whitespace() {
        queue_matches |= token == qnum;
        // Регистр шестнадцатеричных цифр — дело печатающего, а не признак принадлежности.
        mark_matches |= token.eq_ignore_ascii_case(&fwmark);
    }
    queue_matches && mark_matches
}

/// Прочитать `/proc` и собрать pid'ы движков, отвечающих признаку.
///
/// Аргументы в `/proc/<pid>/cmdline` разделены нулевым байтом — склеиваем пробелом, потому что
/// именно в таком виде их печатает и ищет человек.
fn our_engines(sig: &Signature) -> Vec<i32> {
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        // Нет procfs — нет и способа узнать своих. Молчим: это не отказ прогона, это
        // отсутствие наблюдения, и дальше нас остановит занятая очередь, если она занята.
        Err(_) => return Vec::new(),
    };

    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
        // Себя не трогаем ни при каких признаках: наша собственная командная строка их не
        // несёт, но проверка дешевле рассуждения о том, почему не несёт.
        .filter(|pid| *pid != std::process::id() as i32)
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline"))
                .map(|raw| {
                    let cmdline = String::from_utf8_lossy(&raw).replace('\0', " ");
                    is_ours(&cmdline, sig)
                })
                .unwrap_or(false)
        })
        .collect()
}

/// Снять свои остатки: движки по признаку и нашу таблицу по имени.
///
/// Идемпотентность входа — не удобство, а условие работы под оркестратором: продукт шлёт
/// `SIGKILL`, по которому не отрабатывает ни один хук, и следующий прогон обязан начинаться с
/// того, что прошлый за собой не убрал. Иначе очередь занята, движок жив, а подбор слеп.
pub async fn sweep_own<R: NftRun>(runner: &R, sig: &Signature) -> SweepReport {
    let engines = our_engines(sig);
    let killed = engines
        .iter()
        .filter(|pid| {
            // SAFETY: pid прочитан из `/proc` и отвечает нашему признаку; сигнал идёт
            // процессу, а не группе (отрицательный pid означал бы группу).
            unsafe { libc::kill(**pid, libc::SIGKILL) == 0 }
        })
        .copied()
        .collect();

    // Таблица сносится ПОСЛЕ движков: пока движок жив, правила ведут в очередь, у которой
    // есть слушатель. Обратный порядок оставил бы окно, в котором пакеты уходят в очередь без
    // читателя, — то есть дроп трафика человека на ровном месте.
    let existed = runner
        .table_names()
        .await
        .map(|tables| tables.iter().any(|(_, name)| *name == sig.table))
        // Не прочитали рулсет — не утверждаем, что таблицы не было. Снос идёт всё равно
        // (он идемпотентен), а в отчёт уходит «не сносили»: соврать в эту сторону дешевле.
        .unwrap_or(false);
    if existed {
        nftables::drop_table(runner, &OwnedTableMarker::planned(&sig.table)).await;
    }

    SweepReport {
        killed,
        table_dropped: existed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig() -> Signature {
        Signature {
            table: "blockcheckw".to_string(),
            qnum: 200,
            desync_mark: 0x1000_0000,
        }
    }

    #[test]
    fn our_own_engine_is_recognised() {
        let cmdline = "/opt/zapret2/nfq2/nfqws2 --uid=65534:65534 --qnum=200 \
                       --fwmark=0x10000000 --filter-mark=1/0xFFFF --payload=tls_client_hello";
        assert!(is_ours(cmdline, &sig()));
    }

    /// САМАЯ ДОРОГАЯ ОШИБКА ЭТОГО МОДУЛЯ — убить чужое. Во встроенном режиме мы обещали
    /// вызывающему не трогать его мир; движок на той же очереди, но с чужой маркой, нам не
    /// принадлежит, и снять его значило бы нарушить обещание ровно там, где оно дано.
    #[test]
    fn a_foreign_engine_on_the_same_queue_is_not_ours() {
        let cmdline = "/opt/zapret2/nfq2/nfqws2 --qnum=200 --fwmark=0x40000000 --dpi-desync=fake";
        assert!(!is_ours(cmdline, &sig()));
    }

    /// И обратное: наша марка на ЧУЖОЙ очереди — это другой прогон bcw, поднятый с другими
    /// ключами. У него свой хозяин, и распоряжаться им мы не вправе.
    #[test]
    fn our_mark_on_another_queue_belongs_to_another_run() {
        let cmdline = "/opt/zapret2/nfq2/nfqws2 --qnum=900 --fwmark=0x10000000";
        assert!(!is_ours(cmdline, &sig()));
    }

    /// Номер очереди сверяется целиком, а не по вхождению: `--qnum=2000` содержит `200`
    /// подстрокой, и наивная проверка сняла бы чужой движок.
    #[test]
    fn a_longer_queue_number_is_not_a_prefix_match() {
        let cmdline = "/opt/zapret2/nfq2/nfqws2 --qnum=2000 --fwmark=0x10000000";
        assert!(
            !is_ours(cmdline, &sig()),
            "2000 — не 200: снять чужой движок из-за общей подстроки нельзя"
        );
    }

    #[test]
    fn an_empty_sweep_reports_itself_as_empty() {
        assert!(SweepReport::default().is_empty());
        assert!(!SweepReport {
            killed: vec![42],
            table_dropped: false
        }
        .is_empty());
    }
}
