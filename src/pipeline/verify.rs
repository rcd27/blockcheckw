//! Инструментовка замера `check`: исход прохода, его журнал и раскладка корпуса по
//! устойчивости.
//!
//! Носители отменённых спекой порогов отсюда снесены (`DATA_TRANSFER_MIN_BYTES` = 32КБ,
//! `min_passes`, голосование 3-из-3, авто-послабление порога, отдельный проход передачи
//! данных): вердикт больше не булев, и голосовать по нему не по чему. Осталась ровно та
//! половина, что зовётся живым кодом, — она же материал для `drift`.

use std::collections::BTreeMap;

use console::style;

use crate::ui::Console;

/// Per-strategy pass/fail tally across all verification passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyTally {
    pub strategy_args: Vec<String>,
    pub pass_count: usize,
    pub fail_count: usize,
}

/// Исход одного прохода для одной стратегии. `bool`, которым обходится
/// `tally_results`, отвечает «прошла ли», но не «почему нет», — а весь вопрос
/// замера именно во втором.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    /// Имя провала — с провода (`reset/tls`) либо от вердикта (`dpi_data_limit`).
    Failed(String),
}

/// Раскладка корпуса по устойчивости плюс причины провалов в каждой группе.
///
/// Три прохода держатся ради ФЛАПАЮЩИХ — тех, кто прошёл не всегда. Стратегия,
/// не прошедшая ни разу, отсеивается и одним проходом; вопрос лишь в том, можно
/// ли по причине отличить её от флапающей СРАЗУ. Поэтому причины считаются по
/// группам раздельно: их смешение и есть та ошибка, что делает замер бесполезным.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StabilityReport {
    /// Прошли все проходы.
    pub always: usize,
    /// Не прошли ни одного.
    pub never: usize,
    /// Прошли часть — ради них и держится повтор.
    pub flapping: usize,
    /// Причины провалов у ни разу не прошедших.
    pub causes_never: BTreeMap<String, usize>,
    /// Причины провалов у флапающих. Если сюда не попадает сброс — сброс
    /// детерминирован, и одного прохода довольно, чтобы судить.
    pub causes_flapping: BTreeMap<String, usize>,
}

/// Раскладка по строкам «стратегия → её исходы». Форма, в которой исходы
/// рождаются у `check`: там внешний цикл идёт по стратегиям, а не по проходам,
/// и при раннем выходе строка КОРОЧЕ числа проходов — недобранное не смеет
/// сойти за успех.
pub fn stability_of(rows: &[Vec<Outcome>], total_passes: usize) -> StabilityReport {
    let mut report = StabilityReport::default();

    for row in rows {
        let passed = row.iter().filter(|o| **o == Outcome::Passed).count();

        // Группа решается ДО подсчёта причин: причина попадает в корзину
        // стратегии целиком, а не отдельного её провала.
        let bucket = if passed == total_passes {
            report.always += 1;
            None
        } else if passed == 0 {
            report.never += 1;
            Some(&mut report.causes_never)
        } else {
            report.flapping += 1;
            Some(&mut report.causes_flapping)
        };

        if let Some(causes) = bucket {
            for outcome in row {
                if let Outcome::Failed(name) = outcome {
                    *causes.entry(name.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    report
}

/// Строка журнала одного прохода: когда, по кому, чем кончилось. Нужна затем,
/// что наблюдения с провода приходят со своими метками времени, и связать их с
/// пробой можно только общей осью — стратегия целиком слишком крупна.
///
/// Не `pub`: единственный потребитель — [`log_pass`] ниже. Наружу не выходит, но и не
/// растворяется в нём — формат журнала проверяется тестом, а не глазами.
fn pass_line(started: f64, at: f64, index: usize, pass: usize, outcome: &Outcome) -> String {
    let (verdict, name) = match outcome {
        Outcome::Passed => ("ok", String::new()),
        Outcome::Failed(name) => ("fail", name.clone()),
    };
    format!(
        "{{\"t0\":{started:.3},\"t\":{at:.3},\"i\":{index},\"pass\":{pass},\"outcome\":\"{verdict}\",\"why\":\"{name}\"}}"
    )
}

/// Часы замера — секунды эпохи. Одна ось с наблюдателем провода, иначе
/// сопоставить их нечем.
pub fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Дописать строку журнала, если замер включён. Молча ничего не делает, когда
/// переменная не названа: инструментовка не смеет мешать обычному прогону.
pub fn log_pass(started: f64, index: usize, pass: usize, outcome: &Outcome) {
    let Ok(path) = std::env::var("BCW_CAUSE_HISTOGRAM") else {
        return;
    };
    let at = now_epoch();
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(file, "{}", pass_line(started, at, index, pass, outcome));
    }
}

/// Напечатать раскладку и, если названа переменная `BCW_CAUSE_HISTOGRAM`, сложить
/// её же в файл. Через переменную, а не всегда: артефакты замера не должны
/// сыпаться в корень дерева у обычного пользователя.
pub fn report_stability(report: &StabilityReport, domain: &str, screen: &mut Console) {
    let total = report.always + report.never + report.flapping;
    if total == 0 {
        return;
    }

    screen.println(&format!(
        "  {} {total} кандидатов: {} прошли всегда, {} ни разу, {} флапают",
        style("замер").bold(),
        report.always,
        report.never,
        report.flapping,
    ));

    let show = |screen: &mut Console, title: &str, causes: &BTreeMap<String, usize>| {
        if causes.is_empty() {
            return;
        }
        let sum: usize = causes.values().sum();
        let mut rows: Vec<(&String, &usize)> = causes.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1));
        screen.println(&format!("    {title} ({sum}):"));
        for (name, count) in rows {
            let share = 100.0 * *count as f64 / sum as f64;
            screen.println(&format!("      {name:<24} {count:>5}  {share:>5.1}%"));
        }
    };
    show(screen, "провалы ни разу не прошедших", &report.causes_never);
    show(screen, "провалы флапающих", &report.causes_flapping);

    let Ok(path) = std::env::var("BCW_CAUSE_HISTOGRAM") else {
        return;
    };
    let json = serde_json::json!({
        "domain": domain,
        "always": report.always,
        "never": report.never,
        "flapping": report.flapping,
        "causes_never": report.causes_never,
        "causes_flapping": report.causes_flapping,
    });
    let line = format!("{json}\n");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut file) => {
            use std::io::Write;
            let _ = file.write_all(line.as_bytes());
        }
        Err(e) => screen.println(&format!("    замер: не записать {path}: {e}")),
    }
}

#[cfg(test)]
mod row_stability_tests {
    use super::*;
    use crate::network::cause::{Cause, Phase};

    #[test]
    fn a_row_shorter_than_the_pass_count_is_not_an_always() {
        // Ранний выход: первый проход упал, остальные не гонялись.
        let rows = vec![vec![Outcome::Failed(Cause::Reset(Phase::Tls).name())]];
        let report = stability_of(&rows, 3);
        assert_eq!(
            report.always, 0,
            "строка из одного провала при трёх проходах — не «прошла всегда»"
        );
        assert_eq!(report.never, 1);
    }

    #[test]
    fn a_row_of_all_passes_is_an_always() {
        let rows = vec![vec![Outcome::Passed, Outcome::Passed, Outcome::Passed]];
        assert_eq!(stability_of(&rows, 3).always, 1);
    }

    #[test]
    fn a_row_mixing_a_pass_and_a_failure_is_flapping_and_its_cause_is_kept() {
        let rows = vec![vec![
            Outcome::Passed,
            Outcome::Failed(Cause::Timeout(Phase::Request).name()),
        ]];
        let report = stability_of(&rows, 2);
        assert_eq!(report.flapping, 1);
        assert_eq!(report.causes_flapping.get("timeout/request"), Some(&1));
    }

    #[test]
    fn causes_of_the_never_group_do_not_leak_into_the_flapping_one() {
        // Первая стратегия не прошла ни разу — сброс. Вторая флапает — тишина.
        let rows = vec![
            vec![
                Outcome::Failed(Cause::Reset(Phase::Tls).name()),
                Outcome::Failed(Cause::Reset(Phase::Tls).name()),
            ],
            vec![
                Outcome::Passed,
                Outcome::Failed(Cause::Timeout(Phase::Request).name()),
            ],
        ];
        let report = stability_of(&rows, 2);
        assert_eq!(report.never, 1);
        assert_eq!(report.flapping, 1);
        assert_eq!(report.causes_never.get("reset/tls"), Some(&2));
        assert_eq!(
            report.causes_never.get("timeout/request"),
            None,
            "тишина флапающей не смеет попасть в счёт стабильно павшей: \
             смешение групп и есть та ошибка, ради устранения которой замер"
        );
        assert_eq!(report.causes_flapping.get("timeout/request"), Some(&1));
        assert_eq!(report.causes_flapping.get("reset/tls"), None);
    }

    #[test]
    fn a_failure_with_no_cause_is_counted_under_its_own_name_not_dropped() {
        let rows = vec![vec![Outcome::Failed("unknown".to_string())]];
        let report = stability_of(&rows, 1);
        assert_eq!(
            report.causes_never.get("unknown"),
            Some(&1),
            "провал без причины обязан быть виден: молча выброшенный, он \
             занизил бы знаменатель и завысил долю всего остального"
        );
    }
}

#[cfg(test)]
mod pass_line_tests {
    use super::*;

    #[test]
    fn a_failed_pass_carries_its_reason_into_the_journal() {
        let line = pass_line(
            1788984490.0,
            1788984497.091,
            7,
            2,
            &Outcome::Failed("reset/tls".to_string()),
        );
        assert_eq!(
            line,
            r#"{"t0":1788984490.000,"t":1788984497.091,"i":7,"pass":2,"outcome":"fail","why":"reset/tls"}"#
        );
    }

    #[test]
    fn a_passing_pass_has_no_reason_but_keeps_its_place_on_the_clock() {
        let line = pass_line(1.0, 1.5, 0, 1, &Outcome::Passed);
        assert_eq!(
            line,
            r#"{"t0":1.000,"t":1.500,"i":0,"pass":1,"outcome":"ok","why":""}"#
        );
    }
}
