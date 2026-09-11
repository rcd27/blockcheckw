use std::collections::BTreeMap;
use std::sync::Arc;

use console::style;

use crate::config::{CoreConfig, Protocol};
use crate::error::TaskResult;
use crate::network::http_client::DATA_TRANSFER_MIN_BYTES;
use crate::nfqws2::plan::FilterMark;
use crate::pipeline::runner::{run_parallel, RunParams, StrategyResult};
use crate::pipeline::worker_task::HttpTestMode;
use crate::ui::Console;

/// Configuration for verification passes.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Number of verification passes (0 = skip verification)
    pub passes: usize,
    /// Minimum passes required to consider a strategy verified
    pub min_passes: usize,
    /// Request timeout in seconds for verification (stricter than scan)
    pub request_timeout: u64,
    /// Data transfer validation config
    pub data_transfer: DataTransferConfig,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            passes: 3,
            min_passes: 3,
            request_timeout: 3,
            data_transfer: DataTransferConfig::default(),
        }
    }
}

/// Configuration for data transfer validation phase.
#[derive(Debug, Clone)]
pub struct DataTransferConfig {
    /// Enable data transfer validation (GET request after HEAD passes)
    pub enabled: bool,
    /// Request timeout in seconds for data transfer test (longer than HEAD)
    pub request_timeout: u64,
    /// Minimum bytes that must be downloaded for a strategy to pass
    pub min_bytes: u64,
}

impl Default for DataTransferConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            request_timeout: 8,
            min_bytes: DATA_TRANSFER_MIN_BYTES,
        }
    }
}

/// Summary of data transfer validation results.
#[derive(Debug)]
pub struct DataTransferSummary {
    pub tested: usize,
    pub passed: usize,
    pub timeout: String,
    pub min_bytes: u64,
}

/// Per-strategy pass/fail tally across all verification passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyTally {
    pub strategy_args: Vec<String>,
    pub pass_count: usize,
    pub fail_count: usize,
}

/// Overall verification result.
#[derive(Debug)]
pub struct VerificationSummary {
    pub total_candidates: usize,
    pub verified_count: usize,
    pub required_passes: usize,
    pub total_passes: usize,
    pub tallies: Vec<StrategyTally>,
    pub verified: Vec<Vec<String>>,
    /// If strict verification yielded 0 results, auto-relax finds the best
    /// non-zero threshold. None if strict already found results or all tallies are 0/N.
    pub relaxed: Option<RelaxedResult>,
    /// Data transfer validation results (None if skipped).
    pub data_transfer_results: Option<DataTransferSummary>,
}

/// Strategies found by lowering the verification threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaxedResult {
    pub actual_min: usize,
    pub strategies: Vec<Vec<String>>,
}

/// Count pass/fail per strategy across N verification passes.
///
/// `pass_outcomes[pass_idx][strategy_idx]` = true if strategy succeeded in that pass.
pub fn tally_results(
    candidates: &[Vec<String>],
    pass_outcomes: &[Vec<bool>],
) -> Vec<StrategyTally> {
    candidates
        .iter()
        .enumerate()
        .map(|(strat_idx, args)| {
            let pass_count = pass_outcomes
                .iter()
                .filter(|pass| pass.get(strat_idx).copied().unwrap_or(false))
                .count();
            let fail_count = pass_outcomes.len() - pass_count;
            StrategyTally {
                strategy_args: args.clone(),
                pass_count,
                fail_count,
            }
        })
        .collect()
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

/// Разложить исходы по устойчивости. `outcomes[pass][strategy]`.
pub fn stability_report(candidates: &[Vec<String>], outcomes: &[Vec<Outcome>]) -> StabilityReport {
    let rows: Vec<Vec<Outcome>> = (0..candidates.len())
        .map(|index| {
            outcomes
                .iter()
                .filter_map(|pass| pass.get(index).cloned())
                .collect()
        })
        .collect();
    stability_of(&rows, outcomes.len())
}

/// Имя провала по вердикту. Причина с провода сильнее: она называет, ЧТО
/// случилось на проводе, тогда как вердикт говорит лишь, как это выглядело
/// сверху. Где провода нет — имя берётся от вердикта, и провал остаётся видимым.
pub fn outcome_of(result: &TaskResult) -> Outcome {
    use crate::network::http_client::HttpVerdict;
    match result {
        TaskResult::Success { .. } => Outcome::Passed,
        // Наша поломка, не свойство стратегии, — отдельным именем.
        TaskResult::Error { .. } => Outcome::Failed("engine_error".to_string()),
        TaskResult::Failed { verdict } => Outcome::Failed(match verdict {
            HttpVerdict::Unavailable { cause, .. } => match cause {
                Some(c) => c.name(),
                None => "unknown".to_string(),
            },
            HttpVerdict::DpiDataLimit { .. } => "dpi_data_limit".to_string(),
            HttpVerdict::DataTransferFailed { .. } => "data_transfer_failed".to_string(),
            HttpVerdict::SuspiciousRedirect { .. } => "suspicious_redirect".to_string(),
            HttpVerdict::ServerReceivesFakes => "server_receives_fakes".to_string(),
            // Успех в ветке провала — противоречие; называем его так, чтобы
            // молча не слиться с сетевой бедой, если он когда-нибудь случится.
            HttpVerdict::Available => "available_but_failed".to_string(),
        }),
    }
}

/// Keep only strategies with pass_count >= min_passes.
pub fn filter_verified(tallies: &[StrategyTally], min_passes: usize) -> Vec<Vec<String>> {
    tallies
        .iter()
        .filter(|t| t.pass_count >= min_passes)
        .map(|t| t.strategy_args.clone())
        .collect()
}

/// When strict verification yields 0 results, find the best relaxed threshold.
///
/// Tries min_passes-1, min_passes-2, ..., 1 and returns the first threshold
/// that produces any results. Returns None if even 1/N gives nothing.
pub fn find_relaxed(tallies: &[StrategyTally], min_passes: usize) -> Option<RelaxedResult> {
    for threshold in (1..min_passes).rev() {
        let strategies = filter_verified(tallies, threshold);
        if !strategies.is_empty() {
            return Some(RelaxedResult {
                actual_min: threshold,
                strategies,
            });
        }
    }
    None
}

/// Строка журнала одного прохода: когда, по кому, чем кончилось. Нужна затем,
/// что наблюдения с провода приходят со своими метками времени, и связать их с
/// пробой можно только общей осью — стратегия целиком слишком крупна, проходов
/// в ней три.
pub fn pass_line(started: f64, at: f64, index: usize, pass: usize, outcome: &Outcome) -> String {
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

/// Исходы прохода в порядке кандидатов — то же сопоставление, что и
/// [`extract_outcomes`], но с сохранением имени провала.
pub fn extract_rich_outcomes(
    candidates: &[Vec<String>],
    results: &[StrategyResult],
) -> Vec<Outcome> {
    candidates
        .iter()
        .map(|args| {
            match results.iter().find(|r| r.strategy_args == *args) {
                Some(found) => outcome_of(&found.result),
                // Проба не вернулась вовсе: дедлайн, снятый план, ошибка джойна.
                None => Outcome::Failed("missing".to_string()),
            }
        })
        .collect()
}

/// Map run_parallel results (arbitrary order) back to candidate order.
///
/// For each candidate, checks if there's a matching StrategyResult with Success.
/// Missing results default to false.
fn extract_outcomes(candidates: &[Vec<String>], results: &[StrategyResult]) -> Vec<bool> {
    candidates
        .iter()
        .map(|args| {
            results
                .iter()
                .any(|r| r.strategy_args == *args && matches!(r.result, TaskResult::Success { .. }))
        })
        .collect()
}

/// Run N verification passes on candidate strategies, return tally and filtered results.
/// If data_transfer is enabled, runs an additional GET-based pass after HEAD passes.
#[allow(clippy::too_many_arguments)] // filter_mark добавлен задачей 8 поверх уже широкого набора параметров
pub async fn run_verification(
    config: &CoreConfig,
    filter_mark: &FilterMark,
    domain: &str,
    protocol: Protocol,
    candidates: &[Vec<String>],
    ips: &[String],
    verify_config: &VerifyConfig,
    screen: &mut Console,
) -> VerificationSummary {
    let verify_core = Arc::new(CoreConfig {
        request_timeout: verify_config.request_timeout,
        ..config.clone()
    });

    let mut all_outcomes: Vec<Vec<bool>> = Vec::with_capacity(verify_config.passes);
    // ЗАМЕР (спайк #verify-histogram): те же исходы, но с именем провала.
    let mut all_named: Vec<Vec<Outcome>> = Vec::with_capacity(verify_config.passes);

    for pass in 1..=verify_config.passes {
        screen.println(&format!(
            "  {} pass {}/{}",
            style("verify").bold(),
            pass,
            verify_config.passes,
        ));

        screen.begin_progress_with_prefix(
            candidates.len() as u64,
            &format!("Verify {protocol} [{pass}/{}]", verify_config.passes),
        );

        let (results, _stats) = run_parallel(RunParams {
            config: &verify_core,
            filter_mark,
            domain,
            protocol,
            strategies: candidates,
            ips,
            multi: Some(screen.multi()),
            external_pb: Some(screen.pb()),
            mode: HttpTestMode::Standard,
            deadline: None,
            success_sink: None,
        })
        .await;

        screen.finish_progress();

        let outcomes = extract_outcomes(candidates, &results);
        all_outcomes.push(outcomes);
        all_named.push(extract_rich_outcomes(candidates, &results));
    }

    report_stability(&stability_report(candidates, &all_named), domain, screen);

    let tallies = tally_results(candidates, &all_outcomes);
    let verified = filter_verified(&tallies, verify_config.min_passes);

    let relaxed = if verified.is_empty() {
        find_relaxed(&tallies, verify_config.min_passes)
    } else {
        None
    };

    // Data transfer validation: only for HTTPS, only for strategies that passed HEAD
    let dt_config = &verify_config.data_transfer;
    let is_https = matches!(protocol, Protocol::HttpsTls12 | Protocol::HttpsTls13);

    let (final_verified, final_relaxed, dt_summary) = if dt_config.enabled && is_https {
        // Pick strategies to test: verified first, fall back to relaxed
        let dt_candidates = if !verified.is_empty() {
            &verified
        } else if let Some(ref r) = relaxed {
            &r.strategies
        } else {
            // Nothing passed HEAD — skip data transfer
            return VerificationSummary {
                total_candidates: candidates.len(),
                verified_count: verified.len(),
                required_passes: verify_config.min_passes,
                total_passes: verify_config.passes,
                tallies,
                verified,
                relaxed,
                data_transfer_results: None,
            };
        };

        screen.println(&format!(
            "  {} data transfer check: {} strategies, GET {}s timeout, min {}B",
            style("verify").bold(),
            dt_candidates.len(),
            dt_config.request_timeout,
            dt_config.min_bytes,
        ));

        screen.begin_progress_with_prefix(
            dt_candidates.len() as u64,
            &format!("Data transfer {protocol}"),
        );

        let dt_core = Arc::new(CoreConfig {
            request_timeout: dt_config.request_timeout,
            ..config.clone()
        });

        let (dt_results, _dt_stats) = run_parallel(RunParams {
            config: &dt_core,
            filter_mark,
            domain,
            protocol,
            strategies: dt_candidates,
            ips,
            multi: Some(screen.multi()),
            external_pb: Some(screen.pb()),
            mode: HttpTestMode::DataTransfer {
                min_bytes: dt_config.min_bytes,
            },
            deadline: None,
            success_sink: None,
        })
        .await;

        screen.finish_progress();

        let dt_passed: Vec<Vec<String>> = dt_results
            .iter()
            .filter(|r| matches!(r.result, TaskResult::Success { .. }))
            .map(|r| r.strategy_args.clone())
            .collect();

        let summary = DataTransferSummary {
            tested: dt_candidates.len(),
            passed: dt_passed.len(),
            timeout: format!("{}s", dt_config.request_timeout),
            min_bytes: dt_config.min_bytes,
        };

        if !verified.is_empty() {
            // Data transfer filters verified strategies
            (dt_passed, None, Some(summary))
        } else {
            // Data transfer filters relaxed strategies
            let new_relaxed = if dt_passed.is_empty() {
                relaxed.clone()
            } else {
                Some(RelaxedResult {
                    actual_min: relaxed.as_ref().map(|r| r.actual_min).unwrap_or(0),
                    strategies: dt_passed,
                })
            };
            (vec![], new_relaxed, Some(summary))
        }
    } else {
        (verified, relaxed, None)
    };

    VerificationSummary {
        total_candidates: candidates.len(),
        verified_count: final_verified.len(),
        required_passes: verify_config.min_passes,
        total_passes: verify_config.passes,
        tallies,
        verified: final_verified,
        relaxed: final_relaxed,
        data_transfer_results: dt_summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{HttpVerdictAvailable, TaskResult};
    use crate::pipeline::runner::StrategyResult;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    // ── tally_results ──────────────────────────────────────────

    #[test]
    fn tally_all_pass() {
        let candidates = vec![args("--a"), args("--b")];
        let outcomes = vec![vec![true, true], vec![true, true], vec![true, true]];
        let tallies = tally_results(&candidates, &outcomes);
        assert_eq!(tallies.len(), 2);
        assert_eq!(tallies[0].pass_count, 3);
        assert_eq!(tallies[0].fail_count, 0);
        assert_eq!(tallies[1].pass_count, 3);
        assert_eq!(tallies[1].fail_count, 0);
    }

    #[test]
    fn tally_mixed() {
        let candidates = vec![args("--a"), args("--b"), args("--c")];
        let outcomes = vec![
            vec![true, true, false],
            vec![true, false, true],
            vec![true, true, false],
        ];
        let tallies = tally_results(&candidates, &outcomes);
        assert_eq!(
            tallies[0],
            StrategyTally {
                strategy_args: args("--a"),
                pass_count: 3,
                fail_count: 0
            }
        );
        assert_eq!(
            tallies[1],
            StrategyTally {
                strategy_args: args("--b"),
                pass_count: 2,
                fail_count: 1
            }
        );
        assert_eq!(
            tallies[2],
            StrategyTally {
                strategy_args: args("--c"),
                pass_count: 1,
                fail_count: 2
            }
        );
    }

    #[test]
    fn tally_all_fail() {
        let candidates = vec![args("--a")];
        let outcomes = vec![vec![false], vec![false], vec![false]];
        let tallies = tally_results(&candidates, &outcomes);
        assert_eq!(tallies[0].pass_count, 0);
        assert_eq!(tallies[0].fail_count, 3);
    }

    #[test]
    fn tally_empty_candidates() {
        let candidates: Vec<Vec<String>> = vec![];
        let outcomes: Vec<Vec<bool>> = vec![vec![], vec![], vec![]];
        let tallies = tally_results(&candidates, &outcomes);
        assert!(tallies.is_empty());
    }

    #[test]
    fn tally_single_pass() {
        let candidates = vec![args("--a"), args("--b")];
        let outcomes = vec![vec![true, false]];
        let tallies = tally_results(&candidates, &outcomes);
        assert_eq!(tallies[0].pass_count, 1);
        assert_eq!(tallies[0].fail_count, 0);
        assert_eq!(tallies[1].pass_count, 0);
        assert_eq!(tallies[1].fail_count, 1);
    }

    // ── filter_verified ────────────────────────────────────────

    #[test]
    fn filter_strict_3_of_3() {
        let tallies = vec![
            StrategyTally {
                strategy_args: args("--a"),
                pass_count: 3,
                fail_count: 0,
            },
            StrategyTally {
                strategy_args: args("--b"),
                pass_count: 2,
                fail_count: 1,
            },
            StrategyTally {
                strategy_args: args("--c"),
                pass_count: 3,
                fail_count: 0,
            },
        ];
        let verified = filter_verified(&tallies, 3);
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0], args("--a"));
        assert_eq!(verified[1], args("--c"));
    }

    #[test]
    fn filter_relaxed_2_of_3() {
        let tallies = vec![
            StrategyTally {
                strategy_args: args("--a"),
                pass_count: 3,
                fail_count: 0,
            },
            StrategyTally {
                strategy_args: args("--b"),
                pass_count: 2,
                fail_count: 1,
            },
            StrategyTally {
                strategy_args: args("--c"),
                pass_count: 1,
                fail_count: 2,
            },
        ];
        let verified = filter_verified(&tallies, 2);
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0], args("--a"));
        assert_eq!(verified[1], args("--b"));
    }

    #[test]
    fn filter_none_pass() {
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 1,
            fail_count: 2,
        }];
        let verified = filter_verified(&tallies, 3);
        assert!(verified.is_empty());
    }

    #[test]
    fn filter_zero_threshold() {
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 0,
            fail_count: 3,
        }];
        let verified = filter_verified(&tallies, 0);
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0], args("--a"));
    }

    // ── extract_outcomes ───────────────────────────────────────

    #[test]
    fn extract_matches_by_args() {
        let candidates = vec![args("--a"), args("--b"), args("--c")];
        let results = vec![
            StrategyResult {
                strategy_args: args("--c"),
                result: TaskResult::Success {
                    verdict: HttpVerdictAvailable,
                    strategy_args: args("--c"),
                },
            },
            StrategyResult {
                strategy_args: args("--a"),
                result: TaskResult::Success {
                    verdict: HttpVerdictAvailable,
                    strategy_args: args("--a"),
                },
            },
            StrategyResult {
                strategy_args: args("--b"),
                result: TaskResult::Failed {
                    verdict: crate::network::http_client::HttpVerdict::Unavailable {
                        reason: "connection refused".to_string(),
                        cause: None,
                    },
                },
            },
        ];
        let outcomes = extract_outcomes(&candidates, &results);
        assert_eq!(outcomes, vec![true, false, true]);
    }

    #[test]
    fn extract_missing_result() {
        let candidates = vec![args("--a")];
        let results: Vec<StrategyResult> = vec![];
        let outcomes = extract_outcomes(&candidates, &results);
        assert_eq!(outcomes, vec![false]);
    }

    // ── VerifyConfig default ───────────────────────────────────

    #[test]
    fn verify_config_defaults() {
        let cfg = VerifyConfig::default();
        assert_eq!(cfg.passes, 3);
        assert_eq!(cfg.min_passes, 3);
        assert_eq!(cfg.request_timeout, 3);
    }

    // ── find_relaxed ───────────────────────────────────────────

    #[test]
    fn relaxed_finds_best_threshold() {
        // strict=3, но --a набрала 2/3, --b 1/3
        let tallies = vec![
            StrategyTally {
                strategy_args: args("--a"),
                pass_count: 2,
                fail_count: 1,
            },
            StrategyTally {
                strategy_args: args("--b"),
                pass_count: 1,
                fail_count: 2,
            },
        ];
        let result = find_relaxed(&tallies, 3).unwrap();
        assert_eq!(result.actual_min, 2);
        assert_eq!(result.strategies, vec![args("--a")]);
    }

    #[test]
    fn relaxed_all_zero() {
        // все 0/3 — даже relaxed не поможет
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 0,
            fail_count: 3,
        }];
        assert!(find_relaxed(&tallies, 3).is_none());
    }

    #[test]
    fn relaxed_falls_to_one() {
        // только 1/3 — порог опустится до 1
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 1,
            fail_count: 2,
        }];
        let result = find_relaxed(&tallies, 3).unwrap();
        assert_eq!(result.actual_min, 1);
        assert_eq!(result.strategies, vec![args("--a")]);
    }

    #[test]
    fn relaxed_not_needed_when_min_is_one() {
        // min_passes=1 — relaxed не вызывается (нечего понижать)
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 0,
            fail_count: 3,
        }];
        assert!(find_relaxed(&tallies, 1).is_none());
    }
}

#[cfg(test)]
mod stability_tests {
    use super::*;
    use crate::network::cause::{Cause, Phase};

    fn strategies(n: usize) -> Vec<Vec<String>> {
        (0..n).map(|i| vec![format!("--strategy-{i}")]).collect()
    }

    #[test]
    fn a_strategy_passing_every_pass_counts_as_always() {
        let report = stability_report(
            &strategies(1),
            &[vec![Outcome::Passed], vec![Outcome::Passed]],
        );
        assert_eq!(report.always, 1);
        assert_eq!(report.flapping, 0);
        assert_eq!(report.never, 0);
    }

    #[test]
    fn a_strategy_passing_some_passes_counts_as_flapping() {
        let report = stability_report(
            &strategies(1),
            &[
                vec![Outcome::Passed],
                vec![Outcome::Failed(Cause::Timeout(Phase::Request).name())],
            ],
        );
        assert_eq!(report.flapping, 1);
        assert_eq!(report.always, 0);
    }

    #[test]
    fn causes_of_the_never_group_do_not_leak_into_the_flapping_one() {
        // Первая стратегия не прошла ни разу — сброс. Вторая флапает — тишина.
        let report = stability_report(
            &strategies(2),
            &[
                vec![
                    Outcome::Failed(Cause::Reset(Phase::Tls).name()),
                    Outcome::Passed,
                ],
                vec![
                    Outcome::Failed(Cause::Reset(Phase::Tls).name()),
                    Outcome::Failed(Cause::Timeout(Phase::Request).name()),
                ],
            ],
        );
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
        let report = stability_report(
            &strategies(1),
            &[vec![Outcome::Failed("unknown".to_string())]],
        );
        assert_eq!(
            report.causes_never.get("unknown"),
            Some(&1),
            "провал без причины обязан быть виден: молча выброшенный, он \
             занизил бы знаменатель и завысил долю всего остального"
        );
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::*;
    use crate::error::HttpVerdictAvailable;
    use crate::network::cause::{Cause, Phase};
    use crate::network::http_client::HttpVerdict;

    #[test]
    fn a_success_is_a_passed_outcome() {
        let result = TaskResult::Success {
            verdict: HttpVerdictAvailable,
            strategy_args: vec![],
        };
        assert_eq!(outcome_of(&result), Outcome::Passed);
    }

    #[test]
    fn a_failure_carrying_a_wire_cause_is_named_by_that_cause() {
        let result = TaskResult::Failed {
            verdict: HttpVerdict::Unavailable {
                reason: "tls: reset".to_string(),
                cause: Some(Cause::Reset(Phase::Tls)),
            },
        };
        assert_eq!(
            outcome_of(&result),
            Outcome::Failed("reset/tls".to_string())
        );
    }

    #[test]
    fn a_verdict_born_above_the_wire_keeps_its_own_name() {
        let result = TaskResult::Failed {
            verdict: HttpVerdict::DpiDataLimit {
                size_download: 16_384,
            },
        };
        assert_eq!(
            outcome_of(&result),
            Outcome::Failed("dpi_data_limit".to_string()),
            "обрезание данных — находка того же ранга, что сброс: у него нет \
             ошибки ввода-вывода, но есть имя, и в гистограмме оно обязано стоять \
             отдельной корзиной, а не в «unknown»"
        );
    }

    #[test]
    fn an_engine_error_is_named_apart_from_any_network_failure() {
        let result = TaskResult::Error {
            error: crate::error::BlockcheckError::Nfqws2Crashed,
        };
        assert_eq!(
            outcome_of(&result),
            Outcome::Failed("engine_error".to_string()),
            "падение движка — не свойство стратегии; смешать его с сетевым \
             провалом значило бы обвинить стратегию в нашей же поломке"
        );
    }
}

#[cfg(test)]
mod rich_outcome_tests {
    use super::*;
    use crate::error::HttpVerdictAvailable;
    use crate::network::cause::{Cause, Phase};
    use crate::network::http_client::HttpVerdict;

    fn failed(cause: Cause) -> TaskResult {
        TaskResult::Failed {
            verdict: HttpVerdict::Unavailable {
                reason: "x".to_string(),
                cause: Some(cause),
            },
        }
    }

    #[test]
    fn outcomes_follow_candidate_order_not_result_order() {
        let candidates = vec![vec!["--a".to_string()], vec!["--b".to_string()]];
        // Результаты приходят из JoinSet в произвольном порядке — здесь обратном.
        let results = vec![
            StrategyResult {
                strategy_args: vec!["--b".to_string()],
                result: failed(Cause::Reset(Phase::Tls)),
            },
            StrategyResult {
                strategy_args: vec!["--a".to_string()],
                result: TaskResult::Success {
                    verdict: HttpVerdictAvailable,
                    strategy_args: vec!["--a".to_string()],
                },
            },
        ];
        assert_eq!(
            extract_rich_outcomes(&candidates, &results),
            vec![Outcome::Passed, Outcome::Failed("reset/tls".to_string())]
        );
    }

    #[test]
    fn a_candidate_with_no_result_at_all_is_named_missing() {
        let candidates = vec![vec!["--a".to_string()]];
        assert_eq!(
            extract_rich_outcomes(&candidates, &[]),
            vec![Outcome::Failed("missing".to_string())],
            "проба, не вернувшая ничего (дедлайн, снятый план), — не провал \
             стратегии; под своим именем она видна, а под чужим лгала бы"
        );
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
