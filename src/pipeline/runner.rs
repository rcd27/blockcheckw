use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use console::style;
use indicatif::{MultiProgress, ProgressBar, ProgressState, ProgressStyle};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::info;

use crate::config::{CoreConfig, Protocol};
use crate::error::{BlockcheckError, TaskResult};
use crate::firewall::nft::SystemNft;
use crate::firewall::nftables;
use crate::nfqws2::plan::{FilterMark, Plan, QueueNum};
use crate::nfqws2::run::SystemNfqws2;
use crate::pipeline::worker_task::{probe_profile, HttpTestMode, ProbeTask};
use crate::system::process;

#[derive(Debug)]
pub struct StrategyResult {
    pub strategy_args: Vec<String>,
    pub result: TaskResult,
}

#[derive(Debug)]
pub struct RunStats {
    pub total: usize,
    pub completed: usize,
    pub successes: usize,
    pub failures: usize,
    pub errors: usize,
    pub elapsed: std::time::Duration,
}

impl RunStats {
    pub fn throughput(&self) -> f64 {
        if self.elapsed.as_secs_f64() > 0.0 {
            self.completed as f64 / self.elapsed.as_secs_f64()
        } else {
            0.0
        }
    }
}

/// Прекратить выдачу новых планов.
///
/// Дедлайн — штатный конец прогона. Shutdown — Ctrl+C: cleanup сносит нашу
/// таблицу первым делом (чтобы не слать пакеты в отвязанный NFQUEUE), и до
/// `process::exit` остаётся окно в сотни миллисекунд. Без этой проверки цикл
/// продолжает лить `add rule ...` в уже снесённую таблицу — это и есть
/// простыня `No such file or directory` из #66.
fn stop_before_batch(deadline: Option<Instant>, now: Instant, shutting_down: bool) -> bool {
    shutting_down || deadline.is_some_and(|dl| now >= dl)
}

/// Parameters for parallel strategy execution.
pub struct RunParams<'a> {
    pub config: &'a CoreConfig,
    /// Свидетельство преflight'а: без него `Plan` не собрать.
    pub filter_mark: &'a FilterMark,
    pub domain: &'a str,
    pub protocol: Protocol,
    pub strategies: &'a [Vec<String>],
    pub ips: &'a [String],
    pub multi: Option<&'a MultiProgress>,
    pub external_pb: Option<&'a ProgressBar>,
    pub mode: HttpTestMode,
    pub deadline: Option<Instant>,
    /// Optional sink that each AVAILABLE strategy's args are pushed into as soon
    /// as it is found, so an interrupt mid-run never loses results.
    pub success_sink: Option<Arc<std::sync::Mutex<Vec<Vec<String>>>>>,
}

fn record_plan_failure(
    chunk: &[Vec<String>],
    error: &BlockcheckError,
    all_results: &mut Vec<StrategyResult>,
    errors: &mut usize,
    multi: Option<&MultiProgress>,
    pb: &ProgressBar,
) {
    let line = format!(
        "nfqws2 plan failed ({} {}): {error}",
        chunk.len(),
        if chunk.len() == 1 {
            "strategy"
        } else {
            "strategies"
        }
    );
    if let Some(m) = multi {
        let _ = m.println(&line);
    } else {
        pb.suspend(|| eprintln!("{line}"));
    }
    for strategy_args in chunk {
        *errors += 1;
        pb.inc(1);
        all_results.push(StrategyResult {
            strategy_args: strategy_args.clone(),
            result: TaskResult::Error {
                error: error.clone(),
            },
        });
    }
}

fn all_as_error(
    strategies: &[Vec<String>],
    error: BlockcheckError,
    elapsed: Duration,
) -> (Vec<StrategyResult>, RunStats) {
    let results: Vec<StrategyResult> = strategies
        .iter()
        .map(|args| StrategyResult {
            strategy_args: args.clone(),
            result: TaskResult::Error {
                error: error.clone(),
            },
        })
        .collect();
    let stats = RunStats {
        total: strategies.len(),
        completed: strategies.len(),
        successes: 0,
        failures: 0,
        errors: strategies.len(),
        elapsed,
    };
    (results, stats)
}

pub async fn run_parallel(params: RunParams<'_>) -> (Vec<StrategyResult>, RunStats) {
    let RunParams {
        config,
        filter_mark,
        domain,
        protocol,
        strategies,
        ips,
        multi,
        external_pb,
        mode,
        deadline,
        success_sink,
    } = params;

    let start = Instant::now();

    if config.profiles_per_instance == 0 {
        return all_as_error(
            strategies,
            BlockcheckError::InvalidConfig {
                reason: "profiles_per_instance is 0: a plan cannot be built without profiles"
                    .to_string(),
            },
            start.elapsed(),
        );
    }

    let table = match nftables::prepare_table(&SystemNft, &config.nft_table).await {
        Ok(t) => t,
        Err(e) => return all_as_error(strategies, e, start.elapsed()),
    };

    let owned_pb;
    let pb: &ProgressBar = match external_pb {
        Some(epb) => epb,
        None => {
            let raw_pb = ProgressBar::new(strategies.len() as u64);
            raw_pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({rate}, ETA {eta})"
                )
                .expect("static template")
                .with_key("rate", |state: &ProgressState, w: &mut dyn Write| {
                    let _ = write!(w, "{:.1}/s", state.per_sec());
                })
                .progress_chars("=>-"),
            );
            raw_pb.enable_steady_tick(std::time::Duration::from_millis(100));
            owned_pb = if let Some(m) = multi {
                m.add(raw_pb)
            } else {
                raw_pb
            };
            &owned_pb
        }
    };

    let mut all_results: Vec<StrategyResult> = Vec::with_capacity(strategies.len());
    let mut successes = 0usize;
    let mut failures = 0usize;
    let mut errors = 0usize;

    let domain: Arc<str> = Arc::from(domain);
    let ips: Arc<[String]> = Arc::from(ips);

    let env = config.nfqws2_env();
    let queue = QueueNum::new(config.base_qnum);
    let permits = Arc::new(Semaphore::new(config.worker_count));

    for chunk in strategies.chunks(config.profiles_per_instance) {
        if stop_before_batch(
            deadline,
            Instant::now(),
            process::background_shutdown_started(),
        ) {
            break;
        }

        let plan = Plan::from_strategies(filter_mark, queue, chunk);

        let mut instance = match SystemNfqws2::start(&env, &plan).await {
            Ok(i) => i,
            Err(e) => {
                record_plan_failure(chunk, &e.into(), &mut all_results, &mut errors, multi, pb);
                continue;
            }
        };

        info!(
            profiles = plan.profiles().len(),
            queue = queue.get(),
            "nfqws2 instance started"
        );

        let ready = match SystemNfqws2::wait_ready(&mut instance).await {
            Ok(r) => r,
            Err(e) => {
                SystemNfqws2::stop(instance).await;
                record_plan_failure(chunk, &e.into(), &mut all_results, &mut errors, multi, pb);
                continue;
            }
        };

        if let Err(e) = nftables::apply_dispatch(
            &SystemNft,
            &table,
            &ready,
            &plan.dispatch(protocol.port()),
            &ips,
        )
        .await
        {
            nftables::remove_dispatch(&SystemNft, &table).await;
            SystemNfqws2::stop(instance).await;
            record_plan_failure(chunk, &e, &mut all_results, &mut errors, multi, pb);
            continue;
        }

        let mut join_set = JoinSet::new();
        let mut pending_args: HashMap<tokio::task::Id, Vec<String>> = HashMap::new();

        for profile in plan.profiles() {
            if stop_before_batch(
                deadline,
                Instant::now(),
                process::background_shutdown_started(),
            ) {
                break;
            }

            let permit = permits
                .clone()
                .acquire_owned()
                .await
                .expect("семафор жив, пока жив run_parallel");
            let task = ProbeTask {
                mark: profile.mark,
                domain: domain.clone(),
                strategy_args: profile.args.clone(),
                protocol,
                ips: ips.clone(),
            };
            let config = config.clone();

            let handle = join_set.spawn(async move {
                let result = probe_profile(&config, &task, mode).await;
                drop(permit);
                (task.strategy_args, result)
            });
            pending_args.insert(handle.id(), profile.args.clone());
        }

        while let Some(join_result) = join_set.join_next().await {
            match join_result {
                Ok((strategy_args, task_result)) => {
                    match &task_result {
                        TaskResult::Success { .. } => {
                            successes += 1;
                            // Persist the win immediately so an interrupt can't lose it.
                            if let Some(sink) = &success_sink {
                                sink.lock().unwrap().push(strategy_args.clone());
                            }
                        }
                        TaskResult::Failed { .. } => failures += 1,
                        TaskResult::Error { .. } => errors += 1,
                    }

                    let test_func = protocol.test_func_name();
                    let header = format!(
                        "- {test_func} ipv4 {domain} : nfqws2 {}",
                        strategy_args.join(" ")
                    );
                    let line = match &task_result {
                        TaskResult::Success { .. } => {
                            format!(
                                "{}\n{}",
                                style(&header).green().bold(),
                                style(&task_result).green().bold()
                            )
                        }
                        TaskResult::Failed { .. } => {
                            format!("{}\n{}", style(&header).dim(), style(&task_result).dim())
                        }
                        TaskResult::Error { .. } => {
                            format!("{}\n{}", style(&header).red(), style(&task_result).red())
                        }
                    };
                    if let Some(m) = multi {
                        let _ = m.println(&line);
                    } else {
                        pb.suspend(|| println!("{line}"));
                    }
                    pb.inc(1);

                    all_results.push(StrategyResult {
                        strategy_args,
                        result: task_result,
                    });
                }
                Err(join_err) => {
                    errors += 1;
                    let line = format!("task join error: {join_err}");
                    if let Some(m) = multi {
                        let _ = m.println(&line);
                    } else {
                        pb.suspend(|| eprintln!("{line}"));
                    }
                    pb.inc(1);

                    let strategy_args = pending_args.remove(&join_err.id()).unwrap_or_default();
                    all_results.push(StrategyResult {
                        strategy_args,
                        result: TaskResult::Error {
                            error: BlockcheckError::TaskJoin {
                                reason: join_err.to_string(),
                            },
                        },
                    });
                }
            }
        }

        nftables::remove_dispatch(&SystemNft, &table).await;
        SystemNfqws2::stop(instance).await;
    }

    if external_pb.is_none() {
        pb.finish_and_clear();
    }

    // Cleanup nftables table — хэндл потребляется, снести повторно нечем.
    let _ = table.drop_table(&SystemNft).await;

    let elapsed = start.elapsed();
    let stats = RunStats {
        total: strategies.len(),
        completed: all_results.len(),
        successes,
        failures,
        errors,
        elapsed,
    };

    info!(
        "Completed {}/{} strategies in {:.2}s ({:.1} strat/sec): {} success, {} failed, {} errors",
        stats.completed,
        stats.total,
        stats.elapsed.as_secs_f64(),
        stats.throughput(),
        stats.successes,
        stats.failures,
        stats.errors
    );

    (all_results, stats)
}

#[cfg(test)]
mod stop_tests {
    use super::stop_before_batch;
    use std::time::{Duration, Instant};

    /// #66: cleanup сносит нашу таблицу раньше, чем пайплайн об этом узнаёт.
    /// Каждый следующий батч утыкается в несуществующую таблицу и печатает
    /// `add chain inet blockcheckw wp_* — No such file or directory`. Именно
    /// эту простыню bol-van получил после Ctrl+C.
    #[test]
    fn shutdown_stops_batches_before_they_hit_a_dropped_table() {
        let ahead = Instant::now() + Duration::from_secs(60);
        assert!(stop_before_batch(Some(ahead), Instant::now(), true));
    }

    /// Дедлайн — штатный конец прогона, он должен продолжать работать.
    #[test]
    fn expired_deadline_stops_batches() {
        let past = Instant::now() - Duration::from_secs(1);
        assert!(stop_before_batch(Some(past), Instant::now(), false));
    }

    #[test]
    fn runs_while_deadline_is_ahead_and_nothing_is_shutting_down() {
        let ahead = Instant::now() + Duration::from_secs(60);
        assert!(!stop_before_batch(Some(ahead), Instant::now(), false));
    }

    #[test]
    fn no_deadline_means_run_until_shutdown() {
        assert!(!stop_before_batch(None, Instant::now(), false));
        assert!(stop_before_batch(None, Instant::now(), true));
    }

    #[tokio::test]
    async fn checking_the_deadline_per_step_stops_sooner_than_once_per_plan() {
        const STEPS: usize = 40;
        const STEP: Duration = Duration::from_millis(5);

        // Старая схема: проверка один раз, на границе "плана" — как было на
        // границе батча до фикса I2.
        let deadline_old = Instant::now() + STEP * 8;
        let mut attempted_old = 0;
        if !stop_before_batch(Some(deadline_old), Instant::now(), false) {
            for _ in 0..STEPS {
                tokio::time::sleep(STEP).await; // имитирует ожидание permit'а/пробы
                attempted_old += 1;
            }
        }

        // Новая схема: проверка перед КАЖДЫМ шагом.
        let deadline_new = Instant::now() + STEP * 8;
        let mut attempted_new = 0;
        for _ in 0..STEPS {
            if stop_before_batch(Some(deadline_new), Instant::now(), false) {
                break;
            }
            tokio::time::sleep(STEP).await;
            attempted_new += 1;
        }

        assert_eq!(
            attempted_old, STEPS,
            "проверка на границе плана не может остановиться раньше конца плана — \
             в этом и была находка I2"
        );
        assert!(
            attempted_new < STEPS,
            "проверка перед каждым шагом обязана остановиться до конца плана, \
             а не пройти все {STEPS}: attempted_new={attempted_new}"
        );
        assert!(
            attempted_new <= STEPS / 2,
            "остановка должна случиться около 8-го шага (дедлайн ушёл на 8*STEP), \
             а не позже: attempted_new={attempted_new}"
        );
    }
}
