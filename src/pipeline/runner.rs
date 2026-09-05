use std::fmt::Write;
use std::sync::Arc;
use std::time::Instant;

use console::style;
use indicatif::{MultiProgress, ProgressBar, ProgressState, ProgressStyle};
use tokio::task::JoinSet;
use tracing::info;

use crate::config::{CoreConfig, Protocol};
use crate::error::TaskResult;
use crate::firewall::nftables;
use crate::pipeline::worker_task::{execute_worker_task_rules_ready, HttpTestMode, WorkerTask};
use crate::system::process;
use crate::worker::slot::WorkerSlot;

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

/// Прекратить выдачу новых батчей.
///
/// Дедлайн — штатный конец прогона. Shutdown — Ctrl+C: cleanup сносит нашу
/// таблицу первым делом (чтобы не слать пакеты в отвязанный NFQUEUE), и до
/// `process::exit` остаётся окно в сотни миллисекунд. Без этой проверки цикл
/// продолжает лить `add chain inet <table> wp_*` в уже снесённую таблицу —
/// это и есть простыня `No such file or directory` из #66.
fn stop_before_batch(deadline: Option<Instant>, now: Instant, shutting_down: bool) -> bool {
    shutting_down || deadline.is_some_and(|dl| now >= dl)
}

/// Parameters for parallel strategy execution.
pub struct RunParams<'a> {
    pub config: &'a CoreConfig,
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

/// Run strategies in parallel batches using worker slots.
///
/// nftables rules are added once per batch (not per strategy), drastically
/// reducing nft fork+exec overhead. Only nfqws2 start/kill and HTTP tests
/// happen per strategy.
pub async fn run_parallel(params: RunParams<'_>) -> (Vec<StrategyResult>, RunStats) {
    let RunParams {
        config,
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
    let slots = WorkerSlot::create_slots(config.worker_count, config.base_qnum);

    // Cleanup any leftover nftables table from a previous crashed run
    nftables::drop_table(&config.nft_table).await;

    // Prepare nftables table once
    if let Err(e) = nftables::prepare_table(&config.nft_table).await {
        let results: Vec<StrategyResult> = strategies
            .iter()
            .map(|args| StrategyResult {
                strategy_args: args.clone(),
                result: TaskResult::Error { error: e.clone() },
            })
            .collect();
        let stats = RunStats {
            total: strategies.len(),
            completed: strategies.len(),
            successes: 0,
            failures: 0,
            errors: strategies.len(),
            elapsed: start.elapsed(),
        };
        return (results, stats);
    }

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

    let batches: Vec<&[Vec<String>]> = strategies.chunks(config.worker_count).collect();

    for batch in batches {
        if stop_before_batch(
            deadline,
            Instant::now(),
            process::background_shutdown_started(),
        ) {
            break;
        }

        // Determine which slots are used in this batch
        let batch_slots: Vec<WorkerSlot> = slots.iter().take(batch.len()).cloned().collect();

        // Add all nftables vmap elements + dispatch rules for this batch
        if let Err(e) =
            nftables::add_all_worker_rules(&config.nft_table, &batch_slots, protocol.port(), &ips)
                .await
        {
            // All strategies in this batch fail
            for strategy_args in batch {
                errors += 1;
                let line = format!("nft batch add failed: {e}");
                if let Some(m) = multi {
                    let _ = m.println(&line);
                } else {
                    pb.suspend(|| eprintln!("{line}"));
                }
                pb.inc(1);
                all_results.push(StrategyResult {
                    strategy_args: strategy_args.clone(),
                    result: TaskResult::Error { error: e.clone() },
                });
            }
            continue;
        }

        // Run all strategies in this batch concurrently (rules are already in place)
        let mut join_set = JoinSet::new();

        for (index, strategy_args) in batch.iter().enumerate() {
            let slot = slots[index].clone();
            let config = config.clone();
            let task = WorkerTask {
                slot,
                domain: domain.clone(),
                strategy_args: strategy_args.clone(),
                protocol,
                ips: ips.clone(),
            };

            join_set.spawn(async move {
                let result = execute_worker_task_rules_ready(&config, &task, mode).await;
                (task.strategy_args, result)
            });
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
                }
            }
        }

        // Remove all rules for this batch in ONE nft call
        nftables::remove_all_worker_rules(&config.nft_table, &batch_slots).await;
    }

    if external_pb.is_none() {
        pb.finish_and_clear();
    }

    // Cleanup nftables table
    nftables::drop_table(&config.nft_table).await;

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
}
