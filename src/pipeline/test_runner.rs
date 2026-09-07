use std::time::Instant;

use crate::config::{CoreConfig, Protocol};
use crate::dto::{PassResult, StrategyStats, StrategyTestResult};
use crate::error::BlockcheckError;
use crate::firewall::nft::{OwnedTable, SystemNft};
use crate::firewall::nftables;
use crate::network::http_client::{http_test, interpret_http_result, pick_random_ip, HttpVerdict};
use crate::nfqws2::plan::{FilterMark, Plan, QueueNum};
use crate::nfqws2::run::SystemNfqws2;
use crate::ui;

pub struct TestConfig {
    pub passes: usize,
    pub delay_ms: u64,
    pub request_timeout: u64,
    pub with_baseline: bool,
}

/// Parse a strategies file: one strategy per line, comments (#) and empty lines skipped.
pub fn parse_strategies_file(content: &str) -> Result<Vec<Vec<String>>, BlockcheckError> {
    let mut strategies = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let args: Vec<String> = shell_split(line);
        if !args.is_empty() {
            strategies.push(args);
        }
    }

    if strategies.is_empty() {
        return Err(BlockcheckError::StrategiesFileEmpty);
    }

    Ok(strategies)
}

/// Simple shell-like splitting: respects quoted strings.
fn shell_split(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = ' ';

    for ch in s.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
            } else {
                current.push(ch);
            }
        } else if ch == '\'' || ch == '"' {
            in_quote = true;
            quote_char = ch;
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// Execute one timed test pass: start nfqws2, apply dispatch, http test, measure latency, cleanup.
#[allow(clippy::too_many_arguments)] // witness/table добавлены задачей 7 поверх уже широкого набора параметров
async fn execute_timed_test(
    config: &CoreConfig,
    witness: &FilterMark,
    table: &OwnedTable,
    domain: &str,
    protocol: Protocol,
    ips: &[String],
    strategy_args: &[String],
    request_timeout: u64,
) -> PassResult {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let start = Instant::now();

    // Собрать план из одного профиля и поднять движок
    let env = config.nfqws2_env();
    let queue = QueueNum::new(config.base_qnum);
    let plan = Plan::from_one(witness, queue, strategy_args);
    let mark = plan.profiles()[0].mark;

    let mut instance = match SystemNfqws2::start(&env, &plan).await {
        Ok(i) => i,
        Err(e) => {
            return PassResult {
                pass_index: 0,
                success: false,
                verdict: format!("ERROR: nfqws2: {e}"),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp,
            };
        }
    };

    // Дождаться, пока движок реально забиндит очередь
    let ready = match SystemNfqws2::wait_ready(&mut instance).await {
        Ok(r) => r,
        Err(e) => {
            SystemNfqws2::stop(instance).await;
            return PassResult {
                pass_index: 0,
                success: false,
                verdict: format!("ERROR: nfqws2: {e}"),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp,
            };
        }
    };

    // Поставить диспетчеризацию — только теперь, когда слушатель точно есть
    if let Err(e) = nftables::apply_dispatch(
        &SystemNft,
        table,
        &ready,
        &plan.dispatch(protocol.port()),
        ips,
    )
    .await
    {
        // Батч атомарен, но `Err` тут может значить и таймаут
        // `run_process_stdin` (15с): нельзя быть уверенным, что nft не успел
        // применить правила до обрыва. Снимаем диспетчеризацию на всякий
        // случай, прежде чем убивать слушателя — иначе `queue to N` рискует
        // остаться стоять без него до конца всего прогона.
        nftables::remove_dispatch(&SystemNft, table).await;
        SystemNfqws2::stop(instance).await;
        return PassResult {
            pass_index: 0,
            success: false,
            verdict: format!("ERROR: nftables: {e}"),
            latency_ms: start.elapsed().as_millis() as u64,
            timestamp,
        };
    }

    // HTTP test with timing
    let ip_str = pick_random_ip(ips).unwrap_or("127.0.0.1");

    let test_start = Instant::now();
    let result = http_test(
        protocol,
        domain,
        ip_str,
        mark.so_mark(),
        request_timeout,
        None,
    )
    .await;
    let verdict = interpret_http_result(&result, domain);
    let success = matches!(verdict, HttpVerdict::Available);
    let verdict_str = format!("{verdict}");
    let latency_ms = test_start.elapsed().as_millis() as u64;

    // best-effort cleanup: снять диспетчеризацию, затем убить nfqws2
    nftables::remove_dispatch(&SystemNft, table).await;
    SystemNfqws2::stop(instance).await;

    PassResult {
        pass_index: 0,
        success,
        verdict: verdict_str,
        latency_ms,
        timestamp,
    }
}

/// Execute one baseline pass (no bypass, no nfqws2).
async fn execute_baseline_pass(
    domain: &str,
    protocol: Protocol,
    ips: &[String],
    request_timeout: u64,
) -> PassResult {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let ip_str = pick_random_ip(ips).unwrap_or("127.0.0.1");

    let test_start = Instant::now();
    let result = http_test(protocol, domain, ip_str, 0, request_timeout, None).await;
    let verdict = interpret_http_result(&result, domain);
    let success = matches!(verdict, HttpVerdict::Available);
    let verdict_str = format!("{verdict}");
    let latency_ms = test_start.elapsed().as_millis() as u64;

    PassResult {
        pass_index: 0,
        success,
        verdict: verdict_str,
        latency_ms,
        timestamp,
    }
}

/// Run strategy tests sequentially. Returns results for baseline (if enabled) + all strategies.
#[allow(clippy::too_many_arguments)] // witness добавлен задачей 7 поверх уже широкого набора параметров
pub async fn run_strategy_tests(
    test_config: &TestConfig,
    core_config: &CoreConfig,
    witness: &FilterMark,
    domain: &str,
    protocol: Protocol,
    ips: &[String],
    strategies: &[Vec<String>],
    screen: &ui::Console,
) -> Vec<StrategyTestResult> {
    let mut results = Vec::new();

    // Подготовить таблицу: один батч, атомарный снос остатков прошлого
    // прогона включительно — см. doc-комментарий `prepare_table`.
    let table = match nftables::prepare_table(&SystemNft, &core_config.nft_table).await {
        Ok(t) => t,
        Err(e) => {
            screen.println(&format!("  ERROR: failed to prepare nftables: {e}"));
            return results;
        }
    };

    // Baseline (if enabled)
    if test_config.with_baseline {
        screen.println(&format!("\n{}", ui::section("Baseline (no bypass)")));

        let mut pass_results = Vec::new();
        for i in 0..test_config.passes {
            let mut result =
                execute_baseline_pass(domain, protocol, ips, test_config.request_timeout).await;
            result.pass_index = i + 1;
            screen.println(&format!(
                "  Pass {:>2}: {}  {}ms",
                result.pass_index,
                if result.success { "SUCCESS" } else { "FAILED " },
                result.latency_ms,
            ));
            pass_results.push(result);

            if test_config.delay_ms > 0 && i + 1 < test_config.passes {
                tokio::time::sleep(std::time::Duration::from_millis(test_config.delay_ms)).await;
            }
        }

        let stats = compute_stats(&pass_results);
        results.push(StrategyTestResult {
            strategy_args: vec!["(baseline — no bypass)".to_string()],
            pass_results,
            stats,
        });
    }

    // Test each strategy
    for (idx, strategy) in strategies.iter().enumerate() {
        screen.println(&format!(
            "\n{}",
            ui::section(&format!("Strategy #{}", idx + 1))
        ));
        screen.println(&format!("  nfqws2 {}", strategy.join(" ")));

        let mut pass_results = Vec::new();
        for i in 0..test_config.passes {
            let mut result = execute_timed_test(
                core_config,
                witness,
                &table,
                domain,
                protocol,
                ips,
                strategy,
                test_config.request_timeout,
            )
            .await;
            result.pass_index = i + 1;
            screen.println(&format!(
                "  Pass {:>2}: {}  {}ms",
                result.pass_index,
                if result.success { "SUCCESS" } else { "FAILED " },
                result.latency_ms,
            ));
            pass_results.push(result);

            if test_config.delay_ms > 0 && i + 1 < test_config.passes {
                tokio::time::sleep(std::time::Duration::from_millis(test_config.delay_ms)).await;
            }
        }

        let stats = compute_stats(&pass_results);
        results.push(StrategyTestResult {
            strategy_args: strategy.clone(),
            pass_results,
            stats,
        });
    }

    // Cleanup: снести таблицу целиком, хэндл потреблён.
    let _ = table.drop_table(&SystemNft).await;

    results
}

pub fn compute_stats(pass_results: &[PassResult]) -> StrategyStats {
    let total = pass_results.len();
    let successes = pass_results.iter().filter(|r| r.success).count();
    let failures = pass_results
        .iter()
        .filter(|r| !r.success && !r.verdict.starts_with("ERROR"))
        .count();
    let errors = pass_results
        .iter()
        .filter(|r| r.verdict.starts_with("ERROR"))
        .count();

    let success_rate = if total > 0 {
        successes as f64 / total as f64
    } else {
        0.0
    };

    // Latency stats from successful passes only
    let mut latencies: Vec<u64> = pass_results
        .iter()
        .filter(|r| r.success)
        .map(|r| r.latency_ms)
        .collect();
    latencies.sort_unstable();

    let (median, p95, p99, min, max) = if latencies.is_empty() {
        (0, 0, 0, 0, 0)
    } else {
        (
            percentile(&latencies, 50),
            percentile(&latencies, 95),
            percentile(&latencies, 99),
            latencies[0],
            latencies[latencies.len() - 1],
        )
    };

    // Error distribution
    let mut error_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in pass_results.iter().filter(|r| !r.success) {
        *error_map.entry(r.verdict.clone()).or_insert(0) += 1;
    }
    let mut error_distribution: Vec<(String, usize)> = error_map.into_iter().collect();
    error_distribution.sort_by_key(|b| std::cmp::Reverse(b.1));

    StrategyStats {
        total_passes: total,
        successes,
        failures,
        errors,
        success_rate,
        latency_median_ms: median,
        latency_p95_ms: p95,
        latency_p99_ms: p99,
        latency_min_ms: min,
        latency_max_ms: max,
        error_distribution,
    }
}

pub fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = (pct as f64 / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_strategies_file_basic() {
        let content = "# Comment\n\n--payload=tls_client_hello --lua-desync=fake:blob=0x1603:ip_ttl=6\n--payload=tls_client_hello --lua-desync=multisplit:pos=1\n";
        let result = parse_strategies_file(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            vec![
                "--payload=tls_client_hello",
                "--lua-desync=fake:blob=0x1603:ip_ttl=6",
            ]
        );
        assert_eq!(
            result[1],
            vec![
                "--payload=tls_client_hello",
                "--lua-desync=multisplit:pos=1",
            ]
        );
    }

    #[test]
    fn test_parse_strategies_file_only_comments() {
        let content = "# Comment\n# Another comment\n\n";
        let result = parse_strategies_file(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_strategies_file_empty() {
        let content = "";
        let result = parse_strategies_file(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_strategies_file_with_whitespace() {
        let content = "  --arg1 --arg2  \n  # skip  \n  --arg3  ";
        let result = parse_strategies_file(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], vec!["--arg1", "--arg2"]);
        assert_eq!(result[1], vec!["--arg3"]);
    }

    #[test]
    fn test_shell_split_basic() {
        let args = shell_split("--foo=bar --baz=qux");
        assert_eq!(args, vec!["--foo=bar", "--baz=qux"]);
    }

    #[test]
    fn test_shell_split_quoted() {
        let args = shell_split("--foo='hello world' --bar");
        assert_eq!(args, vec!["--foo=hello world", "--bar"]);
    }

    #[test]
    fn test_compute_stats_all_success() {
        let results = vec![
            PassResult {
                pass_index: 1,
                success: true,
                verdict: "Available".into(),
                latency_ms: 100,
                timestamp: 0,
            },
            PassResult {
                pass_index: 2,
                success: true,
                verdict: "Available".into(),
                latency_ms: 200,
                timestamp: 0,
            },
            PassResult {
                pass_index: 3,
                success: true,
                verdict: "Available".into(),
                latency_ms: 150,
                timestamp: 0,
            },
        ];
        let stats = compute_stats(&results);
        assert_eq!(stats.total_passes, 3);
        assert_eq!(stats.successes, 3);
        assert_eq!(stats.failures, 0);
        assert_eq!(stats.errors, 0);
        assert!((stats.success_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(stats.latency_min_ms, 100);
        assert_eq!(stats.latency_max_ms, 200);
        assert_eq!(stats.latency_median_ms, 150);
    }

    #[test]
    fn test_compute_stats_mixed() {
        let results = vec![
            PassResult {
                pass_index: 1,
                success: true,
                verdict: "Available".into(),
                latency_ms: 100,
                timestamp: 0,
            },
            PassResult {
                pass_index: 2,
                success: false,
                verdict: "UNAVAILABLE code=28".into(),
                latency_ms: 3000,
                timestamp: 0,
            },
            PassResult {
                pass_index: 3,
                success: true,
                verdict: "Available".into(),
                latency_ms: 200,
                timestamp: 0,
            },
        ];
        let stats = compute_stats(&results);
        assert_eq!(stats.successes, 2);
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.error_distribution.len(), 1);
        assert_eq!(stats.error_distribution[0].0, "UNAVAILABLE code=28");
    }

    #[test]
    fn test_compute_stats_all_failed() {
        let results = vec![
            PassResult {
                pass_index: 1,
                success: false,
                verdict: "UNAVAILABLE code=28".into(),
                latency_ms: 3000,
                timestamp: 0,
            },
            PassResult {
                pass_index: 2,
                success: false,
                verdict: "UNAVAILABLE code=28".into(),
                latency_ms: 3000,
                timestamp: 0,
            },
        ];
        let stats = compute_stats(&results);
        assert_eq!(stats.latency_median_ms, 0);
    }

    #[test]
    fn test_compute_stats_empty() {
        let results: Vec<PassResult> = vec![];
        let stats = compute_stats(&results);
        assert_eq!(stats.total_passes, 0);
        assert!((stats.success_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_percentile_basic() {
        let data = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert_eq!(percentile(&data, 50), 60);
        assert_eq!(percentile(&data, 0), 10);
        assert_eq!(percentile(&data, 100), 100);

        let data3 = vec![100, 200, 300];
        assert_eq!(percentile(&data3, 50), 200);
        assert_eq!(percentile(&data3, 95), 300);
    }

    #[test]
    fn test_percentile_single() {
        assert_eq!(percentile(&[42], 50), 42);
        assert_eq!(percentile(&[42], 99), 42);
    }

    #[test]
    fn test_percentile_empty() {
        assert_eq!(percentile(&[], 50), 0);
    }
}
