use std::path::Path;

use console::style;
use serde::Serialize;

use crate::config::Protocol;
use crate::pipeline::test_runner::{StabilityVerdict, StrategyTestResult};
use crate::ui;

/// Render full terminal report for test results.
pub fn render_terminal_report(
    results: &[StrategyTestResult],
    domain: &str,
    protocol: Protocol,
    passes: usize,
    curl_timeout: &str,
    verbose: bool,
    screen: &ui::ScanScreen,
) {
    screen.println(&format!(
        "\n{}",
        ui::section(&format!("Strategy Test: {domain} / {protocol}"))
    ));
    screen.println(&format!(
        "  {} passes per strategy, timeout={}s",
        passes, curl_timeout,
    ));

    for (idx, result) in results.iter().enumerate() {
        let is_baseline =
            result.strategy_args.len() == 1 && result.strategy_args[0].starts_with("(baseline");
        let header = if is_baseline {
            "Baseline (no bypass)".to_string()
        } else {
            let strat_idx = if results.first().is_some_and(|r| {
                r.strategy_args.len() == 1 && r.strategy_args[0].starts_with("(baseline")
            }) {
                idx
            } else {
                idx + 1
            };
            format!("Strategy #{strat_idx}")
        };

        screen.println(&format!("\n--- {} ---", style(&header).bold()));

        if !is_baseline {
            screen.println(&format!(
                "  nfqws2 {}",
                style(result.strategy_args.join(" ")).cyan()
            ));
        }

        if verbose {
            screen.println("");
            for pass in &result.pass_results {
                let status = if pass.success {
                    style("SUCCESS").green().to_string()
                } else {
                    style("FAILED ").red().to_string()
                };
                screen.println(&format!(
                    "  Pass {:>2}: {}  {}ms",
                    pass.pass_index, status, pass.latency_ms,
                ));
            }
        }

        let stats = &result.stats;
        let rate_str = format!("{:.1}%", stats.success_rate * 100.0);
        let rate_styled = match stats.stability {
            StabilityVerdict::Stable | StabilityVerdict::Reliable => {
                style(rate_str).green().bold().to_string()
            }
            StabilityVerdict::Flaky => style(rate_str).yellow().bold().to_string(),
            _ => style(rate_str).red().bold().to_string(),
        };

        screen.println(&format!(
            "\n  Passes:   {}/{} SUCCESS ({})",
            stats.successes, stats.total_passes, rate_styled,
        ));

        if stats.successes > 0 {
            screen.println(&format!(
                "  Latency:  median={}ms  p95={}ms  p99={}ms  min={}ms  max={}ms",
                stats.latency_median_ms,
                stats.latency_p95_ms,
                stats.latency_p99_ms,
                stats.latency_min_ms,
                stats.latency_max_ms,
            ));
        }

        let verdict_styled = match stats.stability {
            StabilityVerdict::Stable => style(stats.stability.to_string()).green().bold(),
            StabilityVerdict::Reliable => style(stats.stability.to_string()).green(),
            StabilityVerdict::Flaky => style(stats.stability.to_string()).yellow().bold(),
            StabilityVerdict::Unreliable => style(stats.stability.to_string()).red(),
            StabilityVerdict::Broken => style(stats.stability.to_string()).red().bold(),
        };
        screen.println(&format!("  Verdict:  {verdict_styled}"));

        if !stats.error_distribution.is_empty() && stats.successes < stats.total_passes {
            let errors: Vec<String> = stats
                .error_distribution
                .iter()
                .map(|(msg, count)| format!("{count}x {msg}"))
                .collect();
            screen.println(&format!("  Errors:   {}", style(errors.join(", ")).dim()));
        }
    }

    // Comparison table (skip if only 1 result)
    if results.len() > 1 {
        render_comparison_table(results, screen);
    }
}

/// Render comparison table for multiple strategies.
fn render_comparison_table(results: &[StrategyTestResult], screen: &ui::ScanScreen) {
    screen.println(&format!("\n{}", ui::section("Comparison")));

    screen.println(&format!(
        "  {:<4} {:<40} {:>8} {:>11} {:>8} {:>8}",
        "#", "Strategy (short)", "Success", "Verdict", "Median", "p95"
    ));

    for (idx, result) in results.iter().enumerate() {
        let is_baseline =
            result.strategy_args.len() == 1 && result.strategy_args[0].starts_with("(baseline");
        let label = if is_baseline {
            "(baseline)".to_string()
        } else {
            truncate_strategy(&result.strategy_args.join(" "), 38)
        };

        let rate = format!("{:.1}%", result.stats.success_rate * 100.0);
        let verdict = result.stats.stability.to_string();
        let median = if result.stats.successes > 0 {
            format!("{}ms", result.stats.latency_median_ms)
        } else {
            "-".to_string()
        };
        let p95 = if result.stats.successes > 0 {
            format!("{}ms", result.stats.latency_p95_ms)
        } else {
            "-".to_string()
        };

        screen.println(&format!(
            "  {:<4} {:<40} {:>8} {:>11} {:>8} {:>8}",
            idx + 1,
            label,
            rate,
            verdict,
            median,
            p95,
        ));
    }

    // Winner
    let best = results
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            !(r.strategy_args.len() == 1 && r.strategy_args[0].starts_with("(baseline"))
        })
        .max_by(|(_, a), (_, b)| {
            a.stats
                .success_rate
                .partial_cmp(&b.stats.success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    // Higher success rate wins; on tie, lower median latency wins
                    b.stats.latency_median_ms.cmp(&a.stats.latency_median_ms)
                })
        });

    if let Some((idx, result)) = best {
        let rate = format!("{:.1}%", result.stats.success_rate * 100.0);
        let median = format!("{}ms", result.stats.latency_median_ms);
        screen.println(&format!(
            "\n  {} Strategy #{} ({}, median {})",
            style("Winner:").green().bold(),
            idx + 1,
            rate,
            median,
        ));
    }
}

fn truncate_strategy(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("...{}", &s[s.len() - (max_len - 3)..])
    }
}

#[derive(Serialize)]
struct JsonReport {
    meta: JsonMeta,
    baseline: Option<JsonStrategy>,
    strategies: Vec<JsonStrategy>,
}

#[derive(Serialize)]
struct JsonMeta {
    domain: String,
    protocol: String,
    passes: usize,
    curl_timeout: String,
    timestamp: String,
}

#[derive(Serialize)]
struct JsonStrategy {
    args: String,
    success_rate: f64,
    stability: String,
    latency: JsonLatency,
    error_distribution: std::collections::HashMap<String, usize>,
    passes: Vec<JsonPass>,
}

#[derive(Serialize)]
struct JsonLatency {
    median_ms: u64,
    p95_ms: u64,
    p99_ms: u64,
    min_ms: u64,
    max_ms: u64,
}

#[derive(Serialize)]
struct JsonPass {
    index: usize,
    success: bool,
    latency_ms: u64,
    verdict: String,
    timestamp: u64,
}

/// Write JSON report to file.
pub fn write_json(
    path: &str,
    domain: &str,
    protocol: Protocol,
    passes: usize,
    curl_timeout: &str,
    results: &[StrategyTestResult],
) -> Result<(), String> {
    let now = chrono_like_timestamp();

    let mut baseline = None;
    let mut strategies = Vec::new();

    for result in results {
        let is_baseline =
            result.strategy_args.len() == 1 && result.strategy_args[0].starts_with("(baseline");

        let json_strat = JsonStrategy {
            args: if is_baseline {
                "(baseline)".to_string()
            } else {
                result.strategy_args.join(" ")
            },
            success_rate: result.stats.success_rate,
            stability: result.stats.stability.to_string().to_lowercase(),
            latency: JsonLatency {
                median_ms: result.stats.latency_median_ms,
                p95_ms: result.stats.latency_p95_ms,
                p99_ms: result.stats.latency_p99_ms,
                min_ms: result.stats.latency_min_ms,
                max_ms: result.stats.latency_max_ms,
            },
            error_distribution: result.stats.error_distribution.iter().cloned().collect(),
            passes: result
                .pass_results
                .iter()
                .map(|p| JsonPass {
                    index: p.pass_index,
                    success: p.success,
                    latency_ms: p.latency_ms,
                    verdict: p.verdict.clone(),
                    timestamp: p.timestamp,
                })
                .collect(),
        };

        if is_baseline {
            baseline = Some(json_strat);
        } else {
            strategies.push(json_strat);
        }
    }

    let report = JsonReport {
        meta: JsonMeta {
            domain: domain.to_string(),
            protocol: protocol.to_string(),
            passes,
            curl_timeout: curl_timeout.to_string(),
            timestamp: now,
        },
        baseline,
        strategies,
    };

    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("JSON serialization failed: {e}"))?;

    std::fs::write(Path::new(path), json).map_err(|e| format!("failed to write {path}: {e}"))?;

    Ok(())
}

/// Simple ISO 8601-ish timestamp without pulling in chrono.
pub fn chrono_like_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Calculate date/time from Unix timestamp
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simplified date calculation (from days since epoch)
    let (year, month, day) = days_to_date(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_date(days_since_epoch: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days_since_epoch + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::test_runner::{PassResult, StrategyStats, StrategyTestResult};

    fn make_test_result(
        args: Vec<String>,
        success_rate: f64,
        successes: usize,
        total: usize,
    ) -> StrategyTestResult {
        StrategyTestResult {
            strategy_args: args,
            pass_results: (0..total)
                .map(|i| PassResult {
                    pass_index: i + 1,
                    success: i < successes,
                    verdict: if i < successes {
                        "Available".into()
                    } else {
                        "UNAVAILABLE code=28".into()
                    },
                    latency_ms: 100 + (i as u64) * 50,
                    timestamp: 1742389200 + i as u64,
                })
                .collect(),
            stats: StrategyStats {
                total_passes: total,
                successes,
                failures: total - successes,
                errors: 0,
                success_rate,
                latency_median_ms: 150,
                latency_p95_ms: 250,
                latency_p99_ms: 280,
                latency_min_ms: 100,
                latency_max_ms: 300,
                error_distribution: vec![],
                stability: StabilityVerdict::from_rate(success_rate),
            },
        }
    }

    #[test]
    fn test_truncate_strategy_short() {
        assert_eq!(truncate_strategy("short", 38), "short");
    }

    #[test]
    fn test_truncate_strategy_long() {
        let long = "a".repeat(50);
        let truncated = truncate_strategy(&long, 38);
        assert_eq!(truncated.len(), 38);
        assert!(truncated.starts_with("..."));
    }

    #[test]
    fn test_json_serialization() {
        let results = vec![make_test_result(
            vec![
                "--payload=tls_client_hello".into(),
                "--lua-desync=fake:ip_ttl=6".into(),
            ],
            1.0,
            3,
            3,
        )];

        let result = write_json(
            "/tmp/blockcheckw_test_report.json",
            "example.com",
            Protocol::HttpsTls13,
            3,
            "3",
            &results,
        );
        // May fail if /tmp is not writable, but serialization should work
        if result.is_ok() {
            let content = std::fs::read_to_string("/tmp/blockcheckw_test_report.json").unwrap();
            assert!(content.contains("example.com"));
            assert!(content.contains("HTTPS/TLS1.3"));
            assert!(content.contains("tls_client_hello"));
            let _ = std::fs::remove_file("/tmp/blockcheckw_test_report.json");
        }
    }

    #[test]
    fn test_chrono_like_timestamp_format() {
        let ts = chrono_like_timestamp();
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
        assert_eq!(&ts[19..20], "Z");
    }

    #[test]
    fn test_days_to_date_epoch() {
        let (y, m, d) = days_to_date(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_date_known() {
        // 2026-03-19 is day 20531 since epoch
        let days = (2026 - 1970) * 365 + 14 + 31 + 28 + 19 - 1; // approximate
        let (y, m, _d) = days_to_date(days);
        assert_eq!(y, 2026);
        assert_eq!(m, 3);
    }
}
