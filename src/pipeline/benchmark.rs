use console::style;

use crate::config::{CoreConfig, Protocol};
use crate::network::dns;
use crate::pipeline::runner::run_parallel;

#[derive(Debug, Clone)]
pub struct BenchmarkPoint {
    pub workers: usize,
    pub elapsed_secs: f64,
    pub throughput: f64,
    pub errors: usize,
}

#[derive(Debug)]
pub struct BenchmarkResult {
    pub points: Vec<BenchmarkPoint>,
    pub recommended_workers: usize,
    pub strategy_count: usize,
    pub domain: String,
    pub protocol: Protocol,
}

pub fn generate_strategies(count: usize) -> Vec<Vec<String>> {
    (1..=count)
        .map(|ttl| {
            vec![
                "--dpi-desync=fake".to_string(),
                format!("--dpi-desync-ttl={ttl}"),
            ]
        })
        .collect()
}

pub fn worker_counts_to_test(max: usize) -> Vec<usize> {
    let mut counts: Vec<usize> = (0..)
        .map(|p| 1usize << p)
        .take_while(|&n| n <= max)
        .collect();
    // Ensure max is included even if not a power of 2
    if counts.last() != Some(&max) {
        counts.push(max);
    }
    counts
}

pub fn default_max_workers() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    cpus * 16
}

/// Find optimal worker count using 90%-of-max-throughput threshold.
///
/// 1. Filter out points with errors
/// 2. Find max throughput
/// 3. Pick the minimum worker count that reaches 90% of max throughput
pub fn find_optimal(points: &[BenchmarkPoint]) -> usize {
    let clean: Vec<&BenchmarkPoint> = points.iter().filter(|p| p.errors == 0).collect();

    if clean.is_empty() {
        return points
            .first()
            .map(|p| p.workers)
            .unwrap_or(1);
    }

    let max_throughput = clean
        .iter()
        .map(|p| p.throughput)
        .fold(0.0_f64, f64::max);

    let threshold = max_throughput * 0.90;

    clean
        .iter()
        .filter(|p| p.throughput >= threshold)
        .min_by_key(|p| p.workers)
        .map(|p| p.workers)
        .unwrap_or_else(|| clean.last().unwrap().workers)
}

fn build_table_text(
    header: &str,
    points: &[BenchmarkPoint],
    base_throughput: f64,
    probe_note: Option<usize>,
) -> String {
    let mut lines = Vec::new();
    lines.push(header.to_string());
    lines.push(format!(
        "{:>8}  {:>10}  {:>10}  {:>7}  {:>6}",
        "Workers", "Elapsed(s)", "Throughput", "Speedup", "Errors"
    ));
    lines.push(format!(
        "{:>8}  {:>10}  {:>10}  {:>7}  {:>6}",
        "-------", "----------", "----------", "-------", "------"
    ));
    for (i, p) in points.iter().enumerate() {
        let speedup = if base_throughput > 0.0 {
            p.throughput / base_throughput
        } else {
            0.0
        };
        let label = if i == 0 && probe_note.is_some() {
            format!("{:>5}*", p.workers)
        } else {
            format!("{:>5}", p.workers)
        };
        lines.push(format!(
            "{label:>8}  {:>10.2}  {:>8.1}/s  {:>6.1}x  {:>6}",
            p.elapsed_secs, p.throughput, speedup, p.errors
        ));
    }
    if let Some(probe_count) = probe_note {
        lines.push(format!(
            "  * baseline probe: {probe_count} strategies (I/O-bound, throughput stable)"
        ));
    }
    lines.join("\n")
}

fn build_table_styled(
    header: &str,
    points: &[BenchmarkPoint],
    base_throughput: f64,
    probe_note: Option<usize>,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("{}", style(header).bold().cyan()));
    lines.push(format!(
        "{:>8}  {:>10}  {:>10}  {:>7}  {:>6}",
        style("Workers").bold(),
        style("Elapsed(s)").bold(),
        style("Throughput").bold(),
        style("Speedup").bold(),
        style("Errors").bold(),
    ));
    lines.push(format!(
        "{:>8}  {:>10}  {:>10}  {:>7}  {:>6}",
        "-------", "----------", "----------", "-------", "------"
    ));
    for (i, p) in points.iter().enumerate() {
        let speedup = if base_throughput > 0.0 {
            p.throughput / base_throughput
        } else {
            0.0
        };
        let label = if i == 0 && probe_note.is_some() {
            format!("{:>5}*", p.workers)
        } else {
            format!("{:>5}", p.workers)
        };
        // Pad data before styling
        let elapsed_str = format!("{:>10.2}", p.elapsed_secs);
        let throughput_str = format!("{:>8.1}/s", p.throughput);
        let speedup_str = format!("{:>6.1}x", speedup);
        let errors_str = format!("{:>6}", p.errors);

        let errors_styled = if p.errors > 0 {
            style(errors_str).red().to_string()
        } else {
            errors_str
        };

        lines.push(format!(
            "{label:>8}  {elapsed_str}  {throughput_str}  {speedup_str}  {errors_styled}",
        ));
    }
    if let Some(probe_count) = probe_note {
        lines.push(format!(
            "  {} baseline probe: {probe_count} strategies (I/O-bound, throughput stable)",
            style("*").dim(),
        ));
    }
    lines.join("\n")
}

pub async fn run_benchmark(
    strategy_count: usize,
    max_workers: usize,
    raw: bool,
) -> Option<BenchmarkResult> {
    use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

    let domain = "rutracker.org";
    let protocol = Protocol::Http;
    let ips = match dns::resolve_ipv4(domain).await {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("DNS resolve failed for {domain}: {e}");
            return None;
        }
    };
    let strategies = generate_strategies(strategy_count);
    let worker_counts = worker_counts_to_test(max_workers);

    let probe_count = 8.min(strategy_count);
    let probe_strategies = generate_strategies(probe_count);
    let has_probe = worker_counts.first() == Some(&1) && strategy_count > probe_count;

    let header = if raw {
        String::new()
    } else {
        format!(
            "=== blockcheckw benchmark ===\ndomain={domain}  protocol={protocol}  strategies={strategy_count}  max_workers={max_workers}\n"
        )
    };

    // MultiProgress: vanilla output scrolls above, table + progress bar stay at bottom
    let multi = MultiProgress::new();

    // Table bar: static text, redrawn as rows are added
    let table_bar = multi.add(ProgressBar::new_spinner());
    table_bar.set_style(ProgressStyle::with_template("{msg}").unwrap());
    let initial_table = if raw {
        build_table_text(&header, &[], 0.0, None)
    } else {
        build_table_styled(&header, &[], 0.0, None)
    };
    table_bar.set_message(initial_table);

    // Progress bar below the table
    let total_steps = probe_count + (worker_counts.len() - 1) * strategy_count;
    let pb = if raw {
        multi.add(ProgressBar::hidden())
    } else {
        let pb = multi.add(ProgressBar::new(total_steps as u64));
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:20.cyan/blue}] {pos}/{len} ({msg}, ETA {eta})"
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb.set_message("-- strat/s");
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb
    };

    let mut points = Vec::new();
    let mut base_throughput: Option<f64> = None;
    let mut total_strategies_done: usize = 0;
    let bench_start = std::time::Instant::now();

    for &wc in &worker_counts {
        let is_probe = wc == 1 && has_probe;
        let run_strategies = if is_probe { &probe_strategies } else { &strategies };
        let run_count = run_strategies.len();

        let config = CoreConfig {
            worker_count: wc,
            ..CoreConfig::default()
        };

        if is_probe {
            pb.set_message(format!("w={wc} probe({probe_count}) ..."));
        } else {
            pb.set_message(format!("w={wc} ..."));
        }

        let (_, stats) = run_parallel(
            &config, domain, protocol, run_strategies, &ips,
            Some(&multi), Some(&pb),
        ).await;

        let point = BenchmarkPoint {
            workers: wc,
            elapsed_secs: stats.elapsed.as_secs_f64(),
            throughput: stats.throughput(),
            errors: stats.errors,
        };

        if base_throughput.is_none() {
            base_throughput = Some(point.throughput);
        }

        points.push(point);

        total_strategies_done += run_count;
        let overall_rate = total_strategies_done as f64 / bench_start.elapsed().as_secs_f64();
        pb.set_message(format!("{overall_rate:.1} strat/s"));

        // Redraw table with new row
        let probe_note = if has_probe { Some(probe_count) } else { None };
        let table = if raw {
            build_table_text(&header, &points, base_throughput.unwrap_or(1.0), probe_note)
        } else {
            build_table_styled(&header, &points, base_throughput.unwrap_or(1.0), probe_note)
        };
        table_bar.set_message(table);

        // Small delay between runs for cleanup
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    pb.finish_and_clear();

    let recommended_workers = find_optimal(&points);

    // Final table with recommendation
    let probe_note = if has_probe { Some(probe_count) } else { None };
    let mut final_table = if raw {
        build_table_text(&header, &points, base_throughput.unwrap_or(1.0), probe_note)
    } else {
        build_table_styled(&header, &points, base_throughput.unwrap_or(1.0), probe_note)
    };
    if !raw {
        final_table.push_str(&format!(
            "\n{}",
            style(format!("Recommended: blockcheckw -w {recommended_workers}")).green().bold()
        ));
    }
    table_bar.finish_with_message(final_table);

    Some(BenchmarkResult {
        points,
        recommended_workers,
        strategy_count,
        domain: domain.to_string(),
        protocol,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_optimal_basic() {
        let points = vec![
            BenchmarkPoint { workers: 1, elapsed_secs: 72.1, throughput: 0.9, errors: 0 },
            BenchmarkPoint { workers: 2, elapsed_secs: 36.8, throughput: 1.7, errors: 0 },
            BenchmarkPoint { workers: 4, elapsed_secs: 19.5, throughput: 3.3, errors: 0 },
            BenchmarkPoint { workers: 8, elapsed_secs: 10.4, throughput: 6.2, errors: 0 },
            BenchmarkPoint { workers: 16, elapsed_secs: 6.1, throughput: 10.5, errors: 0 },
            BenchmarkPoint { workers: 32, elapsed_secs: 3.5, throughput: 18.3, errors: 0 },
            BenchmarkPoint { workers: 64, elapsed_secs: 2.4, throughput: 27.1, errors: 0 },
            BenchmarkPoint { workers: 128, elapsed_secs: 2.8, throughput: 22.7, errors: 0 },
        ];
        assert_eq!(find_optimal(&points), 64);
    }

    #[test]
    fn test_find_optimal_skips_errors() {
        let points = vec![
            BenchmarkPoint { workers: 1, elapsed_secs: 10.0, throughput: 1.0, errors: 0 },
            BenchmarkPoint { workers: 4, elapsed_secs: 3.0, throughput: 3.5, errors: 0 },
            BenchmarkPoint { workers: 8, elapsed_secs: 1.5, throughput: 7.0, errors: 5 },
        ];
        assert_eq!(find_optimal(&points), 4);
    }

    #[test]
    fn test_find_optimal_all_errors() {
        let points = vec![
            BenchmarkPoint { workers: 4, elapsed_secs: 5.0, throughput: 2.0, errors: 1 },
            BenchmarkPoint { workers: 8, elapsed_secs: 3.0, throughput: 3.0, errors: 2 },
        ];
        assert_eq!(find_optimal(&points), 4);
    }

    #[test]
    fn test_worker_counts_to_test() {
        assert_eq!(worker_counts_to_test(64), vec![1, 2, 4, 8, 16, 32, 64]);
        assert_eq!(worker_counts_to_test(48), vec![1, 2, 4, 8, 16, 32, 48]);
        assert_eq!(worker_counts_to_test(1), vec![1]);
    }

    #[test]
    fn test_generate_strategies() {
        let strats = generate_strategies(3);
        assert_eq!(strats.len(), 3);
        assert_eq!(strats[0], vec!["--dpi-desync=fake", "--dpi-desync-ttl=1"]);
        assert_eq!(strats[2], vec!["--dpi-desync=fake", "--dpi-desync-ttl=3"]);
    }
}
