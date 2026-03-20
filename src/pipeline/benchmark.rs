use console::style;

use crate::config::{CoreConfig, Protocol};
use crate::network::dns;
use crate::pipeline::runner::run_parallel_with_deadline;
use crate::pipeline::worker_task::HttpTestMode;
use crate::strategy::generator;

#[derive(Debug, Clone)]
pub struct BenchmarkPoint {
    pub workers: usize,
    pub elapsed_secs: f64,
    pub throughput: f64,
    pub completed: usize,
    pub successes: usize,
    pub errors: usize,
    /// Peak memory delta (MB) — difference in MemAvailable during the run.
    /// Approximates total RAM consumed by blockcheckw + nfqws2 child processes.
    pub peak_mem_mb: f64,
}

#[derive(Debug)]
pub struct BenchmarkResult {
    pub points: Vec<BenchmarkPoint>,
    pub recommended_workers: usize,
    pub domain: String,
    pub protocol: Protocol,
}

/// Read MemAvailable from /proc/meminfo in KB.
fn mem_available_kb() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if line.starts_with("MemAvailable:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

pub fn worker_counts_to_test(max: usize) -> Vec<usize> {
    let mut counts: Vec<usize> = (0..)
        .map(|p| 1usize << p)
        .take_while(|&n| n <= max)
        .collect();
    if counts.last() != Some(&max) {
        counts.push(max);
    }
    counts.retain(|&n| n >= 4);
    counts
}

pub fn default_max_workers() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cpus * 64).min(1024)
}

/// Find optimal worker count: highest throughput with zero errors.
pub fn find_optimal(points: &[BenchmarkPoint]) -> usize {
    let clean: Vec<&BenchmarkPoint> = points.iter().filter(|p| p.errors == 0).collect();

    if clean.is_empty() {
        return points
            .iter()
            .min_by(|a, b| {
                a.errors.cmp(&b.errors)
                    .then(b.throughput.partial_cmp(&a.throughput).unwrap_or(std::cmp::Ordering::Equal))
            })
            .map(|p| p.workers)
            .unwrap_or(8);
    }

    clean
        .iter()
        .max_by(|a, b| a.throughput.partial_cmp(&b.throughput).unwrap_or(std::cmp::Ordering::Equal))
        .map(|p| p.workers)
        .unwrap_or(8)
}

fn build_table_styled(
    header: &str,
    points: &[BenchmarkPoint],
    base_throughput: f64,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("{}", style(header).bold().cyan()));
    lines.push(format!(
        "{:>8}  {:>10}  {:>10}  {:>7}  {:>9}  {:>8}  {:>6}  {:>8}",
        style("Workers").bold(),
        style("Elapsed(s)").bold(),
        style("Throughput").bold(),
        style("Speedup").bold(),
        style("Completed").bold(),
        style("Success").bold(),
        style("Errors").bold(),
        style("Peak RAM").bold(),
    ));
    lines.push(format!(
        "{:>8}  {:>10}  {:>10}  {:>7}  {:>9}  {:>8}  {:>6}  {:>8}",
        "-------", "----------", "----------", "-------", "---------", "--------", "------", "--------"
    ));
    for p in points {
        let speedup = if base_throughput > 0.0 {
            p.throughput / base_throughput
        } else {
            0.0
        };
        let errors_str = format!("{:>6}", p.errors);
        let errors_styled = if p.errors > 0 {
            style(errors_str).red().to_string()
        } else {
            errors_str
        };
        let ram_str = if p.peak_mem_mb > 0.0 {
            format!("{:.0}MB", p.peak_mem_mb)
        } else {
            format!("{:>7}", "?")
        };

        lines.push(format!(
            "{:>8}  {:>10.2}  {:>8.1}/s  {:>6.1}x  {:>9}  {:>8}  {errors_styled}  {ram_str:>8}",
            p.workers, p.elapsed_secs, p.throughput, speedup, p.completed, p.successes,
        ));
    }
    lines.join("\n")
}

fn build_table_text(
    header: &str,
    points: &[BenchmarkPoint],
    base_throughput: f64,
) -> String {
    let mut lines = Vec::new();
    lines.push(header.to_string());
    lines.push(format!(
        "{:>8}  {:>10}  {:>10}  {:>7}  {:>9}  {:>8}  {:>6}  {:>8}",
        "Workers", "Elapsed(s)", "Throughput", "Speedup", "Completed", "Success", "Errors", "Peak RAM"
    ));
    lines.push(format!(
        "{:>8}  {:>10}  {:>10}  {:>7}  {:>9}  {:>8}  {:>6}  {:>8}",
        "-------", "----------", "----------", "-------", "---------", "--------", "------", "--------"
    ));
    for p in points {
        let speedup = if base_throughput > 0.0 {
            p.throughput / base_throughput
        } else {
            0.0
        };
        let ram = if p.peak_mem_mb > 0.0 { format!("{:.0}MB", p.peak_mem_mb) } else { "?".into() };
        lines.push(format!(
            "{:>8}  {:>10.2}  {:>8.1}/s  {:>6.1}x  {:>9}  {:>8}  {:>6}  {:>8}",
            p.workers, p.elapsed_secs, p.throughput, speedup, p.completed, p.successes, p.errors, ram,
        ));
    }
    lines.join("\n")
}

pub async fn run_benchmark(
    time_per_level: u64,
    max_workers: usize,
    raw: bool,
    domain: &str,
    protocol: Protocol,
) -> Option<BenchmarkResult> {
    use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

    let ips = match dns::resolve_ipv4(domain).await {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("DNS resolve failed for {domain}: {e}");
            return None;
        }
    };
    let strategies = generator::generate_strategies(protocol);
    let corpus_size = strategies.len();
    let worker_counts = worker_counts_to_test(max_workers);
    let level_count = worker_counts.len();

    let header = if raw {
        format!(
            "domain={domain}  protocol={protocol}  corpus={corpus_size}  time_per_level={time_per_level}s  max_workers={max_workers}"
        )
    } else {
        format!(
            "=== blockcheckw benchmark ===\n\
             domain={domain}  protocol={protocol}  corpus={corpus_size} strategies\n\
             {time_per_level}s per level, {level_count} levels ({} total est.)\n",
            format_duration(time_per_level * level_count as u64),
        )
    };

    let multi = MultiProgress::new();

    let table_bar = multi.add(ProgressBar::new_spinner());
    table_bar.set_style(ProgressStyle::with_template("{msg}").unwrap());
    table_bar.set_message(if raw {
        build_table_text(&header, &[], 0.0)
    } else {
        build_table_styled(&header, &[], 0.0)
    });

    let level_pb = if raw {
        multi.add(ProgressBar::hidden())
    } else {
        let pb = multi.add(ProgressBar::new(level_count as u64));
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} levels {msg}"
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(200));
        pb
    };

    let mut points = Vec::new();
    let mut base_throughput: Option<f64> = None;

    for (level_idx, &wc) in worker_counts.iter().enumerate() {
        let config = CoreConfig {
            worker_count: wc,
            ..CoreConfig::default()
        };

        level_pb.set_message(format!("w={wc}"));

        // Measure memory: sample MemAvailable before and during the run
        let mem_before = mem_available_kb();
        let min_mem = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        let min_mem_clone = min_mem.clone();
        let mem_sampler = tokio::spawn(async move {
            loop {
                if let Some(avail) = mem_available_kb() {
                    min_mem_clone.fetch_min(avail, std::sync::atomic::Ordering::Relaxed);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(time_per_level);

        let (_results, stats) = run_parallel_with_deadline(
            &config, domain, protocol, &strategies, &ips,
            Some(&multi), None, HttpTestMode::Standard,
            Some(deadline),
        ).await;

        mem_sampler.abort();

        let peak_mem_mb = match mem_before {
            Some(before) => {
                let min_during = min_mem.load(std::sync::atomic::Ordering::Relaxed);
                if min_during < before {
                    (before - min_during) as f64 / 1024.0
                } else {
                    0.0
                }
            }
            None => 0.0,
        };

        let point = BenchmarkPoint {
            workers: wc,
            elapsed_secs: stats.elapsed.as_secs_f64(),
            throughput: stats.throughput(),
            completed: stats.completed,
            successes: stats.successes,
            errors: stats.errors,
            peak_mem_mb,
        };

        if base_throughput.is_none() {
            base_throughput = Some(point.throughput);
        }

        points.push(point);

        level_pb.set_position((level_idx + 1) as u64);

        let table = if raw {
            build_table_text(&header, &points, base_throughput.unwrap_or(1.0))
        } else {
            build_table_styled(&header, &points, base_throughput.unwrap_or(1.0))
        };
        table_bar.set_message(table);

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    level_pb.finish_and_clear();

    let recommended_workers = find_optimal(&points);

    let mut final_table = if raw {
        build_table_text(&header, &points, base_throughput.unwrap_or(1.0))
    } else {
        build_table_styled(&header, &points, base_throughput.unwrap_or(1.0))
    };
    if !raw {
        final_table.push_str(&format!(
            "\n{}",
            style(format!("Recommended: blockcheckw -w {recommended_workers} scan")).green().bold()
        ));
    }
    table_bar.finish_with_message(final_table);

    Some(BenchmarkResult {
        points,
        recommended_workers,
        domain: domain.to_string(),
        protocol,
    })
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m{}s", secs / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_optimal_basic() {
        let points = vec![
            BenchmarkPoint { workers: 4, elapsed_secs: 19.5, throughput: 3.3, completed: 64, successes: 64, errors: 0, peak_mem_mb: 0.0 },
            BenchmarkPoint { workers: 8, elapsed_secs: 10.4, throughput: 6.2, completed: 64, successes: 64, errors: 0, peak_mem_mb: 0.0 },
            BenchmarkPoint { workers: 64, elapsed_secs: 2.4, throughput: 27.1, completed: 64, successes: 64, errors: 0, peak_mem_mb: 0.0 },
            BenchmarkPoint { workers: 128, elapsed_secs: 2.0, throughput: 32.0, completed: 64, successes: 64, errors: 0, peak_mem_mb: 0.0 },
            BenchmarkPoint { workers: 256, elapsed_secs: 1.8, throughput: 35.0, completed: 60, successes: 60, errors: 4, peak_mem_mb: 0.0 },
        ];
        assert_eq!(find_optimal(&points), 128);
    }

    #[test]
    fn test_find_optimal_all_errors() {
        let points = vec![
            BenchmarkPoint { workers: 4, elapsed_secs: 5.0, throughput: 2.0, completed: 10, successes: 3, errors: 1, peak_mem_mb: 0.0 },
            BenchmarkPoint { workers: 8, elapsed_secs: 3.0, throughput: 3.0, completed: 10, successes: 5, errors: 2, peak_mem_mb: 0.0 },
        ];
        assert_eq!(find_optimal(&points), 4);
    }

    #[test]
    fn test_worker_counts_to_test() {
        assert_eq!(worker_counts_to_test(64), vec![4, 8, 16, 32, 64]);
        assert_eq!(worker_counts_to_test(48), vec![4, 8, 16, 32, 48]);
        assert_eq!(worker_counts_to_test(512), vec![4, 8, 16, 32, 64, 128, 256, 512]);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m30s");
        assert_eq!(format_duration(600), "10m0s");
    }
}
