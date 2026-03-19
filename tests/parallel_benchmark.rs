//! Integration benchmark: tests parallel strategy execution with different worker counts.
//!
//! Requires: root, nfqws2 installed, nftables available.
//! Run: `sudo cargo test --test parallel_bench -- --nocapture`

use std::time::Instant;

use blockcheckw::config::{CoreConfig, Protocol};
use blockcheckw::pipeline::runner::run_parallel;

/// Generate N test strategies (fake with TTL 1..N).
fn generate_strategies(count: usize) -> Vec<Vec<String>> {
    (1..=count)
        .map(|ttl| {
            vec![
                "--dpi-desync=fake".to_string(),
                format!("--dpi-desync-ttl={ttl}"),
            ]
        })
        .collect()
}

/// Check that no zombie nfqws2 processes remain.
fn check_no_nfqws2_zombies() -> bool {
    let output = std::process::Command::new("pidof")
        .arg("nfqws2")
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim().is_empty() {
                true
            } else {
                eprintln!("WARNING: nfqws2 processes still running: {}", stdout.trim());
                false
            }
        }
        Err(_) => true, // pidof not found or error — assume clean
    }
}

/// Check that the nftables table has been dropped.
fn check_nft_table_dropped(table: &str) -> bool {
    let output = std::process::Command::new("nft")
        .args(["list", "table", "inet", table])
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                eprintln!("WARNING: nft table '{}' still exists!", table);
                false
            } else {
                true
            }
        }
        Err(_) => true,
    }
}

struct BenchRow {
    worker_count: usize,
    strategies: usize,
    elapsed_ms: u128,
    throughput: f64,
    successes: usize,
    failures: usize,
    errors: usize,
    clean_nfqws2: bool,
    clean_nft: bool,
}

#[tokio::test]
async fn parallel_scaling_bench() {
    // Skip if not root
    if !nix_is_root() {
        eprintln!("SKIPPED: parallel_scaling_bench requires root. Run with: sudo cargo test --test parallel_bench -- --nocapture");
        return;
    }

    let domain = "rutracker.org";
    let protocol = Protocol::Http;
    let ips = vec!["172.67.182.217".to_string()];
    let strategy_count = 128;
    let strategies = generate_strategies(strategy_count);
    let worker_counts = [8, 16, 64];

    let mut rows: Vec<BenchRow> = Vec::new();

    for &wc in &worker_counts {
        let config = CoreConfig {
            worker_count: wc,
            ..CoreConfig::default()
        };

        eprintln!("\n--- Running with worker_count={wc}, strategies={strategy_count} ---");
        let start = Instant::now();

        let (results, stats) = run_parallel(&config, domain, protocol, &strategies, &ips, None, None).await;

        let elapsed_ms = start.elapsed().as_millis();

        // Verify cleanup
        // Small delay to let processes terminate
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let clean_nfqws2 = check_no_nfqws2_zombies();
        let clean_nft = check_nft_table_dropped(&config.nft_table);

        rows.push(BenchRow {
            worker_count: wc,
            strategies: strategy_count,
            elapsed_ms,
            throughput: stats.throughput(),
            successes: stats.successes,
            failures: stats.failures,
            errors: stats.errors,
            clean_nfqws2,
            clean_nft,
        });

        assert!(clean_nft, "nftables table not cleaned up for worker_count={wc}");
        assert!(clean_nfqws2, "nfqws2 zombies found for worker_count={wc}");
        assert_eq!(
            results.len(),
            strategy_count,
            "wrong result count for worker_count={wc}"
        );
    }

    // Print scaling table
    eprintln!("\n{}", "=".repeat(90));
    eprintln!(
        "{:<12} {:<12} {:<12} {:<14} {:<8} {:<8} {:<8} {:<6} {:<6}",
        "Workers", "Strategies", "Elapsed(ms)", "Throughput", "Success", "Failed", "Errors", "NFT", "NFQWS2"
    );
    eprintln!("{}", "-".repeat(90));
    for r in &rows {
        eprintln!(
            "{:<12} {:<12} {:<12} {:<14.2} {:<8} {:<8} {:<8} {:<6} {:<6}",
            r.worker_count,
            r.strategies,
            r.elapsed_ms,
            r.throughput,
            r.successes,
            r.failures,
            r.errors,
            if r.clean_nft { "OK" } else { "FAIL" },
            if r.clean_nfqws2 { "OK" } else { "FAIL" },
        );
    }
    eprintln!("{}", "=".repeat(90));
}

fn nix_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
