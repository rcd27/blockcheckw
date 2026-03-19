use std::sync::Arc;

use clap::{Parser, Subcommand};
use console::style;
use tokio::signal;
use tracing::info;

use blockcheckw::config::{CoreConfig, DnsMode, Protocol};
use blockcheckw::error::TaskResult;
use blockcheckw::firewall::nftables;
use blockcheckw::network::{dns, isp};
use blockcheckw::network::dns::DnsSpoofResult;
use blockcheckw::pipeline::baseline;
use blockcheckw::pipeline::benchmark;
use blockcheckw::pipeline::runner::run_parallel;
use blockcheckw::pipeline::verify::{self, VerifyConfig};
use blockcheckw::strategy::{generator, rank};
use blockcheckw::ui;

#[derive(Parser)]
#[command(name = "blockcheckw", about = "Parallel DPI bypass strategy scanner")]
struct Cli {
    /// Number of parallel workers
    #[arg(short, long, default_value_t = 8)]
    workers: usize,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run parallel scaling benchmark to find optimal worker count
    Benchmark {
        /// Number of strategies to generate (fake TTL 1..N)
        #[arg(short, long, default_value_t = 64)]
        strategies: usize,

        /// Maximum number of workers to test (default: CPU cores * 16)
        #[arg(short = 'M', long)]
        max_workers: Option<usize>,

        /// Raw output: table only, no recommendation (for scripts)
        #[arg(long)]
        raw: bool,
    },

    /// Scan domain for working DPI bypass strategies
    Scan {
        /// Target domain to check
        #[arg(short, long, default_value = "rutracker.org")]
        domain: String,

        /// Protocols to test (comma-separated: http,tls12,tls13)
        #[arg(short, long, default_value = "http,tls12,tls13")]
        protocols: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Number of verification passes (0 = skip verification)
        #[arg(long, default_value_t = 3)]
        verify_passes: usize,

        /// Minimum passes required to consider a strategy verified (default: = verify-passes)
        #[arg(long)]
        verify_min: Option<usize>,

        /// curl --max-time for verification passes (seconds)
        #[arg(long, default_value = "3")]
        verify_timeout: String,

        /// Show per-strategy verification tallies
        #[arg(long)]
        verbose: bool,

        /// Overall scan timeout in seconds (0 = no limit)
        #[arg(long, default_value_t = 0)]
        timeout: u64,

        /// Show top N ranked strategies per protocol (0 = all)
        #[arg(long, default_value_t = 5)]
        top: usize,
    },
}

#[tokio::main]
async fn main() {
    // Panic hook: cleanup nftables table on panic (async runtime may be dead, use sync Command)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", "zapret"])
            .output();
        default_hook(info);
    }));

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Benchmark {
            strategies,
            max_workers,
            raw,
        }) => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                .init();

            let config = CoreConfig::default();
            if !handle_bypass_conflicts(&config.nft_table).await {
                std::process::exit(1);
            }

            let max = max_workers.unwrap_or_else(benchmark::default_max_workers);
            benchmark::run_benchmark(strategies, max, raw).await;
        }
        Some(Command::Scan {
            domain,
            protocols,
            dns,
            verify_passes,
            verify_min,
            verify_timeout,
            verbose,
            timeout,
            top,
        }) => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                .init();

            let protocols = match blockcheckw::config::parse_protocols(&protocols) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };
            let dns_mode = match blockcheckw::config::parse_dns_mode(&dns) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };
            let verify_config = VerifyConfig {
                passes: verify_passes,
                min_passes: verify_min.unwrap_or(verify_passes),
                curl_max_time: verify_timeout,
            };
            run_scan(cli.workers, &domain, &protocols, dns_mode, &verify_config, verbose, timeout, top).await;
        }
        None => run_default(cli.workers).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_scan(workers: usize, domain: &str, protocols: &[Protocol], dns_mode: DnsMode, verify_config: &VerifyConfig, verbose: bool, timeout_secs: u64, top_n: usize) {
    let config = Arc::new(CoreConfig {
        worker_count: workers,
        ..CoreConfig::default()
    });

    // Signal handler: cleanup nftables on Ctrl+C
    let cleanup_config = config.clone();
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            eprintln!("\nCtrl+C received, cleaning up...");
            nftables::drop_table(&cleanup_config.nft_table).await;
            std::process::exit(130);
        }
    });

    let mut screen = ui::ScanScreen::new();

    // 0. ISP info
    if let Some(info) = isp::detect_ip_info().await {
        screen.add_info_line(&format!("  ISP: {info}"));
    }

    // 1. DNS resolve
    screen.println(&ui::section("DNS resolve"));
    screen.println(&format!("  dns mode: {}", style(dns_mode.to_string()).bold()));
    let ips = match dns::resolve_domain(domain, dns_mode).await {
        Ok(resolution) => {
            screen.println(&format!(
                "  {} {} {} (via {})",
                domain,
                ui::ARROW,
                style(resolution.ips.join(", ")).bold(),
                resolution.method,
            ));

            // Show spoofing check result in output and info bar
            if let Some(ref spoof) = resolution.spoof_result {
                match spoof {
                    DnsSpoofResult::Clean => {
                        screen.println(&format!(
                            "  {}DNS spoofing check: {}",
                            ui::CHECKMARK,
                            style("clean").green(),
                        ));
                    }
                    DnsSpoofResult::Spoofed { details } => {
                        screen.println(&format!(
                            "  {}DNS spoofing detected: {}",
                            ui::WARN,
                            style(details).yellow().bold(),
                        ));
                    }
                    DnsSpoofResult::CheckFailed { reason } => {
                        screen.println(&format!(
                            "  {}DNS spoofing check failed: {}",
                            ui::WARN,
                            style(reason).yellow(),
                        ));
                    }
                }
            }

            // Add DNS info to status bar
            let dns_status = ui::dns_info_line(
                domain,
                &resolution.ips,
                resolution.method,
                &resolution.spoof_result,
            );
            screen.add_info_line(&dns_status);

            resolution.ips
        }
        Err(e) => {
            eprintln!("{} {e}", style("ERROR:").red().bold());
            std::process::exit(1);
        }
    };

    // 1b. Check for conflicting DPI bypass processes
    if !handle_bypass_conflicts(&config.nft_table).await {
        std::process::exit(1);
    }

    // 2. Baseline per protocol
    screen.newline();
    screen.println(&ui::section("Baseline (without bypass)"));
    let mut blocked_protocols = Vec::new();

    for &protocol in protocols {
        let result = baseline::test_baseline(domain, protocol, &config.curl_max_time, &ips).await;
        screen.println(&baseline::format_baseline_verdict_styled(&result));
        if result.is_blocked() {
            blocked_protocols.push(protocol);
        }
    }

    if blocked_protocols.is_empty() {
        screen.newline();
        screen.println(&format!(
            "{}",
            style("All protocols are available without bypass. Nothing to scan.").green()
        ));
        return;
    }

    let blocked_names: Vec<String> = blocked_protocols.iter().map(|p| p.to_string()).collect();
    screen.newline();
    screen.println(&ui::blocked_list(&blocked_names.join(", ")));

    // 3. Scan each blocked protocol
    //                       protocol, strategies,    success, fail,  err,   elapsed, unstable
    #[allow(clippy::type_complexity)]
    let mut summary: Vec<(Protocol, Vec<Vec<String>>, usize, usize, usize, f64, bool)> = Vec::new();
    let mut timed_out = false;

    let scan_future = async {
        for &protocol in &blocked_protocols {
            // Re-check for conflicts before each protocol scan
            let conflicts = detect_bypass_conflicts(&config.nft_table).await;
            if !conflicts.is_empty() {
                screen.println(&format!(
                    "  {} {}",
                    style("!").yellow().bold(),
                    style("conflicting DPI bypass restarted, killing again...").yellow(),
                ));
                resolve_bypass_conflicts(&conflicts).await;
            }

            screen.newline();
            screen.println(&ui::section(&format!("Scanning {protocol}")));
            let strategies = generator::generate_strategies(protocol);
            screen.println(&format!(
                "  generated {} strategies, workers={}",
                style(strategies.len()).bold(),
                style(config.worker_count).bold()
            ));

            screen.begin_progress(strategies.len() as u64);

            let (results, stats) = run_parallel(
                &config,
                domain,
                protocol,
                &strategies,
                &ips,
                Some(screen.multi()),
                Some(screen.pb()),
            )
            .await;

            screen.finish_progress();

            let working: Vec<Vec<String>> = results
                .iter()
                .filter(|r| matches!(r.result, TaskResult::Success { .. }))
                .map(|r| r.strategy_args.clone())
                .collect();

            screen.println(&ui::stats_line(
                stats.completed,
                stats.successes,
                stats.failures,
                stats.errors,
                stats.elapsed.as_secs_f64(),
                stats.throughput(),
            ));

            // 3b. Verification
            let (final_strategies, is_unstable) = if verify_config.passes > 0 && !working.is_empty() {
                // Re-check for conflicts before verify (production services may have restarted)
                let conflicts = detect_bypass_conflicts(&config.nft_table).await;
                if !conflicts.is_empty() {
                    screen.println(&format!(
                        "  {} {}",
                        style("!").yellow().bold(),
                        style("conflicting DPI bypass restarted during scan, killing again...").yellow(),
                    ));
                    resolve_bypass_conflicts(&conflicts).await;
                }

                screen.newline();
                screen.println(&ui::section(&format!("Verifying {protocol}")));
                screen.println(&format!(
                    "  {} candidates, {} passes, timeout={}s",
                    style(working.len()).bold(),
                    style(verify_config.passes).bold(),
                    verify_config.curl_max_time,
                ));

                let summary_v = verify::run_verification(
                    &config,
                    domain,
                    protocol,
                    &working,
                    &ips,
                    verify_config,
                    &mut screen,
                )
                .await;

                screen.println(&ui::verify_summary_line(
                    summary_v.verified_count,
                    summary_v.total_candidates,
                    summary_v.required_passes,
                    summary_v.total_passes,
                ));

                if verbose {
                    for tally in &summary_v.tallies {
                        screen.println(&ui::verify_tally_line(tally, summary_v.required_passes));
                    }
                }

                if !summary_v.verified.is_empty() {
                    (summary_v.verified, false)
                } else if let Some(relaxed) = &summary_v.relaxed {
                    screen.println(&ui::verify_relaxed_header(
                        summary_v.required_passes,
                        summary_v.total_passes,
                        relaxed.actual_min,
                        relaxed.strategies.len(),
                    ));
                    for tally in summary_v.tallies.iter().filter(|t| t.pass_count >= relaxed.actual_min) {
                        screen.println(&ui::verify_tally_line(tally, relaxed.actual_min));
                    }
                    (relaxed.strategies.clone(), true)
                } else {
                    (vec![], false)
                }
            } else {
                (working, false)
            };

            summary.push((
                protocol,
                final_strategies,
                stats.successes,
                stats.failures,
                stats.errors,
                stats.elapsed.as_secs_f64(),
                is_unstable,
            ));
        }
    };

    if timeout_secs > 0 {
        let deadline = std::time::Duration::from_secs(timeout_secs);
        if tokio::time::timeout(deadline, scan_future).await.is_err() {
            timed_out = true;
            nftables::drop_table(&config.nft_table).await;
            screen.newline();
            screen.println(&format!(
                "{} scan timed out after {}s — showing partial results",
                style("WARNING:").yellow().bold(),
                timeout_secs,
            ));
        }
    } else {
        scan_future.await;
    }

    // 4. Summary
    screen.newline();
    screen.println(&ui::section(&format!("Summary for {domain}")));

    if timed_out {
        screen.println(&format!(
            "  {} scan timed out after {}s",
            style("!").yellow().bold(),
            timeout_secs,
        ));
    }

    // Available protocols (not blocked)
    for &protocol in protocols {
        if !blocked_protocols.contains(&protocol) {
            screen.println(&ui::summary_available(&protocol.to_string()));
        }
    }

    // Blocked protocols results (ranked)
    for (protocol, strategies, _successes, _failures, _errors, _elapsed, unstable) in &summary {
        let proto = protocol.to_string();
        if strategies.is_empty() {
            screen.println(&ui::summary_no_strategies(&proto));
        } else {
            let ranked = rank::rank_strategies(strategies);
            let total = ranked.len();
            let show = if top_n == 0 || top_n >= total { total } else { top_n };

            if *unstable {
                screen.println(&ui::summary_found_unstable(&proto, total));
            } else {
                screen.println(&ui::summary_found(&proto, total));
            }

            screen.println(&ui::top_strategies_header(&proto, show, total));
            for (i, score) in ranked.iter().take(show).enumerate() {
                screen.println(&ui::ranked_strategy_line(i + 1, score));
            }

            if top_n > 0 && total > top_n {
                screen.println(&format!(
                    "  {} (use --top 0 to show all)",
                    style(format!("... and {} more", total - top_n)).dim()
                ));
            }
        }
    }

    screen.finish_info();
}

async fn run_default(workers: usize) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Arc::new(CoreConfig {
        worker_count: workers,
        ..CoreConfig::default()
    });

    // Signal handler: cleanup nftables on Ctrl+C
    let cleanup_config = config.clone();
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("Ctrl+C received, cleaning up nftables table...");
            nftables::drop_table(&cleanup_config.nft_table).await;
            std::process::exit(130);
        }
    });

    let domain = "rutracker.org";
    let protocol = Protocol::Http;
    let ips = match dns::resolve_ipv4(domain).await {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("DNS resolve failed for {domain}: {e}");
            std::process::exit(1);
        }
    };

    let strategies: Vec<Vec<String>> = vec![
        vec!["--dpi-desync=fake".to_string(), "--dpi-desync-ttl=1".to_string()],
        vec!["--dpi-desync=fake".to_string(), "--dpi-desync-ttl=2".to_string()],
        vec!["--dpi-desync=fake".to_string(), "--dpi-desync-ttl=3".to_string()],
    ];

    info!("blockcheckw starting: {protocol} {domain}");
    info!("workers={}, strategies={}", config.worker_count, strategies.len());

    let (results, stats) = run_parallel(&config, domain, protocol, &strategies, &ips, None, None).await;

    info!("=== Results ===");
    for r in &results {
        info!("nfqws2 {} : {}", r.strategy_args.join(" "), r.result);
    }

    info!(
        "Total: {} | Success: {} | Failed: {} | Errors: {} | {:.2}s ({:.1} strat/sec)",
        stats.total,
        stats.successes,
        stats.failures,
        stats.errors,
        stats.elapsed.as_secs_f64(),
        stats.throughput()
    );
}

struct BypassConflicts {
    has_nfqws2_processes: bool,
    /// (family, table_name) pairs, e.g. ("inet", "zapret2")
    conflicting_tables: Vec<(String, String)>,
}

impl BypassConflicts {
    fn is_empty(&self) -> bool {
        !self.has_nfqws2_processes && self.conflicting_tables.is_empty()
    }
}

/// Detect conflicting DPI bypass processes and nftables tables.
async fn detect_bypass_conflicts(own_table: &str) -> BypassConflicts {
    use blockcheckw::system::process::run_process;

    let mut conflicts = BypassConflicts {
        has_nfqws2_processes: false,
        conflicting_tables: Vec::new(),
    };

    // Check for other nfqws2 processes
    if let Ok(result) = run_process(&["pgrep", "-c", "nfqws2"], 3_000).await {
        if result.exit_code == 0 {
            if let Ok(count) = result.stdout.trim().parse::<u32>() {
                if count > 0 {
                    conflicts.has_nfqws2_processes = true;
                }
            }
        }
    }

    // Check for other nftables tables with queue rules on ports 80/443
    if let Ok(result) = run_process(&["nft", "list", "tables"], 3_000).await {
        if result.exit_code == 0 {
            for line in result.stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0] == "table" {
                    let family = parts[1];
                    let table_name = parts[2];
                    if table_name != own_table && table_name != "fw4" {
                        if let Ok(table_content) = run_process(
                            &["nft", "list", "table", family, table_name],
                            3_000,
                        ).await {
                            if table_content.exit_code == 0
                                && table_content.stdout.contains("queue")
                                && (table_content.stdout.contains("dport 443")
                                    || table_content.stdout.contains("dport { 80, 443"))
                            {
                                conflicts.conflicting_tables.push(
                                    (family.to_string(), table_name.to_string()),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    conflicts
}

/// Kill all nfqws2 processes and drop conflicting nft tables.
async fn resolve_bypass_conflicts(conflicts: &BypassConflicts) {
    use blockcheckw::system::process::run_process;

    if conflicts.has_nfqws2_processes {
        let _ = run_process(&["killall", "nfqws2"], 5_000).await;
        // Give processes time to exit
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    for (family, table) in &conflicts.conflicting_tables {
        let _ = run_process(&["nft", "delete", "table", family, table], 5_000).await;
    }
}

/// Display conflicts and prompt user. Returns true if should proceed.
async fn handle_bypass_conflicts(own_table: &str) -> bool {
    let conflicts = detect_bypass_conflicts(own_table).await;
    if conflicts.is_empty() {
        return true;
    }

    eprintln!();
    eprintln!(
        "{} {}",
        style("WARNING").yellow().bold(),
        style("conflicting DPI bypass detected:").yellow()
    );
    if conflicts.has_nfqws2_processes {
        eprintln!(
            "  {} running nfqws2 processes found",
            style("!").yellow().bold(),
        );
    }
    for (family, table) in &conflicts.conflicting_tables {
        eprintln!(
            "  {} nft table '{} {}' has queue rules intercepting port 443",
            style("!").yellow().bold(), family, table
        );
    }

    // Prompt user
    eprintln!();
    eprint!(
        "  {} ",
        style("Kill nfqws2 and drop conflicting nft tables to proceed? [Y/n] ").bold()
    );

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        eprintln!("{}", style("Aborted.").red());
        return false;
    }

    resolve_bypass_conflicts(&conflicts).await;
    eprintln!(
        "  {} {}",
        style("OK").green().bold(),
        "conflicting processes killed, nft tables dropped"
    );
    true
}
