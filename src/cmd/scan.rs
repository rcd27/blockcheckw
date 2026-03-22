use std::sync::Arc;

use console::style;

use blockcheckw::config::{CoreConfig, DnsMode, Protocol};
use blockcheckw::error::TaskResult;
use blockcheckw::firewall::nftables;
use blockcheckw::network::dns::DnsSpoofResult;
use blockcheckw::network::{dns, isp};
use blockcheckw::pipeline::baseline;
use blockcheckw::pipeline::runner::run_parallel;
use blockcheckw::pipeline::scan_report::{ScanProtocolResult, ScanReport, StrategyEntry};
use blockcheckw::pipeline::test_report;
use blockcheckw::pipeline::worker_task::HttpTestMode;
use blockcheckw::strategy::generator;
use blockcheckw::ui;

use super::{
    chrono_local_prefix, handle_bypass_conflicts, resolve_bypass_conflicts_if_any, restore_service,
    set_nft_backup, set_stopped_service, spawn_cleanup_handler,
};

/// Per-protocol scan results.
struct ProtocolSummary {
    protocol: Protocol,
    strategies: Vec<Vec<String>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_scan(
    workers: usize,
    domain: &str,
    protocols: &[Protocol],
    dns_mode: DnsMode,
    timeout_secs: u64,
    top_n: usize,
    output: Option<&str>,
    from_file: Option<&str>,
) {
    let config = Arc::new(CoreConfig {
        worker_count: workers,
        ..CoreConfig::default()
    });

    let cleanup = spawn_cleanup_handler(&config.nft_table);

    let mut screen = ui::ScanScreen::new();

    // 0. ISP info
    if let Some(info) = isp::detect_ip_info().await {
        screen.add_info_line(&format!("  ISP: {info}"));
    }

    // 1. DNS resolve
    screen.println(&ui::section("DNS resolve"));
    screen.println(&format!(
        "  dns mode: {}",
        style(dns_mode.to_string()).bold()
    ));
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
    let stopped = match handle_bypass_conflicts(&config.nft_table).await {
        Ok(result) => result,
        Err(()) => std::process::exit(1),
    };
    let (stopped_service, nft_backup) = match stopped {
        Some((mgr, backup)) => {
            set_stopped_service(&cleanup, mgr.clone()).await;
            set_nft_backup(&cleanup, backup.clone()).await;
            (Some(mgr), backup)
        }
        None => (None, None),
    };

    // 2. Baseline per protocol
    screen.newline();
    screen.println(&ui::section("Baseline (without bypass)"));
    let mut blocked_protocols = Vec::new();

    for &protocol in protocols {
        let result = baseline::test_baseline(domain, protocol, config.request_timeout, &ips).await;
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
        // Restore zapret2 before early return
        if let Some(ref mgr) = stopped_service {
            restore_service(mgr, &nft_backup).await;
        }
        return;
    }

    let blocked_names: Vec<String> = blocked_protocols.iter().map(|p| p.to_string()).collect();
    screen.newline();
    screen.println(&ui::blocked_list(&blocked_names.join(", ")));

    // 3. Scan each blocked protocol
    let mut summary: Vec<ProtocolSummary> = Vec::new();
    let mut timed_out = false;

    let scan_future = async {
        for &protocol in &blocked_protocols {
            // Re-check for conflicts before each protocol scan
            resolve_bypass_conflicts_if_any(&config.nft_table).await;

            screen.newline();
            screen.println(&ui::section(&format!("Scanning {protocol}")));
            let strategies = if let Some(path) = from_file {
                match generator::load_strategies_from_file(
                    std::path::Path::new(path),
                    Some(protocol),
                ) {
                    Ok(s) => {
                        screen.println(&format!(
                            "  loaded {} strategies from {}, workers={}",
                            style(s.len()).bold(),
                            style(path).cyan(),
                            style(config.worker_count).bold()
                        ));
                        s
                    }
                    Err(e) => {
                        screen.println(&format!(
                            "  {} failed to read {}: {e}",
                            style("ERROR:").red().bold(),
                            style(path).cyan(),
                        ));
                        continue;
                    }
                }
            } else {
                let s = generator::generate_strategies(protocol);
                screen.println(&format!(
                    "  {} strategies, workers={}",
                    style(s.len()).bold(),
                    style(config.worker_count).bold()
                ));
                s
            };

            screen.begin_progress_with_prefix(
                strategies.len() as u64,
                &format!("Scanning {protocol}"),
            );

            let (results, stats) = run_parallel(
                &config,
                domain,
                protocol,
                &strategies,
                &ips,
                Some(screen.multi()),
                Some(screen.pb()),
                HttpTestMode::Standard,
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

            summary.push(ProtocolSummary {
                protocol,
                strategies: working,
            });
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

    // Blocked protocols results
    for entry in &summary {
        let proto = entry.protocol.to_string();
        if entry.strategies.is_empty() {
            screen.println(&ui::summary_no_strategies(&proto));
        } else {
            let total = entry.strategies.len();
            let show = if top_n == 0 || top_n >= total {
                total
            } else {
                top_n
            };

            screen.println(&ui::summary_found(&proto, total));

            screen.println(&ui::top_strategies_header(&proto, show, total));
            for (i, args) in entry.strategies.iter().take(show).enumerate() {
                screen.println(&ui::numbered_strategy_line(i + 1, args));
            }

            if top_n > 0 && total > top_n {
                screen.println(&format!(
                    "  {} (use --top 0 to show all)",
                    style(format!("... and {} more", total - top_n)).dim()
                ));
            }
        }
    }

    // 5. Write strategies to file
    if let Some(path) = output {
        let (content, count) = format_strategies_file(domain, &summary);
        match write_report(path, &content) {
            Ok(()) => screen.println(&format!(
                "\n  {} {} strategies written to {}",
                style("OK").green().bold(),
                count,
                style(path).cyan(),
            )),
            Err(e) => screen.println(&format!(
                "\n  {} failed to write {}: {e}",
                style("ERROR:").red().bold(),
                style(path).cyan(),
            )),
        }
    }

    // 6. Write reports (always)
    let now = chrono_local_prefix();

    let (content, count) = format_vanilla_report(domain, &summary);
    let vanilla_path = format!("{now}_report_vanilla.txt");
    match write_report(&vanilla_path, &content) {
        Ok(()) => screen.println(&format!(
            "  {} vanilla report: {} strategies → {}",
            style("OK").green().bold(),
            count,
            style(&vanilla_path).cyan(),
        )),
        Err(e) => screen.println(&format!(
            "  {} failed to write vanilla report: {e}",
            style("ERROR:").red().bold(),
        )),
    }

    let (content, count) = format_scan_report(domain, &summary);
    let scan_path = format!("{now}_scan.json");
    match write_report(&scan_path, &content) {
        Ok(()) => screen.println(&format!(
            "  {} scan report: {} strategies → {}",
            style("OK").green().bold(),
            count,
            style(&scan_path).cyan(),
        )),
        Err(e) => screen.println(&format!(
            "  {} failed to write scan report: {e}",
            style("ERROR:").red().bold(),
        )),
    }

    if count > 0 {
        screen.println(&format!(
            "\n{}",
            style(format!(
                ">>> Next step: sudo blockcheckw -w {workers} check --from-file {vanilla_path} -d {domain} <<<"
            ))
            .yellow()
            .bold()
        ));
    }

    screen.finish_info();

    // Restore zapret2 if we stopped it
    if let Some(ref mgr) = stopped_service {
        restore_service(mgr, &nft_backup).await;
    }
}

// ── Report formatting (pure) ────────────────────────────────────────────────

/// Format scan report as JSON. Returns (content, strategy_count).
fn format_scan_report(domain: &str, summary: &[ProtocolSummary]) -> (String, usize) {
    let timestamp = test_report::chrono_like_timestamp();
    let mut total = 0;

    let protocols: Vec<ScanProtocolResult> = summary
        .iter()
        .filter(|entry| !entry.strategies.is_empty())
        .map(|entry| {
            let strategies: Vec<String> = entry
                .strategies
                .iter()
                .map(|args| format!("nfqws2 {}", args.join(" ")))
                .collect();
            total += strategies.len();
            ScanProtocolResult {
                protocol: entry.protocol.to_string(),
                total: strategies.len(),
                strategies,
            }
        })
        .collect();

    let strategies: Vec<StrategyEntry> = summary
        .iter()
        .filter(|entry| !entry.strategies.is_empty())
        .flat_map(|entry| {
            entry.strategies.iter().map(|args| StrategyEntry {
                protocol: entry.protocol.to_string(),
                args: args.join(" "),
                coverage: 1,
            })
        })
        .collect();

    let report = ScanReport {
        domain: domain.to_string(),
        timestamp,
        total,
        working: total,
        protocols,
        strategies,
    };

    let json = serde_json::to_string_pretty(&report).unwrap();
    (json, total)
}

/// Format vanilla blockcheck2-compatible report. Returns (content, strategy_count).
/// Format: `curl_test_<proto> ipv4 <domain> : nfqws2 <args>`
fn format_vanilla_report(domain: &str, summary: &[ProtocolSummary]) -> (String, usize) {
    use std::fmt::Write as _;

    let mut buf = String::new();
    let mut total = 0;

    writeln!(buf, "* SUMMARY").unwrap();

    for entry in summary {
        let test_name = match entry.protocol {
            Protocol::Http => "curl_test_http",
            Protocol::HttpsTls12 => "curl_test_https_tls12",
            Protocol::HttpsTls13 => "curl_test_https_tls13",
        };
        for s in &entry.strategies {
            writeln!(buf, "{test_name} ipv4 {domain} : nfqws2 {}", s.join(" ")).unwrap();
            total += 1;
        }
    }

    (buf, total)
}

/// Format strategies file (args only). Returns (content, strategy_count).
fn format_strategies_file(domain: &str, summary: &[ProtocolSummary]) -> (String, usize) {
    use std::fmt::Write as _;

    let timestamp = test_report::chrono_like_timestamp();
    let mut buf = String::new();
    let mut total = 0;

    writeln!(buf, "# blockcheckw scan results for {domain}").unwrap();
    writeln!(buf, "# {timestamp}").unwrap();

    for entry in summary {
        if entry.strategies.is_empty() {
            continue;
        }
        writeln!(buf).unwrap();
        writeln!(
            buf,
            "# {} — {} strategies",
            entry.protocol,
            entry.strategies.len()
        )
        .unwrap();

        for args in &entry.strategies {
            writeln!(buf, "{}", args.join(" ")).unwrap();
        }
        total += entry.strategies.len();
    }

    (buf, total)
}

// ── Report I/O ──────────────────────────────────────────────────────────────

fn write_report(path: &str, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)?;
    blockcheckw::system::elevate::chown_to_caller(path);
    Ok(())
}
