use std::sync::Arc;

use console::style;
use tokio::signal;

use blockcheckw::config::{CoreConfig, DnsMode, Protocol};
use blockcheckw::error::TaskResult;
use blockcheckw::firewall::nftables;
use blockcheckw::network::dns::DnsSpoofResult;
use blockcheckw::network::{dns, isp};
use blockcheckw::pipeline::baseline;
use blockcheckw::pipeline::runner::run_parallel;
use blockcheckw::pipeline::test_report;
use blockcheckw::pipeline::worker_task::HttpTestMode;
use blockcheckw::strategy::{generator, rank};
use blockcheckw::ui;

use super::{
    chrono_local_prefix, detect_bypass_conflicts, handle_bypass_conflicts, resolve_bypass_conflicts,
};

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

    // Signal handler: cleanup nftables on Ctrl+C
    // FIXME: handler fires only once; a second Ctrl+C won't be caught.
    // Also, process::exit(130) may skip Drop impls for running nfqws2 processes.
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
    if !handle_bypass_conflicts(&config.nft_table).await {
        std::process::exit(1);
    }

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
        return;
    }

    let blocked_names: Vec<String> = blocked_protocols.iter().map(|p| p.to_string()).collect();
    screen.newline();
    screen.println(&ui::blocked_list(&blocked_names.join(", ")));

    // 3. Scan each blocked protocol
    //                       protocol, strategies,    success, fail,  err,   elapsed
    #[allow(clippy::type_complexity)]
    let mut summary: Vec<(Protocol, Vec<Vec<String>>, usize, usize, usize, f64)> = Vec::new();
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

            summary.push((
                protocol,
                working,
                stats.successes,
                stats.failures,
                stats.errors,
                stats.elapsed.as_secs_f64(),
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
    for (protocol, strategies, _successes, _failures, _errors, _elapsed) in &summary {
        let proto = protocol.to_string();
        if strategies.is_empty() {
            screen.println(&ui::summary_no_strategies(&proto));
        } else {
            let ranked = rank::rank_strategies(strategies);
            let total = ranked.len();
            let show = if top_n == 0 || top_n >= total {
                total
            } else {
                top_n
            };

            screen.println(&ui::summary_found(&proto, total));

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

    // 5. Write strategies to file
    if let Some(path) = output {
        match write_strategies_file(path, domain, &summary) {
            Ok(count) => {
                blockcheckw::system::elevate::chown_to_caller(path);
                screen.println(&format!(
                    "\n  {} {} strategies written to {}",
                    style("OK").green().bold(),
                    count,
                    style(path).cyan(),
                ));
            }
            Err(e) => {
                screen.println(&format!(
                    "\n  {} failed to write {}: {e}",
                    style("ERROR:").red().bold(),
                    style(path).cyan(),
                ));
            }
        }
    }

    // 6. Write reports (always)
    let now = chrono_local_prefix();
    let vanilla_path = format!("{now}_report_vanilla.txt");
    match write_vanilla_report(&vanilla_path, domain, &summary) {
        Ok(count) => {
            blockcheckw::system::elevate::chown_to_caller(&vanilla_path);
            screen.println(&format!(
                "  {} vanilla report: {} strategies → {}",
                style("OK").green().bold(),
                count,
                style(&vanilla_path).cyan(),
            ));
        }
        Err(e) => {
            screen.println(&format!(
                "  {} failed to write vanilla report: {e}",
                style("ERROR:").red().bold(),
            ));
        }
    }

    let ranked_path = format!("{now}_report.txt");
    match write_ranked_report(&ranked_path, domain, &summary) {
        Ok(count) => {
            blockcheckw::system::elevate::chown_to_caller(&ranked_path);
            screen.println(&format!(
                "  {} ranked report: {} strategies → {}",
                style("OK").green().bold(),
                count,
                style(&ranked_path).cyan(),
            ));
        }
        Err(e) => {
            screen.println(&format!(
                "  {} failed to write ranked report: {e}",
                style("ERROR:").red().bold(),
            ));
        }
    }

    screen.finish_info();
}

/// Write ranked report with scores and stars.
#[allow(clippy::type_complexity)]
fn write_ranked_report(
    path: &str,
    domain: &str,
    summary: &[(Protocol, Vec<Vec<String>>, usize, usize, usize, f64)],
) -> std::io::Result<usize> {
    use std::fmt::Write as _;

    let mut buf = String::new();
    let mut total = 0;

    writeln!(buf, "# blockcheckw ranked report for {domain}").unwrap();

    for (protocol, strategies, _, _, _, _) in summary {
        if strategies.is_empty() {
            continue;
        }
        let ranked = rank::rank_strategies(strategies);
        writeln!(buf).unwrap();
        writeln!(buf, "# {protocol} — {} strategies", ranked.len()).unwrap();

        for (i, score) in ranked.iter().enumerate() {
            let stars = match score.stars {
                3 => "***",
                2 => "** ",
                _ => "*  ",
            };
            writeln!(
                buf,
                "#{:<4} {} [score={:>3} perf={:>3} simple={:>3}] nfqws2 {}",
                i + 1,
                stars,
                score.total,
                score.performance,
                score.simplicity,
                score.strategy_args.join(" "),
            )
            .unwrap();
            total += 1;
        }
    }

    std::fs::write(path, buf)?;
    Ok(total)
}

/// Write a vanilla blockcheck2-compatible report.
/// Format: `curl_test_<proto> ipv4 <domain> : nfqws2 <args>`
#[allow(clippy::type_complexity)]
fn write_vanilla_report(
    path: &str,
    domain: &str,
    summary: &[(Protocol, Vec<Vec<String>>, usize, usize, usize, f64)],
) -> std::io::Result<usize> {
    use std::fmt::Write as _;

    let mut buf = String::new();
    let mut total = 0;

    writeln!(buf, "* SUMMARY").unwrap();

    for (protocol, strategies, _, _, _, _) in summary {
        let test_name = match protocol {
            Protocol::Http => "curl_test_http",
            Protocol::HttpsTls12 => "curl_test_https_tls12",
            Protocol::HttpsTls13 => "curl_test_https_tls13",
        };
        for s in strategies {
            writeln!(buf, "{test_name} ipv4 {domain} : nfqws2 {}", s.join(" ")).unwrap();
            total += 1;
        }
    }

    std::fs::write(path, buf)?;
    Ok(total)
}

#[allow(clippy::type_complexity)]
fn write_strategies_file(
    path: &str,
    domain: &str,
    summary: &[(Protocol, Vec<Vec<String>>, usize, usize, usize, f64)],
) -> std::io::Result<usize> {
    use std::fmt::Write as _;

    let timestamp = test_report::chrono_like_timestamp();
    let mut buf = String::new();
    let mut total_count = 0;

    writeln!(buf, "# blockcheckw scan results for {domain}").unwrap();
    writeln!(buf, "# {timestamp}").unwrap();

    for (protocol, strategies, _, _, _, _) in summary {
        if strategies.is_empty() {
            continue;
        }
        let ranked = rank::rank_strategies(strategies);
        writeln!(buf).unwrap();
        writeln!(buf, "# {} — {} strategies", protocol, ranked.len()).unwrap();

        for score in &ranked {
            writeln!(buf, "{}", score.strategy_args.join(" ")).unwrap();
        }
        total_count += ranked.len();
    }

    std::fs::write(path, buf)?;
    Ok(total_count)
}
