use std::sync::Arc;

use console::style;

use blockcheckw::config::{CoreConfig, DnsMode, Protocol};
use blockcheckw::error::TaskResult;
use blockcheckw::firewall::nftables;
use blockcheckw::network::dns::DnsSpoofResult;
use blockcheckw::network::{dns, isp, via::Via};
use blockcheckw::pipeline::baseline;
use blockcheckw::pipeline::report::{self, ProtocolSummary};
use blockcheckw::pipeline::runner::{run_parallel, RunParams};
use blockcheckw::pipeline::worker_task::HttpTestMode;
use blockcheckw::strategy::generator;
use blockcheckw::ui;

use tracing::{info_span, Instrument};

use super::{
    chrono_local_prefix, handle_bypass_conflicts, resolve_bypass_conflicts_if_any, restore_service,
    set_nft_backup, set_stopped_service, spawn_cleanup_handler,
};

pub struct ScanParams<'a> {
    pub workers: usize,
    pub domain: &'a str,
    pub protocols: &'a [Protocol],
    pub dns_mode: DnsMode,
    pub timeout_secs: u64,
    pub top_n: usize,
    pub output: Option<&'a str>,
    pub from_file: Option<&'a str>,
    pub via: Option<&'a Via>,
}

#[tracing::instrument(
    name = "bcw.scan",
    skip(params),
    fields(domain = %params.domain, workers = params.workers, found = tracing::field::Empty)
)]
pub async fn run_scan(params: ScanParams<'_>) {
    // Привязка к trace'у демона — единым стежком на bcw.root в main.rs (через
    // .instrument(root) + set_parent_from_env). bcw.scan наследует контекст от
    // bcw.root как обычный tracing-ребёнок; повторный set_parent здесь
    // переподвешивал бы его к selection и осиротил bcw.root.
    let ScanParams {
        workers,
        domain,
        protocols,
        dns_mode,
        timeout_secs,
        top_n,
        output,
        from_file,
        via,
    } = params;
    let config = Arc::new(CoreConfig {
        worker_count: workers,
        ..CoreConfig::default()
    });

    let cleanup = spawn_cleanup_handler(&config.nft_table);

    let mut screen = ui::Console::new();

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
            screen.error(&e.to_string());
            // TODO(BL-041): process::exit минует force_flush в main → span'ы сбоя теряются.
            std::process::exit(1);
        }
    };

    // 1b. Remote gateway route setup
    if let Some(v) = via {
        if !v.check_reachable(&screen).await {
            std::process::exit(1);
        }
        v.add_routes(&ips).await;
    }

    // 1c. Check for conflicting DPI bypass processes
    let stopped = match handle_bypass_conflicts(&config.nft_table, &screen).await {
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

    let baseline_span = info_span!("bcw.baseline", blocked = tracing::field::Empty);
    async {
        for &protocol in protocols {
            let result =
                baseline::test_baseline(domain, protocol, config.request_timeout, &ips).await;
            screen.println(&baseline::format_baseline_verdict_styled(&result));
            if result.is_blocked() {
                blocked_protocols.push(protocol);
            }
        }
    }
    .instrument(baseline_span.clone())
    .await;
    baseline_span.record("blocked", blocked_protocols.len());

    if blocked_protocols.is_empty() {
        screen.newline();
        screen.println(&format!(
            "{}",
            style("All protocols are available without bypass. Nothing to scan.").green()
        ));
        // Машиночитаемый исход в stdout: структурный отчёт с blocked=[] —
        // отличает «не заблокирован» от «заблокирован, но обход не найден»
        // (оба дают пустой strategies). Без этого демон видит пустой stdout
        // и ошибочно гонит check на пустом файле.
        let (scan_json, _) = report::build_scan_report(domain, &blocked_protocols, &[]);
        super::print_stdout_graceful(&scan_json, &screen);
        // Restore routes + zapret2 before early return
        if let Some(v) = via {
            v.cleanup().await;
        }
        if let Some(ref mgr) = stopped_service {
            restore_service(mgr, &nft_backup, &screen).await;
        }
        // Легитимный исход «ничего не заблокировано» — пишем found=0, иначе
        // span bcw.scan уходит без поля и неотличим от обрыва инструментации.
        tracing::Span::current().record("found", 0_usize);
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

            let proto_span = info_span!(
                "bcw.scan.protocol",
                protocol = %protocol,
                total = tracing::field::Empty,
                success = tracing::field::Empty,
                failed = tracing::field::Empty,
            );
            let (results, stats) = run_parallel(RunParams {
                config: &config,
                domain,
                protocol,
                strategies: &strategies,
                ips: &ips,
                multi: Some(screen.multi()),
                external_pb: Some(screen.pb()),
                mode: HttpTestMode::Standard,
                deadline: None,
            })
            .instrument(proto_span.clone())
            .await;
            proto_span.record("total", stats.completed);
            proto_span.record("success", stats.successes);
            proto_span.record("failed", stats.failures);

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
        let (content, count) = report::build_strategies_file(domain, &summary);
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

    // 6. Write reports (always) — before stdout, which may break on pipe
    let now = chrono_local_prefix();

    let (content, count) = report::build_vanilla_report(domain, &summary);
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

    let (content, count) = report::build_scan_report(domain, &blocked_protocols, &summary);
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

    // 7. JSON to stdout (for pipe support) — after artifacts are saved
    let (scan_json, _) = report::build_scan_report(domain, &blocked_protocols, &summary);
    super::print_stdout_graceful(&scan_json, &screen);
    screen.newline();

    if count > 0 {
        screen.println(&format!(
            "\n{}\n",
            style(format!(
                ">>> Next step: sudo blockcheckw -w {workers} check --from-file {vanilla_path} -d {domain} <<<"
            ))
            .yellow()
            .bold()
        ));
    }

    tracing::Span::current().record(
        "found",
        summary.iter().map(|e| e.strategies.len()).sum::<usize>(),
    );

    screen.finish_info();

    // Cleanup routes + restore zapret2
    if let Some(v) = via {
        v.cleanup().await;
    }
    if let Some(ref mgr) = stopped_service {
        restore_service(mgr, &nft_backup, &screen).await;
    }
}

// ── Report I/O ──────────────────────────────────────────────────────────────

fn write_report(path: &str, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)?;
    blockcheckw::system::elevate::chown_to_caller(path);
    Ok(())
}
