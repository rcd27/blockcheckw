use std::sync::Arc;

use console::style;

use blockcheckw::config::{CoreConfig, DnsMode, Protocol};
use blockcheckw::dto::BlockType;
use blockcheckw::error::TaskResult;
use blockcheckw::firewall::nftables;
use blockcheckw::network::dns::DnsSpoofResult;
use blockcheckw::network::http_client::{
    http_test_data, interpret_data_transfer_result, BodyMode, DATA_TRANSFER_MIN_BYTES,
};
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
    set_nft_backup, set_scan_progress, set_stopped_service, spawn_cleanup_handler, ScanProgress,
};

/// Timeout for the throttle data probe. Generous so a slow-but-honest link
/// isn't mislabelled as throttled — a real DPI cap stalls near-zero well within.
const DATA_PROBE_TIMEOUT_SECS: u64 = 10;

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
    /// Proxy used ONLY to verify aliveness of IP-blocked hosts (not to route the
    /// scan). Splits `IpBlocked` into `SynBlocked` (alive via this proxy) vs
    /// `HostDead`. Validated as a proxy by the caller; reachability checked here.
    pub alive_via: Option<&'a Via>,
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
        alive_via,
    } = params;
    let config = Arc::new(CoreConfig {
        worker_count: workers,
        ..CoreConfig::default()
    });

    let cleanup = spawn_cleanup_handler(&config.nft_table);

    // Result accumulator visible to the signal handler — found strategies survive
    // a Ctrl+C / SIGTERM / timeout mid-scan (#41).
    let progress = ScanProgress::new(domain.to_string(), output.map(String::from));
    set_scan_progress(&cleanup, progress.clone()).await;

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
    let (ips, dns_spoofed) = match dns::resolve_domain(domain, dns_mode).await {
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

            // Orthogonal to block_type: system DNS poisoned but the scan continues
            // on the clean (DoH) IPs resolve_domain fell back to. Reported as a flag.
            let spoofed = dns::is_dns_spoofed(resolution.spoof_result.as_ref());
            (resolution.ips, spoofed)
        }
        Err(e) => {
            screen.error(&e.to_string());
            // TODO(BL-041): process::exit минует force_flush в main → span'ы сбоя теряются.
            std::process::exit(1);
        }
    };

    progress.lock().unwrap().set_dns_spoofed(dns_spoofed);

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
        // HEAD passed for every protocol — but a throttled host returns HEAD 200
        // while capping the actual download. One data probe (GET up to 64KB)
        // distinguishes NotBlocked from Throttled before declaring "nothing to scan".
        let block_type = match ips.first() {
            Some(ip) => {
                let proto = protocols.first().copied().unwrap_or(Protocol::HttpsTls12);
                let result = http_test_data(
                    proto,
                    domain,
                    ip,
                    0,
                    DATA_PROBE_TIMEOUT_SECS,
                    BodyMode::LimitedTo(DATA_TRANSFER_MIN_BYTES * 2),
                    None,
                )
                .await;
                let verdict =
                    interpret_data_transfer_result(&result, domain, DATA_TRANSFER_MIN_BYTES);
                if baseline::is_throttle_verdict(&verdict) {
                    BlockType::Throttled
                } else {
                    BlockType::NotBlocked
                }
            }
            None => BlockType::NotBlocked,
        };

        screen.newline();
        screen.println(&match block_type {
            BlockType::Throttled => style(
                "All protocols pass HEAD, but data transfer is throttled (DPI data cap). Nothing to scan.",
            )
            .yellow()
            .to_string(),
            _ => style("All protocols are available without bypass. Nothing to scan.")
                .green()
                .to_string(),
        });
        // Машиночитаемый исход в stdout: структурный отчёт с blocked=[] —
        // отличает «не заблокирован» от «заблокирован, но обход не найден»
        // (оба дают пустой strategies). Без этого демон видит пустой stdout
        // и ошибочно гонит check на пустом файле.
        let (scan_json, _) =
            report::build_scan_report(domain, block_type, dns_spoofed, &blocked_protocols, &[]);
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

    progress
        .lock()
        .unwrap()
        .set_blocked(blocked_protocols.clone());

    // Verify the --alive-via proxy before trusting it: a dead proxy would mislabel
    // every IP-blocked host as host-dead. Unreachable → drop it (fall back to the
    // unrefined IpBlocked). Only matters now that a domain is actually blocked.
    let alive_via = match alive_via {
        Some(av) => {
            screen.println(&format!(
                "  {} --alive-via: probing IP-blocked hosts through the proxy ONLY to split \
                 SYN-blocked (host alive) vs host-dead — the scan itself is not routed through it",
                ui::ARROW,
            ));
            if av.check_reachable(&screen).await {
                Some(av)
            } else {
                screen.println(&format!(
                    "  {} --alive-via proxy unreachable → IP-blocked hosts stay IpBlocked \
                     (no SYN-blocked / host-dead split)",
                    ui::WARN,
                ));
                None
            }
        }
        None => None,
    };

    // Classify the block kind once: a dropped direct SYN = IpBlocked (desync can't
    // help — no handshake); a completed handshake with a blocked verdict =
    // SniBlocked (desync applies). With --alive-via, a dropped direct SYN is
    // refined into SynBlocked (host alive via the proxy) vs HostDead. Reported so
    // a consumer routes on network-truth without re-probing.
    let block_type = match ips.first() {
        None => BlockType::classify(true, false, false, None),
        Some(ip) => {
            let direct =
                blockcheckw::network::reachability::tcp_reachable(ip, config.request_timeout).await;
            let proxy_reachable = match (direct, alive_via) {
                (false, Some(av)) => Some(
                    blockcheckw::network::reachability::ip_reachable(
                        ip,
                        config.request_timeout,
                        Some(av),
                    )
                    .await,
                ),
                _ => None,
            };
            BlockType::classify(true, direct, false, proxy_reachable)
        }
    };
    progress.lock().unwrap().set_block_type(block_type);

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
            // Hand the sink to run_parallel so each AVAILABLE strategy is captured
            // the instant it is found, not only at the end of the protocol.
            let sink = progress.lock().unwrap().begin_protocol(protocol);
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
                success_sink: Some(sink),
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
            // Fold this protocol into the interrupt-safe accumulator.
            progress.lock().unwrap().finish_protocol();
        }
    };

    if timeout_secs > 0 {
        let deadline = std::time::Duration::from_secs(timeout_secs);
        if tokio::time::timeout(deadline, scan_future).await.is_err() {
            timed_out = true;
            // scan_future was cancelled mid-protocol — recover everything found so
            // far, including the in-progress protocol's partial results (#41).
            summary = progress.lock().unwrap().snapshot();
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

    let (content, count) = report::build_scan_report(
        domain,
        block_type,
        dns_spoofed,
        &blocked_protocols,
        &summary,
    );
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
    let (scan_json, _) = report::build_scan_report(
        domain,
        block_type,
        dns_spoofed,
        &blocked_protocols,
        &summary,
    );
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

/// Paths and count produced by [`write_scan_reports`].
pub(crate) struct WrittenReports {
    pub scan_path: String,
    pub count: usize,
}

/// Write the scan artifacts (optional strategies file, vanilla report, scan JSON)
/// from a summary. Used by the signal handler to persist partial results on
/// interrupt; the normal path (steps 5–7 above) keeps its own richer printing.
pub(crate) fn write_scan_reports(
    domain: &str,
    output: Option<&str>,
    block_type: BlockType,
    dns_spoofed: bool,
    blocked: &[blockcheckw::config::Protocol],
    summary: &[ProtocolSummary],
) -> std::io::Result<WrittenReports> {
    let now = chrono_local_prefix();

    if let Some(path) = output {
        let (content, _) = report::build_strategies_file(domain, summary);
        write_report(path, &content)?;
    }

    let (content, _) = report::build_vanilla_report(domain, summary);
    write_report(&format!("{now}_report_vanilla.txt"), &content)?;

    let (content, count) =
        report::build_scan_report(domain, block_type, dns_spoofed, blocked, summary);
    let scan_path = format!("{now}_scan.json");
    write_report(&scan_path, &content)?;

    Ok(WrittenReports { scan_path, count })
}
