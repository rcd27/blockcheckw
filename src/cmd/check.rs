use std::sync::Arc;

use console::style;

use blockcheckw::config::{CoreConfig, DnsMode};
use blockcheckw::network::{dns, isp};
use blockcheckw::pipeline::check;
use blockcheckw::strategy::{generator, rank};
use blockcheckw::ui;

use super::{
    handle_bypass_conflicts, restore_service, set_nft_backup, set_stopped_service,
    spawn_cleanup_handler,
};

pub async fn run_check_cmd(
    domain: &str,
    from_file: &str,
    dns_mode: DnsMode,
    timeout: u64,
    take: usize,
    passes: usize,
    output: Option<&str>,
) {
    let config = Arc::new(CoreConfig {
        worker_count: 1,
        request_timeout: timeout,
        ..CoreConfig::default()
    });

    let cleanup = spawn_cleanup_handler(&config.nft_table);

    let mut screen = ui::Console::new();

    // Load strategies from vanilla file and sort by structural simplicity
    let mut strategies = match generator::load_tagged_strategies(std::path::Path::new(from_file)) {
        Ok(s) => s,
        Err(e) => {
            screen.error(&format!("failed to read {}: {e}", style(from_file).cyan()));
            std::process::exit(1);
        }
    };
    rank::sort_by_simplicity(&mut strategies);

    let mut flags = String::new();
    if take > 0 {
        flags.push_str(&format!(", --take {take}"));
    }
    if passes >= 2 {
        flags.push_str(&format!(", --passes {passes}"));
    }
    screen.println(&format!(
        "{} loaded {} strategies from {}{}",
        style("check").bold().cyan(),
        style(strategies.len()).bold(),
        style(from_file).cyan(),
        flags,
    ));

    // ISP info
    if let Some(info) = isp::detect_ip_info().await {
        screen.add_info_line(&format!("  ISP: {info}"));
    }

    // DNS resolve
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
            resolution.ips
        }
        Err(e) => {
            screen.error(&e.to_string());
            std::process::exit(1);
        }
    };

    // Check for conflicts
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

    // Run check
    screen.newline();
    screen.println(&ui::section("Checking strategies (data transfer)"));
    screen.println(&format!(
        "  {}",
        style("Tip: use --take 10 to stop after 10 verified per protocol").yellow()
    ));

    let report = check::run_check(
        &config,
        domain,
        &strategies,
        &ips,
        take,
        passes,
        &mut screen,
    )
    .await;

    // Summary
    screen.newline();
    screen.println(&ui::section("Check summary"));
    screen.println(&format!(
        "  total: {} | working: {} | elapsed: {:.1}s",
        report.total,
        style(report.working).green().bold(),
        report.elapsed_secs,
    ));

    // Output JSON — file first (stdout may break on pipe), then stdout
    let json = serde_json::to_string_pretty(&report).expect("report serialization");

    let path = output.map(String::from).unwrap_or_else(|| {
        let prefix = super::chrono_local_prefix();
        format!("{prefix}_check.json")
    });

    match std::fs::write(&path, &json) {
        Ok(()) => {
            blockcheckw::system::elevate::chown_to_caller(&path);
            screen.println(&format!(
                "  {} JSON report → {}",
                style("OK").green().bold(),
                style(&path).cyan(),
            ));
        }
        Err(e) => {
            screen.println(&format!(
                "  {} failed to write {}: {e}",
                style("ERROR:").red().bold(),
                style(&path).cyan(),
            ));
        }
    }

    super::print_stdout_graceful(&json, &screen);
    screen.newline();

    // Restore zapret2 if we stopped it
    if let Some(ref mgr) = stopped_service {
        restore_service(mgr, &nft_backup, &screen).await;
    }
}
