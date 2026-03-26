use std::sync::Arc;
use std::time::Instant;

use console::style;
use indicatif::ProgressBar;
use tokio::sync::Semaphore;

use blockcheckw::config::{DnsMode, Protocol};
use blockcheckw::dto::{BlockType, DomainStatus, StatusReport};
use blockcheckw::network::http_client::{
    http_test_data, pick_random_ip, BodyMode, DATA_TRANSFER_MIN_BYTES,
};
use blockcheckw::network::{dns, isp};
use blockcheckw::pipeline::test_report::chrono_like_timestamp;
use blockcheckw::ui;
use blockcheckw::ui::{CHECKMARK, CROSS};

use super::chrono_local_prefix;

pub struct StatusParams<'a> {
    pub domain_list: &'a str,
    pub dns_mode: DnsMode,
    pub timeout: u64,
    pub output: Option<&'a str>,
}

/// Single probe result for one domain.
struct ProbeResult {
    domain: String,
    block_type: BlockType,
    speed_kbps: Option<f64>,
}

/// Try TCP connect to IP:443. Returns true if connection succeeds (IP not blocked).
async fn tcp_reachable(ip: &str, timeout_secs: u64) -> bool {
    let addr = format!("{ip}:443");
    let timeout = std::time::Duration::from_secs(timeout_secs);
    tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

/// Resolve + classify + probe a single domain.
async fn resolve_and_probe(domain: &str, dns_mode: DnsMode, timeout_secs: u64) -> ProbeResult {
    // Step 1: DNS
    let ips = match dns::resolve_domain(domain, dns_mode).await {
        Ok(r) if !r.ips.is_empty() => r.ips,
        _ => {
            return ProbeResult {
                domain: domain.to_string(),
                block_type: BlockType::DnsFailed,
                speed_kbps: None,
            }
        }
    };
    let ip = match pick_random_ip(&ips) {
        Some(ip) => ip,
        None => {
            return ProbeResult {
                domain: domain.to_string(),
                block_type: BlockType::DnsFailed,
                speed_kbps: None,
            }
        }
    };

    // Step 2: TCP connect — IP blocked?
    if !tcp_reachable(ip, timeout_secs).await {
        return ProbeResult {
            domain: domain.to_string(),
            block_type: BlockType::IpBlocked,
            speed_kbps: None,
        };
    }

    // Step 3: TLS + HTTP — SNI blocked?
    // Status uses relaxed check: HTTP 200 + any data = available.
    // Unlike check (which enforces 32KB for 16KB DPI cap detection),
    // status just answers "is this domain reachable right now?"
    let start = Instant::now();
    let result = http_test_data(
        Protocol::HttpsTls12,
        domain,
        ip,
        0,
        timeout_secs,
        BodyMode::LimitedTo(DATA_TRANSFER_MIN_BYTES * 2),
    )
    .await;
    let elapsed = start.elapsed();

    let got_response = result.error.is_none() && result.status_code.is_some_and(|c| c != 0);
    let downloaded = result.size_download.unwrap_or(0);

    if got_response {
        let speed_kbps = if downloaded > 0 {
            let secs = elapsed.as_secs_f64();
            Some(if secs > 0.0 {
                downloaded as f64 / secs / 1024.0 * 8.0
            } else {
                0.0
            })
        } else {
            None
        };
        ProbeResult {
            domain: domain.to_string(),
            block_type: BlockType::Available,
            speed_kbps,
        }
    } else {
        ProbeResult {
            domain: domain.to_string(),
            block_type: BlockType::SniBlocked,
            speed_kbps: None,
        }
    }
}

/// Resolve DNS + probe all domains in parallel, returning results.
async fn probe_all(
    domains: &[String],
    dns_mode: DnsMode,
    timeout_secs: u64,
    pb: &ProgressBar,
    status_bar: Option<ProgressBar>,
) -> Vec<ProbeResult> {
    let semaphore = Arc::new(Semaphore::new(256));
    let pb = pb.clone();

    let tasks: Vec<_> = domains
        .iter()
        .map(|domain| {
            let domain = domain.clone();
            let sem = semaphore.clone();
            let pb = pb.clone();
            let sb = status_bar.clone();
            tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                if let Some(ref bar) = sb {
                    bar.set_message(format!("{}", console::style(&domain).dim()));
                    bar.tick();
                }
                let r = resolve_and_probe(&domain, dns_mode, timeout_secs).await;
                pb.inc(1);

                let (icon, detail) = match r.block_type {
                    BlockType::Available => (
                        format!("{}", console::style(format!("{CHECKMARK}")).green()),
                        r.speed_kbps
                            .map(|s| format!("{:.0} Kbps", s))
                            .unwrap_or_default(),
                    ),
                    BlockType::IpBlocked => (
                        format!("{}", console::style(format!("{CROSS}")).red()),
                        format!("{}", console::style("IP blocked").red()),
                    ),
                    BlockType::SniBlocked => (
                        format!("{}", console::style(format!("{CROSS}")).yellow()),
                        format!("{}", console::style("SNI blocked").yellow()),
                    ),
                    BlockType::DnsFailed => (
                        format!("{}", console::style(format!("{CROSS}")).dim()),
                        format!("{}", console::style("DNS failed").dim()),
                    ),
                };
                let line = format!("  {:<30} {}  {}", domain, icon, detail);
                pb.suspend(|| eprintln!("{line}"));

                r
            })
        })
        .collect();

    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        if let Ok(result) = task.await {
            results.push(result);
        }
    }
    results
}

/// Load domains from file (one per line, skip empty and comments).
fn load_domain_list(path: &str) -> Result<Vec<String>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let domains: Vec<String> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect();
    if domains.is_empty() {
        return Err(format!("no domains found in {path}"));
    }
    Ok(domains)
}

pub async fn run_status_cmd(params: StatusParams<'_>) {
    let StatusParams {
        domain_list,
        dns_mode,
        timeout,
        output,
    } = params;

    let mut con = ui::Console::new();

    let domains = match load_domain_list(domain_list) {
        Ok(d) => d,
        Err(e) => {
            con.error(&e);
            std::process::exit(1);
        }
    };

    con.section("Status");
    con.println(&format!("  {} domains from {}", domains.len(), domain_list));

    // ISP detection in background
    let isp_handle = tokio::spawn(isp::detect_ip_info());

    // DNS resolve + probe in one pass
    let total = domains.len();
    let probe_start = Instant::now();
    con.begin_progress(total as u64);
    con.add_info_line("");
    let status_bar = con.last_info_bar();
    let results = probe_all(&domains, dns_mode, timeout, con.pb(), status_bar).await;
    con.finish_progress();
    let elapsed = probe_start.elapsed();

    if let Ok(Some(info)) = isp_handle.await {
        con.add_info_line(&format!("ISP: {info}"));
    }

    // Count by block type
    let available = results
        .iter()
        .filter(|r| r.block_type == BlockType::Available)
        .count();
    let sni_blocked = results
        .iter()
        .filter(|r| r.block_type == BlockType::SniBlocked)
        .count();
    let ip_blocked = results
        .iter()
        .filter(|r| r.block_type == BlockType::IpBlocked)
        .count();
    let dns_failed = results
        .iter()
        .filter(|r| r.block_type == BlockType::DnsFailed)
        .count();

    // Build report
    let domain_statuses: Vec<DomainStatus> = results
        .iter()
        .map(|r| DomainStatus {
            domain: r.domain.clone(),
            block_type: r.block_type,
            speed_kbps: r.speed_kbps,
        })
        .collect();

    let speeds: Vec<f64> = domain_statuses
        .iter()
        .filter_map(|d| d.speed_kbps)
        .collect();
    let avg_speed = if speeds.is_empty() {
        None
    } else {
        Some(speeds.iter().sum::<f64>() / speeds.len() as f64)
    };

    // Summary
    con.newline();
    con.section("Status summary");
    con.println(&format!(
        "  available: {} | SNI blocked: {} | IP blocked: {} | elapsed: {:.1}s{}",
        style(format!("{available}/{total}")).green().bold(),
        style(sni_blocked).yellow().bold(),
        style(ip_blocked).red().bold(),
        elapsed.as_secs_f64(),
        avg_speed
            .map(|s| format!(" | avg speed: {:.0} Kbps", s))
            .unwrap_or_default(),
    ));
    if sni_blocked > 0 {
        con.println(&format!(
            "  {} SNI-blocked domains can be bypassed with zapret2",
            style(sni_blocked).yellow().bold(),
        ));
    }
    if ip_blocked > 0 {
        con.println(&format!(
            "  {} IP-blocked domains require VPN",
            style(ip_blocked).red().bold(),
        ));
    }

    // JSON report
    let report = StatusReport {
        timestamp: chrono_like_timestamp(),
        total,
        available,
        sni_blocked,
        ip_blocked,
        dns_failed,
        avg_speed_kbps: avg_speed,
        domains: domain_statuses,
    };

    let json = serde_json::to_string_pretty(&report).unwrap_or_default();

    let path = output
        .map(|p| p.to_string())
        .unwrap_or_else(|| format!("{}_status.json", chrono_local_prefix()));

    match std::fs::write(&path, &json) {
        Ok(()) => {
            blockcheckw::system::elevate::chown_to_caller(&path);
            con.newline();
            con.ok(&format!("report saved to {path}"));
        }
        Err(e) => con.error(&format!("cannot write {path}: {e}")),
    }
}
