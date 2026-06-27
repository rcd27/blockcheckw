use std::sync::atomic::{AtomicUsize, Ordering};
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
use blockcheckw::network::{dns, isp, via::Via};
use blockcheckw::pipeline::test_report::chrono_like_timestamp;
use blockcheckw::ui;
use blockcheckw::ui::{CHECKMARK, CROSS};

use super::chrono_local_prefix;

pub struct StatusParams<'a> {
    pub domain_list: &'a str,
    pub dns_mode: DnsMode,
    pub timeout: u64,
    pub output: Option<&'a str>,
    pub via: Option<&'a Via>,
}

/// Single probe result for one domain.
struct ProbeResult {
    domain: String,
    block_type: BlockType,
    speed_kbps: Option<f64>,
}

/// Resolve + classify + probe a single domain.
/// When `via` is set, adds a route for resolved IPs through the remote gateway.
async fn resolve_and_probe(
    domain: &str,
    dns_mode: DnsMode,
    timeout_secs: u64,
    via: Option<&Via>,
) -> ProbeResult {
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

    // Step 1b: add route via remote gateway (idempotent, skips already-added IPs)
    if let Some(v) = via {
        v.add_routes(&ips).await;
    }

    // Step 2: TCP connect — IP blocked?
    let ip_ok = blockcheckw::network::reachability::ip_reachable(ip, timeout_secs, via).await;
    if !ip_ok {
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
        via,
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
            block_type: BlockType::NotBlocked,
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
///
/// Up to 256 domains are probed concurrently. During the run the caller sees:
///   - a progress bar ticking after each completed domain,
///   - a sticky info-bar showing `[N active] current_domain`.
///
/// The info-bar shows the *last started* domain, not necessarily the slowest one,
/// but the `[N active]` counter keeps updating so the user knows work is happening
/// even when a slow domain stalls the displayed name.
async fn probe_all(
    domains: &[String],
    dns_mode: DnsMode,
    timeout_secs: u64,
    via: Option<&Via>,
    pb: &ProgressBar,
    status_bar: Option<ProgressBar>,
) -> Vec<ProbeResult> {
    let semaphore = Arc::new(Semaphore::new(256));
    // Tracks how many probes are currently in-flight (displayed in info-bar).
    let in_flight = Arc::new(AtomicUsize::new(0));
    let pb = pb.clone();
    let via = via.cloned();

    let tasks: Vec<_> = domains
        .iter()
        .map(|domain| {
            let domain = domain.clone();
            let sem = semaphore.clone();
            let pb = pb.clone();
            let sb = status_bar.clone();
            let flight = in_flight.clone();
            let via = via.clone();
            tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let active = flight.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(ref bar) = sb {
                    bar.set_message(format!(
                        "{} {}",
                        console::style(format!("[{active} active]")).dim(),
                        console::style(&domain).dim(),
                    ));
                    bar.tick();
                }
                let r = resolve_and_probe(&domain, dns_mode, timeout_secs, via.as_ref()).await;
                flight.fetch_sub(1, Ordering::Relaxed);
                pb.inc(1);
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
        via,
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

    // Remote gateway check (before probing)
    if let Some(v) = via {
        if !v.check_reachable(&con).await {
            std::process::exit(1);
        }
    }

    // ISP detection runs concurrently with domain probes
    let isp_handle = tokio::spawn(isp::detect_ip_info());

    // ── Parallel probe ───────────────────────────────────────────────────
    // All domains are resolved + probed in one pass with progress bar
    // and a sticky info-bar showing "[N active] domain".
    // When --via is set, each probe adds a route for resolved IPs.
    let total = domains.len();
    let probe_start = Instant::now();
    con.begin_progress(total as u64);
    con.add_info_line(""); // empty info-bar slot for status_bar updates
    let status_bar = con.last_info_bar();
    let results = probe_all(&domains, dns_mode, timeout, via, con.pb(), status_bar).await;
    con.finish_progress();
    let elapsed = probe_start.elapsed();

    // Clean up routes added during probing
    if let Some(v) = via {
        v.cleanup().await;
    }

    if let Ok(Some(info)) = isp_handle.await {
        con.add_info_line(&format!("ISP: {info}"));
    }

    // ── Sort results for the summary table ───────────────────────────────
    // Order: Available (fastest first) → SNI blocked → IP blocked → DNS failed
    let mut sorted = results;
    sorted.sort_by(|a, b| {
        let order = |bt: &BlockType| match bt {
            BlockType::NotBlocked => 0,
            BlockType::Throttled => 1,
            BlockType::SniBlocked => 2,
            BlockType::IpBlocked => 3,
            BlockType::SynBlocked => 4,
            BlockType::HostDead => 5,
            BlockType::DnsFailed => 6,
        };
        order(&a.block_type)
            .cmp(&order(&b.block_type))
            .then_with(|| {
                b.speed_kbps
                    .unwrap_or(0.0)
                    .partial_cmp(&a.speed_kbps.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    // ── Aggregate counters ───────────────────────────────────────────────
    let available = sorted
        .iter()
        .filter(|r| r.block_type == BlockType::NotBlocked)
        .count();
    let sni_blocked = sorted
        .iter()
        .filter(|r| r.block_type == BlockType::SniBlocked)
        .count();
    let ip_blocked = sorted
        .iter()
        .filter(|r| r.block_type == BlockType::IpBlocked)
        .count();
    let dns_failed = sorted
        .iter()
        .filter(|r| r.block_type == BlockType::DnsFailed)
        .count();

    // ── Build JSON-serializable report ───────────────────────────────────
    let domain_statuses: Vec<DomainStatus> = sorted
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

    // ── Summary table ────────────────────────────────────────────────────
    // Printed after all probes complete so columns can be properly aligned.
    // Domain column width adapts to the longest domain name.
    con.newline();
    con.section("Status summary");

    let domain_col_w = sorted
        .iter()
        .map(|r| r.domain.len())
        .max()
        .unwrap_or(6)
        .max(6); // minimum 6 chars ("Domain" header)

    let header = format!(
        "  {:<domain_col_w$}  {:^12}  {:>10}",
        style("Domain").bold(),
        style("Status").bold(),
        style("Speed").bold(),
    );
    let separator = format!("  {}", style("─".repeat(domain_col_w + 26)).dim());

    con.println(&header);
    con.println(&separator);

    for r in &sorted {
        let (status_str, speed_str) = match r.block_type {
            BlockType::NotBlocked => (
                format!("{} {}", CHECKMARK, style("not blocked").green()),
                r.speed_kbps
                    .map(|s| format!("{:.0} Kbps", s))
                    .unwrap_or_default(),
            ),
            BlockType::Throttled => (
                format!("{} {}", CROSS, style("throttled").yellow()),
                r.speed_kbps
                    .map(|s| format!("{:.0} Kbps", s))
                    .unwrap_or_default(),
            ),
            BlockType::SniBlocked => (
                format!("{} {}", CROSS, style("SNI blocked").yellow()),
                String::new(),
            ),
            BlockType::IpBlocked => (
                format!("{} {}", CROSS, style("IP blocked").red()),
                String::new(),
            ),
            BlockType::SynBlocked => (
                format!("{} {}", CROSS, style("SYN blocked").red()),
                String::new(),
            ),
            BlockType::HostDead => (
                format!("{} {}", CROSS, style("host dead").dim()),
                String::new(),
            ),
            BlockType::DnsFailed => (
                format!("{} {}", CROSS, style("DNS failed").dim()),
                String::new(),
            ),
        };
        con.println(&format!(
            "  {:<domain_col_w$}  {:<12}  {:>10}",
            r.domain, status_str, speed_str,
        ));
    }

    // Footer: totals + actionable hints
    con.println(&separator);
    con.println(&format!(
        "  not blocked: {} | SNI blocked: {} | IP blocked: {} | DNS failed: {} | elapsed: {:.1}s{}",
        style(format!("{available}/{total}")).green().bold(),
        style(sni_blocked).yellow().bold(),
        style(ip_blocked).red().bold(),
        style(dns_failed).dim(),
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

    // ── Persist JSON report ──────────────────────────────────────────────
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
