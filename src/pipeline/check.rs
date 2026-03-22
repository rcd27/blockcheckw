use std::time::Instant;

use console::style;
use serde::Serialize;

use crate::config::{CoreConfig, Protocol, NFQWS2_INIT_DELAY_MS};
use crate::firewall::nftables;
use crate::network::http_client::{http_test_data, pick_random_ip, BodyMode, HttpResult};
use crate::strategy::generator::TaggedStrategy;
use crate::ui;
use crate::worker::nfqws2::start_nfqws2;
use crate::worker::slot::WorkerSlot;

/// Result of checking a single strategy.
#[derive(Debug, Clone, Serialize)]
pub struct CheckedStrategy {
    pub protocol: String,
    pub args: String,
    pub working: bool,
    pub bytes_downloaded: u64,
    pub latency_ms: u64,
    pub speed_kbps: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A strategy that passed verification with factual metrics.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedStrategy {
    pub protocol: String,
    pub args: String,
    pub coverage: usize,
    pub success_rate: f64,
    pub median_latency_ms: u64,
    pub median_speed_kbps: f64,
    pub passes_ok: usize,
    pub passes_total: usize,
}

/// Full check output document.
#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub domain: String,
    pub timestamp: String,
    pub total: usize,
    pub working: usize,
    pub elapsed_secs: f64,
    pub strategies: Vec<VerifiedStrategy>,
}

/// Verify strategies from a vanilla report with real data transfer.
///
/// Each strategy is tested `passes` times. If the first pass fails, the strategy
/// is dropped immediately (early-exit). `--take N` stops after finding N strategies
/// with 100% success rate per protocol.
pub async fn run_check(
    config: &CoreConfig,
    domain: &str,
    strategies: &[TaggedStrategy],
    ips: &[String],
    take: usize,
    passes: usize,
    screen: &mut ui::ScanScreen,
) -> CheckReport {
    let start = Instant::now();
    let slot = WorkerSlot::create_slots(1, config.base_qnum)
        .into_iter()
        .next()
        .unwrap();

    // Prepare nftables table
    nftables::drop_table(&config.nft_table).await;
    if let Err(e) = nftables::prepare_table(&config.nft_table).await {
        screen.println(&format!(
            "  {} failed to prepare nftables: {e}",
            style("ERROR:").red().bold(),
        ));
        return CheckReport {
            domain: domain.to_string(),
            timestamp: timestamp_iso(),
            total: strategies.len(),
            working: 0,
            elapsed_secs: start.elapsed().as_secs_f64(),
            strategies: vec![],
        };
    }

    screen.println(&format!(
        "  {}",
        style(format!(
            "Verifying {} strategies ({passes} passes, early-exit on first fail)",
            strategies.len()
        ))
        .bold()
        .underlined(),
    ));

    let mut verified: Vec<VerifiedStrategy> = Vec::new();
    let mut checked_count: usize = 0;
    // --take: count perfect (all passes OK) strategies per protocol
    let mut perfect_per_proto: std::collections::HashMap<Protocol, usize> =
        std::collections::HashMap::new();

    for (idx, tagged) in strategies.iter().enumerate() {
        // Skip this protocol if we already have enough perfect strategies
        if take > 0 {
            let perfect = perfect_per_proto
                .get(&tagged.protocol)
                .copied()
                .unwrap_or(0);
            if perfect >= take {
                continue;
            }
        }

        let args_str = tagged.args.join(" ");
        if checked_count > 0 {
            screen.println(&format!("  {}", style("─".repeat(60)).dim()));
        }
        screen.println(&format!(
            "  [{}/{}] {} nfqws2 {}",
            idx + 1,
            strategies.len(),
            style(tagged.protocol.to_string()).bold(),
            style(&args_str).cyan(),
        ));

        checked_count += 1;

        // Run passes with early-exit: if first pass fails, skip remaining
        let mut ok_count: usize = 0;
        let mut total_run: usize = 0;
        let mut speeds: Vec<f64> = Vec::with_capacity(passes);
        let mut latencies: Vec<u64> = Vec::with_capacity(passes);
        let mut last_error: Option<String> = None;

        for pass_idx in 0..passes {
            let checked = check_single_strategy(config, &slot, domain, tagged, ips).await;
            total_run = pass_idx + 1;

            if checked.working {
                ok_count += 1;
                speeds.push(checked.speed_kbps);
                latencies.push(checked.latency_ms);
            } else {
                last_error = checked.error;
                // Early-exit: first fail → drop this strategy
                break;
            }
        }

        if ok_count == total_run && ok_count == passes {
            // All passes OK
            speeds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            latencies.sort();
            let median_speed = speeds[speeds.len() / 2];
            let median_latency = latencies[latencies.len() / 2];

            screen.println(&format!(
                "    {} median {}ms, {:.1} KB/s",
                style("OK").green().bold(),
                median_latency,
                median_speed,
            ));

            *perfect_per_proto.entry(tagged.protocol).or_insert(0) += 1;

            verified.push(VerifiedStrategy {
                protocol: tagged.protocol.to_string(),
                args: args_str,
                coverage: tagged.coverage,
                success_rate: 1.0,
                median_latency_ms: median_latency,
                median_speed_kbps: median_speed,
                passes_ok: ok_count,
                passes_total: passes,
            });
        } else {
            let reason = last_error.as_deref().unwrap_or("failed");
            screen.println(&format!(
                "    {} {}/{} {}",
                style("FAIL").red().bold(),
                ok_count,
                total_run,
                style(reason).red(),
            ));
        }

        // Check if all protocols have reached the take limit
        if take > 0 {
            let all_protos: std::collections::HashSet<Protocol> =
                strategies.iter().map(|s| s.protocol).collect();
            let all_satisfied = all_protos
                .iter()
                .all(|p| perfect_per_proto.get(p).copied().unwrap_or(0) >= take);
            if all_satisfied {
                screen.println(&format!(
                    "  {} found {} verified strategies per protocol, stopping",
                    style("--take").bold(),
                    take,
                ));
                break;
            }
        }
    }

    // Sort by speed descending (all are 100% success rate due to early-exit)
    verified.sort_by(|a, b| {
        b.median_speed_kbps
            .partial_cmp(&a.median_speed_kbps)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Cleanup
    nftables::drop_table(&config.nft_table).await;

    CheckReport {
        domain: domain.to_string(),
        timestamp: timestamp_iso(),
        total: checked_count,
        working: verified.len(),
        elapsed_secs: start.elapsed().as_secs_f64(),
        strategies: verified,
    }
}

/// Check one strategy: nfqws2 → nftables → GET → measure → cleanup.
async fn check_single_strategy(
    config: &CoreConfig,
    slot: &WorkerSlot,
    domain: &str,
    tagged: &TaggedStrategy,
    ips: &[String],
) -> CheckedStrategy {
    let protocol = tagged.protocol;
    let args_str = tagged.args.join(" ");

    let make_failed = |error: String| CheckedStrategy {
        protocol: protocol.to_string(),
        args: args_str.clone(),
        working: false,
        bytes_downloaded: 0,
        latency_ms: 0,
        speed_kbps: 0.0,
        error: Some(error),
    };

    // 1. Start nfqws2
    let mut nfqws2_process = match start_nfqws2(config, slot.qnum, &tagged.args) {
        Ok(p) => p,
        Err(e) => return make_failed(format!("nfqws2: {e}")),
    };

    // 2. Wait for nfqws2 to bind, verify it didn't crash
    if let Err(code) = nfqws2_process.wait_for_ready(NFQWS2_INIT_DELAY_MS).await {
        return make_failed(format!("nfqws2 exited immediately (code {code})"));
    }

    // 3. Add outgoing nftables rule
    let postnat_handle = match nftables::add_worker_rule(
        &config.nft_table,
        slot.fwmark,
        protocol.port(),
        slot.qnum,
        ips,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            nfqws2_process.kill().await;
            return make_failed(format!("nftables postnat: {e}"));
        }
    };

    // 4. Add incoming SYN,ACK rule
    let prenat_handle = match nftables::add_incoming_rule(
        &config.nft_table,
        slot.fwmark,
        protocol.port(),
        slot.qnum,
        ips,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            // best-effort cleanup
            let _ = nftables::remove_rule(&config.nft_table, postnat_handle).await;
            nfqws2_process.kill().await;
            return make_failed(format!("nftables prenat: {e}"));
        }
    };

    // 5. HTTP GET with data transfer
    let ip = match pick_random_ip(ips) {
        Some(ip) => ip,
        None => {
            // best-effort cleanup
            let _ = nftables::remove_worker_rules(&config.nft_table, postnat_handle, prenat_handle)
                .await;
            nfqws2_process.kill().await;
            return make_failed("no IP addresses".to_string());
        }
    };

    let test_start = Instant::now();
    let result = http_test_data(
        protocol,
        domain,
        ip,
        slot.fwmark,
        config.request_timeout,
        BodyMode::Unlimited,
    )
    .await;
    let latency_ms = test_start.elapsed().as_millis() as u64;

    // 6. Cleanup: remove rules first, then kill nfqws2 (best-effort)
    let _ = nftables::remove_worker_rules(&config.nft_table, postnat_handle, prenat_handle).await;
    nfqws2_process.kill().await;

    // 7. Interpret for check: got an HTTP status code = strategy works.
    //    DPI blocks manifest as timeouts/connection resets — never as HTTP responses.
    let (working, error) = interpret_check_result(&result, domain);
    let bytes_downloaded = result.size_download.unwrap_or(0);
    let speed_kbps = if working && latency_ms > 0 {
        (bytes_downloaded as f64 / 1024.0) / (latency_ms as f64 / 1000.0)
    } else {
        0.0
    };

    CheckedStrategy {
        protocol: protocol.to_string(),
        args: args_str,
        working,
        bytes_downloaded,
        latency_ms,
        speed_kbps,
        error,
    }
}

/// Check-specific interpretation of HTTP results.
///
/// Unlike scan's `interpret_http_result`, this is simple and permissive:
/// - Error (timeout, reset) → FAIL (DPI blocked us)
/// - HTTP 400 → FAIL (server received our fakes — broken strategy)
/// - Redirect to a different domain → FAIL (ISP captive portal / block page)
/// - Any other HTTP response → OK (strategy works)
fn interpret_check_result(result: &HttpResult, domain: &str) -> (bool, Option<String>) {
    if let Some(err) = &result.error {
        return (false, Some(err.clone()));
    }

    match result.status_code {
        Some(400) => (false, Some("server received fakes (HTTP 400)".to_string())),
        Some(code @ (301 | 302 | 307 | 308)) => {
            let location = extract_redirect_location(&result.headers);
            if location.to_lowercase().contains(&domain.to_lowercase()) {
                (true, None)
            } else {
                (
                    false,
                    Some(format!(
                        "redirect to foreign domain: {location} (HTTP {code})"
                    )),
                )
            }
        }
        Some(code) => {
            let size = result.size_download.unwrap_or(0);
            if size == 0 {
                (false, Some(format!("empty body (HTTP {code})")))
            } else {
                (true, None)
            }
        }
        None => (false, Some("no response".to_string())),
    }
}

/// Extract Location header value from raw headers string.
fn extract_redirect_location(headers: &str) -> String {
    headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("location:"))
        .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default()
}

fn timestamp_iso() -> String {
    use std::process::Command;
    let output = Command::new("date").arg("--iso-8601=seconds").output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("{secs}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speed_calculation() {
        // 10240 bytes in 1000ms = 10 KB/s
        let latency_ms: u64 = 1000;
        let bytes: u64 = 10240;
        let speed = (bytes as f64 / 1024.0) / (latency_ms as f64 / 1000.0);
        assert!((speed - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_speed_zero_latency() {
        let latency_ms: u64 = 0;
        let speed = if latency_ms > 0 {
            (1024.0_f64 / 1024.0) / (latency_ms as f64 / 1000.0)
        } else {
            0.0
        };
        assert_eq!(speed, 0.0);
    }

    #[test]
    fn test_checked_strategy_serialization() {
        let cs = CheckedStrategy {
            protocol: "HTTPS/TLS1.2".to_string(),
            args: "--payload=tls_client_hello --lua-desync=fake".to_string(),
            working: true,
            bytes_downloaded: 51234,
            latency_ms: 340,
            speed_kbps: 147.2,
            error: None,
        };
        let json = serde_json::to_string(&cs).unwrap();
        assert!(json.contains("\"working\":true"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_check_report_serialization() {
        let report = CheckReport {
            domain: "rutracker.org".to_string(),
            timestamp: "2026-03-21T12:00:00+03:00".to_string(),
            total: 2,
            working: 1,
            elapsed_secs: 5.3,
            strategies: vec![],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"domain\": \"rutracker.org\""));
        assert!(json.contains("\"working\": 1"));
    }

    #[test]
    fn test_check_report_with_best() {
        let best = VerifiedStrategy {
            protocol: "HTTPS/TLS1.2".to_string(),
            args: "--payload=tls_client_hello --lua-desync=fake".to_string(),
            coverage: 1,
            success_rate: 1.0,
            median_latency_ms: 320,
            median_speed_kbps: 5.5,
            passes_ok: 3,
            passes_total: 3,
        };
        let report = CheckReport {
            domain: "rutracker.org".to_string(),
            timestamp: "2026-03-21T12:00:00+03:00".to_string(),
            total: 5,
            working: 3,
            elapsed_secs: 10.0,
            strategies: vec![best],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"success_rate\": 1.0"));
    }

    #[test]
    fn test_verified_strategy_serialization() {
        let vs = VerifiedStrategy {
            protocol: "HTTP".to_string(),
            args: "--payload=http_req --lua-desync=fake".to_string(),
            coverage: 1,
            success_rate: 0.67,
            median_latency_ms: 450,
            median_speed_kbps: 2.5,
            passes_ok: 2,
            passes_total: 3,
        };
        let json = serde_json::to_string(&vs).unwrap();
        assert!(json.contains("\"success_rate\":0.67"));
        assert!(json.contains("\"median_speed_kbps\":2.5"));
        assert!(json.contains("\"passes_ok\":2"));
    }
}
