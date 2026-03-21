use std::time::Instant;

use console::style;
use serde::Serialize;

use crate::config::{CoreConfig, NFQWS2_INIT_DELAY_MS};
use crate::firewall::nftables;
use crate::network::http_client::{http_test_data, pick_random_ip, HttpResult};
use crate::pipeline::test_runner::{compute_stats, PassResult, StabilityVerdict};
use crate::strategy::generator::TaggedStrategy;
use crate::strategy::rank;
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

/// A strategy that passed Phase 2 verification with stability metrics.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedStrategy {
    pub protocol: String,
    pub args: String,
    pub success_rate: f64,
    pub median_latency_ms: u64,
    pub stability: StabilityVerdict,
    pub rank_score: u32,
    pub final_score: f64,
}

/// Full check output document.
#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub domain: String,
    pub timestamp: String,
    pub total: usize,
    pub working: usize,
    pub elapsed_secs: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best: Option<VerifiedStrategy>,
    pub strategies: Vec<CheckedStrategy>,
}

/// Run two-phase check to find the best strategy.
///
/// **Phase 1 (screening):** sequential single-pass check of all strategies.
/// `take` controls early stop: 0 = check all, N > 0 = stop after N working strategies found.
///
/// **Phase 2 (verification):** each working strategy is re-tested `passes` times.
/// Stability and rank scores are combined to pick the best one.
///
/// If `passes` is 0 or 1, Phase 2 is skipped (single-pass mode, backward compatible).
pub async fn run_check(
    config: &CoreConfig,
    domain: &str,
    strategies: &[TaggedStrategy],
    ips: &[String],
    take: usize,
    passes: usize,
    screen: &ui::ScanScreen,
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
            best: None,
            strategies: vec![],
        };
    }

    // ── Phase 1: screening ──
    screen.println(&format!(
        "  {}",
        style("Phase 1: screening").bold().underlined(),
    ));

    let mut results = Vec::with_capacity(strategies.len());
    let mut working_tagged: Vec<&TaggedStrategy> = Vec::new();
    let mut working_count: usize = 0;
    let mut checked_count: usize = 0;

    for (idx, tagged) in strategies.iter().enumerate() {
        if idx > 0 {
            screen.println(&format!("  {}", style("─".repeat(60)).dim()));
        }

        let args_str = tagged.args.join(" ");
        screen.println(&format!(
            "  [{}/{}] {} nfqws2 {}",
            idx + 1,
            strategies.len(),
            style(tagged.protocol.to_string()).bold(),
            style(&args_str).cyan(),
        ));

        let checked = check_single_strategy(config, &slot, domain, tagged, ips).await;
        checked_count += 1;

        let status = if checked.working {
            working_count += 1;
            format!(
                "    {} {}B, {}ms, {:.1} KB/s",
                style("OK").green().bold(),
                checked.bytes_downloaded,
                checked.latency_ms,
                checked.speed_kbps,
            )
        } else {
            let reason = checked.error.as_deref().unwrap_or("failed");
            format!("    {} {}", style("FAIL").red().bold(), style(reason).red(),)
        };
        screen.println(&status);

        if checked.working {
            working_tagged.push(tagged);
            results.push(checked);
        }

        if take > 0 && working_count >= take {
            screen.println(&format!(
                "  {} found {} working strategies, stopping early ({} of {} checked)",
                style("--take").bold(),
                working_count,
                checked_count,
                strategies.len(),
            ));
            break;
        }
    }

    // ── Phase 2: verification ──
    let best = if passes >= 2 && !working_tagged.is_empty() {
        screen.newline();
        screen.println(&format!(
            "  {}",
            style(format!(
                "Phase 2: verifying {} strategies ({passes} passes each)",
                working_tagged.len()
            ))
            .bold()
            .underlined(),
        ));

        let mut verified: Vec<VerifiedStrategy> = Vec::new();

        for (idx, tagged) in working_tagged.iter().enumerate() {
            let args_str = tagged.args.join(" ");
            screen.println(&format!(
                "  [{}/{}] {} nfqws2 {}",
                idx + 1,
                working_tagged.len(),
                style(tagged.protocol.to_string()).bold(),
                style(&args_str).cyan(),
            ));

            // Run K passes, collect PassResults
            let mut pass_results = Vec::with_capacity(passes);
            for pass_idx in 0..passes {
                let checked = check_single_strategy(config, &slot, domain, tagged, ips).await;
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                pass_results.push(PassResult {
                    pass_index: pass_idx + 1,
                    success: checked.working,
                    verdict: if checked.working {
                        "OK".to_string()
                    } else {
                        checked.error.unwrap_or_else(|| "FAIL".to_string())
                    },
                    latency_ms: checked.latency_ms,
                    timestamp,
                });
            }

            let stats = compute_stats(&pass_results);
            let rank_score = rank::score_strategy(&tagged.args);

            // final_score = stability(success_rate) * 0.6 + rank_score * 0.4
            let stability_score = stats.success_rate * 100.0;
            let final_score = stability_score * 0.6 + rank_score.total as f64 * 0.4;

            screen.println(&format!(
                "    {}: {}/{} OK, median {}ms, {} (rank {}), final {:.1}",
                style(&stats.stability).bold(),
                stats.successes,
                stats.total_passes,
                stats.latency_median_ms,
                style(format!("★{}", rank_score.stars)).yellow(),
                rank_score.total,
                final_score,
            ));

            verified.push(VerifiedStrategy {
                protocol: tagged.protocol.to_string(),
                args: args_str,
                success_rate: stats.success_rate,
                median_latency_ms: stats.latency_median_ms,
                stability: stats.stability,
                rank_score: rank_score.total,
                final_score,
            });
        }

        // Sort by final_score descending
        verified.sort_by(|a, b| b.final_score.partial_cmp(&a.final_score).unwrap());

        if let Some(best) = verified.first() {
            screen.newline();
            screen.println(&format!(
                "  {} {} nfqws2 {}",
                style("BEST:").green().bold(),
                style(&best.protocol).bold(),
                style(&best.args).cyan().bold(),
            ));
            screen.println(&format!(
                "    success_rate: {:.0}%, median: {}ms, stability: {}, rank: {}, final: {:.1}",
                best.success_rate * 100.0,
                best.median_latency_ms,
                best.stability,
                best.rank_score,
                best.final_score,
            ));
        }

        verified.into_iter().next()
    } else {
        None
    };

    // Cleanup
    nftables::drop_table(&config.nft_table).await;

    CheckReport {
        domain: domain.to_string(),
        timestamp: timestamp_iso(),
        total: checked_count,
        working: working_count,
        elapsed_secs: start.elapsed().as_secs_f64(),
        best,
        strategies: results,
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
        0, // unlimited — we just need any response
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
        Some(_) => (true, None),
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
            best: None,
            strategies: vec![
                CheckedStrategy {
                    protocol: "HTTP".to_string(),
                    args: "--payload=http_req".to_string(),
                    working: true,
                    bytes_downloaded: 10240,
                    latency_ms: 500,
                    speed_kbps: 20.0,
                    error: None,
                },
                CheckedStrategy {
                    protocol: "HTTPS/TLS1.2".to_string(),
                    args: "--payload=tls_client_hello".to_string(),
                    working: false,
                    bytes_downloaded: 0,
                    latency_ms: 2000,
                    speed_kbps: 0.0,
                    error: Some("timeout".to_string()),
                },
            ],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"domain\": \"rutracker.org\""));
        assert!(json.contains("\"working\": 1"));
        assert!(json.contains("\"error\": \"timeout\""));
        // best is None, so "best" should not appear in JSON
        assert!(!json.contains("\"best\""));
    }

    #[test]
    fn test_check_report_with_best() {
        let best = VerifiedStrategy {
            protocol: "HTTPS/TLS1.2".to_string(),
            args: "--payload=tls_client_hello --lua-desync=fake".to_string(),
            success_rate: 1.0,
            median_latency_ms: 320,
            stability: StabilityVerdict::Stable,
            rank_score: 80,
            final_score: 92.0,
        };
        let report = CheckReport {
            domain: "rutracker.org".to_string(),
            timestamp: "2026-03-21T12:00:00+03:00".to_string(),
            total: 5,
            working: 3,
            elapsed_secs: 10.0,
            best: Some(best),
            strategies: vec![],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"best\""));
        assert!(json.contains("\"final_score\": 92.0"));
        assert!(json.contains("\"stability\": \"stable\""));
    }

    #[test]
    fn test_final_score_calculation() {
        // success_rate=1.0 (100%), rank_score=80
        // stability_score = 100.0, final = 100*0.6 + 80*0.4 = 60+32 = 92
        let stability_score = 1.0 * 100.0;
        let rank_total = 80_u32;
        let final_score = stability_score * 0.6 + rank_total as f64 * 0.4;
        assert!((final_score - 92.0).abs() < 0.01);

        // success_rate=0.5, rank_score=100
        // stability_score = 50.0, final = 50*0.6 + 100*0.4 = 30+40 = 70
        let stability_score = 0.5 * 100.0;
        let rank_total = 100_u32;
        let final_score = stability_score * 0.6 + rank_total as f64 * 0.4;
        assert!((final_score - 70.0).abs() < 0.01);
    }

    #[test]
    fn test_verified_strategy_serialization() {
        let vs = VerifiedStrategy {
            protocol: "HTTP".to_string(),
            args: "--payload=http_req --lua-desync=fake".to_string(),
            success_rate: 0.67,
            median_latency_ms: 450,
            stability: StabilityVerdict::Flaky,
            rank_score: 75,
            final_score: 70.2,
        };
        let json = serde_json::to_string(&vs).unwrap();
        assert!(json.contains("\"stability\":\"flaky\""));
        assert!(json.contains("\"success_rate\":0.67"));
        assert!(json.contains("\"rank_score\":75"));
    }
}
