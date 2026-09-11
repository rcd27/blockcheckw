use std::time::Instant;

use console::style;
use tracing::{info_span, Instrument};

use crate::config::{CoreConfig, Protocol};
use crate::dto::{CheckReport, CheckedStrategy, VerifiedStrategy};
use crate::firewall::nft::{OwnedTable, SystemNft};
use crate::firewall::nftables;
use crate::network::http_client::{http_test_data, pick_random_ip, BodyMode, HttpResult};
use crate::nfqws2::plan::{FilterMark, Plan, QueueNum};
use crate::nfqws2::run::SystemNfqws2;
use crate::strategy::generator::TaggedStrategy;
use crate::ui;

/// Verify strategies from a vanilla report with real data transfer.
///
/// Each strategy is tested `passes` times. If the first pass fails, the strategy
/// is dropped immediately (early-exit). `--take N` stops after finding N strategies
/// with 100% success rate per protocol.
#[allow(clippy::too_many_arguments)] // witness добавлен задачей 7 поверх уже широкого набора параметров
pub async fn run_check(
    config: &CoreConfig,
    witness: &FilterMark,
    domain: &str,
    strategies: &[TaggedStrategy],
    ips: &[String],
    take: usize,
    passes: usize,
    screen: &mut ui::Console,
) -> CheckReport {
    let start = Instant::now();

    let table = match nftables::prepare_table(&SystemNft, &config.nft_table).await {
        Ok(t) => t,
        Err(e) => {
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
    };

    screen.println(&format!(
        "  {}",
        style(format!(
            "Verifying {} strategies ({passes} passes, early-exit on first fail)",
            strategies.len()
        ))
        .bold()
        .underlined(),
    ));

    // ЗАМЕР (спайк #verify-histogram): под переменной ранний выход снимается —
    // иначе флапающих не видно вовсе, они умирают на первом же провале, и
    // вопрос «стоило ли повторять» остаётся без данных.
    let measure_all = std::env::var("BCW_MEASURE_ALL_PASSES").is_ok();
    if measure_all {
        screen.println(&format!(
            "  {} ранний выход снят: гоняем все {passes} проходов",
            style("замер").bold(),
        ));
    }
    let mut rows: Vec<Vec<crate::pipeline::verify::Outcome>> = Vec::new();

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

        // Span на проверку конкретной стратегии (ребёнок bcw.check). Здесь живёт
        // причина FAIL (connect/timeout) — то, ради чего трейсинг и затевался.
        let strategy_span = info_span!(
            "bcw.check.strategy",
            protocol = %tagged.protocol,
            args = %args_str,
            status = tracing::field::Empty,
            reason = tracing::field::Empty,
        );
        let mut row: Vec<crate::pipeline::verify::Outcome> = Vec::with_capacity(passes);
        async {
            for pass_idx in 0..passes {
                let started = crate::pipeline::verify::now_epoch();
                let checked =
                    check_single_strategy(config, witness, &table, domain, tagged, ips).await;
                total_run = pass_idx + 1;

                let outcome = match checked.working {
                    true => crate::pipeline::verify::Outcome::Passed,
                    false => crate::pipeline::verify::Outcome::Failed(
                        checked
                            .failure
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                    ),
                };
                crate::pipeline::verify::log_pass(started, checked_count, pass_idx + 1, &outcome);
                row.push(outcome);

                if checked.working {
                    ok_count += 1;
                    speeds.push(checked.speed_kbps);
                    latencies.push(checked.latency_ms);
                } else {
                    last_error = checked.error;
                    // Early-exit: first fail → drop this strategy
                    if !measure_all {
                        break;
                    }
                }
            }
        }
        .instrument(strategy_span.clone())
        .await;

        rows.push(row);

        if ok_count == total_run && ok_count == passes {
            // All passes OK
            strategy_span.record("status", "working");
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
            strategy_span.record("status", "fail");
            strategy_span.record("reason", reason);
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

    crate::pipeline::verify::report_stability(
        &crate::pipeline::verify::stability_of(&rows, passes),
        domain,
        screen,
    );

    // Sort by speed descending (all are 100% success rate due to early-exit)
    verified.sort_by(|a, b| {
        b.median_speed_kbps
            .partial_cmp(&a.median_speed_kbps)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Cleanup
    let _ = table.drop_table(&SystemNft).await;

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
    witness: &FilterMark,
    table: &OwnedTable,
    domain: &str,
    tagged: &TaggedStrategy,
    ips: &[String],
) -> CheckedStrategy {
    let protocol = tagged.protocol;
    let args_str = tagged.args.join(" ");

    let make_failed = |error: String| CheckedStrategy {
        failure: Some("engine_error".to_string()),
        protocol: protocol.to_string(),
        args: args_str.clone(),
        working: false,
        bytes_downloaded: 0,
        latency_ms: 0,
        speed_kbps: 0.0,
        error: Some(error),
    };

    // 1. Собрать план из одного профиля и поднять движок
    let env = config.nfqws2_env();
    let queue = QueueNum::new(config.base_qnum);
    let plan = Plan::from_one(witness, queue, &tagged.args);
    let mark = plan.profiles()[0].mark;

    let mut instance = match SystemNfqws2::start(&env, &plan).await {
        Ok(i) => i,
        Err(e) => return make_failed(format!("nfqws2: {e}")),
    };

    // 2. Дождаться, пока движок реально забиндит очередь
    let ready = match SystemNfqws2::wait_ready(&mut instance).await {
        Ok(r) => r,
        Err(e) => {
            SystemNfqws2::stop(instance).await;
            return make_failed(format!("nfqws2: {e}"));
        }
    };

    // 3. Поставить диспетчеризацию — только теперь, когда слушатель точно есть
    if let Err(e) = nftables::apply_dispatch(
        &SystemNft,
        table,
        &ready,
        &plan.dispatch(protocol.port()),
        ips,
    )
    .await
    {
        // Батч атомарен, но `Err` тут может значить и таймаут
        // `run_process_stdin` (15с): нельзя быть уверенным, что nft не успел
        // применить правила до обрыва. Снимаем диспетчеризацию на всякий
        // случай, прежде чем убивать слушателя — иначе `queue to N` рискует
        // остаться стоять без него до конца всего прогона.
        nftables::remove_dispatch(&SystemNft, table).await;
        SystemNfqws2::stop(instance).await;
        return make_failed(format!("nftables: {e}"));
    }

    // 4. HTTP GET with data transfer. `ips` гарантированно непусты:
    // `apply_dispatch` выше уже прогнал `validate_ip_set`, отвергающий
    // пустой список, и вернул `Ok` — значит, эта проверка не могла провалиться.
    let ip = pick_random_ip(ips).expect("apply_dispatch already validated ips is non-empty");

    let test_start = Instant::now();
    let result = http_test_data(
        protocol,
        domain,
        ip,
        mark.so_mark(),
        config.request_timeout,
        BodyMode::Unlimited,
        None,
    )
    .await;
    let latency_ms = test_start.elapsed().as_millis() as u64;

    // 5. Cleanup: снять диспетчеризацию, затем убить nfqws2 (best-effort)
    nftables::remove_dispatch(&SystemNft, table).await;
    SystemNfqws2::stop(instance).await;

    // 6. Interpret for check: got an HTTP status code = strategy works.
    //    DPI blocks manifest as timeouts/connection resets — never as HTTP responses.
    let (working, error, named) = interpret_check_result(&result, domain);
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
        // Имя провала — с провода, где он есть; иначе по тому, что видно сверху.
        failure: match working {
            true => None,
            false => Some(match (result.cause, named) {
                (Some(c), _) => c.name(),
                (None, Some(name)) => name.to_string(),
                (None, None) => "unknown".to_string(),
            }),
        },
    }
}

/// Check-specific interpretation of HTTP results.
///
/// Unlike scan's `interpret_http_result`, this is simple and permissive:
/// - Error (timeout, reset) → FAIL (DPI blocked us)
/// - HTTP 400 → FAIL (server received our fakes — broken strategy)
/// - Redirect to a different domain → FAIL (ISP captive portal / block page)
/// - Any other HTTP response → OK (strategy works)
fn interpret_check_result(
    result: &HttpResult,
    domain: &str,
) -> (bool, Option<String>, Option<&'static str>) {
    if let Some(err) = &result.error {
        return (false, Some(err.clone()), None);
    }

    match result.status_code {
        Some(400) => (
            false,
            Some("server received fakes (HTTP 400)".to_string()),
            Some("server_receives_fakes"),
        ),
        Some(code @ (301 | 302 | 307 | 308)) => {
            let location = extract_redirect_location(&result.headers);
            if location.to_lowercase().contains(&domain.to_lowercase()) {
                (true, None, None)
            } else {
                (
                    false,
                    Some(format!(
                        "redirect to foreign domain: {location} (HTTP {code})"
                    )),
                    Some("foreign_redirect"),
                )
            }
        }
        Some(code) => {
            let size = result.size_download.unwrap_or(0);
            if size == 0 {
                (
                    false,
                    Some(format!("empty body (HTTP {code})")),
                    Some("empty_body"),
                )
            } else {
                (true, None, None)
            }
        }
        None => (false, Some("no response".to_string()), Some("no_response")),
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
    crate::pipeline::test_report::chrono_like_timestamp()
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
    fn an_empty_body_failure_is_named_and_not_left_unknown() {
        let result = HttpResult {
            status_code: Some(200),
            headers: String::new(),
            error: None,
            size_download: Some(0),
            cause: None,
        };
        let (working, _, failure) = interpret_check_result(&result, "rutracker.org");
        assert!(!working);
        assert_eq!(
            failure,
            Some("empty_body"),
            "пустое тело при живом коде — вероятная обрезка данных цензором; \
             без имени она уходит в «unknown» и перестаёт быть уликой"
        );
    }

    #[test]
    fn a_redirect_to_a_foreign_domain_is_named_apart() {
        let result = HttpResult {
            status_code: Some(302),
            headers: "Location: http://blocked.gov.ru/\r\n".to_string(),
            error: None,
            size_download: None,
            cause: None,
        };
        let (working, _, failure) = interpret_check_result(&result, "rutracker.org");
        assert!(!working);
        assert_eq!(failure, Some("foreign_redirect"));
    }

    #[test]
    fn timestamp_is_utc_iso_8601() {
        let timestamp = timestamp_iso();
        assert_eq!(timestamp.len(), 20);
        assert_eq!(&timestamp[10..11], "T");
        assert!(timestamp.ends_with('Z'));
        assert!(!timestamp[..19].chars().all(|ch| ch.is_ascii_digit()));
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
            failure: None,
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
