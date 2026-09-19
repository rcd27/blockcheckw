//! Pure report-building functions.
//!
//! All functions here are `f(data) -> result` — no I/O, no side effects.
//! They transform intermediate scan/universal results into final report structures.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use crate::config::Protocol;
use crate::dto::{
    BlockType, DnsSpoofed, Outcome, RunProvenance, ScanProtocolResult, ScanReport, StrategyEntry,
    UniversalProtocolResult, UniversalReport, UniversalStrategy,
};
use crate::pipeline::test_report;

// ── Scan report building ─────────────────────────────────────────────────────

/// Intermediate per-protocol scan results (I/O-free data).
#[derive(Clone)]
pub struct ProtocolSummary {
    pub protocol: Protocol,
    pub strategies: Vec<Vec<String>>,
}

/// Из чего собирается отчёт скана.
///
/// Структурой, а не списком аргументов: их стало семь, и позиционный вызов с двумя
/// соседними булевыми — приглашение перепутать их местами молча.
pub struct ScanReportInput<'a> {
    pub domain: &'a str,
    pub block_type: BlockType,
    pub dns_spoofed: DnsSpoofed,
    pub blocked: &'a [Protocol],
    pub summary: &'a [ProtocolSummary],
    /// ЧТО СЛУЧИЛОСЬ С ПРОГОНОМ. Читается потребителем прежде `strategies`.
    pub outcome: Outcome,
    /// Фактические условия прогона.
    pub run: RunProvenance,
}

/// Build scan JSON report from intermediate results. Returns (json, strategy_count).
pub fn build_scan_report(input: ScanReportInput<'_>) -> (String, usize) {
    let ScanReportInput {
        domain,
        block_type,
        dns_spoofed,
        blocked,
        summary,
        outcome,
        mut run,
    } = input;
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

    run.total = total;
    run.tried = total;
    let report = ScanReport {
        schema: crate::dto::SCHEMA,
        outcome,
        run,
        domain: domain.to_string(),
        timestamp,
        block_type,
        dns_spoofed,
        total,
        working: total,
        blocked: blocked.iter().map(|p| p.to_string()).collect(),
        protocols,
        strategies,
    };

    let json = serde_json::to_string_pretty(&report).expect("report serialization");
    (json, total)
}

/// Build vanilla blockcheck2-compatible report. Returns (content, strategy_count).
/// Format: `curl_test_<proto> ipv4 <domain> : nfqws2 <args>`
pub fn build_vanilla_report(domain: &str, summary: &[ProtocolSummary]) -> (String, usize) {
    let mut buf = String::new();
    let mut total = 0;

    let _ = writeln!(buf, "* SUMMARY");

    for entry in summary {
        let test_name = match entry.protocol {
            Protocol::Http => "curl_test_http",
            Protocol::HttpsTls12 => "curl_test_https_tls12",
            Protocol::HttpsTls13 => "curl_test_https_tls13",
        };
        for s in &entry.strategies {
            let _ = writeln!(buf, "{test_name} ipv4 {domain} : nfqws2 {}", s.join(" "));
            total += 1;
        }
    }

    (buf, total)
}

/// Build strategies-only file (one per line). Returns (content, strategy_count).
pub fn build_strategies_file(domain: &str, summary: &[ProtocolSummary]) -> (String, usize) {
    let timestamp = test_report::chrono_like_timestamp();
    let mut buf = String::new();
    let mut total = 0;

    let _ = writeln!(buf, "# blockcheckw scan results for {domain}");
    let _ = writeln!(buf, "# {timestamp}");

    for entry in summary {
        if entry.strategies.is_empty() {
            continue;
        }
        let _ = writeln!(buf);
        let _ = writeln!(
            buf,
            "# {} — {} strategies",
            entry.protocol,
            entry.strategies.len()
        );

        for args in &entry.strategies {
            let _ = writeln!(buf, "{}", args.join(" "));
        }
        total += entry.strategies.len();
    }

    (buf, total)
}

// ── Universal report building ────────────────────────────────────────────────

/// Intermediate per-protocol universal scan results (I/O-free data).
pub struct UniversalProtocolData {
    pub protocol: Protocol,
    pub strategies: Vec<(Vec<String>, usize)>,
    pub tested_domains: Vec<String>,
    pub excluded_domains: Vec<String>,
}

/// Rank raw hit counts into sorted (args, coverage) pairs.
pub fn rank_by_coverage(hits: HashMap<String, usize>) -> Vec<(Vec<String>, usize)> {
    let mut ranked: Vec<(Vec<String>, usize)> = hits
        .into_iter()
        .map(|(key, count)| {
            let args: Vec<String> = key.split_whitespace().map(String::from).collect();
            (args, count)
        })
        .collect();
    ranked.sort_by_key(|b| std::cmp::Reverse(b.1));
    ranked
}

/// Build universal JSON report from intermediate results.
pub fn build_universal_report(sample: usize, results: &[UniversalProtocolData]) -> UniversalReport {
    let flat_strategies: Vec<StrategyEntry> = results
        .iter()
        .flat_map(|r| {
            r.strategies.iter().map(|(args, count)| StrategyEntry {
                protocol: r.protocol.to_string(),
                args: args.join(" "),
                coverage: *count,
            })
        })
        .collect();

    UniversalReport {
        timestamp: test_report::chrono_like_timestamp(),
        domains_sampled: sample,
        protocols: results
            .iter()
            .map(|r| UniversalProtocolResult {
                protocol: r.protocol.to_string(),
                domains_tested: r.tested_domains.clone(),
                domains_excluded: r.excluded_domains.clone(),
                strategies: r
                    .strategies
                    .iter()
                    .map(|(args, count)| UniversalStrategy {
                        args: args.join(" "),
                        coverage: *count,
                    })
                    .collect(),
            })
            .collect(),
        strategies: flat_strategies,
    }
}

/// Filter out excluded domains from original list. Returns cleaned list as string.
pub fn build_cleaned_domain_list(
    all_domains: &[String],
    results: &[UniversalProtocolData],
) -> Option<String> {
    let all_excluded: HashSet<&str> = results
        .iter()
        .flat_map(|r| r.excluded_domains.iter().map(|s| s.as_str()))
        .collect();

    if all_excluded.is_empty() {
        return None;
    }

    let cleaned: String = all_domains
        .iter()
        .filter(|d| !all_excluded.contains(d.as_str()))
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");

    Some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Отчёт скана с умолчаниями теста: предмет проверок ниже — состав отчёта, а не исход
    /// и не условия прогона, поэтому они задаются одним местом.
    fn input<'a>(
        domain: &'a str,
        block_type: BlockType,
        dns_spoofed: DnsSpoofed,
        blocked: &'a [Protocol],
        summary: &'a [ProtocolSummary],
    ) -> ScanReportInput<'a> {
        ScanReportInput {
            domain,
            block_type,
            dns_spoofed,
            blocked,
            summary,
            outcome: Outcome::NothingWorks { candidates: 0 },
            run: RunProvenance::of(&crate::config::CoreConfig::default(), "auto", false),
        }
    }

    #[test]
    fn scan_report_not_blocked_has_empty_blocked_list() {
        let (json, count) = build_scan_report(input(
            "example.com",
            BlockType::NotBlocked,
            DnsSpoofed::Unchecked,
            &[],
            &[],
        ));
        assert_eq!(count, 0);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["blocked"].as_array().unwrap().len(), 0);
        assert_eq!(v["strategies"].as_array().unwrap().len(), 0);
        assert_eq!(v["dns_spoofed"], "unchecked");
    }

    #[test]
    fn scan_report_blocked_no_strategies_lists_blocked_protocols() {
        // Заблокирован TLS1.2, но рабочих стратегий нет: strategies пуст,
        // blocked непуст — это и отличает «заблокирован» от «не заблокирован».
        let summary = vec![ProtocolSummary {
            protocol: Protocol::HttpsTls12,
            strategies: vec![],
        }];
        let (json, count) = build_scan_report(input(
            "example.com",
            BlockType::SniBlocked,
            DnsSpoofed::Clean,
            &[Protocol::HttpsTls12],
            &summary,
        ));
        assert_eq!(count, 0);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["blocked"], serde_json::json!(["HTTPS/TLS1.2"]));
        assert_eq!(v["strategies"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn scan_report_includes_block_type() {
        // block_type is the network-layer verdict (IP-blackhole vs SNI-block) a
        // consumer reads straight from the scan output. Serialized snake_case.
        let (json, _) = build_scan_report(input(
            "example.com",
            crate::dto::BlockType::IpBlocked,
            DnsSpoofed::Clean,
            &[Protocol::HttpsTls12],
            &[],
        ));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["block_type"], "ip_blocked");
    }

    #[test]
    fn scan_report_carries_dns_spoofed_state() {
        // dns_spoofed ортогонально block_type: резолвер отравлен, а вердикт снят по чистым
        // DoH-адресам. Здесь: подмена есть, блокировки нет.
        let (json, _) = build_scan_report(input(
            "example.com",
            BlockType::NotBlocked,
            DnsSpoofed::Spoofed,
            &[],
            &[],
        ));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["dns_spoofed"], "spoofed");
        assert_eq!(v["block_type"], "not_blocked");
    }

    /// Контракт с продуктом: версия формата, исход и условия прогона обязаны быть в КАЖДОМ
    /// отчёте. Читатель, который их не нашёл, не знает ни что читает, ни что случилось.
    #[test]
    fn every_report_carries_schema_outcome_and_provenance() {
        let (json, _) = build_scan_report(input(
            "example.com",
            BlockType::SniBlocked,
            DnsSpoofed::Clean,
            &[Protocol::HttpsTls12],
            &[],
        ));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["schema"], crate::dto::SCHEMA);
        assert_eq!(v["outcome"], "nothing_works");
        for field in [
            "bcw_version",
            "workers",
            "profiles_per_instance",
            "dns",
            "qnum",
            "nft_table",
            "mark_base",
            "desync_mark",
            "process_group",
            "embedded",
            "tried",
            "total",
        ] {
            assert!(
                !v["run"][field].is_null(),
                "провенанс обязан нести {field}: замер без своих условий — половина замера"
            );
        }
        assert_eq!(v["run"]["qnum"], 200);
        assert_eq!(v["run"]["mark_base"], "0x20000000");
    }

    #[test]
    fn scan_report_blocked_with_strategies_populates_both() {
        let summary = vec![ProtocolSummary {
            protocol: Protocol::HttpsTls12,
            strategies: vec![vec!["--payload=tls_client_hello".to_string()]],
        }];
        let (json, count) = build_scan_report(input(
            "example.com",
            BlockType::SniBlocked,
            DnsSpoofed::Clean,
            &[Protocol::HttpsTls12],
            &summary,
        ));
        assert_eq!(count, 1);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["blocked"], serde_json::json!(["HTTPS/TLS1.2"]));
        assert_eq!(v["strategies"].as_array().unwrap().len(), 1);
    }
}
