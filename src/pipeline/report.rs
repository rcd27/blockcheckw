//! Pure report-building functions.
//!
//! All functions here are `f(data) -> result` — no I/O, no side effects.
//! They transform intermediate scan/universal results into final report structures.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use crate::config::Protocol;
use crate::dto::{
    ScanProtocolResult, ScanReport, StrategyEntry, UniversalProtocolResult, UniversalReport,
    UniversalStrategy,
};
use crate::pipeline::test_report;

// ── Scan report building ─────────────────────────────────────────────────────

/// Intermediate per-protocol scan results (I/O-free data).
pub struct ProtocolSummary {
    pub protocol: Protocol,
    pub strategies: Vec<Vec<String>>,
}

/// Build scan JSON report from intermediate results. Returns (json, strategy_count).
pub fn build_scan_report(domain: &str, summary: &[ProtocolSummary]) -> (String, usize) {
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

    let report = ScanReport {
        domain: domain.to_string(),
        timestamp,
        total,
        working: total,
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
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
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
