//! Data Transfer Objects — all JSON-serializable report structures in one place.
//!
//! These structs define the public contract for scan/check/universal JSON reports
//! and inter-command data exchange (e.g. `scan | check` pipe).

use serde::{Deserialize, Serialize};

// ── Shared (used across commands) ────────────────────────────────────────────

/// Single strategy entry for interchange between commands (scan → check pipe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyEntry {
    pub protocol: String,
    pub args: String,
    /// Domain coverage: 1 for scan/vanilla, N for universal.
    pub coverage: usize,
}

// ── Scan report ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScanProtocolResult {
    pub protocol: String,
    pub total: usize,
    pub strategies: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub domain: String,
    pub timestamp: String,
    /// Network-layer verdict (IP-blackhole vs SNI-block vs available/dns-failed).
    /// Lets a consumer route on the block kind without re-probing: `IpBlocked`
    /// means desync can't help (no handshake), `SniBlocked` means it can.
    pub block_type: BlockType,
    /// System resolver confirmed poisoned (system DNS diverged from DoH). Orthogonal
    /// to `block_type`, which is measured on the clean (DoH) IPs: a domain can be
    /// `dns_spoofed` yet `not_blocked`. Signals "don't trust system DNS, use DoH".
    pub dns_spoofed: bool,
    pub total: usize,
    pub working: usize,
    /// Protocols that failed the no-bypass baseline (i.e. are DPI-blocked).
    /// Empty ⟺ domain is not blocked. Distinguishes "not blocked" from
    /// "blocked but no working strategy" — both yield empty `strategies`.
    pub blocked: Vec<String>,
    pub protocols: Vec<ScanProtocolResult>,
    /// Flat list of all working strategies for interchange with check.
    pub strategies: Vec<StrategyEntry>,
}

// ── Check report ─────────────────────────────────────────────────────────────

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

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub domain: String,
    pub timestamp: String,
    pub total: usize,
    pub working: usize,
    pub elapsed_secs: f64,
    pub strategies: Vec<VerifiedStrategy>,
}

// ── Universal report ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct UniversalStrategy {
    pub args: String,
    pub coverage: usize,
}

#[derive(Debug, Serialize)]
pub struct UniversalProtocolResult {
    pub protocol: String,
    pub domains_tested: Vec<String>,
    pub domains_excluded: Vec<String>,
    pub strategies: Vec<UniversalStrategy>,
}

#[derive(Debug, Serialize)]
pub struct UniversalReport {
    pub timestamp: String,
    pub domains_sampled: usize,
    pub protocols: Vec<UniversalProtocolResult>,
    /// Flat list of all strategies for interchange with check.
    pub strategies: Vec<StrategyEntry>,
}

// ── Status report ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockType {
    /// Domain is accessible
    NotBlocked,
    /// Handshake and HEAD succeed, but bulk data is throttled — capped after a
    /// few KB (DPI data limit) or otherwise choked. The page loads; video and
    /// downloads stall. Desync may help if SNI-triggered; per-IP throttle needs
    /// a different egress.
    Throttled,
    /// Direct TCP connect fails, with no proxy probe to refine the cause →
    /// IP-level block of unknown kind. Desync can't help (no handshake).
    IpBlocked,
    /// Direct SYN dropped, yet the IP is reachable via a proxy → the SYN is
    /// filtered on this path while the host is alive. Changing egress bypasses it.
    SynBlocked,
    /// Unreachable both directly and via a proxy → the host is down everywhere.
    HostDead,
    /// TCP connects but TLS/data fails → DPI/SNI block, zapret can bypass
    SniBlocked,
    /// DNS resolution failed
    DnsFailed,
}

impl BlockType {
    /// Classify a domain from stepped probe outcomes (DNS → direct TCP → response,
    /// plus an optional proxy reachability probe). When the direct SYN fails, a
    /// proxy comparison splits IP-level failure into [`SynBlocked`](Self::SynBlocked)
    /// (alive elsewhere, path-filtered) and [`HostDead`](Self::HostDead) (down everywhere);
    /// without a proxy it stays the unrefined [`IpBlocked`](Self::IpBlocked).
    /// `proxy_reachable`: `None` = no proxy probe, `Some(true/false)` = proxy result.
    pub fn classify(
        dns_ok: bool,
        direct_reachable: bool,
        got_response: bool,
        proxy_reachable: Option<bool>,
    ) -> BlockType {
        match (dns_ok, direct_reachable, got_response, proxy_reachable) {
            (false, _, _, _) => BlockType::DnsFailed,
            (true, true, true, _) => BlockType::NotBlocked,
            (true, true, false, _) => BlockType::SniBlocked,
            (true, false, _, None) => BlockType::IpBlocked,
            (true, false, _, Some(true)) => BlockType::SynBlocked,
            (true, false, _, Some(false)) => BlockType::HostDead,
        }
    }
}

impl std::fmt::Display for BlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockType::NotBlocked => write!(f, "not blocked"),
            BlockType::Throttled => write!(f, "throttled"),
            BlockType::IpBlocked => write!(f, "IP blocked"),
            BlockType::SynBlocked => write!(f, "SYN blocked"),
            BlockType::HostDead => write!(f, "host dead"),
            BlockType::SniBlocked => write!(f, "SNI blocked"),
            BlockType::DnsFailed => write!(f, "DNS failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainStatus {
    pub domain: String,
    pub block_type: BlockType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed_kbps: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub timestamp: String,
    pub total: usize,
    pub available: usize,
    pub sni_blocked: usize,
    pub ip_blocked: usize,
    pub dns_failed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_speed_kbps: Option<f64>,
    pub domains: Vec<DomainStatus>,
}

// ── Strategy test results (test_runner) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PassResult {
    pub pass_index: usize,
    pub success: bool,
    pub verdict: String,
    pub latency_ms: u64,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct StrategyTestResult {
    pub strategy_args: Vec<String>,
    pub pass_results: Vec<PassResult>,
    pub stats: StrategyStats,
}

#[derive(Debug, Serialize)]
pub struct StrategyStats {
    pub total_passes: usize,
    pub successes: usize,
    pub failures: usize,
    pub errors: usize,
    pub success_rate: f64,
    pub latency_median_ms: u64,
    pub latency_p95_ms: u64,
    pub latency_p99_ms: u64,
    pub latency_min_ms: u64,
    pub latency_max_ms: u64,
    pub error_distribution: Vec<(String, usize)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_dns_failure_is_dns_failed() {
        assert_eq!(
            BlockType::classify(false, false, false, None),
            BlockType::DnsFailed
        );
    }

    #[test]
    fn classify_tcp_unreachable_without_proxy_is_ip_blocked() {
        assert_eq!(
            BlockType::classify(true, false, false, None),
            BlockType::IpBlocked
        );
    }

    #[test]
    fn classify_handshake_but_no_response_is_sni_blocked() {
        assert_eq!(
            BlockType::classify(true, true, false, None),
            BlockType::SniBlocked
        );
    }

    #[test]
    fn classify_response_received_is_not_blocked() {
        assert_eq!(
            BlockType::classify(true, true, true, None),
            BlockType::NotBlocked
        );
    }

    #[test]
    fn classify_syn_dropped_but_alive_via_proxy_is_syn_blocked() {
        // Direct SYN never answered, yet the IP serves through a proxy: the SYN is
        // dropped on this path while the host is alive. Fixable by changing egress.
        assert_eq!(
            BlockType::classify(true, false, false, Some(true)),
            BlockType::SynBlocked
        );
    }

    #[test]
    fn classify_unreachable_everywhere_is_host_dead() {
        assert_eq!(
            BlockType::classify(true, false, false, Some(false)),
            BlockType::HostDead
        );
    }

    #[test]
    fn classify_direct_fail_without_proxy_stays_ip_blocked() {
        assert_eq!(
            BlockType::classify(true, false, false, None),
            BlockType::IpBlocked
        );
    }
}
