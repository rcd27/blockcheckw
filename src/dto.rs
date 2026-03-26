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
    pub total: usize,
    pub working: usize,
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
