use serde::{Deserialize, Serialize};

/// Universal strategy entry — the interchange format between commands.
/// scan → check, universal → check, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyEntry {
    pub protocol: String,
    pub args: String,
    /// Domain coverage: 1 for scan/vanilla, N for universal.
    pub coverage: usize,
}

/// Per-protocol scan results for JSON report.
#[derive(Debug, Serialize)]
pub struct ScanProtocolResult {
    pub protocol: String,
    pub total: usize,
    pub strategies: Vec<String>,
}

/// Full scan output document (JSON).
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
