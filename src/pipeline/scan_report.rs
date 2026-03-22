use serde::Serialize;

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
}
