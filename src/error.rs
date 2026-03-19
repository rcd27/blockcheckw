use std::fmt;

#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockcheckError {
    #[error("nftables command failed: {command}\nstderr: {stderr}")]
    Nftables { command: String, stderr: String },

    #[error("cannot parse nft rule handle from output: {output}")]
    NftHandleParse { output: String },

    #[error("nfqws2 start failed: {reason}")]
    Nfqws2Start { reason: String },

    #[error("nfqws2 crashed during test")]
    Nfqws2Crashed,

    #[error("failed to spawn process: {reason}")]
    ProcessSpawn { reason: String },

    #[error("process timed out after {timeout_ms}ms")]
    ProcessTimeout { timeout_ms: u64 },

    #[error("DNS resolve failed for {domain}: {reason}")]
    DnsResolveFailed { domain: String, reason: String },

    #[error("no IPv4 addresses found for {domain}")]
    DnsNoAddresses { domain: String },
}

#[derive(Debug)]
pub enum TaskResult {
    Success {
        verdict: CurlVerdictAvailable,
        strategy_args: Vec<String>,
    },
    Failed {
        verdict: super::network::curl::CurlVerdict,
    },
    Error {
        error: BlockcheckError,
    },
}

#[derive(Debug)]
pub struct CurlVerdictAvailable;

impl fmt::Display for TaskResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskResult::Success { .. } => write!(f, "!!!!! AVAILABLE !!!!!"),
            TaskResult::Failed { verdict } => write!(f, "{verdict}"),
            TaskResult::Error { error } => write!(f, "ERROR: {error}"),
        }
    }
}
