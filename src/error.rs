use std::fmt;

#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockcheckError {
    #[error("nftables command failed: {command}\nstderr: {stderr}")]
    Nftables { command: String, stderr: String },

    #[error("nfqws2 start failed: {reason}")]
    Nfqws2Start { reason: String },

    #[error(
        "queue {queue} is already in use by another process: find and stop it \
         (check `cat /proc/net/netfilter/nfnetlink_queue`)"
    )]
    Nfqws2QueueBusy { queue: u16 },

    #[error("nfqws2 is incompatible with this build of blockcheckw: {reason}")]
    Nfqws2Incompatible { reason: String },

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

    #[error("strategies file is empty (no valid strategy lines found)")]
    StrategiesFileEmpty,

    #[error("HTTP client build failed: {reason}")]
    HttpClientBuild { reason: String },

    #[error(
        "readiness witness was issued for queue {witnessed}, but rules target queue {requested}"
    )]
    QueueWitnessMismatch { witnessed: u16, requested: u16 },

    #[error("invalid parallelism configuration: {reason}")]
    InvalidConfig { reason: String },

    #[error("probe task did not complete: {reason}")]
    TaskJoin { reason: String },
}

impl From<crate::nfqws2::Error> for BlockcheckError {
    fn from(e: crate::nfqws2::Error) -> Self {
        use crate::nfqws2::Error as E;
        match e {
            E::QueueBusy { queue } => BlockcheckError::Nfqws2QueueBusy { queue },
            E::NoFilterMark | E::LuaVersionMismatch { .. } => BlockcheckError::Nfqws2Incompatible {
                reason: e.to_string(),
            },
            other => BlockcheckError::Nfqws2Start {
                reason: other.to_string(),
            },
        }
    }
}

#[derive(Debug)]
pub enum TaskResult {
    Success {
        verdict: HttpVerdictAvailable,
        strategy_args: Vec<String>,
    },
    Failed {
        verdict: super::network::http_client::HttpVerdict,
    },
    Error {
        error: BlockcheckError,
    },
}

#[derive(Debug)]
pub struct HttpVerdictAvailable;

impl fmt::Display for TaskResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskResult::Success { .. } => write!(f, "!!!!! AVAILABLE !!!!!"),
            TaskResult::Failed { verdict } => write!(f, "{verdict}"),
            TaskResult::Error { error } => write!(f, "ERROR: {error}"),
        }
    }
}
