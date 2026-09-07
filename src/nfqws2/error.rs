#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("nfqws2 failed to start: {reason}")]
    Spawn { reason: String },

    #[error("nfqws2 exited immediately (code {code}): {stderr}")]
    ExitedImmediately { code: i32, stderr: String },

    #[error("nfqws2 did not bind queue {queue} within {timeout_ms}ms: {stderr}")]
    QueueNotBound {
        queue: u16,
        timeout_ms: u64,
        stderr: String,
    },

    #[error("nfqws2 --help timed out after {timeout_ms}ms")]
    ProbeTimeout { timeout_ms: u64 },

    #[error(
        "queue {queue} is already in use by another process: find and stop it \
         (check `cat /proc/net/netfilter/nfnetlink_queue`)"
    )]
    QueueBusy { queue: u16 },

    #[error("nfqws2 does not support --filter-mark: requires build >= v1.0.5")]
    NoFilterMark,

    #[error("lua scripts from a different zapret2 version: update {lua_dir}")]
    LuaVersionMismatch { lua_dir: String },
}
