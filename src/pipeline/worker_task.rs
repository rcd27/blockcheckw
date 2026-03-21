use crate::config::{CoreConfig, Protocol, NFQWS2_INIT_DELAY_MS};
use crate::error::{BlockcheckError, HttpVerdictAvailable, TaskResult};
use crate::firewall::nftables;
use crate::network::http_client::{
    http_test, http_test_data, interpret_data_transfer_result, interpret_http_result,
    pick_random_ip, HttpVerdict,
};
use crate::worker::nfqws2::start_nfqws2;
use crate::worker::slot::WorkerSlot;

#[derive(Debug, Clone, Copy, Default)]
pub enum HttpTestMode {
    /// Standard mode: HEAD for HTTPS, GET for HTTP
    #[default]
    Standard,
    /// Data transfer mode: GET with size_download check
    DataTransfer { min_bytes: u64 },
}

#[derive(Debug)]
pub struct WorkerTask {
    pub slot: WorkerSlot,
    pub domain: String,
    pub strategy_args: Vec<String>,
    pub protocol: Protocol,
    pub ips: Vec<String>,
}

/// Execute a full worker task cycle with standard mode.
pub async fn execute_worker_task(config: &CoreConfig, task: &WorkerTask) -> TaskResult {
    execute_worker_task_with_mode(config, task, HttpTestMode::Standard).await
}

/// Execute a full worker task cycle:
/// 1. Start nfqws2 (listener FIRST — packets hitting NFQUEUE without a listener are dropped)
/// 2. Sleep for init delay (wait for nfqws2 to bind to NFQUEUE)
/// 3. Add outgoing nftables rule (postnat)
/// 4. Add incoming SYN,ACK nftables rule (prenat, for autottl)
/// 5. Run HTTP test with SO_MARK on socket (pre-connect)
/// 6. Interpret result
/// 7. Cleanup: remove rules FIRST, then kill nfqws2
pub async fn execute_worker_task_with_mode(
    config: &CoreConfig,
    task: &WorkerTask,
    mode: HttpTestMode,
) -> TaskResult {
    // Step 1: Start nfqws2 FIRST — must be listening before rules direct packets to NFQUEUE
    let mut nfqws2_process = match start_nfqws2(config, task.slot.qnum, &task.strategy_args) {
        Ok(p) => p,
        Err(e) => {
            return TaskResult::Error { error: e };
        }
    };

    // Step 2: Wait for nfqws2 to bind to NFQUEUE
    tokio::time::sleep(std::time::Duration::from_millis(NFQWS2_INIT_DELAY_MS)).await;

    // Step 3: Add outgoing nftables rule (postnat)
    let postnat_handle = match nftables::add_worker_rule(
        &config.nft_table,
        task.slot.fwmark,
        task.protocol.port(),
        task.slot.qnum,
        &task.ips,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            nfqws2_process.kill().await;
            return TaskResult::Error { error: e };
        }
    };

    // Step 4: Add incoming SYN,ACK rule (prenat)
    let prenat_handle = match nftables::add_incoming_rule(
        &config.nft_table,
        task.slot.fwmark,
        task.protocol.port(),
        task.slot.qnum,
        &task.ips,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            let _ = nftables::remove_rule(&config.nft_table, postnat_handle).await;
            nfqws2_process.kill().await;
            return TaskResult::Error { error: e };
        }
    };

    // Step 5-6: HTTP test with marked socket, interpret result
    let ip = match pick_random_ip(&task.ips) {
        Some(ip) => ip,
        None => {
            let _ = nftables::remove_worker_rules(&config.nft_table, postnat_handle, prenat_handle)
                .await;
            nfqws2_process.kill().await;
            return TaskResult::Error {
                error: BlockcheckError::DnsNoAddresses {
                    domain: task.domain.clone(),
                },
            };
        }
    };

    let verdict = match mode {
        HttpTestMode::Standard => {
            let result = http_test(
                task.protocol,
                &task.domain,
                ip,
                task.slot.fwmark,
                config.request_timeout,
            )
            .await;
            interpret_http_result(&result, &task.domain)
        }
        HttpTestMode::DataTransfer { min_bytes } => {
            let result = http_test_data(
                task.protocol,
                &task.domain,
                ip,
                task.slot.fwmark,
                config.request_timeout,
                0, // unlimited
            )
            .await;
            interpret_data_transfer_result(&result, &task.domain, min_bytes)
        }
    };

    let result = match verdict {
        HttpVerdict::Available => TaskResult::Success {
            verdict: HttpVerdictAvailable,
            strategy_args: task.strategy_args.clone(),
        },
        other => TaskResult::Failed { verdict: other },
    };

    // Step 7: Cleanup — remove rules FIRST (stop intercepting), then kill nfqws2
    let _ = nftables::remove_worker_rules(&config.nft_table, postnat_handle, prenat_handle).await;
    nfqws2_process.kill().await;

    result
}

/// Execute a worker task assuming nftables rules are already in place.
/// Only starts/kills nfqws2 and runs the HTTP test.
/// Used when rules are managed at the batch level (not per-strategy).
pub async fn execute_worker_task_rules_ready(
    config: &CoreConfig,
    task: &WorkerTask,
    mode: HttpTestMode,
) -> TaskResult {
    // Start nfqws2
    let mut nfqws2_process = match start_nfqws2(config, task.slot.qnum, &task.strategy_args) {
        Ok(p) => p,
        Err(e) => {
            return TaskResult::Error { error: e };
        }
    };

    // Wait for nfqws2 to bind to NFQUEUE
    tokio::time::sleep(std::time::Duration::from_millis(NFQWS2_INIT_DELAY_MS)).await;

    // HTTP test with marked socket
    let ip = match pick_random_ip(&task.ips) {
        Some(ip) => ip,
        None => {
            nfqws2_process.kill().await;
            return TaskResult::Error {
                error: BlockcheckError::DnsNoAddresses {
                    domain: task.domain.clone(),
                },
            };
        }
    };

    let verdict = match mode {
        HttpTestMode::Standard => {
            let result = http_test(
                task.protocol,
                &task.domain,
                ip,
                task.slot.fwmark,
                config.request_timeout,
            )
            .await;
            interpret_http_result(&result, &task.domain)
        }
        HttpTestMode::DataTransfer { min_bytes } => {
            let result = http_test_data(
                task.protocol,
                &task.domain,
                ip,
                task.slot.fwmark,
                config.request_timeout,
                0, // unlimited
            )
            .await;
            interpret_data_transfer_result(&result, &task.domain, min_bytes)
        }
    };

    nfqws2_process.kill().await;

    match verdict {
        HttpVerdict::Available => TaskResult::Success {
            verdict: HttpVerdictAvailable,
            strategy_args: task.strategy_args.clone(),
        },
        other => TaskResult::Failed { verdict: other },
    }
}
