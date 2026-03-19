use crate::config::{CoreConfig, Protocol, NFQWS2_INIT_DELAY_MS};
use crate::error::{CurlVerdictAvailable, TaskResult};
use crate::firewall::nftables;
use crate::network::curl::{curl_test, interpret_curl_result, pick_random_ip, CurlVerdict};
use crate::worker::nfqws2::start_nfqws2;
use crate::worker::slot::WorkerSlot;

#[derive(Debug)]
pub struct WorkerTask {
    pub slot: WorkerSlot,
    pub domain: String,
    pub strategy_args: Vec<String>,
    pub protocol: Protocol,
    pub ips: Vec<String>,
}

/// Execute a full worker task cycle:
/// 1. Start nfqws2 (listener FIRST — packets hitting NFQUEUE without a listener are dropped)
/// 2. Sleep for init delay (wait for nfqws2 to bind to NFQUEUE)
/// 3. Add outgoing nftables rule (postnat)
/// 4. Add incoming SYN,ACK nftables rule (prenat, for autottl)
/// 5. Run curl test
/// 6. Interpret result
/// 7. Cleanup: remove rules FIRST, then kill nfqws2
pub async fn execute_worker_task(config: &CoreConfig, task: &WorkerTask) -> TaskResult {
    // Step 1: Start nfqws2 FIRST — must be listening before rules direct packets to NFQUEUE
    let mut nfqws2_process = match start_nfqws2(config, task.slot.qnum, &task.strategy_args) {
        Ok(p) => p,
        Err(e) => {
            return TaskResult::Error { error: e };
        }
    };

    // Step 2: Wait for nfqws2 to bind to NFQUEUE
    tokio::time::sleep(std::time::Duration::from_millis(NFQWS2_INIT_DELAY_MS)).await;

    // Step 3: Add outgoing nftables rule (postnat) — listener is ready
    let postnat_handle = match nftables::add_worker_rule(
        &config.nft_table,
        &task.slot.sport_range(),
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

    // Step 4: Add incoming SYN,ACK rule (prenat, for autottl) — listener is ready
    let prenat_handle = match nftables::add_incoming_rule(
        &config.nft_table,
        &task.slot.sport_range(),
        task.protocol.port(),
        task.slot.qnum,
        &task.ips,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            // Cleanup postnat rule + kill nfqws2
            let _ = nftables::remove_rule(&config.nft_table, postnat_handle).await;
            nfqws2_process.kill().await;
            return TaskResult::Error { error: e };
        }
    };

    // Step 5-6: curl test + interpret result
    let local_port = task.slot.local_port_arg();
    let ip = pick_random_ip(&task.ips);
    let curl_result = curl_test(
        task.protocol,
        &task.domain,
        Some(&local_port),
        &config.curl_max_time,
        ip,
    )
    .await;

    let verdict = interpret_curl_result(&curl_result, &task.domain);

    let result = match verdict {
        CurlVerdict::Available => TaskResult::Success {
            verdict: CurlVerdictAvailable,
            strategy_args: task.strategy_args.clone(),
        },
        other => TaskResult::Failed { verdict: other },
    };

    // Step 7: Cleanup — remove rules FIRST (stop intercepting), then kill nfqws2
    let _ = nftables::remove_rule(&config.nft_table, postnat_handle).await;
    let _ = nftables::remove_prenat_rule(&config.nft_table, prenat_handle).await;
    nfqws2_process.kill().await;

    result
}
