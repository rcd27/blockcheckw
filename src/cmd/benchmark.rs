use blockcheckw::config::CoreConfig;
use blockcheckw::pipeline::benchmark;

use super::{handle_bypass_conflicts, restore_service};

pub async fn run_benchmark_cmd(
    time: u64,
    max_workers: Option<usize>,
    domain: &str,
    protocol: &str,
    raw: bool,
) {
    let protocol = match blockcheckw::config::parse_protocols(protocol) {
        Ok(p) => p[0],
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    };

    let config = CoreConfig::default();
    let stopped_service = match handle_bypass_conflicts(&config.nft_table).await {
        Ok(svc) => svc,
        Err(()) => std::process::exit(1),
    };

    let max = max_workers.unwrap_or_else(benchmark::default_max_workers);
    benchmark::run_benchmark(time, max, raw, domain, protocol).await;

    // Restore zapret2 if we stopped it
    if let Some(ref mgr) = stopped_service {
        restore_service(mgr).await;
    }
}
