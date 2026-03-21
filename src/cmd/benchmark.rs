use blockcheckw::config::CoreConfig;
use blockcheckw::pipeline::benchmark;

use super::handle_bypass_conflicts;

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
    if !handle_bypass_conflicts(&config.nft_table).await {
        std::process::exit(1);
    }

    let max = max_workers.unwrap_or_else(benchmark::default_max_workers);
    benchmark::run_benchmark(time, max, raw, domain, protocol).await;
}
