use blockcheckw::config::CoreConfig;
use blockcheckw::pipeline::benchmark;
use blockcheckw::ui;

use super::{handle_bypass_conflicts, restore_service};

pub async fn run_benchmark_cmd(
    time: u64,
    max_workers: Option<u16>,
    domain: &str,
    protocol: &str,
    raw: bool,
) {
    let con = ui::Console::new();

    let protocol = match blockcheckw::config::parse_protocols(protocol) {
        Ok(p) => p[0],
        Err(e) => {
            con.error(&e.to_string());
            std::process::exit(1);
        }
    };

    let config = CoreConfig::default();
    let stopped = match handle_bypass_conflicts(&config.nft_table, &con).await {
        Ok(result) => result,
        Err(()) => std::process::exit(1),
    };
    let (stopped_service, nft_backup) = match stopped {
        Some((mgr, backup)) => (Some(mgr), backup),
        None => (None, None),
    };

    let max = max_workers
        .map(|w| w as usize)
        .unwrap_or_else(benchmark::default_max_workers);
    let raw = raw || !console::Term::stderr().is_term();
    benchmark::run_benchmark(time, max, raw, domain, protocol).await;

    // Restore zapret2 if we stopped it
    if let Some(ref mgr) = stopped_service {
        restore_service(mgr, &nft_backup, &con).await;
    }
}
