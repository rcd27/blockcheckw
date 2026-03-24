use std::collections::HashMap;
use std::sync::Arc;

use console::style;

use blockcheckw::config::{CoreConfig, DnsMode, Protocol};
use blockcheckw::error::TaskResult;
use blockcheckw::network::dns;
use blockcheckw::pipeline::report::{self, UniversalProtocolData};
use blockcheckw::pipeline::runner::{run_parallel, RunParams};
use blockcheckw::pipeline::worker_task::HttpTestMode;
use blockcheckw::strategy::generator;
use blockcheckw::ui;

use super::{
    handle_bypass_conflicts, restore_service, set_nft_backup, set_stopped_service,
    spawn_cleanup_handler,
};

/// Load domain list from file, filtering out invalid entries.
fn load_domain_list(path: &str) -> Result<Vec<String>, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let domains: Vec<String> = data
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !l.starts_with('.')) // skip TLD masks like ".ua"
        .filter(|l| l.contains('.')) // must have at least one dot
        .map(String::from)
        .collect();
    if domains.is_empty() {
        return Err(format!("no valid domains found in {path}"));
    }
    Ok(domains)
}

/// Simple deterministic shuffle (Fisher-Yates with LCG PRNG seeded from system time).
fn shuffle(domains: &[String]) -> Vec<String> {
    let mut result: Vec<String> = domains.to_vec();
    let mut rng = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    for i in (1..result.len()).rev() {
        // LCG step
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (rng >> 33) as usize % (i + 1);
        result.swap(i, j);
    }
    result
}

pub async fn run_universal(
    workers: usize,
    domain_list: &str,
    protocols: &[Protocol],
    dns_mode: DnsMode,
    sample: usize,
    output: Option<&str>,
) {
    let config = Arc::new(CoreConfig {
        worker_count: workers,
        ..CoreConfig::default()
    });

    let cleanup = spawn_cleanup_handler(&config.nft_table);

    let mut screen = ui::Console::new();

    // Load domain list
    let all_domains = match load_domain_list(domain_list) {
        Ok(d) => d,
        Err(e) => {
            screen.error(&e.to_string());
            std::process::exit(1);
        }
    };

    screen.println(&format!(
        "{} {} domains from {}, target sample {}",
        style("universal").bold().cyan(),
        style(all_domains.len()).bold(),
        style(domain_list).cyan(),
        style(sample).bold(),
    ));

    // Check for conflicts
    let stopped = match handle_bypass_conflicts(&config.nft_table, &screen).await {
        Ok(result) => result,
        Err(()) => std::process::exit(1),
    };
    let (stopped_service, nft_backup) = match stopped {
        Some((mgr, backup)) => {
            set_stopped_service(&cleanup, mgr.clone()).await;
            set_nft_backup(&cleanup, backup.clone()).await;
            (Some(mgr), backup)
        }
        None => (None, None),
    };

    // Shuffle domain list for random sampling
    let candidates = shuffle(&all_domains);

    // Full brute-force scan per protocol
    let mut results: Vec<UniversalProtocolData> = Vec::new();

    for &protocol in protocols {
        screen.newline();
        screen.println(&ui::section(&format!("Universal scan ({protocol})")));

        let corpus = generator::generate_strategies(protocol);
        screen.println(&format!(
            "  corpus: {} strategies, target: {} domains, workers={}",
            style(corpus.len()).bold(),
            style(sample).bold(),
            style(config.worker_count).bold(),
        ));

        let mut hits: HashMap<String, usize> = HashMap::new();
        let mut tested_domains: Vec<String> = Vec::new();
        let mut excluded_domains: Vec<String> = Vec::new();

        screen.add_info_line(&format!("  domains: 0/{sample} tested, 0 excluded"));

        for domain in &candidates {
            if tested_domains.len() >= sample {
                break;
            }

            // Resolve
            let ips = match dns::resolve_domain(domain, dns_mode).await {
                Ok(r) => r.ips,
                Err(_) => {
                    excluded_domains.push(domain.to_string());
                    screen.update_info_line(&format!(
                        "  domains: {}/{sample} tested, {} excluded",
                        tested_domains.len(),
                        excluded_domains.len(),
                    ));
                    continue;
                }
            };

            screen.begin_progress_with_prefix(corpus.len() as u64, domain);

            let (scan_results, _stats) = run_parallel(RunParams {
                config: &config,
                domain,
                protocol,
                strategies: &corpus,
                ips: &ips,
                multi: Some(screen.multi()),
                external_pb: Some(screen.pb()),
                mode: HttpTestMode::Standard,
                deadline: None,
            })
            .await;

            screen.finish_progress();

            let working: Vec<&Vec<String>> = scan_results
                .iter()
                .filter(|r| matches!(r.result, TaskResult::Success { .. }))
                .map(|r| &r.strategy_args)
                .collect();

            if working.is_empty() {
                excluded_domains.push(domain.to_string());
                screen.update_info_line(&format!(
                    "  domains: {}/{sample} tested, {} excluded",
                    tested_domains.len(),
                    excluded_domains.len(),
                ));
                continue;
            }

            tested_domains.push(domain.to_string());
            screen.update_info_line(&format!(
                "  domains: {}/{sample} tested, {} excluded",
                tested_domains.len(),
                excluded_domains.len(),
            ));

            for args in &working {
                *hits.entry(args.join(" ")).or_insert(0) += 1;
            }
        }

        screen.finish_info();

        if tested_domains.is_empty() {
            screen.println(&format!(
                "  {}",
                style("no domains with working strategies").yellow()
            ));
            results.push(UniversalProtocolData {
                protocol,
                strategies: vec![],
                tested_domains,
                excluded_domains,
            });
            continue;
        }

        // Sort by coverage descending
        let ranked = report::rank_by_coverage(hits);

        screen.println(&format!(
            "  Result: {} strategies across {} domains ({} excluded)",
            style(ranked.len()).bold(),
            style(tested_domains.len()).green(),
            excluded_domains.len(),
        ));

        results.push(UniversalProtocolData {
            protocol,
            strategies: ranked,
            tested_domains,
            excluded_domains,
        });
    }

    // Summary
    screen.newline();
    screen.println(&ui::section("Universal scan summary"));

    for res in &results {
        let tested = res.tested_domains.len();
        if res.strategies.is_empty() {
            screen.println(&format!(
                "  {}: {}",
                res.protocol,
                style("no strategies found").red(),
            ));
        } else {
            let best_hits = res.strategies.first().map(|(_, c)| *c).unwrap_or(0);
            let perfect_count = res.strategies.iter().filter(|(_, c)| *c == tested).count();
            screen.println(&format!(
                "  {}: {} strategies, best coverage {}/{} domains, {} with 100%",
                res.protocol,
                style(res.strategies.len()).bold(),
                style(best_hits).green().bold(),
                tested,
                style(perfect_count).green().bold(),
            ));
        }
    }

    // Save report
    let report = report::build_universal_report(sample, &results);
    let json = serde_json::to_string_pretty(&report).expect("report serialization");

    // Save artifacts BEFORE writing to stdout — stdout may break (pipe closed)
    let path = output.map(String::from).unwrap_or_else(|| {
        let prefix = super::chrono_local_prefix();
        format!("{prefix}_universal.json")
    });

    match std::fs::write(&path, &json) {
        Ok(()) => {
            blockcheckw::system::elevate::chown_to_caller(&path);
            screen.println(&format!(
                "  {} JSON report → {}",
                style("OK").green().bold(),
                style(&path).cyan(),
            ));
        }
        Err(e) => {
            screen.println(&format!(
                "  {} failed to write report: {e}",
                style("ERROR:").red().bold(),
            ));
        }
    }

    // Save cleaned domain list (original minus all excluded domains)
    if let Some(cleaned) = report::build_cleaned_domain_list(&all_domains, &results) {
        let base = domain_list.strip_suffix(".cleaned").unwrap_or(domain_list);
        let cleaned_path = format!("{base}.cleaned");
        let excluded_count = results
            .iter()
            .flat_map(|r| &r.excluded_domains)
            .collect::<std::collections::HashSet<_>>()
            .len();
        match std::fs::write(&cleaned_path, &cleaned) {
            Ok(()) => {
                blockcheckw::system::elevate::chown_to_caller(&cleaned_path);
                screen.println(&format!(
                    "  {} cleaned domain list ({} excluded) → {}",
                    style("OK").green().bold(),
                    excluded_count,
                    style(&cleaned_path).cyan(),
                ));
            }
            Err(e) => {
                screen.println(&format!(
                    "  {} failed to write cleaned list: {e}",
                    style("ERROR:").red().bold(),
                ));
            }
        }
    }

    // JSON to stdout (for pipe support) — after artifacts are saved
    super::print_stdout_graceful(&json, &screen);
    screen.newline();

    // Hint for next step
    let has_strategies = results.iter().any(|r| !r.strategies.is_empty());
    if has_strategies {
        let example_domain = results
            .iter()
            .find_map(|r| r.tested_domains.first())
            .map(|s| s.as_str())
            .unwrap_or("<domain>");
        screen.println(&format!(
            "\n{}\n",
            style(format!(
                ">>> Next step: sudo blockcheckw check --from-file {path} -d {example_domain} <<<"
            ))
            .yellow()
            .bold()
        ));
    }

    // Restore zapret2
    if let Some(ref mgr) = stopped_service {
        restore_service(mgr, &nft_backup, &screen).await;
    }
}
