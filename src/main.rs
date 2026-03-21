use std::sync::Arc;

use clap::{CommandFactory, Parser, Subcommand};
use console::style;
use tokio::signal;
use tracing::info;

use blockcheckw::config::{CoreConfig, DnsMode, Protocol};
use blockcheckw::error::TaskResult;
use blockcheckw::firewall::nftables;
use blockcheckw::network::dns::DnsSpoofResult;
use blockcheckw::network::{dns, isp};
use blockcheckw::pipeline::baseline;
use blockcheckw::pipeline::benchmark;
use blockcheckw::pipeline::check;
use blockcheckw::pipeline::runner::run_parallel;
use blockcheckw::pipeline::test_report;
use blockcheckw::pipeline::worker_task::HttpTestMode;
use blockcheckw::strategy::{generator, rank};
use blockcheckw::ui;

const fn help_styles() -> clap::builder::styling::Styles {
    use clap::builder::styling::{AnsiColor, Color, Style, Styles};

    Styles::styled()
        .header(
            Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow)))
                .bold()
                .underline(),
        )
        .usage(
            Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow)))
                .bold(),
        )
        .literal(
            Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Green)))
                .bold(),
        )
        .placeholder(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))))
}

#[derive(Parser)]
#[command(
    name = "blockcheckw",
    about = "Parallel DPI bypass strategy scanner",
    styles = help_styles(),
)]
struct Cli {
    /// Number of parallel workers
    #[arg(short, long, default_value_t = 8)]
    workers: usize,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run parallel scaling benchmark to find optimal worker count
    Benchmark {
        /// Seconds to run per worker-count level
        #[arg(short, long, default_value_t = 30)]
        time: u64,

        /// Maximum number of workers to test
        #[arg(short = 'M', long)]
        max_workers: Option<usize>,

        /// Target domain
        #[arg(short, long, default_value = "rutracker.org")]
        domain: String,

        /// Protocol to benchmark (http, tls12, tls13)
        #[arg(short, long, default_value = "tls12")]
        protocol: String,

        /// Raw output: table only, no recommendation (for scripts)
        #[arg(long)]
        raw: bool,
    },

    /// Generate shell completions (prints to stdout, or installs with --install)
    Completions {
        /// Shell to generate completions for (auto-detected if omitted)
        #[arg(value_enum)]
        shell: Option<clap_complete::Shell>,

        /// Install completions into the appropriate system directory
        #[arg(long)]
        install: bool,
    },

    /// Check strategies from a vanilla report with real data transfer
    Check {
        /// Path to vanilla report file (curl_test_* format)
        #[arg(long)]
        from_file: String,

        /// Target domain to check
        #[arg(short, long, default_value = "rutracker.org")]
        domain: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Request timeout per strategy in seconds
        #[arg(long, default_value_t = 6)]
        timeout: u64,

        /// Stop after finding N working strategies (0 = check all)
        #[arg(long, default_value_t = 0)]
        take: usize,

        /// Verification passes per working strategy in Phase 2 (0 or 1 = skip Phase 2)
        #[arg(long, default_value_t = 3)]
        passes: usize,

        /// Save JSON report to file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Scan domain for working DPI bypass strategies
    Scan {
        /// Target domain to check
        #[arg(short, long, default_value = "rutracker.org")]
        domain: String,

        /// Protocols to test (comma-separated: http,tls12,tls13)
        #[arg(short, long, default_value = "http,tls12,tls13")]
        protocols: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Overall scan timeout in seconds (0 = no limit)
        #[arg(long, default_value_t = 0)]
        timeout: u64,

        /// Show top N ranked strategies per protocol (0 = all)
        #[arg(long, default_value_t = 5)]
        top: usize,

        /// Save found strategies to file
        #[arg(short, long)]
        output: Option<String>,

        /// Load strategies from file instead of using built-in corpus
        #[arg(long)]
        from_file: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    // Panic hook: cleanup nftables table on panic (async runtime may be dead, use sync Command)
    // FIXME: if nft hangs, the process will hang forever (no timeout on sync Command)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", "zapret"])
            .output();
        default_hook(info);
    }));

    let cli = Cli::parse();

    // Completions don't need root — handle before elevation
    if let Some(Command::Completions { shell, install }) = &cli.command {
        let shell = shell.unwrap_or_else(|| {
            detect_shell().unwrap_or_else(|| {
                eprintln!(
                    "Could not detect shell. Specify it explicitly: blockcheckw completions bash"
                );
                std::process::exit(1);
            })
        });

        if *install {
            install_completions(shell);
        } else {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "blockcheckw",
                &mut std::io::stdout(),
            );
        }
        return;
    }

    blockcheckw::system::elevate::require_root();
    blockcheckw::system::elevate::tune_tcp();
    blockcheckw::system::elevate::raise_nofile_limit();

    match cli.command {
        Some(Command::Benchmark {
            time,
            max_workers,
            domain,
            protocol,
            raw,
        }) => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                .init();

            let protocol = match blockcheckw::config::parse_protocols(&protocol) {
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
            benchmark::run_benchmark(time, max, raw, &domain, protocol).await;
        }
        Some(Command::Check {
            from_file,
            domain,
            dns,
            timeout,
            take,
            passes,
            output,
        }) => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                .init();

            let dns_mode = match blockcheckw::config::parse_dns_mode(&dns) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };

            run_check_cmd(
                &domain,
                &from_file,
                dns_mode,
                timeout,
                take,
                passes,
                output.as_deref(),
            )
            .await;
        }
        Some(Command::Scan {
            domain,
            protocols,
            dns,
            timeout,
            top,
            output,
            from_file,
        }) => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                .init();

            let protocols = match blockcheckw::config::parse_protocols(&protocols) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };
            let dns_mode = match blockcheckw::config::parse_dns_mode(&dns) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };
            run_scan(
                cli.workers,
                &domain,
                &protocols,
                dns_mode,
                timeout,
                top,
                output.as_deref(),
                from_file.as_deref(),
            )
            .await;
        }
        Some(Command::Completions { .. }) => unreachable!("handled above"),
        None => run_default(cli.workers).await,
    }
}

// TODO: run_scan and conflict detection logic should be extracted from main.rs into a
// library module so they can be unit-tested and reused
#[allow(clippy::too_many_arguments)]
async fn run_scan(
    workers: usize,
    domain: &str,
    protocols: &[Protocol],
    dns_mode: DnsMode,
    timeout_secs: u64,
    top_n: usize,
    output: Option<&str>,
    from_file: Option<&str>,
) {
    let config = Arc::new(CoreConfig {
        worker_count: workers,
        ..CoreConfig::default()
    });

    // Signal handler: cleanup nftables on Ctrl+C
    // FIXME: handler fires only once; a second Ctrl+C won't be caught.
    // Also, process::exit(130) may skip Drop impls for running nfqws2 processes.
    let cleanup_config = config.clone();
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            eprintln!("\nCtrl+C received, cleaning up...");
            nftables::drop_table(&cleanup_config.nft_table).await;
            std::process::exit(130);
        }
    });

    let mut screen = ui::ScanScreen::new();

    // 0. ISP info
    if let Some(info) = isp::detect_ip_info().await {
        screen.add_info_line(&format!("  ISP: {info}"));
    }

    // 1. DNS resolve
    screen.println(&ui::section("DNS resolve"));
    screen.println(&format!(
        "  dns mode: {}",
        style(dns_mode.to_string()).bold()
    ));
    let ips = match dns::resolve_domain(domain, dns_mode).await {
        Ok(resolution) => {
            screen.println(&format!(
                "  {} {} {} (via {})",
                domain,
                ui::ARROW,
                style(resolution.ips.join(", ")).bold(),
                resolution.method,
            ));

            // Show spoofing check result in output and info bar
            if let Some(ref spoof) = resolution.spoof_result {
                match spoof {
                    DnsSpoofResult::Clean => {
                        screen.println(&format!(
                            "  {}DNS spoofing check: {}",
                            ui::CHECKMARK,
                            style("clean").green(),
                        ));
                    }
                    DnsSpoofResult::Spoofed { details } => {
                        screen.println(&format!(
                            "  {}DNS spoofing detected: {}",
                            ui::WARN,
                            style(details).yellow().bold(),
                        ));
                    }
                    DnsSpoofResult::CheckFailed { reason } => {
                        screen.println(&format!(
                            "  {}DNS spoofing check failed: {}",
                            ui::WARN,
                            style(reason).yellow(),
                        ));
                    }
                }
            }

            // Add DNS info to status bar
            let dns_status = ui::dns_info_line(
                domain,
                &resolution.ips,
                resolution.method,
                &resolution.spoof_result,
            );
            screen.add_info_line(&dns_status);

            resolution.ips
        }
        Err(e) => {
            eprintln!("{} {e}", style("ERROR:").red().bold());
            std::process::exit(1);
        }
    };

    // 1b. Check for conflicting DPI bypass processes
    if !handle_bypass_conflicts(&config.nft_table).await {
        std::process::exit(1);
    }

    // 2. Baseline per protocol
    screen.newline();
    screen.println(&ui::section("Baseline (without bypass)"));
    let mut blocked_protocols = Vec::new();

    for &protocol in protocols {
        let result = baseline::test_baseline(domain, protocol, config.request_timeout, &ips).await;
        screen.println(&baseline::format_baseline_verdict_styled(&result));
        if result.is_blocked() {
            blocked_protocols.push(protocol);
        }
    }

    if blocked_protocols.is_empty() {
        screen.newline();
        screen.println(&format!(
            "{}",
            style("All protocols are available without bypass. Nothing to scan.").green()
        ));
        return;
    }

    let blocked_names: Vec<String> = blocked_protocols.iter().map(|p| p.to_string()).collect();
    screen.newline();
    screen.println(&ui::blocked_list(&blocked_names.join(", ")));

    // 3. Scan each blocked protocol
    //                       protocol, strategies,    success, fail,  err,   elapsed
    #[allow(clippy::type_complexity)]
    let mut summary: Vec<(Protocol, Vec<Vec<String>>, usize, usize, usize, f64)> = Vec::new();
    let mut timed_out = false;

    let scan_future = async {
        for &protocol in &blocked_protocols {
            // Re-check for conflicts before each protocol scan
            let conflicts = detect_bypass_conflicts(&config.nft_table).await;
            if !conflicts.is_empty() {
                screen.println(&format!(
                    "  {} {}",
                    style("!").yellow().bold(),
                    style("conflicting DPI bypass restarted, killing again...").yellow(),
                ));
                resolve_bypass_conflicts(&conflicts).await;
            }

            screen.newline();
            screen.println(&ui::section(&format!("Scanning {protocol}")));
            let strategies = if let Some(path) = from_file {
                match generator::load_strategies_from_file(
                    std::path::Path::new(path),
                    Some(protocol),
                ) {
                    Ok(s) => {
                        screen.println(&format!(
                            "  loaded {} strategies from {}, workers={}",
                            style(s.len()).bold(),
                            style(path).cyan(),
                            style(config.worker_count).bold()
                        ));
                        s
                    }
                    Err(e) => {
                        screen.println(&format!(
                            "  {} failed to read {}: {e}",
                            style("ERROR:").red().bold(),
                            style(path).cyan(),
                        ));
                        continue;
                    }
                }
            } else {
                let s = generator::generate_strategies(protocol);
                screen.println(&format!(
                    "  {} strategies, workers={}",
                    style(s.len()).bold(),
                    style(config.worker_count).bold()
                ));
                s
            };

            screen.begin_progress_with_prefix(
                strategies.len() as u64,
                &format!("Scanning {protocol}"),
            );

            let (results, stats) = run_parallel(
                &config,
                domain,
                protocol,
                &strategies,
                &ips,
                Some(screen.multi()),
                Some(screen.pb()),
                HttpTestMode::Standard,
            )
            .await;

            screen.finish_progress();

            let working: Vec<Vec<String>> = results
                .iter()
                .filter(|r| matches!(r.result, TaskResult::Success { .. }))
                .map(|r| r.strategy_args.clone())
                .collect();

            screen.println(&ui::stats_line(
                stats.completed,
                stats.successes,
                stats.failures,
                stats.errors,
                stats.elapsed.as_secs_f64(),
                stats.throughput(),
            ));

            summary.push((
                protocol,
                working,
                stats.successes,
                stats.failures,
                stats.errors,
                stats.elapsed.as_secs_f64(),
            ));
        }
    };

    if timeout_secs > 0 {
        let deadline = std::time::Duration::from_secs(timeout_secs);
        if tokio::time::timeout(deadline, scan_future).await.is_err() {
            timed_out = true;
            nftables::drop_table(&config.nft_table).await;
            screen.newline();
            screen.println(&format!(
                "{} scan timed out after {}s — showing partial results",
                style("WARNING:").yellow().bold(),
                timeout_secs,
            ));
        }
    } else {
        scan_future.await;
    }

    // 4. Summary
    screen.newline();
    screen.println(&ui::section(&format!("Summary for {domain}")));

    if timed_out {
        screen.println(&format!(
            "  {} scan timed out after {}s",
            style("!").yellow().bold(),
            timeout_secs,
        ));
    }

    // Available protocols (not blocked)
    for &protocol in protocols {
        if !blocked_protocols.contains(&protocol) {
            screen.println(&ui::summary_available(&protocol.to_string()));
        }
    }

    // Blocked protocols results (ranked)
    for (protocol, strategies, _successes, _failures, _errors, _elapsed) in &summary {
        let proto = protocol.to_string();
        if strategies.is_empty() {
            screen.println(&ui::summary_no_strategies(&proto));
        } else {
            let ranked = rank::rank_strategies(strategies);
            let total = ranked.len();
            let show = if top_n == 0 || top_n >= total {
                total
            } else {
                top_n
            };

            screen.println(&ui::summary_found(&proto, total));

            screen.println(&ui::top_strategies_header(&proto, show, total));
            for (i, score) in ranked.iter().take(show).enumerate() {
                screen.println(&ui::ranked_strategy_line(i + 1, score));
            }

            if top_n > 0 && total > top_n {
                screen.println(&format!(
                    "  {} (use --top 0 to show all)",
                    style(format!("... and {} more", total - top_n)).dim()
                ));
            }
        }
    }

    // 5. Write strategies to file
    if let Some(path) = output {
        match write_strategies_file(path, domain, &summary) {
            Ok(count) => {
                blockcheckw::system::elevate::chown_to_caller(path);
                screen.println(&format!(
                    "\n  {} {} strategies written to {}",
                    style("OK").green().bold(),
                    count,
                    style(path).cyan(),
                ));
            }
            Err(e) => {
                screen.println(&format!(
                    "\n  {} failed to write {}: {e}",
                    style("ERROR:").red().bold(),
                    style(path).cyan(),
                ));
            }
        }
    }

    // 6. Write reports (always)
    let now = chrono_local_prefix();
    let vanilla_path = format!("{now}_report_vanilla.txt");
    match write_vanilla_report(&vanilla_path, domain, &summary) {
        Ok(count) => {
            blockcheckw::system::elevate::chown_to_caller(&vanilla_path);
            screen.println(&format!(
                "  {} vanilla report: {} strategies → {}",
                style("OK").green().bold(),
                count,
                style(&vanilla_path).cyan(),
            ));
        }
        Err(e) => {
            screen.println(&format!(
                "  {} failed to write vanilla report: {e}",
                style("ERROR:").red().bold(),
            ));
        }
    }

    let ranked_path = format!("{now}_report.txt");
    match write_ranked_report(&ranked_path, domain, &summary) {
        Ok(count) => {
            blockcheckw::system::elevate::chown_to_caller(&ranked_path);
            screen.println(&format!(
                "  {} ranked report: {} strategies → {}",
                style("OK").green().bold(),
                count,
                style(&ranked_path).cyan(),
            ));
        }
        Err(e) => {
            screen.println(&format!(
                "  {} failed to write ranked report: {e}",
                style("ERROR:").red().bold(),
            ));
        }
    }

    screen.finish_info();
}

/// Write ranked report with scores and stars.
#[allow(clippy::type_complexity)]
fn write_ranked_report(
    path: &str,
    domain: &str,
    summary: &[(Protocol, Vec<Vec<String>>, usize, usize, usize, f64)],
) -> std::io::Result<usize> {
    use std::fmt::Write as _;

    let mut buf = String::new();
    let mut total = 0;

    writeln!(buf, "# blockcheckw ranked report for {domain}").unwrap();

    for (protocol, strategies, _, _, _, _) in summary {
        if strategies.is_empty() {
            continue;
        }
        let ranked = rank::rank_strategies(strategies);
        writeln!(buf).unwrap();
        writeln!(buf, "# {protocol} — {} strategies", ranked.len()).unwrap();

        for (i, score) in ranked.iter().enumerate() {
            let stars = match score.stars {
                3 => "***",
                2 => "** ",
                _ => "*  ",
            };
            writeln!(
                buf,
                "#{:<4} {} [score={:>3} perf={:>3} simple={:>3}] nfqws2 {}",
                i + 1,
                stars,
                score.total,
                score.performance,
                score.simplicity,
                score.strategy_args.join(" "),
            )
            .unwrap();
            total += 1;
        }
    }

    std::fs::write(path, buf)?;
    Ok(total)
}

/// Generate a local-time prefix for report filenames: "2026-03-20_18-30"
fn chrono_local_prefix() -> String {
    use std::process::Command;
    // Use `date` for local timezone — no chrono dependency
    let output = Command::new("date").arg("+%Y-%m-%d_%H-%M").output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            // Fallback: UTC epoch-based
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("{secs}")
        }
    }
}

/// Write a vanilla blockcheck2-compatible report.
/// Format: `curl_test_<proto> ipv4 <domain> : nfqws2 <args>`
#[allow(clippy::type_complexity)]
fn write_vanilla_report(
    path: &str,
    domain: &str,
    summary: &[(Protocol, Vec<Vec<String>>, usize, usize, usize, f64)],
) -> std::io::Result<usize> {
    use std::fmt::Write as _;

    let mut buf = String::new();
    let mut total = 0;

    writeln!(buf, "* SUMMARY").unwrap();

    for (protocol, strategies, _, _, _, _) in summary {
        let test_name = match protocol {
            Protocol::Http => "curl_test_http",
            Protocol::HttpsTls12 => "curl_test_https_tls12",
            Protocol::HttpsTls13 => "curl_test_https_tls13",
        };
        for s in strategies {
            writeln!(buf, "{test_name} ipv4 {domain} : nfqws2 {}", s.join(" ")).unwrap();
            total += 1;
        }
    }

    std::fs::write(path, buf)?;
    Ok(total)
}

#[allow(clippy::type_complexity)]
fn write_strategies_file(
    path: &str,
    domain: &str,
    summary: &[(Protocol, Vec<Vec<String>>, usize, usize, usize, f64)],
) -> std::io::Result<usize> {
    use std::fmt::Write as _;

    let timestamp = test_report::chrono_like_timestamp();
    let mut buf = String::new();
    let mut total_count = 0;

    writeln!(buf, "# blockcheckw scan results for {domain}").unwrap();
    writeln!(buf, "# {timestamp}").unwrap();

    for (protocol, strategies, _, _, _, _) in summary {
        if strategies.is_empty() {
            continue;
        }
        let ranked = rank::rank_strategies(strategies);
        writeln!(buf).unwrap();
        writeln!(buf, "# {} — {} strategies", protocol, ranked.len()).unwrap();
        for score in &ranked {
            writeln!(buf, "{}", score.strategy_args.join(" ")).unwrap();
        }
        total_count += ranked.len();
    }

    std::fs::write(path, buf)?;
    Ok(total_count)
}

fn detect_shell() -> Option<clap_complete::Shell> {
    let shell_env = std::env::var("SHELL").ok()?;
    let shell_name = std::path::Path::new(&shell_env).file_name()?.to_str()?;
    match shell_name {
        "bash" => Some(clap_complete::Shell::Bash),
        "zsh" => Some(clap_complete::Shell::Zsh),
        "fish" => Some(clap_complete::Shell::Fish),
        "elvish" => Some(clap_complete::Shell::Elvish),
        "pwsh" | "powershell" => Some(clap_complete::Shell::PowerShell),
        _ => None,
    }
}

fn install_completions(shell: clap_complete::Shell) {
    use std::fs;
    use std::path::PathBuf;

    let (dir, filename) = match shell {
        clap_complete::Shell::Bash => {
            // Prefer user-local dir, fallback to system
            let user_dir = dirs_for_bash();
            (user_dir, "blockcheckw".to_string())
        }
        clap_complete::Shell::Zsh => {
            let dir = zsh_completions_dir().unwrap_or_else(|| {
                eprintln!("Could not determine zsh completions directory.");
                eprintln!("Print to stdout instead: blockcheckw completions zsh");
                std::process::exit(1);
            });
            (dir, "_blockcheckw".to_string())
        }
        clap_complete::Shell::Fish => {
            let home = std::env::var("HOME").unwrap_or_default();
            let dir = PathBuf::from(home).join(".config/fish/completions");
            (dir, "blockcheckw.fish".to_string())
        }
        _ => {
            eprintln!("--install is not supported for {shell}. Print to stdout instead:");
            eprintln!("  blockcheckw completions {shell}");
            std::process::exit(1);
        }
    };

    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("Failed to create {}: {e}", dir.display());
        std::process::exit(1);
    }

    let path = dir.join(&filename);
    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "blockcheckw", &mut buf);

    match fs::write(&path, &buf) {
        Ok(()) => {
            eprintln!("Completions installed to {}", path.display());
            match shell {
                clap_complete::Shell::Bash => {
                    eprintln!("Restart your shell or run: source {}", path.display());
                }
                clap_complete::Shell::Zsh => {
                    eprintln!("Restart your shell or run: autoload -Uz compinit && compinit");
                }
                clap_complete::Shell::Fish => {
                    eprintln!("Completions will be loaded automatically on next shell start.");
                }
                _ => {}
            }
        }
        Err(e) => {
            eprintln!("Failed to write {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

fn dirs_for_bash() -> std::path::PathBuf {
    use std::path::PathBuf;
    // System-wide directory (works if running as root or user has write access)
    let system = PathBuf::from("/etc/bash_completion.d");
    if system.is_dir() {
        // Check if writable
        let test_file = system.join(".blockcheckw_write_test");
        if std::fs::write(&test_file, "").is_ok() {
            let _ = std::fs::remove_file(&test_file);
            return system;
        }
    }
    // User-local: ~/.local/share/bash-completion/completions
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".local/share/bash-completion/completions")
}

fn zsh_completions_dir() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    // Try common paths in order
    let candidates = [
        // User-local
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".zfunc")),
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".local/share/zsh/site-functions")),
        // System-wide
        Some(PathBuf::from("/usr/local/share/zsh/site-functions")),
        Some(PathBuf::from("/usr/share/zsh/site-functions")),
    ];

    // First try existing writable dirs
    for dir in candidates.iter().flatten() {
        if dir.is_dir() {
            let test = dir.join(".blockcheckw_write_test");
            if std::fs::write(&test, "").is_ok() {
                let _ = std::fs::remove_file(&test);
                return Some(dir.clone());
            }
        }
    }

    // Fallback: create user-local dir
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".local/share/zsh/site-functions"))
}

async fn run_check_cmd(
    domain: &str,
    from_file: &str,
    dns_mode: DnsMode,
    timeout: u64,
    take: usize,
    passes: usize,
    output: Option<&str>,
) {
    let config = Arc::new(CoreConfig {
        worker_count: 1,
        request_timeout: timeout,
        ..CoreConfig::default()
    });

    // Signal handler: cleanup nftables on Ctrl+C
    let cleanup_config = config.clone();
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            eprintln!("\nCtrl+C received, cleaning up...");
            nftables::drop_table(&cleanup_config.nft_table).await;
            std::process::exit(130);
        }
    });

    let mut screen = ui::ScanScreen::new();

    // Load strategies from vanilla file
    let strategies = match generator::load_tagged_strategies(std::path::Path::new(from_file)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{} failed to read {}: {e}",
                style("ERROR:").red().bold(),
                style(from_file).cyan(),
            );
            std::process::exit(1);
        }
    };

    let mut flags = String::new();
    if take > 0 {
        flags.push_str(&format!(", --take {take}"));
    }
    if passes >= 2 {
        flags.push_str(&format!(", --passes {passes}"));
    }
    screen.println(&format!(
        "{} loaded {} strategies from {}{}",
        style("check").bold().cyan(),
        style(strategies.len()).bold(),
        style(from_file).cyan(),
        flags,
    ));

    // ISP info
    if let Some(info) = isp::detect_ip_info().await {
        screen.add_info_line(&format!("  ISP: {info}"));
    }

    // DNS resolve
    screen.println(&ui::section("DNS resolve"));
    screen.println(&format!(
        "  dns mode: {}",
        style(dns_mode.to_string()).bold()
    ));
    let ips = match dns::resolve_domain(domain, dns_mode).await {
        Ok(resolution) => {
            screen.println(&format!(
                "  {} {} {} (via {})",
                domain,
                ui::ARROW,
                style(resolution.ips.join(", ")).bold(),
                resolution.method,
            ));
            resolution.ips
        }
        Err(e) => {
            eprintln!("{} {e}", style("ERROR:").red().bold());
            std::process::exit(1);
        }
    };

    // Check for conflicts
    if !handle_bypass_conflicts(&config.nft_table).await {
        std::process::exit(1);
    }

    // Run check
    screen.newline();
    screen.println(&ui::section("Checking strategies (data transfer)"));

    let report = check::run_check(&config, domain, &strategies, &ips, take, passes, &screen).await;

    // Summary
    screen.newline();
    screen.println(&ui::section("Check summary"));
    screen.println(&format!(
        "  total: {} | working: {} | elapsed: {:.1}s",
        report.total,
        style(report.working).green().bold(),
        report.elapsed_secs,
    ));
    if let Some(ref best) = report.best {
        screen.println(&format!(
            "  {} {} nfqws2 {}",
            style("BEST:").green().bold(),
            style(&best.protocol).bold(),
            style(&best.args).cyan().bold(),
        ));
    }

    // Output JSON
    let json = serde_json::to_string_pretty(&report).unwrap();

    if let Some(path) = output {
        match std::fs::write(path, &json) {
            Ok(()) => {
                blockcheckw::system::elevate::chown_to_caller(path);
                screen.println(&format!(
                    "  {} JSON report → {}",
                    style("OK").green().bold(),
                    style(path).cyan(),
                ));
            }
            Err(e) => {
                screen.println(&format!(
                    "  {} failed to write {}: {e}",
                    style("ERROR:").red().bold(),
                    style(path).cyan(),
                ));
            }
        }
    } else {
        screen.finish_info();
        println!("{json}");
    }
}

async fn run_default(workers: usize) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Arc::new(CoreConfig {
        worker_count: workers,
        ..CoreConfig::default()
    });

    // Signal handler: cleanup nftables on Ctrl+C
    let cleanup_config = config.clone();
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("Ctrl+C received, cleaning up nftables table...");
            nftables::drop_table(&cleanup_config.nft_table).await;
            std::process::exit(130);
        }
    });

    let domain = "rutracker.org";
    let protocol = Protocol::Http;
    let ips = match dns::resolve_ipv4(domain).await {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("DNS resolve failed for {domain}: {e}");
            std::process::exit(1);
        }
    };

    let strategies: Vec<Vec<String>> = vec![
        vec![
            "--dpi-desync=fake".to_string(),
            "--dpi-desync-ttl=1".to_string(),
        ],
        vec![
            "--dpi-desync=fake".to_string(),
            "--dpi-desync-ttl=2".to_string(),
        ],
        vec![
            "--dpi-desync=fake".to_string(),
            "--dpi-desync-ttl=3".to_string(),
        ],
    ];

    info!("blockcheckw starting: {protocol} {domain}");
    info!(
        "workers={}, strategies={}",
        config.worker_count,
        strategies.len()
    );

    let (results, stats) = run_parallel(
        &config,
        domain,
        protocol,
        &strategies,
        &ips,
        None,
        None,
        HttpTestMode::Standard,
    )
    .await;

    info!("=== Results ===");
    for r in &results {
        info!("nfqws2 {} : {}", r.strategy_args.join(" "), r.result);
    }

    info!(
        "Total: {} | Success: {} | Failed: {} | Errors: {} | {:.2}s ({:.1} strat/sec)",
        stats.total,
        stats.successes,
        stats.failures,
        stats.errors,
        stats.elapsed.as_secs_f64(),
        stats.throughput()
    );
}

struct BypassConflicts {
    has_nfqws2_processes: bool,
    /// (family, table_name) pairs, e.g. ("inet", "zapret2")
    conflicting_tables: Vec<(String, String)>,
}

impl BypassConflicts {
    fn is_empty(&self) -> bool {
        !self.has_nfqws2_processes && self.conflicting_tables.is_empty()
    }
}

/// Detect conflicting DPI bypass processes and nftables tables.
async fn detect_bypass_conflicts(own_table: &str) -> BypassConflicts {
    use blockcheckw::system::process::run_process;

    let mut conflicts = BypassConflicts {
        has_nfqws2_processes: false,
        conflicting_tables: Vec::new(),
    };

    // Check for other nfqws2 processes
    if let Ok(result) = run_process(&["pgrep", "-c", "nfqws2"], 3_000).await {
        if result.exit_code == 0 {
            if let Ok(count) = result.stdout.trim().parse::<u32>() {
                if count > 0 {
                    conflicts.has_nfqws2_processes = true;
                }
            }
        }
    }

    // Check for other nftables tables with queue rules on ports 80/443
    if let Ok(result) = run_process(&["nft", "list", "tables"], 3_000).await {
        if result.exit_code == 0 {
            for line in result.stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0] == "table" {
                    let family = parts[1];
                    let table_name = parts[2];
                    if table_name != own_table && table_name != "fw4" {
                        if let Ok(table_content) =
                            run_process(&["nft", "list", "table", family, table_name], 3_000).await
                        {
                            if table_content.exit_code == 0
                                && table_content.stdout.contains("queue")
                                && (table_content.stdout.contains("dport 443")
                                    || table_content.stdout.contains("dport { 80, 443"))
                            {
                                conflicts
                                    .conflicting_tables
                                    .push((family.to_string(), table_name.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }

    conflicts
}

/// Kill all nfqws2 processes and drop conflicting nft tables.
async fn resolve_bypass_conflicts(conflicts: &BypassConflicts) {
    use blockcheckw::system::process::run_process;

    if conflicts.has_nfqws2_processes {
        // FIXME: killall kills ALL nfqws2 processes system-wide, including production ones
        let _ = run_process(&["killall", "nfqws2"], 5_000).await;
        // Give processes time to exit
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    for (family, table) in &conflicts.conflicting_tables {
        let _ = run_process(&["nft", "delete", "table", family, table], 5_000).await;
    }
}

/// Display conflicts and prompt user. Returns true if should proceed.
async fn handle_bypass_conflicts(own_table: &str) -> bool {
    let conflicts = detect_bypass_conflicts(own_table).await;
    if conflicts.is_empty() {
        return true;
    }

    eprintln!();
    eprintln!(
        "{} {}",
        style("WARNING").yellow().bold(),
        style("conflicting DPI bypass detected:").yellow()
    );
    if conflicts.has_nfqws2_processes {
        eprintln!(
            "  {} running nfqws2 processes found",
            style("!").yellow().bold(),
        );
    }
    for (family, table) in &conflicts.conflicting_tables {
        eprintln!(
            "  {} nft table '{} {}' has queue rules intercepting port 443",
            style("!").yellow().bold(),
            family,
            table
        );
    }

    // Prompt user
    eprintln!();
    eprint!(
        "  {} ",
        style("Kill nfqws2 and drop conflicting nft tables to proceed? [Y/n] ").bold()
    );

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        eprintln!("{}", style("Aborted.").red());
        return false;
    }

    resolve_bypass_conflicts(&conflicts).await;
    eprintln!(
        "  {} conflicting processes killed, nft tables dropped",
        style("OK").green().bold()
    );
    true
}
