use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

mod cmd;

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
    version,
    about = "Parallel DPI bypass strategy scanner",
    styles = help_styles(),
)]
struct Cli {
    /// Number of parallel workers
    #[arg(short, long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=2048))]
    workers: u16,

    /// Auto-confirm all prompts (non-interactive mode)
    #[arg(long, global = true)]
    auto: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run parallel scaling benchmark to find optimal worker count
    Benchmark {
        /// Seconds to run per worker-count level
        #[arg(short, long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(5..))]
        time: u64,

        /// Maximum number of workers to test
        #[arg(short = 'M', long, value_parser = clap::value_parser!(u16).range(1..=2048))]
        max_workers: Option<u16>,

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
        /// Path to report file (reads from stdin if omitted and pipe detected)
        #[arg(long)]
        from_file: Option<String>,

        /// Target domain to check
        #[arg(short, long, default_value = "rutracker.org")]
        domain: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Request timeout per strategy in seconds
        #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u64).range(1..=60))]
        timeout: u64,

        /// Stop after finding N verified strategies per protocol (0 = check all)
        #[arg(long, default_value_t = 0)]
        take: usize,

        /// Verification passes per strategy (early-exit on first fail)
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u16).range(1..=100))]
        passes: u16,

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

    /// Find universal strategies that work across multiple blocked domains
    Universal {
        /// Path to file with blocked domains (one per line)
        #[arg(long)]
        domain_list: String,

        /// Protocols to test (comma-separated: http,tls12,tls13)
        #[arg(short, long, default_value = "tls12")]
        protocols: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Number of domains to sample from the list
        #[arg(long, default_value_t = 10)]
        sample: usize,

        /// Save report to file
        #[arg(short, long)]
        output: Option<String>,
    },
}

/// Return true if a named arg was explicitly provided on the command line.
fn is_explicit(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

/// Pick the effective value: CLI-explicit wins, then config, then clap default.
/// Returns owned String to avoid borrow conflicts with persisted config mutation.
fn resolve_str(
    matches: &clap::ArgMatches,
    id: &str,
    cli_val: &str,
    persisted: &Option<String>,
) -> String {
    if is_explicit(matches, id) {
        cli_val.to_string()
    } else {
        persisted.as_deref().unwrap_or(cli_val).to_string()
    }
}

/// For protocols: stored as Vec, CLI as comma-separated string.
fn resolve_protocols(
    matches: &clap::ArgMatches,
    cli_val: &str,
    persisted: &Option<Vec<String>>,
) -> String {
    if is_explicit(matches, "protocols") {
        cli_val.to_string()
    } else {
        persisted
            .as_ref()
            .map(|v| v.join(","))
            .unwrap_or_else(|| cli_val.to_string())
    }
}

fn resolve_u16(matches: &clap::ArgMatches, id: &str, cli_val: u16, persisted: Option<u16>) -> u16 {
    if is_explicit(matches, id) {
        cli_val
    } else {
        persisted.unwrap_or(cli_val)
    }
}

#[tokio::main]
async fn main() {
    // Panic hook: cleanup nftables table on panic (async runtime may be dead, use sync Command)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Ok(mut child) = std::process::Command::new("nft")
            .args(["delete", "table", "inet", "zapret"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            const TIMEOUT_MS: u64 = 3000;
            const POLL_INTERVAL_MS: u64 = 100;
            for _ in 0..(TIMEOUT_MS / POLL_INTERVAL_MS) {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS))
                    }
                    Err(_) => break,
                }
            }
            let _ = child.kill();
        }
        default_hook(info);
    }));

    // Parse CLI: get both typed struct and raw matches (for value_source detection)
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    // Completions don't need root — handle before elevation
    if let Some(Command::Completions { shell, install }) = &cli.command {
        let shell = shell.unwrap_or_else(|| {
            cmd::completions::detect_shell().unwrap_or_else(|| {
                eprintln!(
                    "Could not detect shell. Specify it explicitly: blockcheckw completions bash"
                );
                std::process::exit(1);
            })
        });

        if *install {
            cmd::completions::install_completions(shell, &mut Cli::command());
        } else {
            cmd::completions::generate_completions(shell, &mut Cli::command());
        }
        return;
    }

    cmd::set_auto_yes(cli.auto);

    blockcheckw::system::elevate::require_root();
    blockcheckw::system::elevate::tune_tcp();
    blockcheckw::system::elevate::raise_nofile_limit();

    // Pre-read stdin for check in pipe mode (before acquiring lock,
    // so the upstream pipe command can finish and release its lock first)
    let stdin_data = {
        use std::io::IsTerminal;
        if matches!(cli.command, Some(Command::Check { .. })) && !std::io::stdin().is_terminal() {
            Some(std::io::read_to_string(std::io::stdin()).unwrap_or_default())
        } else {
            None
        }
    };

    // Prevent parallel execution — keep _lock alive until process exits
    let _lock = cmd::acquire_instance_lock();

    cmd::check_prerequisites();

    // Init tracing for all subcommands (warn level)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    // Load persisted config
    let mut persisted = blockcheckw::persist::load();

    // Resolve effective workers (top-level arg)
    let eff_workers = resolve_u16(&matches, "workers", cli.workers, persisted.workers);
    if is_explicit(&matches, "workers") {
        persisted.workers = Some(cli.workers);
    }

    match cli.command {
        Some(Command::Benchmark {
            time,
            max_workers,
            domain,
            protocol,
            raw,
        }) => {
            let sub = matches.subcommand_matches("benchmark").unwrap();
            let eff_domain = resolve_str(sub, "domain", &domain, &persisted.domain);

            if is_explicit(sub, "domain") {
                persisted.domain = Some(domain.clone());
            }
            blockcheckw::persist::save(&persisted);

            cmd::benchmark::run_benchmark_cmd(time, max_workers, &eff_domain, &protocol, raw).await;
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
            let sub = matches.subcommand_matches("check").unwrap();

            let eff_domain = resolve_str(sub, "domain", &domain, &persisted.domain);
            let eff_dns = resolve_str(sub, "dns", &dns, &persisted.dns);

            if is_explicit(sub, "domain") {
                persisted.domain = Some(domain.clone());
            }
            if is_explicit(sub, "dns") {
                persisted.dns = Some(dns.clone());
            }
            blockcheckw::persist::save(&persisted);

            // Determine input source: --from-file, pre-read stdin pipe, or error
            let (source, stdin_tmp) = if let Some(path) = from_file {
                (path, None)
            } else if let Some(ref data) = stdin_data {
                // Write pre-read stdin to temp file for load_tagged_strategies
                let tmp = std::env::temp_dir().join("blockcheckw_stdin.json");
                if let Err(e) = std::fs::write(&tmp, data) {
                    eprintln!("ERROR: cannot write temp file: {e}");
                    std::process::exit(1);
                }
                (tmp.to_string_lossy().into_owned(), Some(tmp))
            } else {
                eprintln!("ERROR: no input — provide --from-file or pipe data to stdin");
                std::process::exit(1);
            };

            let dns_mode = match blockcheckw::config::parse_dns_mode(&eff_dns) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };

            cmd::check::run_check_cmd(
                &eff_domain,
                &source,
                dns_mode,
                timeout,
                take,
                passes as usize,
                output.as_deref(),
            )
            .await;

            // Clean up temp file from stdin pipe
            if let Some(tmp) = stdin_tmp {
                let _ = std::fs::remove_file(tmp);
            }
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
            let sub = matches.subcommand_matches("scan").unwrap();

            let eff_domain = resolve_str(sub, "domain", &domain, &persisted.domain);
            let eff_protocols = resolve_protocols(sub, &protocols, &persisted.protocols);
            let eff_dns = resolve_str(sub, "dns", &dns, &persisted.dns);

            if is_explicit(sub, "domain") {
                persisted.domain = Some(domain.clone());
            }
            if is_explicit(sub, "protocols") {
                persisted.protocols =
                    Some(protocols.split(',').map(|s| s.trim().to_string()).collect());
            }
            if is_explicit(sub, "dns") {
                persisted.dns = Some(dns.clone());
            }
            blockcheckw::persist::save(&persisted);

            let protocols = match blockcheckw::config::parse_protocols(&eff_protocols) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };
            let dns_mode = match blockcheckw::config::parse_dns_mode(&eff_dns) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };
            cmd::scan::run_scan(
                eff_workers as usize,
                &eff_domain,
                &protocols,
                dns_mode,
                timeout,
                top,
                output.as_deref(),
                from_file.as_deref(),
            )
            .await;
        }
        Some(Command::Universal {
            domain_list,
            protocols,
            dns,
            sample,
            output,
        }) => {
            let sub = matches.subcommand_matches("universal").unwrap();

            let eff_protocols = resolve_protocols(sub, &protocols, &persisted.protocols);
            let eff_dns = resolve_str(sub, "dns", &dns, &persisted.dns);

            if is_explicit(sub, "domain_list") {
                persisted.domain_list = Some(domain_list.clone());
            }
            if is_explicit(sub, "protocols") {
                persisted.protocols =
                    Some(protocols.split(',').map(|s| s.trim().to_string()).collect());
            }
            if is_explicit(sub, "dns") {
                persisted.dns = Some(dns.clone());
            }
            blockcheckw::persist::save(&persisted);

            let protocols = match blockcheckw::config::parse_protocols(&eff_protocols) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };
            let dns_mode = match blockcheckw::config::parse_dns_mode(&eff_dns) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };
            cmd::universal::run_universal(
                eff_workers as usize,
                &domain_list,
                &protocols,
                dns_mode,
                sample,
                output.as_deref(),
            )
            .await;
        }
        Some(Command::Completions { .. }) => unreachable!("handled above"),
        None => {
            Cli::command().print_help().unwrap();
        }
    }
}
