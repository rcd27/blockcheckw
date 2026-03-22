use clap::{CommandFactory, Parser, Subcommand};

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

    let cli = Cli::parse();

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

    blockcheckw::system::elevate::require_root();
    blockcheckw::system::elevate::tune_tcp();
    blockcheckw::system::elevate::raise_nofile_limit();

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

    match cli.command {
        Some(Command::Benchmark {
            time,
            max_workers,
            domain,
            protocol,
            raw,
        }) => {
            cmd::benchmark::run_benchmark_cmd(time, max_workers, &domain, &protocol, raw).await;
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
            let dns_mode = match blockcheckw::config::parse_dns_mode(&dns) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            };

            cmd::check::run_check_cmd(
                &domain,
                &from_file,
                dns_mode,
                timeout,
                take,
                passes as usize,
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
            cmd::scan::run_scan(
                cli.workers as usize,
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
        None => {
            Cli::command().print_help().unwrap();
        }
    }
}
