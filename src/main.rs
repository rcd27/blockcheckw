use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

mod cmd;
mod tracing_otel;

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

/// Верхнеуровневая справка перечисляет только команды: таймауты, DNS-режим и
/// число проходов задаются флагами конкретной команды (#66).
const AFTER_HELP: &str = "\
Examples:
  blockcheckw scan -d rutracker.org                скан домена на работающие страты
  blockcheckw scan -d example.com -p tls12         проверка только TLS 1.2
  blockcheckw scan -d example.com -o report.json   сохранить отчёт в файл
  blockcheckw check --from-file report.json        проверка найденных страт
  blockcheckw universal --domain-list domains.txt  подбор пересекающихся страт для разных доменов
  blockcheckw status --domain-list domains.txt     оценка эффективности работающего zapret2

Per-command flags (timeouts, DNS mode, passes, worker count):
  blockcheckw <command> --help";

#[derive(Parser)]
#[command(
    name = "blockcheckw",
    about = "Parallel DPI bypass strategy scanner",
    after_help = AFTER_HELP,
    styles = help_styles(),
)]
struct Cli {
    /// Print version and check for updates
    #[arg(short = 'V', long)]
    version: bool,

    /// Upgrade to the latest release
    #[arg(long)]
    upgrade: bool,

    /// Number of parallel workers
    #[arg(short, long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=2048))]
    workers: u16,

    /// How many strategies to keep loaded in one nfqws2 process at a time
    #[arg(long, default_value_t = 1024)]
    profiles_per_instance: usize,

    /// Auto-confirm all prompts (non-interactive mode)
    #[arg(long, global = true)]
    auto: bool,

    /// Route traffic through a gateway or proxy (e.g. 100.64.0.5, localhost:8888, socks5://host:1080)
    #[arg(long, global = true)]
    via: Option<String>,

    /// Embedded mode: do NOT detect/cleanup foreign DPI-bypass nft tables or nfqws2 processes
    /// (the caller owns the nft state). Without this, scan deletes any non-own queue-on-443 table.
    #[arg(long, global = true)]
    no_conflict_cleanup: bool,

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

    /// Check strategies from a vanilla report with real data transfer.
    /// В JSON читать надо `observed`/`admits` (судьба цели), а не `working`:
    /// «не наблюдали» и «наблюдали пустоту» оба дают `working: false`.
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

        /// Stop the SEARCH after N strategies bringing the target to Good, per protocol
        /// (0 = check all). Выдачу не урезает: в отчёт идёт всякая наблюдённая стратегия,
        /// ранжированная по судьбе.
        #[arg(long, default_value_t = 0)]
        take: usize,

        /// УСТАРЕЛ и игнорируется: вердикт больше не булев, и голосовать не по чему.
        /// Круг судеб либо сужен наблюдением, либо честно широк.
        #[arg(long, default_value_t = 1)]
        passes: usize,

        /// Чистый egress для снятия эталона ответа. Без него `Good` объявить нельзя —
        /// «байты текут» и «ресурс тот самый» неразличимы (см. Fate::Mirage).
        #[arg(long, value_name = "ENDPOINT")]
        reference_via: Option<String>,

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

        /// Verify aliveness of IP-blocked hosts through this egress ONLY (does NOT
        /// route the scan). When the direct SYN is dropped, a probe through this
        /// proxy splits the verdict into SYN-blocked (host alive elsewhere) vs
        /// host-dead. Same endpoint format as --via (e.g. socks5://host:1080).
        #[arg(long)]
        alive_via: Option<String>,
    },

    /// Show zapret2 effectiveness: compare access with and without the service
    Status {
        /// Path to file with blocked domains (one per line)
        #[arg(long)]
        domain_list: String,

        /// DNS resolution mode: auto, system, doh
        #[arg(long, default_value = "auto")]
        dns: String,

        /// Request timeout per domain in seconds
        #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u64).range(1..=60))]
        timeout: u64,

        /// Save JSON report to file
        #[arg(short, long)]
        output: Option<String>,
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
        blockcheckw::network::via::Via::cleanup_sync();
        // Сносим ТОЛЬКО свою таблицу: метку выдаёт firewall-слой, другой
        // команды из неё не собрать (#66). Таймаут внутри — panic-хук без
        // него уводил роутеры в перезагрузку.
        let _ = blockcheckw::firewall::nft::NftRunSync::run(
            &blockcheckw::firewall::nft::SystemNftSync,
            blockcheckw::firewall::nft::OwnedTableMarker::planned(
                blockcheckw::config::DEFAULT_NFT_TABLE,
            )
            .drop_batch(),
        );
        default_hook(info);
    }));

    // Parse CLI: get both typed struct and raw matches (for value_source detection)
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    // --version: print version + check for updates (no root needed)
    if cli.version {
        print_version_and_check().await;
        return;
    }

    // --upgrade: download and install latest release (no root needed)
    if cli.upgrade {
        run_upgrade().await;
        return;
    }

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

    // Без команды — печатаем справку и выходим. Это должно случиться до
    // require_root() и prereq-проверок: иначе голый `blockcheckw` поднимает
    // права через sudo и выдаёт диагностику окружения вместо help (#66).
    if cli.command.is_none() {
        let _ = Cli::command().print_help();
        println!();
        return;
    }

    cmd::set_auto_yes(cli.auto);
    cmd::set_skip_conflict_cleanup(cli.no_conflict_cleanup);
    let via = cli.via.map(|raw| {
        blockcheckw::network::via::Via::parse(&raw).unwrap_or_else(|e| {
            eprintln!("ERROR: --via: {e}");
            std::process::exit(1);
        })
    });

    // --via и --reference-via несовместимы: весь прогон уже идёт через шлюз (--via),
    // и «чистый egress» через второй шлюз ничего не доказывает, а маршруты подерутся.
    // Проверяем до всякой работы — раньше require_root() и прочих побочных эффектов.
    if via.is_some() {
        if let Some(Command::Check {
            reference_via: Some(_),
            ..
        }) = &cli.command
        {
            eprintln!(
                "ERROR: --via и --reference-via несовместимы: весь прогон уже идёт через \
                 шлюз, эталон через второй шлюз ничего не доказывает"
            );
            std::process::exit(1);
        }
    }

    blockcheckw::system::elevate::require_root();
    blockcheckw::system::elevate::raise_nofile_limit();

    // `--workers` is global, but `check` verifies strategies sequentially by design —
    // warn (once, post-elevation) so users don't expect it to change `check` throughput (#33).
    if is_explicit(&matches, "workers") && matches!(cli.command, Some(Command::Check { .. })) {
        eprintln!(
            "{}--workers has no effect on `check` (it verifies strategies sequentially by design)",
            blockcheckw::ui::WARN,
        );
    }

    // Load persisted config
    let mut persisted = blockcheckw::persist::load();

    // Resolve effective workers (top-level arg)
    let eff_workers = resolve_u16(&matches, "workers", cli.workers, persisted.workers);
    if is_explicit(&matches, "workers") {
        persisted.workers = Some(cli.workers);
    }

    // #68: план не может обслужить больше проб в полёте, чем в нём загружено
    // профилей, а номер профиля не помещается в марку за потолком маски —
    // ловим здесь, на разборе аргументов, а не паникой в уже запущенном проце.
    //
    // Валидация аргументов обязана идти ДО любых побочных эффектов — в
    // частности, до `check_prerequisites` ниже, который живьём спавнит
    // nfqws2 (`smoke_sync`). Раньше проверка стояла после преflight'а: явно
    // мусорный `--profiles-per-instance` отвергался только после того, как
    // движок уже запускался и убивался вхолостую.
    if let Err(e) =
        blockcheckw::config::validate_parallelism(eff_workers as usize, cli.profiles_per_instance)
    {
        eprintln!("ERROR: {e}");
        std::process::exit(2);
    }

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

    // Status doesn't need nfqws2/nft — skip prereqs
    let prereq = if !matches!(cli.command, Some(Command::Status { .. })) {
        let console = blockcheckw::ui::Console::new();
        let prereq = cmd::check_prerequisites(&console);
        drop(console);
        Some(prereq)
    } else {
        None
    };

    // Init tracing: stderr-fmt всегда + OTLP-слой, если задан endpoint (feature otel).
    let otel_guard = tracing_otel::init();

    // Корневой span команды под родителем из TRACEPARENT (если демон прислал) —
    // так bcw.scan/bcw.check висят детьми selection-span'а демона.
    use tracing::Instrument;
    let cmd_name = match &cli.command {
        Some(Command::Scan { .. }) => "bcw.scan",
        Some(Command::Check { .. }) => "bcw.check",
        _ => "bcw.cmd",
    };
    let root = tracing::info_span!("bcw.root", cmd = cmd_name);
    tracing_otel::set_parent_from_env(&root);

    // Диспатч под bcw.root через .instrument, НЕ .enter(): держать enter-guard
    // через .await — анти-паттерн tracing. При поллинге фьючи на другом потоке
    // tokio thread-local «текущий span» теряется → bcw.scan/check рождаются
    // корнями, а потомки (baseline/protocol) разлетаются по отдельным trace_id.
    // .instrument перевходит в span на КАЖДЫЙ poll → потомки наследуют trace_id
    // bcw.root (единый trace и в standalone, без присланного родителя).
    async {
        match cli.command {
            Some(Command::Benchmark {
                time,
                max_workers,
                domain,
                protocol,
                raw,
            }) => {
                let sub = matches
                    .subcommand_matches("benchmark")
                    .expect("clap guarantees subcommand");
                let eff_domain = resolve_str(sub, "domain", &domain, &persisted.domain);

                if is_explicit(sub, "domain") {
                    persisted.domain = Some(domain.clone());
                }
                blockcheckw::persist::save(&persisted);

                cmd::benchmark::run_benchmark_cmd(
                    time,
                    max_workers,
                    &eff_domain,
                    &protocol,
                    raw,
                    cli.profiles_per_instance,
                    prereq
                        .as_ref()
                        .expect("benchmark requires prerequisites (skipped only for `status`)"),
                )
                .await;
            }
            Some(Command::Check {
                from_file,
                domain,
                dns,
                timeout,
                take,
                passes,
                reference_via,
                output,
            }) => {
                let sub = matches
                    .subcommand_matches("check")
                    .expect("clap guarantees subcommand");

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

                let reference_via = reference_via.map(|raw| {
                    blockcheckw::network::via::Via::parse(&raw).unwrap_or_else(|e| {
                        eprintln!("ERROR: --reference-via: {e}");
                        std::process::exit(1);
                    })
                });

                cmd::check::run_check_cmd(cmd::check::CheckParams {
                    domain: &eff_domain,
                    from_file: &source,
                    dns_mode,
                    timeout,
                    take,
                    passes,
                    output: output.as_deref(),
                    via: via.as_ref(),
                    reference_via: reference_via.as_ref(),
                    prereq: prereq
                        .as_ref()
                        .expect("check requires prerequisites (skipped only for `status`)"),
                })
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
                alive_via,
            }) => {
                let sub = matches
                    .subcommand_matches("scan")
                    .expect("clap guarantees subcommand");

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
                // --alive-via: a proxy used ONLY to verify aliveness of IP-blocked
                // hosts (not to route the scan). Must be a proxy we can tcp-connect
                // through; reachability is verified later in run_scan.
                let alive_via_proxy = alive_via.as_ref().map(|raw| {
                    let v = blockcheckw::network::via::Via::parse(raw).unwrap_or_else(|e| {
                        eprintln!("ERROR: --alive-via: {e}");
                        std::process::exit(1);
                    });
                    if !v.is_proxy() {
                        eprintln!(
                            "ERROR: --alive-via must be a proxy (e.g. socks5://host:1080) — it is \
                             used only to tcp-connect through for an aliveness probe, not to route"
                        );
                        std::process::exit(1);
                    }
                    v
                });

                cmd::scan::run_scan(cmd::scan::ScanParams {
                    workers: eff_workers as usize,
                    profiles_per_instance: cli.profiles_per_instance,
                    domain: &eff_domain,
                    protocols: &protocols,
                    dns_mode,
                    timeout_secs: timeout,
                    top_n: top,
                    output: output.as_deref(),
                    from_file: from_file.as_deref(),
                    via: via.as_ref(),
                    alive_via: alive_via_proxy.as_ref(),
                    prereq: prereq
                        .as_ref()
                        .expect("scan requires prerequisites (skipped only for `status`)"),
                })
                .await;
            }
            Some(Command::Universal {
                domain_list,
                protocols,
                dns,
                sample,
                output,
            }) => {
                let sub = matches
                    .subcommand_matches("universal")
                    .expect("clap guarantees subcommand");

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
                    cli.profiles_per_instance,
                    &domain_list,
                    &protocols,
                    dns_mode,
                    sample,
                    output.as_deref(),
                    via.as_ref(),
                    prereq
                        .as_ref()
                        .expect("universal requires prerequisites (skipped only for `status`)"),
                )
                .await;
            }
            Some(Command::Status {
                domain_list,
                dns,
                timeout,
                output,
            }) => {
                let sub = matches
                    .subcommand_matches("status")
                    .expect("clap guarantees subcommand");

                let eff_dns = resolve_str(sub, "dns", &dns, &persisted.dns);

                if is_explicit(sub, "dns") {
                    persisted.dns = Some(dns.clone());
                }
                blockcheckw::persist::save(&persisted);

                let dns_mode = match blockcheckw::config::parse_dns_mode(&eff_dns) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("ERROR: {e}");
                        std::process::exit(1);
                    }
                };

                cmd::status::run_status_cmd(cmd::status::StatusParams {
                    domain_list: &domain_list,
                    dns_mode,
                    timeout,
                    output: output.as_deref(),
                    via: via.as_ref(),
                })
                .await;
            }
            Some(Command::Completions { .. }) => unreachable!("handled above"),
            None => unreachable!("справка без команды печатается до elevation"),
        }
    }
    .instrument(root)
    .await;

    // bcw.root закрыт (.instrument уронил span по завершении фьючи). Принудительно
    // выгружаем OTLP-буфер до выхода (см. OtelGuard::shutdown). Без feature otel —
    // no-op. Пути std::process::exit (ошибки prereq) сюда не доходят — их span'ы не нужны.
    otel_guard.shutdown().await;
}

/// Print current version and check GitHub for updates.
async fn print_version_and_check() {
    use console::style;

    let current = env!("CARGO_PKG_VERSION");
    println!("blockcheckw v{current}");

    eprint!("checking for updates... ");
    match blockcheckw::network::update_check::check_latest_release(current).await {
        Some(release) => {
            eprintln!(
                "{}",
                style(format!("newer version available: {}", release.tag))
                    .yellow()
                    .bold()
            );
            eprintln!(
                "  upgrade: {}",
                style("blockcheckw --upgrade").green().bold()
            );
        }
        None => {
            eprintln!("{}", style("up to date").green());
        }
    }
}

const INSTALL_SCRIPT_URL: &str =
    "https://raw.githubusercontent.com/rcd27/blockcheckw/main/scripts/install.sh";

fn install_dir_from_exe(exe: &std::path::Path) -> Option<std::path::PathBuf> {
    exe.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
}

fn download_install_script(destination: &std::path::Path) -> Result<(), String> {
    let curl = std::process::Command::new("curl")
        .args(["-fSL", "--retry", "3", "-o"])
        .arg(destination)
        .arg(INSTALL_SCRIPT_URL)
        .status();
    if matches!(curl, Ok(ref status) if status.success()) {
        return Ok(());
    }

    let _ = std::fs::remove_file(destination);
    let wget = std::process::Command::new("wget")
        .args(["-q", "-O"])
        .arg(destination)
        .arg(INSTALL_SCRIPT_URL)
        .status();
    if matches!(wget, Ok(ref status) if status.success()) {
        return Ok(());
    }

    let _ = std::fs::remove_file(destination);
    Err("failed to download install script with curl or wget".to_string())
}

/// Download and install the latest release.
async fn run_upgrade() {
    use console::style;

    let current = env!("CARGO_PKG_VERSION");
    let con = blockcheckw::ui::Console::new();

    con.println(&format!("blockcheckw v{current}"));
    con.println("checking for updates...");

    match blockcheckw::network::update_check::check_latest_release(current).await {
        Some(release) => {
            con.ok(&format!(
                "newer version available: {} → {}",
                style(format!("v{current}")).dim(),
                style(&release.tag).green().bold(),
            ));
            con.println("  running install script...");
            con.newline();

            let install_dir = std::env::current_exe()
                .ok()
                .as_deref()
                .and_then(install_dir_from_exe)
                .unwrap_or_else(|| {
                    con.error("cannot determine current install directory");
                    std::process::exit(1);
                });
            let script_path =
                std::env::temp_dir().join(format!("blockcheckw-install-{}.sh", std::process::id()));
            if let Err(e) = download_install_script(&script_path) {
                con.error(&e);
                std::process::exit(1);
            }

            let status = std::process::Command::new("/bin/sh")
                .arg(&script_path)
                .env("INSTALL_DIR", &install_dir)
                .status();
            let _ = std::fs::remove_file(&script_path);

            match status {
                Ok(s) if s.success() => {
                    con.newline();
                    con.ok("upgrade complete");
                }
                _ => {
                    con.newline();
                    con.error("upgrade failed");
                    std::process::exit(1);
                }
            }
        }
        None => {
            con.ok(&format!("v{current} is the latest version"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_uses_current_executable_directory() {
        let exe = std::path::Path::new("custom")
            .join("bin")
            .join("blockcheckw");
        assert_eq!(
            install_dir_from_exe(&exe),
            Some(std::path::Path::new("custom").join("bin"))
        );
    }

    #[test]
    fn scan_accepts_alive_via_flag() {
        let cli = Cli::try_parse_from([
            "blockcheckw",
            "scan",
            "-d",
            "example.com",
            "--alive-via",
            "socks5://127.0.0.1:1080",
        ])
        .expect("parse");
        match cli.command {
            Some(Command::Scan { alive_via, .. }) => {
                assert_eq!(alive_via.as_deref(), Some("socks5://127.0.0.1:1080"));
            }
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn scan_alive_via_defaults_to_none() {
        let cli = Cli::try_parse_from(["blockcheckw", "scan", "-d", "example.com"]).expect("parse");
        match cli.command {
            Some(Command::Scan { alive_via, .. }) => assert_eq!(alive_via, None),
            _ => panic!("expected Scan command"),
        }
    }

    /// #68: `--profiles-per-instance` — глобальный флаг (как `--workers`), стоит
    /// ДО имени подкоманды. Ловит регресс, если кто-то случайно перенесёт его
    /// внутрь `Command::Scan` при рефакторинге — тогда этот же вызов перестал
    /// бы парситься.
    #[test]
    fn profiles_per_instance_parses_before_subcommand() {
        let cli = Cli::try_parse_from([
            "blockcheckw",
            "--profiles-per-instance",
            "256",
            "scan",
            "-d",
            "example.com",
        ])
        .expect("parse");
        assert_eq!(cli.profiles_per_instance, 256);
    }

    #[test]
    fn profiles_per_instance_defaults_to_1024() {
        let cli = Cli::try_parse_from(["blockcheckw", "scan", "-d", "example.com"]).expect("parse");
        assert_eq!(cli.profiles_per_instance, 1024);
    }
}
