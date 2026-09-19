use std::io::IsTerminal;
use std::sync::Arc;

use console::style;

use blockcheckw::config::{CoreConfig, DnsMode, Protocol};
use blockcheckw::dto::{BrokenReason, CheckReport, Outcome, RunProvenance};
use blockcheckw::network::patience::Patience;
use blockcheckw::network::{dns, isp, via::Via};
use blockcheckw::pipeline::{check, reference};
use blockcheckw::strategy::{generator, rank};
use blockcheckw::ui;

use super::{handle_bypass_conflicts, restore_service, set_stopped_service, spawn_cleanup_handler};

pub struct CheckParams<'a> {
    pub domain: &'a str,
    pub from_file: &'a str,
    pub dns_mode: DnsMode,
    pub timeout: u64,
    /// Порог тишины пробы (`Expiry::Idle`), миллисекунды.
    pub idle_ms: u64,
    pub take: usize,
    /// `M` — сколько раз мерить байтовую ось (спека §6-тер).
    pub passes: usize,
    pub output: Option<&'a str>,
    pub via: Option<&'a Via>,
    /// Чистый egress для обоих эталонов: снимается дважды (по два прохода) для КАЖДОГО
    /// из двух путей — `probe_path` и `identity_path` (решение 2 спеки §6-тер).
    pub reference_via: Option<&'a Via>,
    /// Путь байтовой оси (`--probe-path`). Главный вердикт: доля вытянутого от эталона
    /// объёма, повторяется `passes` раз.
    pub probe_path: &'a str,
    /// Путь оси подлинности (`--identity-path`). Побочный вердикт: точная сверка с
    /// эталоном по этому пути, один раз. Только она может дать круг `[Fate::Mirage]`.
    pub identity_path: &'a str,
    pub prereq: &'a super::Prerequisites,
}

#[tracing::instrument(
    name = "bcw.check",
    skip(params),
    fields(domain = %params.domain, take = params.take, working = tracing::field::Empty)
)]
pub async fn run_check_cmd(params: CheckParams<'_>) {
    // Привязка к trace'у демона — единым стежком на bcw.root в main.rs. bcw.check
    // наследует контекст от bcw.root; повторный set_parent осиротил бы bcw.root.
    let CheckParams {
        domain,
        from_file,
        dns_mode,
        timeout,
        idle_ms,
        take,
        passes,
        output,
        via,
        reference_via,
        probe_path,
        identity_path,
        prereq,
    } = params;

    // Пути приводятся к абсолютным один раз, здесь: дальше они едут и в пробы, и в
    // эталоны, и разойтись не должны.
    let probe_path = blockcheckw::network::http_client::normalize_probe_path(probe_path);
    let identity_path = blockcheckw::network::http_client::normalize_probe_path(identity_path);

    let config = Arc::new(CoreConfig {
        worker_count: 1,
        profiles_per_instance: 1,
        request_timeout: timeout,
        ..CoreConfig::default()
    });

    let cleanup = spawn_cleanup_handler(&config.nft_table);

    let mut screen = ui::Console::new();

    // Load strategies from vanilla file and sort by structural simplicity
    let mut strategies = match generator::load_tagged_strategies(std::path::Path::new(from_file)) {
        Ok(s) => s,
        Err(e) => {
            screen.error(&format!("failed to read {}: {e}", style(from_file).cyan()));
            fail_with(
                BrokenReason::InputUnreadable,
                domain,
                output,
                &config,
                &dns_mode.to_string(),
                &screen,
            );
        }
    };
    rank::sort_by_simplicity(&mut strategies);

    let mut flags = String::new();
    if take > 0 {
        flags.push_str(&format!(", --take {take}"));
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
            screen.error(&e.to_string());
            // ОТЧЁТ ПИШЕТСЯ И ПРИ ОТКАЗЕ. Прежде здесь был голый выход: продукт видел
            // отсутствие файла, читал его как `Unreadable` и ждал молча, не зная, что
            // сломалось имя, а не цель.
            fail_with(
                BrokenReason::DnsFailed,
                domain,
                output,
                &config,
                &dns_mode.to_string(),
                &screen,
            );
        }
    };

    // Эталоны: по две пробы через чистый egress для КАЖДОГО пути (решение 2 спеки
    // §6-тер), ПОСЛЕ резолва DNS и ДО подъёма движка — движок не должен работать
    // вхолостую, пока мы ходим за эталонами. Отсутствие одного эталона не отменяет
    // другого: без байтового эталона молчит доля, без эталона подлинности — `Mirage`.
    // Эталон снимается тем транспортом, каким идут пробы (`reference_protocol`); TLS нужен
    // всегда — им ходит контроль.
    let mut references = reference::References::default();
    match reference_via {
        Some(clean) => {
            let mut transports = vec![Protocol::HttpsTls12];
            for tagged in &strategies {
                let transport = reference::reference_protocol(tagged.protocol);
                if !transports.contains(&transport) {
                    transports.push(transport);
                }
            }
            for transport in transports {
                let byte_reference = reference::take_reference(
                    clean,
                    transport,
                    domain,
                    &ips,
                    timeout,
                    2,
                    &probe_path,
                )
                .await;
                let identity_reference = reference::take_reference(
                    clean,
                    transport,
                    domain,
                    &ips,
                    timeout,
                    2,
                    &identity_path,
                )
                .await;
                let scheme = match transport {
                    Protocol::Http => "http",
                    _ => "https",
                };
                screen.add_info_line(&match &byte_reference {
                    Some(_) => format!("  {scheme}: эталон объёма снят через чистый egress"),
                    None => format!(
                        "  {scheme}: эталон объёма НЕ снят: доли не будет, полнота — по завершённому телу"
                    ),
                });
                screen.add_info_line(&match &identity_reference {
                    Some(_) => format!("  {scheme}: эталон подлинности снят через чистый egress"),
                    None => format!(
                        "  {scheme}: эталон подлинности НЕ снят: Mirage не проверяется, круг судеб останется широким"
                    ),
                });
                references.insert(transport, byte_reference, identity_reference);
            }
        }
        None => screen.add_info_line(
            "  без --reference-via: полнота — по завершённому телу, заглушку (Mirage) не отличить",
        ),
    }

    // Remote gateway route setup
    if let Some(v) = via {
        if !v.check_reachable(&screen).await {
            std::process::exit(1);
        }
        v.add_routes(&ips).await;
    }

    // Check for conflicts
    let stopped = match handle_bypass_conflicts(&config.nft_table, &screen).await {
        Ok(result) => result,
        Err(()) => std::process::exit(1),
    };
    let stopped_service = match stopped {
        Some(mgr) => {
            set_stopped_service(&cleanup, mgr.clone()).await;
            Some(mgr)
        }
        None => None,
    };

    // Run check
    screen.newline();
    screen.println(&ui::section("Checking strategies (data transfer)"));
    screen.println(&format!(
        "  байтовая ось: {} ({passes}x)  |  ось подлинности: {}",
        style(&probe_path).bold(),
        style(&identity_path).bold(),
    ));
    let patience = Patience::new(
        std::time::Duration::from_millis(idle_ms),
        std::time::Duration::from_secs(timeout),
    );
    screen.println(&format!(
        "  терпение пробы: тишина {} мс, потолок {} с",
        style(idle_ms).bold(),
        style(timeout).bold(),
    ));
    screen.println(&format!(
        "  {}",
        style("Tip: use --take 10 to stop after 10 verified per protocol").yellow()
    ));

    let report = check::run_check(
        &config,
        &prereq.filter_mark,
        domain,
        &strategies,
        &ips,
        take,
        passes,
        patience,
        &references,
        &probe_path,
        &identity_path,
        &mut screen,
    )
    .await;
    tracing::Span::current().record("working", report.working);

    // Summary
    screen.newline();
    screen.println(&ui::section("Check summary"));
    screen.println(&format!(
        "  total: {} | working: {} | elapsed: {:.1}s",
        report.total,
        style(report.working).green().bold(),
        report.elapsed_secs,
    ));

    // Итог для человека: на роутере нет jq, а список, размазанный по логу между FAIL,
    // глазами не собрать.
    if report.inconclusive {
        screen.println(&format!(
            "  {} контроль без десинка прошёл сам — домен на этой линии не режется, обход не нужен",
            style("ВНИМАНИЕ:").yellow().bold(),
        ));
    } else {
        let working = check::working_by_protocol(&report);
        if working.is_empty() {
            screen.println(&format!(
                "  {}",
                style("рабочих стратегий не найдено").red().bold()
            ));
        }
        for (protocol, args) in working {
            screen.println(&format!(
                "{}",
                style(format!(
                    "=== Рабочие стратегии {protocol} ({}) ===",
                    args.len()
                ))
                .bold()
                .green()
            ));
            for (i, strategy) in args.iter().enumerate() {
                screen.println(&format!(
                    "  #{:<2} nfqws2 {}",
                    i + 1,
                    style(strategy).cyan()
                ));
            }
        }
    }

    // Output JSON — file first (stdout may break on pipe), then stdout
    let json = serde_json::to_string_pretty(&report).expect("report serialization");

    let path = output.map(String::from).unwrap_or_else(|| {
        let prefix = super::chrono_local_prefix();
        format!("{prefix}_check.json")
    });

    // Атомарно: отчёт читает ЧУЖОЙ процесс, и половина файла даёт ему `Unreadable` —
    // суждения о цели из этого не выходит, человек просто ждёт.
    match blockcheckw::system::atomic::write_atomic(std::path::Path::new(&path), &json) {
        Ok(()) => {
            screen.println(&format!(
                "  {} JSON report → {}",
                style("OK").green().bold(),
                style(&path).cyan(),
            ));
        }
        Err(e) => {
            screen.println(&format!(
                "  {} failed to write {}: {e}",
                style("ERROR:").red().bold(),
                style(&path).cyan(),
            ));
        }
    }

    // В терминал JSON не льём: он уже в файле выше и похоронил бы итог. В stdout он нужен
    // только тому, кто стоит дальше в пайпе или пишет в файл.
    if !std::io::stdout().is_terminal() {
        super::print_stdout_graceful(&json, &screen);
    }
    screen.newline();

    // Cleanup routes + restore zapret2
    if let Some(v) = via {
        v.cleanup().await;
    }
    if let Some(ref mgr) = stopped_service {
        restore_service(mgr, &screen).await;
    }
}

/// Записать отчёт о ПОЛОМКЕ ИНСТРУМЕНТА и выйти кодом этой поломки.
///
/// Зачем отдельной функцией: отказных путей несколько, а вести себя они обязаны одинаково.
/// Молчаливый выход — худшее, что мы можем сделать для того, кто нас позвал: у него на руках
/// остаётся отсутствие файла, неотличимое от «подбор ещё идёт», и он ждёт.
fn fail_with(
    reason: BrokenReason,
    domain: &str,
    output: Option<&str>,
    config: &CoreConfig,
    dns: &str,
    screen: &ui::Console,
) -> ! {
    let outcome = Outcome::Broken { reason };
    let code = outcome.exit_code();
    let report = CheckReport {
        schema: blockcheckw::dto::SCHEMA,
        outcome,
        run: RunProvenance::of(config, dns, blockcheckw::nfqws2::mark::is_embedded()),
        domain: domain.to_string(),
        timestamp: blockcheckw::pipeline::check::timestamp_iso(),
        total: 0,
        working: 0,
        elapsed_secs: 0.0,
        strategies: vec![],
        control: None,
        inconclusive: false,
    };
    let json = serde_json::to_string_pretty(&report).expect("report serialization");
    let path = output.map(String::from).unwrap_or_else(|| {
        let prefix = super::chrono_local_prefix();
        format!("{prefix}_check.json")
    });
    if let Err(e) = blockcheckw::system::atomic::write_atomic(std::path::Path::new(&path), &json) {
        screen.error(&format!(
            "не удалось записать отчёт об отказе в {path}: {e}"
        ));
    }
    // TODO(BL-041): process::exit минует force_flush в main → span'ы сбоя теряются.
    std::process::exit(code);
}
