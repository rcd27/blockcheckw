use std::time::Instant;

use console::style;
use tracing::{info_span, Instrument};

use crate::config::{CoreConfig, Protocol};
use crate::dto::{CheckReport, CheckedStrategy, ControlVerdict, VerifiedStrategy};
use crate::firewall::nft::{OwnedTable, SystemNft};
use crate::firewall::nftables;
use crate::network::http_client::{http_test_data, pick_random_ip, BodyMode, Ended, HttpResult};
use crate::nfqws2::plan::{FilterMark, Plan, QueueNum};
use crate::nfqws2::run::SystemNfqws2;
use crate::pipeline::fate::{self, Admits, Fate, Observed, ALL_FATES};
use crate::pipeline::observe;
use crate::pipeline::reference::{agrees, ContentPrint, Reference};
use crate::pipeline::verify::{self, Outcome};
use crate::strategy::generator::TaggedStrategy;
use crate::strategy::rank;
use crate::ui;

/// Прогнать стратегии из vanilla-отчёта с настоящей передачей данных и СУДИТЬ СУДЬБУ
/// цели по каждой.
///
/// Спека §6-тер: ДВЕ пробы, две работы. Байтовая ось (главная) идёт по `probe_path` и
/// повторяется `passes` (`M`) раз — из неё растут частота полной доставки и медиана
/// доли `вытянуто/эталон`. Ось подлинности идёт по `identity_path` ОДИН раз — только
/// она может сузить круг судеб до `[Fate::Mirage]`. Обе пробы судятся ОДНОЙ мерой у
/// контроля (без десинка) и у каждой стратегии — `measure_channel` ниже.
///
/// В отчёт идёт всякая НАБЛЮДЁННАЯ стратегия — та, чей круг судеб (ось подлинности) уже
/// полного, — а не только прошедшая. Порядок выдачи задаёт `rank::fate_order`: частота
/// полной доставки, медиана доли, ступень круга, простота (спека §6-тер). `--take N`
/// считает только ПРОШЕДШИЕ (`working`): он останавливает ПОИСК, а не урезает выдачу, и
/// когда не прошёл никто, список всё равно выдаётся ранжированным, а не пустым.
///
/// `passes` больше не сокращается первым провалом (решение 3 спеки §6-тер): частота
/// требует всех `M` измерений, иначе `2/3` неотличимо от `0/3`. `M = 0` — честный исход
/// «не наблюдали», а не паника (`all_passes_succeeded`).
#[allow(clippy::too_many_arguments)] // две оси и их эталоны добавлены спекой §6-тер поверх уже широкого набора
pub async fn run_check(
    config: &CoreConfig,
    witness: &FilterMark,
    domain: &str,
    strategies: &[TaggedStrategy],
    ips: &[String],
    take: usize,
    passes: usize,
    byte_reference: Option<&Reference>,
    identity_reference: Option<&Reference>,
    probe_path: &str,
    identity_path: &str,
    screen: &mut ui::Console,
) -> CheckReport {
    let start = Instant::now();

    let table = match nftables::prepare_table(&SystemNft, &config.nft_table).await {
        Ok(t) => t,
        Err(e) => {
            screen.println(&format!(
                "  {} failed to prepare nftables: {e}",
                style("ERROR:").red().bold(),
            ));
            return CheckReport {
                domain: domain.to_string(),
                timestamp: timestamp_iso(),
                total: strategies.len(),
                working: 0,
                elapsed_secs: start.elapsed().as_secs_f64(),
                strategies: vec![],
                control: None,
                inconclusive: false,
            };
        }
    };

    // КОНТРОЛЬ. `fwmark = 0` не совпадает с правилом диспетчеризации, и проба идёт мимо
    // движка: это и есть «а что будет без десинка вообще». Без него всякое «работает»
    // ниже может оказаться свойством линии, а не стратегии. Судится ТОЙ ЖЕ мерой, что и
    // стратегии (спека §6-бис/6-тер) — иначе на линии без эталона контроль никогда не
    // «проходит», и `inconclusive` не срабатывает, сколько бы домен ни открывался без
    // десинка. Контроль не кандидат: в гистограмму устойчивости (`stability_of`) не идёт.
    let control_ip = pick_random_ip(ips).expect("ips проверены вызывающим");
    let control_reading = measure_channel(
        Protocol::HttpsTls12,
        domain,
        control_ip,
        0,
        config.request_timeout,
        probe_path,
        identity_path,
        passes,
        byte_reference,
        identity_reference,
        None,
    )
    .await;
    let control_ok = control_reading
        .byte_passes
        .iter()
        .filter(|p| p.full_delivery)
        .count();
    let inconclusive = all_passes_succeeded(control_ok, control_reading.byte_passes.len(), passes);

    if inconclusive {
        screen.println(&format!(
            "  {} контроль без десинка сам прошёл — домен на этой линии не режется. \
             О стратегиях этот прогон молчит.",
            style("ВНИМАНИЕ:").yellow().bold(),
        ));
    }

    let control = Some(ControlVerdict {
        observed: control_reading.identity_observed.name().to_string(),
        admits: control_reading
            .identity_circle
            .0
            .iter()
            .map(|f| format!("{f:?}"))
            .collect(),
    });

    screen.println(&format!(
        "  {}",
        style(format!(
            "Verifying {} strategies ({passes} passes on {probe_path}, identity via {identity_path})",
            strategies.len()
        ))
        .bold()
        .underlined(),
    ));

    // В отчёт идёт всякая НАБЛЮДЁННАЯ стратегия, а не только приведшая цель к `Good`
    // (спека §6.2). Порядок задаёт `rank::fate_order` ниже.
    let mut verified: Vec<VerifiedStrategy> = Vec::new();
    // Ранг по судьбе, нога в ногу с `verified`: запись сюда происходит ровно там же,
    // где `verified.push`, иначе `zip` ниже разъедется.
    let mut judged: Vec<rank::Ranked> = Vec::new();
    let mut checked_count: usize = 0;
    // Сколько строк ПРОШЛО (`working`) — это и есть `working` отчёта, а вовсе не длина
    // списка.
    let mut working_count: usize = 0;
    // --take: count strategies that PASSED (`working`), per protocol
    let mut perfect_per_proto: std::collections::HashMap<Protocol, usize> =
        std::collections::HashMap::new();
    // Раскладка корпуса по устойчивости (решение 7 спеки §6-тер): строка на стратегию,
    // исход на каждый из `M` проходов байтовой оси. `stability_of`/`report_stability`
    // были сохранены ровно для этого, когда их вызов сняли при `passes == 1`.
    let mut rows: Vec<Vec<Outcome>> = Vec::new();

    for (idx, tagged) in strategies.iter().enumerate() {
        // Skip this protocol if we already have enough perfect strategies
        if take > 0 {
            let perfect = perfect_per_proto
                .get(&tagged.protocol)
                .copied()
                .unwrap_or(0);
            if perfect >= take {
                continue;
            }
        }

        let args_str = tagged.args.join(" ");
        if checked_count > 0 {
            screen.println(&format!("  {}", style("─".repeat(60)).dim()));
        }
        screen.println(&format!(
            "  [{}/{}] {} nfqws2 {}",
            idx + 1,
            strategies.len(),
            style(tagged.protocol.to_string()).bold(),
            style(&args_str).cyan(),
        ));

        checked_count += 1;

        // Span на проверку конкретной стратегии (ребёнок bcw.check). Здесь живёт
        // причина FAIL (connect/timeout) — то, ради чего трейсинг и затевался.
        let strategy_span = info_span!(
            "bcw.check.strategy",
            protocol = %tagged.protocol,
            args = %args_str,
            status = tracing::field::Empty,
            reason = tracing::field::Empty,
        );
        let (checked, outcomes) = async {
            check_single_strategy(
                config,
                witness,
                &table,
                domain,
                tagged,
                ips,
                passes,
                byte_reference,
                identity_reference,
                probe_path,
                identity_path,
                checked_count,
            )
            .await
        }
        .instrument(strategy_span.clone())
        .await;

        rows.push(outcomes);

        if checked.working {
            strategy_span.record("status", "working");
            screen.println(&format!(
                "    {} {}/{} full delivery, median {}ms, share {}",
                style("OK").green().bold(),
                checked.passes_ok,
                checked.passes_total,
                checked.latency_ms,
                checked
                    .median_share
                    .map(|s| format!("{s:.2}"))
                    .unwrap_or_else(|| "—".to_string()),
            ));
            *perfect_per_proto.entry(tagged.protocol).or_insert(0) += 1;
            working_count += 1;
        } else {
            let reason = checked.error.as_deref().unwrap_or("failed");
            strategy_span.record("status", "fail");
            strategy_span.record("reason", reason);
            screen.println(&format!(
                "    {} {}/{} full delivery {} [{}]",
                style("FAIL").red().bold(),
                checked.passes_ok,
                checked.passes_total,
                style(reason).red(),
                style(circle_name(checked.circle)).dim(),
            ));
        }

        // Критерий попадания в отчёт: стратегия либо наблюдена (ось подлинности), либо
        // работает (ось байтов). Ось подлинности решает, что показать в `admits`, но не
        // решает, показывать ли вообще — это решает `working`. Спека §6.2: рабочая
        // стратегия не имеет права отсутствовать в выдаче, человек видит её вместо
        // пустого списка.
        if belongs_in_report(checked.circle, checked.working) {
            verified.push(VerifiedStrategy {
                protocol: tagged.protocol.to_string(),
                args: args_str.clone(),
                coverage: tagged.coverage,
                success_rate: match checked.passes_total {
                    0 => 0.0,
                    total => checked.passes_ok as f64 / total as f64,
                },
                median_latency_ms: checked.latency_ms,
                median_speed_kbps: checked.speed_kbps,
                passes_ok: checked.passes_ok,
                passes_total: checked.passes_total,
                median_share: checked.median_share,
                observed: checked.observed.clone(),
                admits: checked.admits.clone(),
                working: checked.working,
            });
            judged.push(rank::Ranked {
                full_delivery: (checked.passes_ok, checked.passes_total),
                median_share: checked.median_share,
                // Круг едет в `CheckedStrategy.circle` значением — строки из `admits`
                // для сортировки не годятся.
                admits: checked.circle,
                simplicity: rank::simplicity_key(&args_str),
            });
        }

        // Check if all protocols have reached the take limit
        if take > 0 {
            let all_protos: std::collections::HashSet<Protocol> =
                strategies.iter().map(|s| s.protocol).collect();
            let all_satisfied = all_protos
                .iter()
                .all(|p| perfect_per_proto.get(p).copied().unwrap_or(0) >= take);
            if all_satisfied {
                screen.println(&format!(
                    "  {} found {} passing strategies per protocol, stopping",
                    style("--take").bold(),
                    take,
                ));
                break;
            }
        }
    }

    // Раскладка корпуса по устойчивости — решение 7 спеки §6-тер: `M` проходов теперь
    // измеряет частоту, а не голосует, и `stability_of` наконец видит флапающих, а не
    // только «всегда»/«никогда».
    let stability = verify::stability_of(&rows, passes);
    verify::report_stability(&stability, domain, screen);

    // Порядок обхода был по простоте — это разумно для ПРОБ. Порядок ВЫДАЧИ задаёт
    // измеренное: до этой строки ранг не знал ни одного факта о канале.
    let mut order: Vec<(rank::Ranked, VerifiedStrategy)> = verified
        .into_iter()
        .zip(judged)
        .map(|(strategy, ranked)| (ranked, strategy))
        .collect();
    order.sort_by(|a, b| rank::fate_order(&a.0, &b.0));
    let verified: Vec<VerifiedStrategy> = order.into_iter().map(|(_, s)| s).collect();

    // Cleanup
    let _ = table.drop_table(&SystemNft).await;

    CheckReport {
        domain: domain.to_string(),
        timestamp: timestamp_iso(),
        total: checked_count,
        working: working_count,
        elapsed_secs: start.elapsed().as_secs_f64(),
        strategies: verified,
        control,
        inconclusive,
    }
}

/// Итог одной пробы байтовой оси (`--probe-path`, одна из `M`).
struct BytePassReading {
    bytes: u64,
    latency_ms: u64,
    /// `fate::passed(observed, ended, identity_circle) И agrees(byte_reference, print)`
    /// — «полная доставка», решение 6 спеки §6-тер: `passed` про связность и про
    /// подлинность (не `[Mirage]`), `agrees` про объём.
    full_delivery: bool,
    /// `None` — эталона объёма нет, доли не существует (решение 2 спеки §6-тер).
    share: Option<f64>,
    /// Короткое имя причины (для гистограммы `BCW_CAUSE_HISTOGRAM`). `None` при
    /// полной доставке.
    reason: Option<String>,
    /// Человекочитаемое сообщение для экрана. `None` при полной доставке.
    message: Option<String>,
}

/// Итог одной «беседы» через канал: ось подлинности (один раз, `--identity-path`) плюс
/// `M` проб байтовой оси (`--probe-path`). Контроль (без десинка) и стратегия судятся
/// этой же структурой, собранной одной и той же функцией (`measure_channel`) — иначе они
/// мерятся разными мерами (спека §6-бис).
struct ChannelReading {
    identity_observed: Observed,
    /// Только эта проба может сузить круг до `[Fate::Mirage]` (спека §6-тер).
    identity_circle: Admits,
    byte_passes: Vec<BytePassReading>,
}

/// Короткое имя причины отказа связности — с провода, где оно есть, иначе по тому, что
/// увидел `interpret_check_result` сверху. Чистая функция: `Cause` строится без сети.
fn connectivity_cause_name(
    cause: Option<crate::network::cause::Cause>,
    named: Option<&str>,
) -> String {
    match (cause, named) {
        (Some(c), _) => c.name(),
        (None, Some(name)) => name.to_string(),
        (None, None) => "unknown".to_string(),
    }
}

/// Почему проход байтовой оси не засчитан полной доставкой. Порядок — от более
/// фундаментального факта к менее: сперва не встал ли разговор вообще (связность),
/// потом не разошёлся ли ОБЪЁМ с эталоном, и только потом — не опровергла ли ПОДЛИННОСТЬ
/// (ось `--identity-path`) весь круг разом. Три причины различны и не должны схлопнуться
/// в одно «failed»: сеть, содержимое и личность ресурса — разные болезни разного лечения.
fn byte_pass_reason(
    connectivity_ok: bool,
    agreed: bool,
    identity_circle: Admits,
    cause_name: Option<String>,
) -> String {
    if !connectivity_ok {
        return cause_name.unwrap_or_else(|| "unknown".to_string());
    }
    if !agreed {
        return "content_diverged_from_reference".to_string();
    }
    if matches!(identity_circle.0, [Fate::Mirage]) {
        return "identity_mirage".to_string();
    }
    "unknown".to_string()
}

/// Медиана доли `вытянуто/эталон` по `M` проходам байтовой оси. `None`, если хоть один
/// проход не имеет доли (эталона объёма не было вовсе — решение 2 спеки §6-тер: доли
/// нет ни у одного прохода, либо у всех, поскольку эталон общий на весь прогон) или
/// проходов не было.
fn median_share_of(shares: &[Option<f64>]) -> Option<f64> {
    if shares.is_empty() || shares.iter().any(Option::is_none) {
        return None;
    }
    let values: Vec<f64> = shares
        .iter()
        .map(|s| s.expect("checked all Some above"))
        .collect();
    Some(crate::pipeline::reference::median(&values))
}

/// Пройти ОБЕ пробы спеки §6-тер по уже установленному пути: ось подлинности один раз
/// (`identity_path`), байтовую ось `passes` раз (`probe_path`), БЕЗ раннего выхода на
/// первом провале (решение 3: частота требует всех `M` измерений). `mark = 0` — контроль
/// без десинка; иначе — метка профиля стратегии. `log_index` — позиция стратегии в
/// прогоне для журнала (`BCW_CAUSE_HISTOGRAM`); `None` у контроля — он не кандидат.
#[allow(clippy::too_many_arguments)] // спека §6-тер: две пробы, два эталона, два пути
async fn measure_channel(
    protocol: Protocol,
    domain: &str,
    ip: &str,
    mark: u32,
    timeout: u64,
    probe_path: &str,
    identity_path: &str,
    passes: usize,
    byte_reference: Option<&Reference>,
    identity_reference: Option<&Reference>,
    log_index: Option<usize>,
) -> ChannelReading {
    // Ось подлинности: один раз, детерминированный путь. Только она сужает до `Mirage`.
    let identity_result = http_test_data(
        protocol,
        domain,
        ip,
        mark,
        timeout,
        BodyMode::Unlimited,
        None,
        identity_path,
    )
    .await;
    let identity_bytes = identity_result.size_download.unwrap_or(0);
    let identity_observed = fate::observe(
        observe::connected_of(identity_result.cause),
        observe::delivery_of(identity_bytes, identity_result.ended),
    );
    let identity_circle = fate::narrow(fate::Evidence {
        observed: identity_observed,
        sag: observe::sag_of(&identity_result.windows),
        attempts: 1,
        reference: identity_reference,
        print: ContentPrint::of(&identity_result),
    });

    // Байтовая ось: `M` проходов, ни один не пропущен первым провалом.
    let mut byte_passes = Vec::with_capacity(passes);
    for pass_idx in 0..passes {
        let started_at = verify::now_epoch();
        let pass_start = Instant::now();
        let result = http_test_data(
            protocol,
            domain,
            ip,
            mark,
            timeout,
            BodyMode::Unlimited,
            None,
            probe_path,
        )
        .await;
        let latency_ms = pass_start.elapsed().as_millis() as u64;
        let bytes = result.size_download.unwrap_or(0);
        let observed = fate::observe(
            observe::connected_of(result.cause),
            observe::delivery_of(bytes, result.ended),
        );
        let connectivity_ok = observed == Observed::Bytes && result.ended != Ended::BodyError;
        let agreed = byte_reference
            .map(|r| agrees(r, &ContentPrint::of(&result)))
            .unwrap_or(false);
        // «Проба засчитана, если passed И agrees» — решение 6 спеки §6-тер. `passed`
        // читает круг ПОДЛИННОСТИ (`identity_circle`), а не круг этого прохода: только
        // ось подлинности вправе сказать `Mirage`.
        let full_delivery = fate::passed(observed, result.ended, identity_circle) && agreed;
        let share = byte_reference.map(|r| r.share(bytes));

        let (_permissive, message_from_interpret, named) = interpret_check_result(&result, domain);
        let cause_name = (!connectivity_ok).then(|| connectivity_cause_name(result.cause, named));
        let reason = (!full_delivery)
            .then(|| byte_pass_reason(connectivity_ok, agreed, identity_circle, cause_name));
        let message = if full_delivery {
            None
        } else if !connectivity_ok {
            message_from_interpret
        } else if !agreed {
            Some(format!("объём {bytes} байт разошёлся с эталоном"))
        } else {
            Some("подлинность разошлась с эталоном (Mirage)".to_string())
        };

        if let Some(index) = log_index {
            let outcome = match &reason {
                None => Outcome::Passed,
                Some(name) => Outcome::Failed(name.clone()),
            };
            verify::log_pass(started_at, index, pass_idx + 1, &outcome);
        }

        byte_passes.push(BytePassReading {
            bytes,
            latency_ms,
            full_delivery,
            share,
            reason,
            message,
        });
    }

    ChannelReading {
        identity_observed,
        identity_circle,
        byte_passes,
    }
}

/// Check one strategy: nfqws2 → nftables → обе пробы (спека §6-тер) → cleanup.
/// Возвращает строку отчёта и исходы `M` проходов байтовой оси — материал для
/// `verify::stability_of` (решение 7 спеки §6-тер).
#[allow(clippy::too_many_arguments)] // две оси и их эталоны добавлены спекой §6-тер поверх уже широкого набора
async fn check_single_strategy(
    config: &CoreConfig,
    witness: &FilterMark,
    table: &OwnedTable,
    domain: &str,
    tagged: &TaggedStrategy,
    ips: &[String],
    passes: usize,
    byte_reference: Option<&Reference>,
    identity_reference: Option<&Reference>,
    probe_path: &str,
    identity_path: &str,
    log_index: usize,
) -> (CheckedStrategy, Vec<Outcome>) {
    let protocol = tagged.protocol;
    let args_str = tagged.args.join(" ");

    // Движок не поднялся — значит мы не наблюдали ничего, и сужать не из чего.
    // Круг остаётся полным (то же самое, что `Observed::Unobserved.admits()`).
    let make_failed = |error: String| {
        (
            CheckedStrategy {
                failure: Some("engine_error".to_string()),
                protocol: protocol.to_string(),
                args: args_str.clone(),
                working: false,
                bytes_downloaded: 0,
                latency_ms: 0,
                speed_kbps: 0.0,
                error: Some(error),
                observed: Observed::Unobserved.name().to_string(),
                admits: ALL_FATES.iter().map(|f| format!("{f:?}")).collect(),
                circle: Admits(&ALL_FATES),
                passes_ok: 0,
                passes_total: 0,
                median_share: None,
            },
            Vec::new(),
        )
    };

    // 1. Собрать план из одного профиля и поднять движок
    let env = config.nfqws2_env();
    let queue = QueueNum::new(config.base_qnum);
    let plan = Plan::from_one(witness, queue, &tagged.args);
    let mark = plan.profiles()[0].mark;

    let mut instance = match SystemNfqws2::start(&env, &plan).await {
        Ok(i) => i,
        Err(e) => return make_failed(format!("nfqws2: {e}")),
    };

    // 2. Дождаться, пока движок реально забиндит очередь
    let ready = match SystemNfqws2::wait_ready(&mut instance).await {
        Ok(r) => r,
        Err(e) => {
            SystemNfqws2::stop(instance).await;
            return make_failed(format!("nfqws2: {e}"));
        }
    };

    // 3. Поставить диспетчеризацию — только теперь, когда слушатель точно есть
    if let Err(e) = nftables::apply_dispatch(
        &SystemNft,
        table,
        &ready,
        &plan.dispatch(protocol.port()),
        ips,
    )
    .await
    {
        // Батч атомарен, но `Err` тут может значить и таймаут
        // `run_process_stdin` (15с): нельзя быть уверенным, что nft не успел
        // применить правила до обрыва. Снимаем диспетчеризацию на всякий
        // случай, прежде чем убивать слушателя — иначе `queue to N` рискует
        // остаться стоять без него до конца всего прогона.
        nftables::remove_dispatch(&SystemNft, table).await;
        SystemNfqws2::stop(instance).await;
        return make_failed(format!("nftables: {e}"));
    }

    // 4. Обе пробы спеки §6-тер. `ips` гарантированно непусты: `apply_dispatch` выше уже
    // прогнал `validate_ip_set`, отвергающий пустой список, и вернул `Ok`.
    let ip = pick_random_ip(ips).expect("apply_dispatch already validated ips is non-empty");

    let reading = measure_channel(
        protocol,
        domain,
        ip,
        mark.so_mark(),
        config.request_timeout,
        probe_path,
        identity_path,
        passes,
        byte_reference,
        identity_reference,
        Some(log_index),
    )
    .await;

    // 5. Cleanup: снять диспетчеризацию, затем убить nfqws2 (best-effort)
    nftables::remove_dispatch(&SystemNft, table).await;
    SystemNfqws2::stop(instance).await;

    // 6. Свести обе пробы в строку отчёта.
    let outcomes: Vec<Outcome> = reading
        .byte_passes
        .iter()
        .map(|p| match &p.reason {
            None => Outcome::Passed,
            Some(name) => Outcome::Failed(name.clone()),
        })
        .collect();

    let passes_ok = reading
        .byte_passes
        .iter()
        .filter(|p| p.full_delivery)
        .count();
    let passes_total = reading.byte_passes.len();
    // `working` спеки §6-тер: подлинность не опровергнута И полная доставка КАЖДЫЙ раз
    // из `M`. `identity_circle == [Mirage]` уже зашит в `full_delivery` каждого прохода
    // через `fate::passed` (решение 6) — отдельной проверки здесь не нужно.
    let working = all_passes_succeeded(passes_ok, passes_total, passes);

    let shares: Vec<Option<f64>> = reading.byte_passes.iter().map(|p| p.share).collect();
    let median_share = median_share_of(&shares);

    let mut ok_bytes: Vec<u64> = reading
        .byte_passes
        .iter()
        .filter(|p| p.full_delivery)
        .map(|p| p.bytes)
        .collect();
    let mut ok_latency: Vec<u64> = reading
        .byte_passes
        .iter()
        .filter(|p| p.full_delivery)
        .map(|p| p.latency_ms)
        .collect();
    ok_bytes.sort_unstable();
    ok_latency.sort_unstable();
    // Медиана по ПОЛНОЙ ДОСТАВКЕ; её может не быть вовсе — наблюдённая, но не прошедшая
    // стратегия тоже идёт в отчёт, и последний проход честнее нуля.
    let bytes_downloaded = ok_bytes
        .get(ok_bytes.len() / 2)
        .copied()
        .or_else(|| reading.byte_passes.last().map(|p| p.bytes))
        .unwrap_or(0);
    let latency_ms = ok_latency
        .get(ok_latency.len() / 2)
        .copied()
        .or_else(|| reading.byte_passes.last().map(|p| p.latency_ms))
        .unwrap_or(0);
    let speed_kbps = if working && latency_ms > 0 {
        (bytes_downloaded as f64 / 1024.0) / (latency_ms as f64 / 1000.0)
    } else {
        0.0
    };

    let last_failed = reading.byte_passes.iter().rev().find(|p| !p.full_delivery);
    let error = last_failed.and_then(|p| p.message.clone());
    let failure = if working {
        None
    } else {
        Some(
            last_failed
                .and_then(|p| p.reason.clone())
                .unwrap_or_else(|| "unknown".to_string()),
        )
    };

    let checked = CheckedStrategy {
        protocol: protocol.to_string(),
        args: args_str,
        working,
        bytes_downloaded,
        latency_ms,
        speed_kbps,
        error,
        failure,
        observed: reading.identity_observed.name().to_string(),
        admits: reading
            .identity_circle
            .0
            .iter()
            .map(|f| format!("{f:?}"))
            .collect(),
        circle: reading.identity_circle,
        passes_ok,
        passes_total,
        median_share,
    };

    (checked, outcomes)
}

/// Check-specific interpretation of HTTP results.
///
/// Unlike scan's `interpret_http_result`, this is simple and permissive:
/// - Error (timeout, reset) → FAIL (DPI blocked us)
/// - HTTP 400 → FAIL (server received our fakes — broken strategy)
/// - Redirect to a different domain → FAIL (ISP captive portal / block page)
/// - Any other HTTP response → OK (strategy works)
fn interpret_check_result(
    result: &HttpResult,
    domain: &str,
) -> (bool, Option<String>, Option<&'static str>) {
    if let Some(err) = &result.error {
        return (false, Some(err.clone()), None);
    }

    match result.status_code {
        Some(400) => (
            false,
            Some("server received fakes (HTTP 400)".to_string()),
            Some("server_receives_fakes"),
        ),
        Some(code @ (301 | 302 | 307 | 308)) => {
            let location = extract_redirect_location(&result.headers);
            if location.to_lowercase().contains(&domain.to_lowercase()) {
                (true, None, None)
            } else {
                (
                    false,
                    Some(format!(
                        "redirect to foreign domain: {location} (HTTP {code})"
                    )),
                    Some("foreign_redirect"),
                )
            }
        }
        Some(code) => {
            let size = result.size_download.unwrap_or(0);
            if size == 0 {
                (
                    false,
                    Some(format!("empty body (HTTP {code})")),
                    Some("empty_body"),
                )
            } else {
                (true, None, None)
            }
        }
        None => (false, Some("no response".to_string()), Some("no_response")),
    }
}

/// Extract Location header value from raw headers string.
fn extract_redirect_location(headers: &str) -> String {
    headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("location:"))
        .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default()
}

fn timestamp_iso() -> String {
    crate::pipeline::test_report::chrono_like_timestamp()
}

/// Стратегия была НАБЛЮДЕНА: её круг судеб уже полного. Полный круг — это
/// `Observed::Unobserved`, то есть «о судьбе ничего»; такая строка не ранжируется вовсе
/// (спека §6) и в отчёт не идёт. Всё остальное идёт — включая `Mirage`, `Trap` и `Dead`:
/// они не рабочие, но они УСТАНОВЛЕНЫ, и человек видит лучшее из имеющегося вместо
/// пустого списка.
fn observed_at_all(circle: Admits) -> bool {
    circle.0 != ALL_FATES.as_slice()
}

/// Решение о попадании стратегии в отчёт. Ось подлинности (круг судеб) решает, что показать
/// в `admits`, но НЕ решает, показывать ли вообще. `working` — вердикт самого продукта:
/// стратегия, признанная рабочей, не имеет права отсутствовать в выдаче, даже если проба
/// подлинности флапнула. Спека §6.2: человек видит лучшее из имеющегося вместо пустого
/// списка.
fn belongs_in_report(circle: Admits, working: bool) -> bool {
    observed_at_all(circle) || working
}

/// Круг судеб одной строкой — для экрана. Одна судьба значит «сузили», несколько —
/// «не сузили», и человеку надо видеть разницу: «не наблюдали» ≠ «наблюдали пустоту».
fn circle_name(circle: Admits) -> String {
    match observed_at_all(circle) {
        false => "не наблюдали".to_string(),
        true => circle
            .0
            .iter()
            .map(|f| format!("{f:?}"))
            .collect::<Vec<_>>()
            .join("|"),
    }
}

/// Все проходы стратегии прошли. Наивная проверка `ok_count == total_run &&
/// ok_count == passes` истинна и при `passes == 0` (`0 == 0 && 0 == 0`) — то есть
/// «все прошли», хотя не прошло ни одного, и `speeds`/`latencies` тогда пусты:
/// индексация медианы паникует. `ok_count > 0` — унаследованный дефект закрыт
/// намеренно, а не только побочным эффектом хардкода `--passes` в единицу.
fn all_passes_succeeded(ok_count: usize, total_run: usize, passes: usize) -> bool {
    ok_count > 0 && ok_count == total_run && ok_count == passes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_zero_does_not_masquerade_as_all_passes_ok() {
        // Унаследованный дефект: `--passes 0` даёт `ok_count == total_run == passes == 0`,
        // старая проверка читала это как «все проходы OK» и падала на индексации пустых
        // `speeds`/`latencies`. `all_passes_succeeded` обязана вернуть false без единого
        // прохода — иначе `bcw check --passes 0` снова паникует.
        assert!(!all_passes_succeeded(0, 0, 0));
    }

    #[test]
    fn all_passes_succeeded_true_when_every_pass_ok() {
        assert!(all_passes_succeeded(3, 3, 3));
    }

    #[test]
    fn not_all_passes_succeeded_when_early_exit_fired() {
        // Первый провал остановил цикл раньше, чем добежали до `passes`.
        assert!(!all_passes_succeeded(0, 1, 3));
    }

    #[test]
    fn test_speed_calculation() {
        // 10240 bytes in 1000ms = 10 KB/s
        let latency_ms: u64 = 1000;
        let bytes: u64 = 10240;
        let speed = (bytes as f64 / 1024.0) / (latency_ms as f64 / 1000.0);
        assert!((speed - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_speed_zero_latency() {
        let latency_ms: u64 = 0;
        let speed = if latency_ms > 0 {
            (1024.0_f64 / 1024.0) / (latency_ms as f64 / 1000.0)
        } else {
            0.0
        };
        assert_eq!(speed, 0.0);
    }

    #[test]
    fn an_empty_body_failure_is_named_and_not_left_unknown() {
        let result = HttpResult {
            status_code: Some(200),
            headers: String::new(),
            error: None,
            size_download: Some(0),
            cause: None,
            ended: Ended::BodyComplete,
            windows: Vec::new(),
        };
        let (working, _, failure) = interpret_check_result(&result, "rutracker.org");
        assert!(!working);
        assert_eq!(
            failure,
            Some("empty_body"),
            "пустое тело при живом коде — вероятная обрезка данных цензором; \
             без имени она уходит в «unknown» и перестаёт быть уликой"
        );
    }

    #[test]
    fn a_redirect_to_a_foreign_domain_is_named_apart() {
        let result = HttpResult {
            status_code: Some(302),
            headers: "Location: http://blocked.gov.ru/\r\n".to_string(),
            error: None,
            size_download: None,
            cause: None,
            ended: Ended::NeverStarted,
            windows: Vec::new(),
        };
        let (working, _, failure) = interpret_check_result(&result, "rutracker.org");
        assert!(!working);
        assert_eq!(failure, Some("foreign_redirect"));
    }

    #[test]
    fn timestamp_is_utc_iso_8601() {
        let timestamp = timestamp_iso();
        assert_eq!(timestamp.len(), 20);
        assert_eq!(&timestamp[10..11], "T");
        assert!(timestamp.ends_with('Z'));
        assert!(!timestamp[..19].chars().all(|ch| ch.is_ascii_digit()));
    }

    /// `CheckedStrategy` НЕ сериализуется ничем: `CheckReport.strategies` — это
    /// `Vec<VerifiedStrategy>`. Прежний тест зеленел на сериализации структуры, которой
    /// никто не сериализует, и потому пропустил ровно то, что ревью и нашло: судьба до
    /// JSON не доезжала. Тест перенаправлен на ту структуру, что в отчёт и попадает.
    #[test]
    fn a_report_row_carries_the_fate_it_was_judged_by() {
        let vs = VerifiedStrategy {
            protocol: "HTTPS/TLS1.2".to_string(),
            args: "--payload=tls_client_hello --lua-desync=fake".to_string(),
            coverage: 1,
            success_rate: 1.0,
            median_latency_ms: 340,
            median_speed_kbps: 147.2,
            passes_ok: 1,
            passes_total: 1,
            median_share: Some(1.02),
            observed: "Bytes".to_string(),
            admits: vec!["Good".to_string()],
            working: true,
        };
        let json = serde_json::to_string(&vs).unwrap();
        assert!(json.contains("\"observed\":\"Bytes\""), "{json}");
        assert!(json.contains("\"admits\":[\"Good\"]"), "{json}");
        assert!(json.contains("\"working\":true"), "{json}");
        assert!(json.contains("\"median_share\":1.02"), "{json}");
    }

    #[test]
    fn a_row_that_is_not_working_still_carries_its_fate_into_json() {
        // Ради этого отчёт и расширен: отказ движка, `Mirage`, `Trap` и таймаут прежде
        // ОДИНАКОВО отсутствовали в JSON, и «не наблюдали» было неотличимо от
        // «наблюдали пустоту».
        let vs = VerifiedStrategy {
            protocol: "HTTPS/TLS1.2".to_string(),
            args: "--lua-desync=fake".to_string(),
            coverage: 1,
            success_rate: 0.0,
            median_latency_ms: 120,
            median_speed_kbps: 0.0,
            passes_ok: 0,
            passes_total: 1,
            median_share: None,
            observed: "Bytes".to_string(),
            admits: vec!["Mirage".to_string()],
            working: false,
        };
        let json = serde_json::to_string(&vs).unwrap();
        assert!(json.contains("\"admits\":[\"Mirage\"]"), "{json}");
        assert!(json.contains("\"working\":false"), "{json}");
        assert!(
            json.contains("\"median_share\":null"),
            "нет эталона объёма — доли не существует, а не «ноль»: {json}"
        );
    }

    #[test]
    fn a_strategy_whose_circle_is_still_full_is_not_in_the_report() {
        // Полный круг значит «о судьбе ничего». Это не последнее место — это отсутствие
        // места (спека §6): такая строка не ранжируется и в отчёт не идёт.
        assert!(!observed_at_all(Admits(&ALL_FATES)));
        assert_eq!(circle_name(Admits(&ALL_FATES)), "не наблюдали");
    }

    #[test]
    fn every_narrowed_circle_is_in_the_report_not_only_good() {
        // Ровно то, чего не хватало: без `--reference-via` круг не сужается до `[Good]`
        // ни у кого, и критерий `working` оставлял отчёт пустым на всех ~300 стратегиях.
        for circle in [
            [Fate::Good].as_slice(),
            [Fate::Grinding].as_slice(),
            [Fate::Mirage].as_slice(),
            [Fate::Trap].as_slice(),
            [Fate::Dead].as_slice(),
            // Круг из трёх — то, что выдаёт `narrow` без эталона: уже полного, значит
            // наблюдение состоялось.
            [Fate::Mirage, Fate::Grinding, Fate::Good].as_slice(),
        ] {
            assert!(observed_at_all(Admits(circle)), "круг {circle:?}");
        }
        assert_eq!(
            circle_name(Admits(&[Fate::Mirage, Fate::Grinding, Fate::Good])),
            "Mirage|Grinding|Good"
        );
    }

    #[test]
    fn test_check_report_serialization() {
        let report = CheckReport {
            domain: "rutracker.org".to_string(),
            timestamp: "2026-03-21T12:00:00+03:00".to_string(),
            total: 2,
            working: 1,
            elapsed_secs: 5.3,
            strategies: vec![],
            control: None,
            inconclusive: false,
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"domain\": \"rutracker.org\""));
        assert!(json.contains("\"working\": 1"));
    }

    #[test]
    fn test_check_report_with_best() {
        let best = VerifiedStrategy {
            protocol: "HTTPS/TLS1.2".to_string(),
            args: "--payload=tls_client_hello --lua-desync=fake".to_string(),
            coverage: 1,
            success_rate: 1.0,
            median_latency_ms: 320,
            median_speed_kbps: 5.5,
            passes_ok: 3,
            passes_total: 3,
            median_share: Some(1.0),
            observed: "Bytes".to_string(),
            admits: vec!["Good".to_string()],
            working: true,
        };
        let report = CheckReport {
            domain: "rutracker.org".to_string(),
            timestamp: "2026-03-21T12:00:00+03:00".to_string(),
            total: 5,
            working: 3,
            elapsed_secs: 10.0,
            strategies: vec![best],
            control: None,
            inconclusive: false,
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"success_rate\": 1.0"));
    }

    #[test]
    fn test_verified_strategy_serialization() {
        let vs = VerifiedStrategy {
            protocol: "HTTP".to_string(),
            args: "--payload=http_req --lua-desync=fake".to_string(),
            coverage: 1,
            success_rate: 0.67,
            median_latency_ms: 450,
            median_speed_kbps: 2.5,
            passes_ok: 2,
            passes_total: 3,
            median_share: Some(0.67),
            observed: "Bytes".to_string(),
            admits: vec!["Grinding".to_string()],
            working: false,
        };
        let json = serde_json::to_string(&vs).unwrap();
        assert!(json.contains("\"success_rate\":0.67"));
        assert!(json.contains("\"median_speed_kbps\":2.5"));
        assert!(json.contains("\"passes_ok\":2"));
    }

    // ── Чистые функции байтовой оси (спека §6-тер): без сети ─────────────────

    #[test]
    fn полная_доставка_недостижима_без_эталона_объёма() {
        // `byte_reference: None` → `agreed` всегда `false` в `measure_channel` — доля не
        // существует, и «полной доставки» без эталона не бывает вовсе (решение 2).
        // Здесь проверяется причина, которую видит пользователь в этом случае.
        assert_eq!(
            byte_pass_reason(true, false, Admits(&[Fate::Good]), None),
            "content_diverged_from_reference"
        );
    }

    #[test]
    fn причина_связности_идёт_первой_даже_если_подлинность_тоже_против() {
        // Порядок проверки byte_pass_reason: связность важнее содержимого важнее
        // подлинности. Оборванная связность не смеет спрятаться за «Mirage».
        let reason = byte_pass_reason(
            false,
            false,
            Admits(&[Fate::Mirage]),
            Some("reset/tls".to_string()),
        );
        assert_eq!(reason, "reset/tls");
    }

    #[test]
    fn причина_mirage_только_когда_связность_и_объём_в_порядке() {
        let reason = byte_pass_reason(true, true, Admits(&[Fate::Mirage]), None);
        assert_eq!(reason, "identity_mirage");
    }

    #[test]
    fn причина_объёма_идёт_раньше_подлинности() {
        // Круг уже [Mirage], но объём САМ по себе разошёлся — сообщать надо про объём,
        // а не молча свалить в «identity_mirage»: у пользователя разное лечение.
        let reason = byte_pass_reason(true, false, Admits(&[Fate::Mirage]), None);
        assert_eq!(reason, "content_diverged_from_reference");
    }

    #[test]
    fn когда_всё_сошлось_причины_нет_но_функция_не_паникует() {
        // Ветка недостижима из `measure_channel` (там `reason` считается только при
        // `!full_delivery`), но `byte_pass_reason` — чистая функция без контракта на
        // недостижимость, и обязана вести себя предсказуемо на любом входе.
        assert_eq!(
            byte_pass_reason(true, true, Admits(&[Fate::Good]), None),
            "unknown"
        );
    }

    // ── Критерий попадания в отчёт: две оси, один вердикт ────────────────────────────

    #[test]
    fn наблюдена_и_работает_попадает_в_отчёт() {
        // Идеальный случай: всё прошло, круг сужен.
        assert!(belongs_in_report(Admits(&[Fate::Good]), true));
    }

    #[test]
    fn наблюдена_и_не_работает_попадает_в_отчёт() {
        // Диагностика: стратегия не прошла, но мы видели её судьбу.
        assert!(belongs_in_report(Admits(&[Fate::Mirage]), false));
    }

    #[test]
    fn не_наблюдена_но_работает_попадает_в_отчёт() {
        // Чинимый дефект: рабочая стратегия не должна исчезать из отчёта,
        // даже если проба подлинности ничего не установила.
        assert!(belongs_in_report(Admits(&ALL_FATES), true));
    }

    #[test]
    fn не_наблюдена_и_не_работает_не_попадает_в_отчёт() {
        // Двойной отказ: ось байтов не прошла, ось подлинности ничего не наблюдала.
        // Такая строка не имеет информативной ценности для человека.
        assert!(!belongs_in_report(Admits(&ALL_FATES), false));
    }

    #[test]
    fn медиана_доли_молчит_когда_эталона_нет_вовсе() {
        assert_eq!(median_share_of(&[None, None]), None);
    }

    #[test]
    fn медиана_доли_молчит_на_пустом_ряде() {
        assert_eq!(median_share_of(&[]), None);
    }

    #[test]
    fn медиана_доли_молчит_если_хоть_один_проход_без_доли() {
        // Эталон общий на весь прогон — либо есть у всех проходов, либо ни у одного.
        // Смешение — брак вызывающего кода, и медиана обязана отказаться, а не соврать.
        assert_eq!(median_share_of(&[Some(1.0), None, Some(0.9)]), None);
    }

    #[test]
    fn медиана_доли_считает_честную_медиану() {
        let median = median_share_of(&[Some(0.4), Some(1.0), Some(0.6)]).expect("все доли есть");
        assert!((median - 0.6).abs() < f64::EPSILON);
    }

    #[test]
    fn имя_причины_связности_берёт_причину_с_провода_прежде_вердикта_сверху() {
        assert_eq!(
            connectivity_cause_name(
                Some(crate::network::cause::Cause::Reset(
                    crate::network::cause::Phase::Tls
                )),
                Some("empty_body")
            ),
            "reset/tls"
        );
    }

    #[test]
    fn имя_причины_связности_падает_на_unknown_без_единой_улики() {
        assert_eq!(connectivity_cause_name(None, None), "unknown");
    }
}
