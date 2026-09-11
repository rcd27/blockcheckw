use std::time::Instant;

use console::style;
use tracing::{info_span, Instrument};

use crate::config::{CoreConfig, Protocol};
use crate::dto::{CheckReport, CheckedStrategy, ControlVerdict, VerifiedStrategy};
use crate::firewall::nft::{OwnedTable, SystemNft};
use crate::firewall::nftables;
use crate::network::http_client::{http_test_data, pick_random_ip, BodyMode, HttpResult};
use crate::nfqws2::plan::{FilterMark, Plan, QueueNum};
use crate::nfqws2::run::SystemNfqws2;
use crate::pipeline::fate::{self, Admits, Observed, ALL_FATES};
use crate::pipeline::observe;
use crate::pipeline::reference::{ContentPrint, Reference};
use crate::strategy::generator::TaggedStrategy;
use crate::strategy::rank;
use crate::ui;

/// Прогнать стратегии из vanilla-отчёта с настоящей передачей данных и СУДИТЬ СУДЬБУ
/// цели по каждой.
///
/// В отчёт идёт всякая НАБЛЮДЁННАЯ стратегия — та, чей круг судеб уже полного, — а не
/// только прошедшая. Порядок выдачи задаёт `rank::fate_order`. `--take N` считает только
/// ПРОШЕДШИЕ (`fate::passed`): он останавливает ПОИСК, а не урезает выдачу, и когда не
/// прошёл никто, список всё равно выдаётся ранжированным, а не пустым (спека §6.2).
///
/// `passes` жёстко равен единице у единственного вызывающего: повторять сужение круга
/// судеб нечем (спека §9). Параметр сохранён — цикл проходов и ранний выход на первом
/// провале ждут возврата повторов.
///
/// ГЛАВНЫЙ вердикт (`working`) выносит `fate::passed`, а НЕ круг судеб (спека §6-бис):
/// «провёл ли десинк нас через DPI» и «подлинный ли ресурс вернулся» — два разных
/// вопроса, и неустановленная подлинность первого не отменяет. Круг остаётся честным и
/// едет в отчёт рядом.
///
/// `probe_path` — путь пробы. Тем же путём снят эталон: сверка по разным путям сравнила
/// бы разные ресурсы.
#[allow(clippy::too_many_arguments)] // witness добавлен задачей 7 поверх уже широкого набора параметров
pub async fn run_check(
    config: &CoreConfig,
    witness: &FilterMark,
    domain: &str,
    strategies: &[TaggedStrategy],
    ips: &[String],
    take: usize,
    passes: usize,
    reference: Option<&Reference>,
    probe_path: &str,
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
    // ниже может оказаться свойством линии, а не стратегии.
    let control_ip = pick_random_ip(ips).expect("ips проверены вызывающим");
    let control_result = http_test_data(
        Protocol::HttpsTls12,
        domain,
        control_ip,
        0,
        config.request_timeout,
        BodyMode::Unlimited,
        None,
        probe_path,
    )
    .await;
    let control_observed = fate::observe(
        observe::connected_of(control_result.cause),
        observe::delivery_of(
            control_result.size_download.unwrap_or(0),
            control_result.ended,
        ),
    );
    let control_admits = fate::narrow(fate::Evidence {
        observed: control_observed,
        sag: observe::sag_of(&control_result.windows),
        attempts: 1,
        reference,
        print: crate::pipeline::reference::ContentPrint::of(&control_result),
    });
    // Замер ни о чём: цель открывается и без нас. Контроль судится ТОЙ ЖЕ мерой, что и
    // стратегии (спека §6-бис) — иначе на линии без эталона круг контроля до `[Good]` не
    // сужается никогда, и `inconclusive` не срабатывает ни разу, сколько бы домен ни
    // открывался без десинка.
    let inconclusive = fate::passed(control_observed, control_result.ended, control_admits);

    if inconclusive {
        screen.println(&format!(
            "  {} контроль без десинка сам прошёл — домен на этой линии не режется. \
             О стратегиях этот прогон молчит.",
            style("ВНИМАНИЕ:").yellow().bold(),
        ));
    }

    let control = Some(ControlVerdict {
        observed: control_observed.name().to_string(),
        admits: control_admits.0.iter().map(|f| format!("{f:?}")).collect(),
    });

    screen.println(&format!(
        "  {}",
        style(format!(
            "Verifying {} strategies ({passes} passes, early-exit on first fail)",
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
    // Сколько строк ПРОШЛО (`fate::passed`) — это и есть `working` отчёта, а вовсе не
    // длина списка.
    let mut working_count: usize = 0;
    // --take: count strategies that PASSED (`fate::passed`), per protocol
    let mut perfect_per_proto: std::collections::HashMap<Protocol, usize> =
        std::collections::HashMap::new();

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

        // Run passes with early-exit: if first pass fails, skip remaining
        let mut ok_count: usize = 0;
        let mut total_run: usize = 0;
        let mut speeds: Vec<f64> = Vec::with_capacity(passes);
        let mut latencies: Vec<u64> = Vec::with_capacity(passes);
        let mut last_error: Option<String> = None;
        // Круг ПОСЛЕДНЕГО прохода, каким бы он ни был. Прежде он переписывался только
        // в ветке `checked.working`, и оттого у всякой строки в `judged` стоял круг
        // `[Good]`: ступени 1–6 в `rank::step` были в бою недостижимы.
        let mut last_circle: Admits = Admits(&ALL_FATES);
        // Само последнее наблюдение — из него растёт строка отчёта: судьба, имя
        // показания, замеры. Без него в отчёт попадали только `Good`.
        let mut last_checked: Option<CheckedStrategy> = None;

        // Span на проверку конкретной стратегии (ребёнок bcw.check). Здесь живёт
        // причина FAIL (connect/timeout) — то, ради чего трейсинг и затевался.
        let strategy_span = info_span!(
            "bcw.check.strategy",
            protocol = %tagged.protocol,
            args = %args_str,
            status = tracing::field::Empty,
            reason = tracing::field::Empty,
        );
        async {
            for pass_idx in 0..passes {
                let started = crate::pipeline::verify::now_epoch();
                let checked = check_single_strategy(
                    config, witness, &table, domain, tagged, ips,
                    // `check` пока не делает повторов внутри одной пробы — они появятся
                    // вместе с многопрофильным прогоном (вне этого плана).
                    1, reference, probe_path,
                )
                .await;
                total_run = pass_idx + 1;

                let outcome = match checked.working {
                    true => crate::pipeline::verify::Outcome::Passed,
                    false => crate::pipeline::verify::Outcome::Failed(
                        checked
                            .failure
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                    ),
                };
                crate::pipeline::verify::log_pass(started, checked_count, pass_idx + 1, &outcome);

                last_circle = checked.circle;
                let working = checked.working;
                if working {
                    ok_count += 1;
                    speeds.push(checked.speed_kbps);
                    latencies.push(checked.latency_ms);
                } else {
                    last_error = checked.error.clone();
                }
                last_checked = Some(checked);
                if !working {
                    // Early-exit: first fail → no more passes for this strategy
                    break;
                }
            }
        }
        .instrument(strategy_span.clone())
        .await;

        speeds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        latencies.sort();
        // Медиана по УСПЕШНЫМ проходам; их может не быть вовсе — наблюдённая, но не
        // приведшая к `Good` стратегия тоже идёт в отчёт, и замер у неё свой.
        let median_speed = speeds.get(speeds.len() / 2).copied();
        let median_latency = latencies.get(latencies.len() / 2).copied();

        let good = all_passes_succeeded(ok_count, total_run, passes);
        if good {
            strategy_span.record("status", "working");
            screen.println(&format!(
                "    {} median {}ms, {:.1} KB/s",
                style("OK").green().bold(),
                median_latency.unwrap_or(0),
                median_speed.unwrap_or(0.0),
            ));
            *perfect_per_proto.entry(tagged.protocol).or_insert(0) += 1;
            working_count += 1;
        } else {
            let reason = last_error.as_deref().unwrap_or("failed");
            strategy_span.record("status", "fail");
            strategy_span.record("reason", reason);
            screen.println(&format!(
                "    {} {}/{} {} [{}]",
                style("FAIL").red().bold(),
                ok_count,
                total_run,
                style(reason).red(),
                style(circle_name(last_circle)).dim(),
            ));
        }

        // Критерий попадания в отчёт — стратегия была НАБЛЮДЕНА, а не «работает».
        // Спека §6.2: `Grinding` (и всё прочее суженное) выдаётся, когда `Good` нет ни
        // у кого, — человек видит лучшее из имеющегося ВМЕСТО ПУСТОГО СПИСКА. Прежде в
        // `verified` пускали только `working`, и без `--reference-via` круг не сужался
        // до `[Good]` ни у кого: отчёт был всегда пуст.
        if let Some(checked) = last_checked.filter(|c| observed_at_all(c.circle)) {
            // Прибор, а не голая длительность: `waited_of` молчит (`None`) на нулевом
            // ожидании — «не мерили», а не «мерили и вышел ноль». Подставить 0 значило
            // бы объявить неизмеренное лучшим из всех: в ранге меньше — значит быстрее
            // (`rank::fate_order`). Кладём наибольшее возможное значение, чтобы
            // неизмеренное никогда не обошло измеренное внутри одной ступени круга.
            let latency_ms = median_latency.unwrap_or(checked.latency_ms);
            let waited_ms = match observe::waited_of(std::time::Duration::from_millis(latency_ms)) {
                Some(waited) => waited.0.as_millis() as u64,
                None => u64::MAX,
            };
            verified.push(VerifiedStrategy {
                protocol: tagged.protocol.to_string(),
                args: args_str.clone(),
                coverage: tagged.coverage,
                success_rate: match total_run {
                    0 => 0.0,
                    run => ok_count as f64 / run as f64,
                },
                median_latency_ms: latency_ms,
                median_speed_kbps: median_speed.unwrap_or(checked.speed_kbps),
                passes_ok: ok_count,
                passes_total: passes,
                observed: checked.observed.clone(),
                admits: checked.admits.clone(),
                working: checked.working,
            });
            judged.push(rank::Ranked {
                // Круг едет в `CheckedStrategy.circle` значением — строки из `admits`
                // для сортировки не годятся.
                admits: last_circle,
                waited_ms,
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

    // Замер устойчивости снят: `passes` жёстко равен единице, значит всякая строка в
    // `stability_of` либо `always`, либо `never`, а `flapping` не может быть ненулевым
    // никогда. Печатать «0 флапают» как РЕЗУЛЬТАТ замера значит рапортовать о том, чего
    // не делали. Сами функции в `verify.rs` остались — они понадобятся, когда вернутся
    // повторы.

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

/// Check one strategy: nfqws2 → nftables → GET → measure → cleanup.
#[allow(clippy::too_many_arguments)] // attempts/reference добавлены задачей 6 поверх уже широкого набора параметров
async fn check_single_strategy(
    config: &CoreConfig,
    witness: &FilterMark,
    table: &OwnedTable,
    domain: &str,
    tagged: &TaggedStrategy,
    ips: &[String],
    attempts: u32,
    reference: Option<&Reference>,
    probe_path: &str,
) -> CheckedStrategy {
    let protocol = tagged.protocol;
    let args_str = tagged.args.join(" ");

    // Движок не поднялся — значит мы не наблюдали ничего, и сужать не из чего.
    // Круг остаётся полным (то же самое, что `Observed::Unobserved.admits()`).
    let make_failed = |error: String| CheckedStrategy {
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

    // 4. HTTP GET with data transfer. `ips` гарантированно непусты:
    // `apply_dispatch` выше уже прогнал `validate_ip_set`, отвергающий
    // пустой список, и вернул `Ok` — значит, эта проверка не могла провалиться.
    let ip = pick_random_ip(ips).expect("apply_dispatch already validated ips is non-empty");

    let test_start = Instant::now();
    let result = http_test_data(
        protocol,
        domain,
        ip,
        mark.so_mark(),
        config.request_timeout,
        BodyMode::Unlimited,
        None,
        probe_path,
    )
    .await;
    let latency_ms = test_start.elapsed().as_millis() as u64;

    // 5. Cleanup: снять диспетчеризацию, затем убить nfqws2 (best-effort)
    nftables::remove_dispatch(&SystemNft, table).await;
    SystemNfqws2::stop(instance).await;

    // 6. Показание и круг судеб. `interpret_check_result` остаётся поставщиком
    //    диагностики (`Cause`, имя провала) — но вердикта больше не выносит:
    //    «есть статус и тело не пусто» есть `Observed::Bytes`, а не «работает».
    let (_permissive, error, named) = interpret_check_result(&result, domain);
    let bytes_downloaded = result.size_download.unwrap_or(0);

    let observed = fate::observe(
        observe::connected_of(result.cause),
        observe::delivery_of(bytes_downloaded, result.ended),
    );
    let admits = fate::narrow(fate::Evidence {
        observed,
        sag: observe::sag_of(&result.windows),
        attempts,
        reference,
        print: ContentPrint::of(&result),
    });
    // ГЛАВНАЯ ось, и она НЕ проекция круга (спека §6-бис): байты потекли, разговор не
    // прервали, содержимое с эталоном не разошлось. Неустановленная подлинность — не
    // свидетельство против.
    let working = fate::passed(observed, result.ended, admits);

    let speed_kbps = if working && latency_ms > 0 {
        (bytes_downloaded as f64 / 1024.0) / (latency_ms as f64 / 1000.0)
    } else {
        0.0
    };

    CheckedStrategy {
        protocol: protocol.to_string(),
        args: args_str,
        working,
        bytes_downloaded,
        latency_ms,
        speed_kbps,
        error,
        // Имя провала — с провода, где он есть; иначе по тому, что видно сверху.
        failure: match working {
            true => None,
            false => Some(match (result.cause, named) {
                (Some(c), _) => c.name(),
                (None, Some(name)) => name.to_string(),
                (None, None) => "unknown".to_string(),
            }),
        },
        observed: observed.name().to_string(),
        admits: admits.0.iter().map(|f| format!("{f:?}")).collect(),
        circle: admits,
    }
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
    use crate::network::http_client::Ended;
    use crate::pipeline::fate::Fate;

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
            observed: "Bytes".to_string(),
            admits: vec!["Good".to_string()],
            working: true,
        };
        let json = serde_json::to_string(&vs).unwrap();
        assert!(json.contains("\"observed\":\"Bytes\""), "{json}");
        assert!(json.contains("\"admits\":[\"Good\"]"), "{json}");
        assert!(json.contains("\"working\":true"), "{json}");
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
            observed: "Bytes".to_string(),
            admits: vec!["Mirage".to_string()],
            working: false,
        };
        let json = serde_json::to_string(&vs).unwrap();
        assert!(json.contains("\"admits\":[\"Mirage\"]"), "{json}");
        assert!(json.contains("\"working\":false"), "{json}");
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
            observed: "Bytes".to_string(),
            admits: vec!["Grinding".to_string()],
            working: false,
        };
        let json = serde_json::to_string(&vs).unwrap();
        assert!(json.contains("\"success_rate\":0.67"));
        assert!(json.contains("\"median_speed_kbps\":2.5"));
        assert!(json.contains("\"passes_ok\":2"));
    }
}
