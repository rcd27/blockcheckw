//! Эталон ответа, снятый через чистый egress. Нужен, чтобы отделить `Mirage` (байты
//! текут, ресурса нет) от настоящего ресурса: пассивно эти судьбы не делятся.

use crate::config::Protocol;
use crate::network::http_client::{http_test_data, BodyMode, HttpResult};
use crate::network::via::Via;

/// Оттиск ответа: то устойчивое, что имеет смысл сверять. Побайтового равенства не
/// требуем — динамическая страница различается от запроса к запросу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentPrint {
    pub status: Option<u16>,
    pub bytes: u64,
}

impl ContentPrint {
    pub fn of(result: &HttpResult) -> ContentPrint {
        ContentPrint {
            status: result.status_code,
            bytes: result.size_download.unwrap_or(0),
        }
    }
}

/// Эталон: не менее двух выборок. Вторая нужна не для точности, а для ДОПУСКА —
/// разброс страницы задаёт сама страница, и выдумывать процент не приходится.
#[derive(Debug, Clone)]
pub struct Reference {
    status: Option<u16>,
    low: u64,
    high: u64,
}

impl Reference {
    /// `None` — выборок меньше двух либо коды ответа разошлись между выборками: в обоих
    /// случаях эталона нет, и судить по нему нельзя.
    pub fn take(prints: Vec<ContentPrint>) -> Option<Reference> {
        let first = prints.first()?;
        if prints.len() < 2 || prints.iter().any(|p| p.status != first.status) {
            return None;
        }
        let low = prints.iter().map(|p| p.bytes).min()?;
        let high = prints.iter().map(|p| p.bytes).max()?;
        Some(Reference {
            status: first.status,
            low,
            high,
        })
    }
}

/// Согласна ли проба с эталоном. Допуск — собственный разброс эталона, отложенный в обе
/// стороны: `[low - span; high + span]`, где `span = high - low`.
pub fn agrees(reference: &Reference, probe: &ContentPrint) -> bool {
    if probe.status != reference.status {
        return false;
    }
    let span = reference.high - reference.low;
    let floor = reference.low.saturating_sub(span);
    let ceiling = reference.high.saturating_add(span);
    (floor..=ceiling).contains(&probe.bytes)
}

/// Снять эталон через чистый egress. Маршруты ставятся НА ВРЕМЯ снятия и снимаются
/// сразу: иначе через шлюз пошли бы и пробы стратегий, и весь замер потерял бы смысл.
///
/// `samples` — сколько выборок. Меньше двух эталона не даёт (см. `Reference::take`):
/// вторая нужна не для точности, а для ДОПУСКА.
pub async fn take_reference(
    clean: &Via,
    protocol: Protocol,
    domain: &str,
    ips: &[String],
    timeout_secs: u64,
    samples: usize,
) -> Option<Reference> {
    let ip = ips.first()?;
    // Два режима `Via` доходят до цели РАЗНЫМИ путями, и оба поддержаны:
    //  * прокси — параметром `via` (`http_single_request` фильтрует его `is_proxy()`
    //    и берёт туннель через `Via::tcp_connect`);
    //  * маршрут — снаружи, установкой `ip route` на время снятия.
    // Потому `Some(clean)` передаётся всегда (в маршрутном режиме он просто не
    // выберется фильтром), а маршруты ставятся только там, где они и нужны.
    let routed = !clean.is_proxy();
    if routed {
        clean.add_routes(ips).await;
    }
    let mut prints = Vec::with_capacity(samples);
    for _ in 0..samples {
        // fwmark = 0: проба идёт мимо диспетчеризации `bcw`, по установленному маршруту.
        let result = http_test_data(
            protocol,
            domain,
            ip,
            0,
            timeout_secs,
            BodyMode::Unlimited,
            Some(clean),
        )
        .await;
        if result.error.is_none() {
            prints.push(ContentPrint::of(&result));
        }
    }
    if routed {
        clean.remove_routes(ips).await;
    }
    Reference::take(prints)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn print(status: u16, bytes: u64) -> ContentPrint {
        ContentPrint {
            status: Some(status),
            bytes,
        }
    }

    #[test]
    fn одной_выборки_для_эталона_мало() {
        // Одна выборка не даёт разброса, а без разброса допуск пришлось бы выдумать.
        assert!(Reference::take(vec![print(200, 100_000)]).is_none());
        assert!(Reference::take(vec![]).is_none());
    }

    #[test]
    fn проба_в_разбросе_эталона_согласна() {
        let reference = Reference::take(vec![print(200, 100_000), print(200, 110_000)])
            .expect("две выборки — эталон");
        assert!(agrees(&reference, &print(200, 105_000)));
        // Границы: span = 10_000, значит [90_000; 120_000] включительно.
        assert!(agrees(&reference, &print(200, 90_000)));
        assert!(agrees(&reference, &print(200, 120_000)));
    }

    #[test]
    fn заглушка_вместо_ресурса_не_согласна_по_объёму() {
        let reference = Reference::take(vec![print(200, 100_000), print(200, 110_000)])
            .expect("две выборки — эталон");
        // Блок-страница провайдера: тот же код, на два порядка меньше.
        assert!(!agrees(&reference, &print(200, 1_200)));
    }

    #[test]
    fn другой_код_ответа_не_согласен_никогда() {
        let reference = Reference::take(vec![print(200, 100_000), print(200, 110_000)])
            .expect("две выборки — эталон");
        assert!(!agrees(&reference, &print(403, 105_000)));
        assert!(!agrees(
            &reference,
            &ContentPrint {
                status: None,
                bytes: 105_000
            }
        ));
    }

    #[test]
    fn эталон_без_разброса_допускает_только_точное_совпадение() {
        // Страница статична: две выборки сошлись байт в байт, span = 0. Допуска нет, и
        // выдумывать его неоткуда — честнее требовать точного совпадения.
        let reference = Reference::take(vec![print(200, 50_000), print(200, 50_000)])
            .expect("две выборки — эталон");
        assert!(agrees(&reference, &print(200, 50_000)));
        assert!(!agrees(&reference, &print(200, 50_001)));
    }
}
