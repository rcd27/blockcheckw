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
    /// `None` — выборок меньше двух, коды ответа разошлись между выборками либо эталон
    /// выродился: во всех трёх случаях эталона нет, и судить по нему нельзя.
    ///
    /// ВЫРОЖДЕНИЕ (`span >= low`). Допуск откладывается в обе стороны на собственный
    /// разброс (`agrees`), поэтому страница, гуляющая на величину собственного размера,
    /// даёт нижнюю границу `0` — и согласной с ней оказывается ЛЮБАЯ проба, включая
    /// блок-страницу в 1200 байт. Различающей способности у такого эталона нет, а
    /// эталон, принимающий всё, хуже отсутствующего: он молча выключает `Mirage`.
    /// Это не порог, а условие вырождения — того же рода, что «выборок меньше двух».
    pub fn take(prints: Vec<ContentPrint>) -> Option<Reference> {
        let first = prints.first()?;
        if prints.len() < 2 || prints.iter().any(|p| p.status != first.status) {
            return None;
        }
        let low = prints.iter().map(|p| p.bytes).min()?;
        let high = prints.iter().map(|p| p.bytes).max()?;
        if high - low >= low {
            return None;
        }
        Some(Reference {
            status: first.status,
            low,
            high,
        })
    }
}

/// Согласна ли проба с эталоном. Допуск — собственный разброс эталона, отложенный в обе
/// стороны: `[low - span; high + span]`, где `span = high - low`.
///
/// Нижняя граница насыщается нулём, и при `span >= low` допуск вырождается в «принимать
/// всё». Такой эталон [`Reference::take`] не выдаёт вовсе — см. её докблок; здесь же
/// насыщение остаётся, потому что структура может быть собрана и мимо конструктора.
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
    fn эталон_гуляющий_на_величину_собственного_размера_не_снимается() {
        // Динамическая страница, разный gzip: 1000 и 2500 байт. `span = 1500 >= low = 1000`,
        // и допуск, отложенный в обе стороны, накрыл бы всё от нуля. Эталон, принимающий
        // всё, хуже отсутствующего: он молча выключает `Mirage` и объявляет заглушку `Good`.
        assert!(Reference::take(vec![print(200, 1_000), print(200, 2_500)]).is_none());
        // Ровно на границе вырождения (`span == low`) эталона тоже нет.
        assert!(Reference::take(vec![print(200, 1_000), print(200, 2_000)]).is_none());
        // На волос внутри — эталон есть: отказ узок и не съедает годных.
        assert!(Reference::take(vec![print(200, 1_000), print(200, 1_999)]).is_some());
    }

    #[test]
    fn нулевой_эталон_не_эталон() {
        // Две пустые выборки: `span = 0 >= low = 0`. Разброса нет, но и размера нет —
        // отличить ресурс от заглушки нечем.
        assert!(Reference::take(vec![print(200, 0), print(200, 0)]).is_none());
    }

    #[test]
    fn допуск_выродившегося_эталона_принимает_всё() {
        // Граница `low < span` в `agrees`: НЕ пробел покрытия, а описание дефекта, ради
        // которого `take` и отказывает. Собираем вырожденный эталон мимо конструктора и
        // показываем, что он согласен с чем угодно — в том числе с блок-страницей.
        let degenerate = Reference {
            status: Some(200),
            low: 1_000,
            high: 2_500,
        };
        assert!(agrees(&degenerate, &print(200, 1)));
        assert!(agrees(&degenerate, &print(200, 4_000)));
        // И потому такой эталон наружу не выходит: единственная дверь — `take`.
        assert!(Reference::take(vec![print(200, 1_000), print(200, 2_500)]).is_none());
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
