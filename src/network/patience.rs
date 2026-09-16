//! Терпение пробы — оператором сроков reflex, а не слепым таймером на весь запрос.
//!
//! Прежде проба жила под одним `tokio::time::timeout` на всё: коннект, рукопожатие,
//! заголовки, тело. Мёртвая стратегия (цензор проглотил `ClientHello`) сжигала его
//! целиком — шесть секунд на пробу, четыре пробы на стратегию, — хотя живой разговор
//! не молчит между шагами и секунды. Замер 16.09 на стенде: 12 из 17 провалов check были
//! `timeout/tls`, то есть тишиной сразу после коннекта.
//!
//! Судит `reflex_core::timeout::Timeout`, и у него ДВА срока, которые нельзя путать:
//! `Idle` — цель молчит дольше порога после последнего шага (вывод о мире), `Ceiling` —
//! мы перестали ждать, хотя цель шла (утверждение о нас). Шаг — всякое продвижение
//! пробы (`Reached::stride`): завершённая фаза или кадр тела. Время — узлы сетки
//! `reflex_core::grid`, а не часы внутри оператора: срок назовут не позже одного узла
//! после наступления.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use reflex_core::detector::DetectorEvent;
use reflex_core::grid;
use reflex_core::mealy::Mealy;
use reflex_core::timeout::{Expiry, Timeout};
use reflex_core::word::{Conversation, Word};

use crate::network::cause::Reached;

/// Шаг сетки сторожа. Цена: срок назовут не позже чем через 50 мс после наступления.
const GRID: Duration = Duration::from_millis(50);

/// Сколько тишины считать молчанием цели и сколько всего мы готовы ждать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Patience {
    pub idle: Duration,
    pub ceiling: Duration,
}

impl Patience {
    pub fn new(idle: Duration, ceiling: Duration) -> Patience {
        Patience { idle, ceiling }
    }

    /// Только потолок: тишина не короче его самого. Для проб, чьи вызывающие порога
    /// тишины пока не называют (scan, status, эталоны) — поведение прежнего таймера.
    pub fn within(ceiling: Duration) -> Patience {
        Patience {
            idle: ceiling,
            ceiling,
        }
    }
}

/// Предмет сторожа — шаг пробы. Сказано разговору: проба и есть один разговор с целью.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stride;

impl Word for Stride {
    type Of = Conversation;
}

/// Сторож одной пробы: оператор сроков и последний уже скормленный ему шаг.
#[derive(Debug, Clone, Copy)]
struct Watch {
    timeout: Timeout<Stride>,
    fed: Instant,
}

impl Watch {
    /// Проба родилась — это первый шаг: от него считаются и тишина, и потолок.
    fn opened(patience: Patience, born: Instant) -> Watch {
        let (timeout, _, ()) =
            Timeout::new(patience.idle, patience.ceiling).step(DetectorEvent::Packet {
                input: Stride,
                at: born,
            });
        Watch { timeout, fed: born }
    }

    /// Узел сетки. Шаг, случившийся после прошлого узла, скармливается ПЕРВЫМ и своим
    /// моментом, а не моментом узла: иначе тишина считалась бы от того, когда мы
    /// посмотрели, а не от того, когда цель ответила. Промежуточные шаги между узлами
    /// сроку не нужны — тишину отодвигает только последний.
    fn at_node(self, last_stride: Instant, node: u64, at: Instant) -> (Watch, Option<Expiry>) {
        let fed = match last_stride > self.fed {
            true => Watch {
                timeout: self
                    .timeout
                    .step(DetectorEvent::Packet {
                        input: Stride,
                        at: last_stride,
                    })
                    .0,
                fed: last_stride,
            },
            false => self,
        };
        let (timeout, spoken, ()) = fed.timeout.step(DetectorEvent::Tick { node, at });
        (
            Watch { timeout, ..fed },
            spoken.first().map(|deadline| deadline.expiry),
        )
    }
}

/// Ждать, пока проба не исчерпает терпение, и назвать, какой срок наступил. Проба идёт
/// рядом (`select!` у вызывающего): кончилась она раньше — сторож просто брошен.
pub fn expired(patience: Patience, reached: &Reached) -> impl Future<Output = Expiry> + Send + '_ {
    watched(Watch::opened(patience, reached.born()), reached, 1)
}

/// Один узел сетки и, если срок не наступил, следующий. Вложенность ограничена
/// потолком: `ceiling / GRID` узлов, 120 на шести секундах.
fn watched(
    watch: Watch,
    reached: &Reached,
    nth: u64,
) -> Pin<Box<dyn Future<Output = Expiry> + Send + '_>> {
    Box::pin(async move {
        tokio::time::sleep_until(grid::node(reached.born(), GRID, nth).into()).await;
        match watch.at_node(reached.last_stride(), nth, Instant::now()) {
            (_, Some(expiry)) => expiry,
            (next, None) => watched(next, reached, nth + 1).await,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: Duration = Duration::from_millis(300);
    const CEILING: Duration = Duration::from_millis(1_000);

    /// Прогнать сторожа по узлам сетки при заданных моментах шагов (мс от рождения).
    /// Возвращает момент узла и срок, названный первым.
    fn first_expiry(patience: Patience, strides: &[u64]) -> Option<(u64, Expiry)> {
        let born = Instant::now();
        let at = |ms: u64| born + Duration::from_millis(ms);
        (1..=100u64)
            .scan(Watch::opened(patience, born), |watch, nth| {
                let now_ms = nth * GRID.as_millis() as u64;
                let last = strides
                    .iter()
                    .copied()
                    .filter(|&s| s <= now_ms)
                    .max()
                    .map(at)
                    .unwrap_or(born);
                let (next, expiry) = watch.at_node(last, nth, at(now_ms));
                *watch = next;
                Some((now_ms, expiry))
            })
            .find_map(|(ms, expiry)| expiry.map(|e| (ms, e)))
    }

    #[test]
    fn silence_after_connect_is_idle_not_ceiling() {
        // Цензор проглотил ClientHello: коннект на 40 мс, дальше ни звука.
        let named = first_expiry(Patience::new(IDLE, CEILING), &[40]);
        assert_eq!(named, Some((350, Expiry::Idle)));
    }

    #[test]
    fn a_live_conversation_is_not_cut_by_silence_and_meets_the_ceiling() {
        // Кадры каждые 200 мс — тишина не дорастает до порога ни разу.
        let strides: Vec<u64> = (1..=10).map(|k| k * 200).collect();
        let named = first_expiry(Patience::new(IDLE, CEILING), &strides);
        assert_eq!(named, Some((1_000, Expiry::Ceiling)));
    }

    #[test]
    fn silence_is_counted_from_the_stride_not_from_the_node_that_saw_it() {
        // Сторож опоздал: шаг в 100 мс увиден лишь узлом в 380 мс (планировщик занят).
        // Тишина обязана кончиться в 400 мс — от ШАГА, а не в 680 — от того, когда
        // посмотрели.
        let born = Instant::now();
        let at = |ms: u64| born + Duration::from_millis(ms);
        let watch = Watch::opened(Patience::new(IDLE, CEILING), born);
        let (watch, early) = watch.at_node(at(100), 1, at(380));
        assert_eq!(early, None);
        let (_, named) = watch.at_node(at(100), 2, at(420));
        assert_eq!(named, Some(Expiry::Idle));
    }

    #[test]
    fn ceiling_only_behaves_like_the_old_timer() {
        // Без шагов вовсе тишина и потолок наступают вместе — названа тишина: цель
        // молчала всё отведённое время. С шагами первым приходит потолок.
        let within = Patience::within(CEILING);
        assert_eq!(first_expiry(within, &[]), Some((1_000, Expiry::Idle)));
        assert_eq!(first_expiry(within, &[500]), Some((1_000, Expiry::Ceiling)));
    }

    #[tokio::test]
    async fn the_watch_names_silence_for_a_probe_that_does_not_stride() {
        let reached = Reached::default();
        reached.mark(crate::network::cause::Phase::Tls);
        let started = Instant::now();
        let expiry = expired(
            Patience::new(Duration::from_millis(100), Duration::from_secs(5)),
            &reached,
        )
        .await;
        assert_eq!(expiry, Expiry::Idle);
        assert!(started.elapsed() < Duration::from_millis(400));
    }
}
