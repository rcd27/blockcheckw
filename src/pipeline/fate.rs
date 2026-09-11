//! Словарь судьбы цели. Взят готовым у `reflex-instrument`: типология и закон `Sound`
//! оплачены их замерами, и вторая реализация разошлась бы с первой молча.

pub use reflex_instrument::fate::{observe, Admits, Delivery, Fate, Observed, ALL_FATES};

use crate::pipeline::reference::{agrees, ContentPrint, Reference};
use reflex_instrument::sag::Sag;

const MIRAGE_ONLY: &[Fate] = &[Fate::Mirage];
const GRINDING_ONLY: &[Fate] = &[Fate::Grinding];
const GOOD_ONLY: &[Fate] = &[Fate::Good];

/// Улики, собранные активной пробой. Парк говорит, что `Bytes` пассивно не делится на
/// три судьбы и делит их активная проба, — вот она.
pub struct Evidence<'a> {
    pub observed: Observed,
    /// Просадка канала. `None` двусмысленно: либо её нет, либо окон не хватило.
    pub sag: Option<Sag>,
    /// Сколько попыток понадобилось, чтобы добыть ответ. Единица — с первого раза.
    pub attempts: u32,
    /// Эталон через чистый egress. `None` — `Good` объявлять не из чего.
    pub reference: Option<&'a Reference>,
    pub print: ContentPrint,
}

/// Сузить круг судеб. Всё, кроме `Bytes`, парк сужает сам; наша работа — только три
/// судьбы, закрытые содержимым.
pub fn narrow(evidence: Evidence<'_>) -> Admits {
    let wide = Admits(evidence.observed.admits());
    if evidence.observed != Observed::Bytes {
        return wide;
    }
    // Без эталона содержимое закрыто, и сузить нечем. Выдать `Good` здесь значило бы
    // утверждать больше наблюдённого.
    let Some(reference) = evidence.reference else {
        return wide;
    };
    if !agrees(reference, &evidence.print) {
        return Admits(MIRAGE_ONLY);
    }
    // Ресурс тот самый. Осталось спросить, что за него заплачено.
    match evidence.attempts > 1 || evidence.sag.is_some() {
        true => Admits(GRINDING_ONLY),
        false => Admits(GOOD_ONLY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn байты_не_означают_что_страта_работает() {
        // Ровно то, что сегодня делает `interpret_check_result`: приехали байты — успех.
        // Парк говорит, что байты допускают три судьбы, и две из них не успех.
        let observed = observe(true, Delivery::Delivered);
        assert_eq!(observed, Observed::Bytes);
        assert_eq!(
            observed.admits(),
            [Fate::Mirage, Fate::Grinding, Fate::Good].as_slice()
        );
    }

    #[test]
    fn брошенное_наблюдение_не_приговор_а_полный_круг() {
        // «Не смотрели» ≠ «смотрели и пусто». Слить их — значит списать всякий свой
        // промах на цензора.
        let observed = observe(true, Delivery::Abandoned);
        assert_eq!(observed, Observed::Unobserved);
        assert_eq!(observed.admits(), ALL_FATES.as_slice());
    }

    #[test]
    fn молчание_после_коннекта_не_то_же_что_молчание_до() {
        // `Trap` (поздоровался впустую) и `Dead` (не поздоровался) лечатся по-разному:
        // у первого прямой путь жив.
        assert_eq!(observe(true, Delivery::Silent), Observed::Mute);
        assert_eq!(observe(false, Delivery::Silent), Observed::NoConnect);
        assert_eq!(Observed::Mute.admits(), [Fate::Trap].as_slice());
        assert_eq!(Observed::NoConnect.admits(), [Fate::Dead].as_slice());
    }

    #[test]
    fn байты_без_коннекта_есть_брак_прибора_а_не_судьба() {
        assert_eq!(observe(false, Delivery::Delivered), Observed::Inconsistent);
        assert_eq!(Observed::Inconsistent.admits(), ALL_FATES.as_slice());
    }

    use crate::pipeline::reference::{ContentPrint, Reference};
    use reflex_instrument::sag::Sag;

    fn эталон() -> Reference {
        Reference::take(vec![
            ContentPrint {
                status: Some(200),
                bytes: 100_000,
            },
            ContentPrint {
                status: Some(200),
                bytes: 110_000,
            },
        ])
        .expect("две выборки")
    }

    fn проба(bytes: u64) -> ContentPrint {
        ContentPrint {
            status: Some(200),
            bytes,
        }
    }

    #[test]
    fn первая_попытка_без_просадки_со_сошедшимся_содержимым_есть_good() {
        let reference = эталон();
        let circle = narrow(Evidence {
            observed: Observed::Bytes,
            sag: None,
            attempts: 1,
            reference: Some(&reference),
            print: проба(105_000),
        });
        assert_eq!(circle.0, [Fate::Good].as_slice());
    }

    #[test]
    fn содержимое_не_сошлось_есть_mirage() {
        // Блок-страница: код тот же, объём на два порядка меньше.
        let reference = эталон();
        let circle = narrow(Evidence {
            observed: Observed::Bytes,
            sag: None,
            attempts: 1,
            reference: Some(&reference),
            print: проба(1_200),
        });
        assert_eq!(circle.0, [Fate::Mirage].as_slice());
    }

    #[test]
    fn повторы_превращают_good_в_grinding() {
        // Ресурс тот самый, но заплачено временем человека.
        let reference = эталон();
        let circle = narrow(Evidence {
            observed: Observed::Bytes,
            sag: None,
            attempts: 3,
            reference: Some(&reference),
            print: проба(105_000),
        });
        assert_eq!(circle.0, [Fate::Grinding].as_slice());
    }

    #[test]
    fn просадка_превращает_good_в_grinding() {
        let reference = эталон();
        let circle = narrow(Evidence {
            observed: Observed::Bytes,
            sag: Some(Sag {
                at_window: 2,
                before_bps: 100_000,
                after_bps: 2_000,
            }),
            attempts: 1,
            reference: Some(&reference),
            print: проба(105_000),
        });
        assert_eq!(circle.0, [Fate::Grinding].as_slice());
    }

    #[test]
    fn несошедшееся_содержимое_остаётся_mirage_даже_с_повторами_и_просадкой() {
        // Приоритет закона: «ресурс не тот» сильнее, чем «ресурс добыт дорого». Заглушку,
        // вытянутую с третьей попытки и с просадкой, `Grinding` назвать нельзя — `Grinding`
        // говорит «ресурс ТОТ САМЫЙ, но заплачено временем», а ресурса здесь нет вовсе.
        //
        // Без этого случая перестановка ветвей `agrees` и `attempts/sag` не красит ни одного
        // теста — проверено ревью.
        let reference = эталон();
        let circle = narrow(Evidence {
            observed: Observed::Bytes,
            sag: Some(Sag {
                at_window: 2,
                before_bps: 100_000,
                after_bps: 2_000,
            }),
            attempts: 3,
            reference: Some(&reference),
            print: проба(1_200),
        });
        assert_eq!(circle.0, [Fate::Mirage].as_slice());
    }

    #[test]
    fn без_эталона_good_объявлять_нельзя() {
        // Круг остаётся широким: «байты текут» и «ресурс тот самый» неразличимы.
        let circle = narrow(Evidence {
            observed: Observed::Bytes,
            sag: None,
            attempts: 1,
            reference: None,
            print: проба(105_000),
        });
        assert_eq!(
            circle.0,
            [Fate::Mirage, Fate::Grinding, Fate::Good].as_slice()
        );
    }

    #[test]
    fn наблюдения_кроме_байтов_сужаются_самим_парком() {
        for observed in [
            Observed::NoConnect,
            Observed::Mute,
            Observed::Unobserved,
            Observed::Inconsistent,
        ] {
            let circle = narrow(Evidence {
                observed,
                sag: None,
                attempts: 1,
                reference: None,
                print: проба(0),
            });
            assert_eq!(circle.0, observed.admits(), "показание {observed:?}");
        }
    }

    #[test]
    fn истинная_судьба_всегда_внутри_круга() {
        // Закон `Sound`: сужение не имеет права выбросить правду. Проверяем, что всякий
        // возвращённый круг — подмножество круга, который допускает само показание.
        let reference = эталон();
        for attempts in [1, 2] {
            for sag in [
                None,
                Some(Sag {
                    at_window: 1,
                    before_bps: 10,
                    after_bps: 1,
                }),
            ] {
                for print in [проба(105_000), проба(1_200)] {
                    let circle = narrow(Evidence {
                        observed: Observed::Bytes,
                        sag,
                        attempts,
                        reference: Some(&reference),
                        print,
                    });
                    assert!(
                        circle
                            .0
                            .iter()
                            .all(|f| Observed::Bytes.admits().contains(f)),
                        "круг вышел за пределы допускаемого показанием"
                    );
                    assert!(!circle.0.is_empty(), "пустой круг — брак прибора");
                }
            }
        }
    }
}
