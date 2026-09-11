//! Словарь судьбы цели. Взят готовым у `reflex-instrument`: типология и закон `Sound`
//! оплачены их замерами, и вторая реализация разошлась бы с первой молча.

pub use reflex_instrument::fate::{observe, Admits, Delivery, Fate, Observed, ALL_FATES};

use crate::network::http_client::Ended;
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

/// Прошла ли стратегия. ГЛАВНАЯ ось замера, и она НЕ проекция круга судеб (спека
/// §6-бис): круг отвечает на вопрос о подлинности ресурса, а здесь спрашивается другое —
/// провёл ли десинк нас через DPI.
///
/// ```text
/// passed = байты цели потекли
///        И разговор не прервали
///        И (эталона нет ИЛИ содержимое сошлось)
/// ```
///
/// `false` — только при ПОЛОЖИТЕЛЬНОМ свидетельстве против: байтов не было
/// (`observed != Bytes`), разговор прервали (`Ended::BodyError` — сброс или TLS-алерт
/// посреди передачи), либо содержимое с эталоном разошлось (круг сузился до
/// `[Fate::Mirage]`). НЕУСТАНОВЛЕННАЯ подлинность — широкий круг без эталона — вердикта
/// о канале не отменяет: «подлинность не доказана, значит не работает» хоронит рабочую
/// стратегию, которую человек уже никогда не увидит.
///
/// `Ended::WeStoppedWaiting` обрывом НЕ считается: до `Observed::Bytes` оно доезжает
/// только с непустым телом, то есть это МЫ перестали ждать, тогда как канал отдавал.
pub fn passed(observed: Observed, ended: Ended, circle: Admits) -> bool {
    observed == Observed::Bytes && ended != Ended::BodyError && !matches!(circle.0, [Fate::Mirage])
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

    // ── Главная ось: `passed` ────────────────────────────────────────────────
    //
    // Таблица на все сочетания показания, исхода чтения и круга судеб. Она — предмет
    // продукта, и проверяется без сети.

    const ШИРОКИЙ: &[Fate] = &[Fate::Mirage, Fate::Grinding, Fate::Good];

    #[test]
    fn таблица_прохода_по_показанию_и_исходу() {
        // Круг взят широкий — тот, что выдаёт `narrow` БЕЗ эталона. По побочной оси он
        // не говорит ничего, и потому главную ось не трогает.
        let таблица: &[(Observed, Ended, bool)] = &[
            // Байты потекли: прошла всюду, кроме обрыва тела.
            (Observed::Bytes, Ended::BodyComplete, true),
            (Observed::Bytes, Ended::LimitReached, true),
            (Observed::Bytes, Ended::WeStoppedWaiting, true),
            (Observed::Bytes, Ended::Denied, true),
            (Observed::Bytes, Ended::NeverStarted, true),
            // Разговор прервали посреди передачи — свидетельство ПРОТИВ.
            (Observed::Bytes, Ended::BodyError, false),
            // Байтов не было: ни один исход чтения этого не исправляет.
            (Observed::Mute, Ended::BodyComplete, false),
            (Observed::Mute, Ended::LimitReached, false),
            (Observed::Mute, Ended::BodyError, false),
            (Observed::Mute, Ended::WeStoppedWaiting, false),
            (Observed::Mute, Ended::Denied, false),
            (Observed::Mute, Ended::NeverStarted, false),
            (Observed::NoConnect, Ended::BodyComplete, false),
            (Observed::NoConnect, Ended::LimitReached, false),
            (Observed::NoConnect, Ended::BodyError, false),
            (Observed::NoConnect, Ended::WeStoppedWaiting, false),
            (Observed::NoConnect, Ended::Denied, false),
            (Observed::NoConnect, Ended::NeverStarted, false),
            (Observed::Unobserved, Ended::BodyComplete, false),
            (Observed::Unobserved, Ended::LimitReached, false),
            (Observed::Unobserved, Ended::BodyError, false),
            (Observed::Unobserved, Ended::WeStoppedWaiting, false),
            (Observed::Unobserved, Ended::Denied, false),
            (Observed::Unobserved, Ended::NeverStarted, false),
            (Observed::Inconsistent, Ended::BodyComplete, false),
            (Observed::Inconsistent, Ended::LimitReached, false),
            (Observed::Inconsistent, Ended::BodyError, false),
            (Observed::Inconsistent, Ended::WeStoppedWaiting, false),
            (Observed::Inconsistent, Ended::Denied, false),
            (Observed::Inconsistent, Ended::NeverStarted, false),
        ];
        for &(observed, ended, ожидание) in таблица {
            assert_eq!(
                passed(observed, ended, Admits(ШИРОКИЙ)),
                ожидание,
                "{observed:?} + {ended:?}"
            );
        }
    }

    #[test]
    fn таблица_прохода_по_кругу_судеб() {
        // Показание и исход держим лучшими: меняется только побочная ось.
        let таблица: &[(&[Fate], bool)] = &[
            // Содержимое сошлось с эталоном.
            (&[Fate::Good], true),
            (&[Fate::Grinding], true),
            // Содержимое РАЗОШЛОСЬ — единственное, чем побочная ось топит главную.
            (&[Fate::Mirage], false),
            // Эталона не было: подлинность не установлена — и это не свидетельство против.
            (ШИРОКИЙ, true),
            // Круг полон: показание `Bytes` такого круга не даёт, но закон всё равно
            // читается по показанию, а не по ширине круга.
            (&ALL_FATES, true),
        ];
        for &(circle, ожидание) in таблица {
            assert_eq!(
                passed(Observed::Bytes, Ended::BodyComplete, Admits(circle)),
                ожидание,
                "круг {circle:?}"
            );
        }
    }

    #[test]
    fn неустановленная_подлинность_не_топит_вердикт_о_канале() {
        // Тот самый девятикратный случай с живой линии: байты через DPI прошли, а
        // эталона нет либо страница гуляет между узлами CDN. Круг честно широк, и
        // стратегия ОБЯЗАНА считаться рабочей.
        assert!(passed(
            Observed::Bytes,
            Ended::BodyComplete,
            Admits(ШИРОКИЙ)
        ));
        // Мутация «working = (круг == [Good])» красит ровно здесь.
        assert!(!matches!(Admits(ШИРОКИЙ).0, [Fate::Good]));
    }

    #[test]
    fn мы_перестали_ждать_это_не_обрыв_разговора() {
        // `WeStoppedWaiting` при непустом теле значит «канал отдавал, а мы ушли».
        // Списать это на цензора значило бы похоронить рабочую стратегию за свой промах.
        assert!(passed(
            Observed::Bytes,
            Ended::WeStoppedWaiting,
            Admits(ШИРОКИЙ)
        ));
        // А сброс посреди передачи — именно обрыв.
        assert!(!passed(Observed::Bytes, Ended::BodyError, Admits(ШИРОКИЙ)));
    }

    #[test]
    fn разошедшееся_содержимое_топит_даже_при_целом_разговоре() {
        // Блок-страница провайдера доезжает целиком и без единой ошибки чтения.
        // Побочная ось здесь высказалась ПОЛОЖИТЕЛЬНО — и только потому топит.
        assert!(!passed(
            Observed::Bytes,
            Ended::BodyComplete,
            Admits(MIRAGE_ONLY)
        ));
    }

    #[test]
    fn проход_и_круг_судеб_живут_порознь() {
        // Ради этого правка и делалась: у одного и того же прохода круг может быть
        // любым из трёх, и вердикт о КАНАЛЕ от этого не меняется.
        let reference = эталон();
        let сошлось = narrow(Evidence {
            observed: Observed::Bytes,
            sag: None,
            attempts: 1,
            reference: Some(&reference),
            print: проба(105_000),
        });
        let без_эталона = narrow(Evidence {
            observed: Observed::Bytes,
            sag: None,
            attempts: 1,
            reference: None,
            print: проба(105_000),
        });
        assert_eq!(сошлось.0, [Fate::Good].as_slice());
        assert_eq!(без_эталона.0, ШИРОКИЙ);
        assert!(passed(Observed::Bytes, Ended::BodyComplete, сошлось));
        assert!(passed(Observed::Bytes, Ended::BodyComplete, без_эталона));
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
