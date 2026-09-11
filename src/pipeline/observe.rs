//! Наблюдения сокета, переведённые в буквы парка. Чистые функции: сеть остаётся у того,
//! кто ленту собирает, толкование живёт здесь и проверяется без неё.

use crate::network::cause::{Cause, Phase};
use crate::network::http_client::Ended;
use crate::pipeline::fate::Delivery;
use reflex_core::mealy::Mealy;
use reflex_core::DetectorEvent;
use reflex_instrument::pace::{PaceInstrument, Waited};
use reflex_instrument::sag::{Sag, SagInstrument};

/// Что доставило плечо. `Abandoned` — честный ответ там, где о цели не установлено
/// ничего: мы перестали ждать (`WeStoppedWaiting`) либо до тела не дошло и почему —
/// неизвестно (`NeverStarted`: таймаут, `Io`, `Protocol`). `Silent` — там, где окно
/// досмотрено и пусто, ЛИБО отказ пришёл определённый (`Denied`): `ECONNREFUSED`,
/// отсутствие маршрута и `RST` есть ОТВЕТ цели, а не его отсутствие, и повторять
/// пробу незачем (`Cause::deterministic`).
pub fn delivery_of(bytes: u64, ended: Ended) -> Delivery {
    match (bytes, ended) {
        // Байты были — остальное неважно: факт о цели состоялся.
        (1.., _) => Delivery::Delivered,
        (0, Ended::WeStoppedWaiting | Ended::NeverStarted) => Delivery::Abandoned,
        // Лимит без единого байта недостижим (лимит считается от байтов), но разбор
        // тотален: ветка есть, и она честнее, чем `unreachable!()`.
        (0, Ended::LimitReached) => Delivery::Abandoned,
        (0, Ended::BodyComplete | Ended::BodyError | Ended::Denied) => Delivery::Silent,
    }
}

/// Встал ли TCP. Фаза отказа и есть ответ: `Phase` упорядочена по прохождению, и всё
/// выше `Connect` достижимо только через установленное соединение.
pub fn connected_of(cause: Option<Cause>) -> bool {
    match cause {
        None => true,
        Some(Cause::Refused) | Some(Cause::Unreachable) => false,
        Some(Cause::Reset(p))
        | Some(Cause::Timeout(p))
        | Some(Cause::Io(p))
        | Some(Cause::Protocol(p)) => p > Phase::Connect,
    }
}

/// Просадка канала по ряду секундных окон. Прибор без состояния — гоняем один шаг.
/// `None` значит «не сузили»: либо просадки нет, либо окон меньше, чем прибору нужно
/// (маховик и хвост он отбрасывает сам). Разные причины, один ответ — и потому
/// толковать `None` как «всё хорошо» нельзя.
pub fn sag_of(windows: &[u64]) -> Option<Sag> {
    let (_, spoken, ()) = SagInstrument.step(DetectorEvent::Packet {
        input: windows.to_vec(),
        at: std::time::Instant::now(),
    });
    spoken.into_iter().next()
}

/// Сколько человек ждал запрошенного. Прибор мерит не «сколько байт», а «сколько ждал»:
/// поток, отдавший мегабайт за две минуты и за две секунды, по объёму неразличим, а
/// переживается противоположно.
pub fn waited_of(elapsed: std::time::Duration) -> Option<Waited> {
    let (_, spoken, ()) = PaceInstrument.step(DetectorEvent::Packet {
        input: elapsed,
        at: std::time::Instant::now(),
    });
    spoken.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn байты_всегда_есть_доставка() {
        // Даже если потом оборвали: байты БЫЛИ, и это факт о цели.
        assert_eq!(delivery_of(1, Ended::BodyError), Delivery::Delivered);
        assert_eq!(
            delivery_of(4096, Ended::WeStoppedWaiting),
            Delivery::Delivered
        );
    }

    #[test]
    fn ноль_байт_и_мы_перестали_ждать_есть_брошенное_наблюдение() {
        // НЕ «цель молчала»: мы не досмотрели. Приговор за это выносить не за что.
        assert_eq!(delivery_of(0, Ended::WeStoppedWaiting), Delivery::Abandoned);
        assert_eq!(delivery_of(0, Ended::NeverStarted), Delivery::Abandoned);
    }

    #[test]
    fn ноль_байт_при_досмотренном_окне_есть_молчание_цели() {
        // Поток закрыт сервером или оборван им: окно досмотрено, и пусто — факт о ЦЕЛИ.
        assert_eq!(delivery_of(0, Ended::BodyComplete), Delivery::Silent);
        assert_eq!(delivery_of(0, Ended::BodyError), Delivery::Silent);
    }

    #[test]
    fn определённый_отказ_до_тела_есть_молчание_цели_а_не_наша_слепота() {
        // `Refused`/`Unreachable`/`RST` приезжают как `Ended::Denied`. Пока они ехали
        // как `NeverStarted`, выходило `Abandoned` → `Unobserved` при любом `connected`,
        // и результат `connected_of` игнорировался всегда, когда байтов не было.
        assert_eq!(delivery_of(0, Ended::Denied), Delivery::Silent);
    }

    #[test]
    fn мёртвая_цель_и_ловушка_становятся_достижимы() {
        // Ровно то, ради чего заведён `Denied`: `Fate::Dead` и `Fate::Trap` рекламируются
        // в README и держат ступени в `rank::step`, а не производились никогда.
        use crate::pipeline::fate::{observe, Fate, Observed};
        let denied = delivery_of(0, Ended::Denied);
        // Отказ на коннекте: TCP не встал.
        let no_connect = observe(connected_of(Some(Cause::Refused)), denied);
        assert_eq!(no_connect, Observed::NoConnect);
        assert_eq!(no_connect.admits(), [Fate::Dead].as_slice());
        // Сброс по SNI: рукопожатие началось, значит TCP встал.
        let mute = observe(connected_of(Some(Cause::Reset(Phase::Tls))), denied);
        assert_eq!(mute, Observed::Mute);
        assert_eq!(mute.admits(), [Fate::Trap].as_slice());
    }

    #[test]
    fn таймаут_коннекта_не_доказывает_что_коннекта_не_было() {
        // Мы перестали ждать SYN/ACK — о цели это не говорит ничего.
        assert!(!connected_of(Some(Cause::Timeout(Phase::Connect))));
        // Отказ и отсутствие маршрута — ОТВЕТ, а не его отсутствие.
        assert!(!connected_of(Some(Cause::Refused)));
        assert!(!connected_of(Some(Cause::Unreachable)));
    }

    #[test]
    fn отказ_на_фазе_выше_коннекта_означает_что_коннект_был() {
        assert!(connected_of(Some(Cause::Reset(Phase::Tls))));
        assert!(connected_of(Some(Cause::Timeout(Phase::Body))));
        // Причины нет вовсе — значит дошли до конца, коннект был.
        assert!(connected_of(None));
    }

    #[test]
    fn просадка_видна_по_ряду_а_не_по_порогу() {
        // Маховик, четыре ровных, обвал, хвост. Планка — первое окно ПОСЛЕ маховика.
        let windows = vec![10_000, 100_000, 100_000, 100_000, 2_000, 2_000, 500];
        let sag = sag_of(&windows).expect("просадка обязана быть названа");
        assert_eq!(sag.before_bps, 100_000);
        assert!(sag.after_bps < sag.before_bps);
    }

    #[test]
    fn ровно_медленный_канал_не_есть_просадка() {
        // Разницу между «всегда медленный» и «начало качаться хреново» даёт только ряд.
        let windows = vec![900, 1_000, 1_000, 1_000, 1_000, 1_000, 900];
        assert_eq!(sag_of(&windows), None);
    }

    #[test]
    fn короткий_разговор_есть_наша_слепота_а_не_отсутствие_просадки() {
        // Меньше четырёх окон — прибор молчит, и это НЕ «всё хорошо».
        assert_eq!(sag_of(&[100_000, 1]), None);
        assert_eq!(sag_of(&[]), None);
    }

    #[test]
    fn нулевое_ожидание_не_показание() {
        // Прибор молчит о нуле: «ждал ноль» значит «не мерили».
        assert_eq!(waited_of(std::time::Duration::ZERO), None);
    }

    #[test]
    fn ожидание_называется_с_адресом_а_не_голой_длительностью() {
        let waited = waited_of(std::time::Duration::from_millis(1500)).expect("показание");
        assert_eq!(waited.0, std::time::Duration::from_millis(1500));
    }
}
