//! Причина провала пробы — то, что сейчас теряется при схлопывании ошибки в строку.
//!
//! ИНСТРУМЕНТОВКА ЗАМЕРА (спайк #verify-histogram). Вопрос, на который она отвечает:
//! какая доля провалов `verify` детерминирована (сброс от DPI), а какая нет (тишина).
//! От этого зависит, можно ли схлопнуть три прохода в один плюс адресный повтор.
//!
//! Две оси, и обе нужны: ВИД отказа и ФАЗА, на которой он случился. Вид без фазы
//! не различает блок по адресу от блока по имени — таймаут на `connect` есть
//! чёрная дыра (`SYN` не дошёл), таймаут после рукопожатия есть тишина уже
//! открытого разговора. Это ровно тот раскол, который на проводе дают
//! `Blackhole` и `Silence`.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

/// Докуда дошла проба. Порядок — это порядок прохождения: каждая следующая
/// фаза достижима только через предыдущую.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    /// TCP-соединение ещё не установлено.
    Connect,
    /// Соединение есть, идёт TLS-рукопожатие.
    Tls,
    /// Рукопожатие прошло, послан запрос, ждём заголовки.
    Request,
    /// Заголовки получены, читаем тело.
    Body,
}

/// Вид отказа вместе с фазой.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cause {
    /// Пришёл RST. Детерминированный отказ — повторять пробу незачем.
    Reset(Phase),
    /// Ничего не пришло за отведённое время. Недетерминированно: потеря пакета
    /// даёт то же самое, и только здесь повтор осмыслен.
    Timeout(Phase),
    /// Порт закрыт (`ECONNREFUSED`) — цель жива и отвечает отказом.
    Refused,
    /// Маршрута нет (`EHOSTUNREACH`/`ENETUNREACH`).
    Unreachable,
    /// Прочая ошибка ввода-вывода.
    Io(Phase),
    /// Не ввод-вывод: TLS-алерт, разбор ответа. Провод жив, не сошлось выше.
    Protocol(Phase),
}

impl Cause {
    /// Имя для гистограммы — публичный контракт замера, не `Debug`.
    pub fn name(&self) -> String {
        match self {
            Cause::Reset(p) => format!("reset/{}", p.name()),
            Cause::Timeout(p) => format!("timeout/{}", p.name()),
            Cause::Refused => "refused".to_string(),
            Cause::Unreachable => "unreachable".to_string(),
            Cause::Io(p) => format!("io/{}", p.name()),
            Cause::Protocol(p) => format!("protocol/{}", p.name()),
        }
    }

    /// Детерминирован ли отказ — то самое, ради чего затеян замер. Сброс есть
    /// ответ цензора, он воспроизведётся; тишина может быть потерей пакета.
    pub fn deterministic(&self) -> bool {
        match self {
            // Сброс, отказ и отсутствие маршрута — ответ, а не его отсутствие:
            // цель или цензор высказались, и повтор скажет то же самое.
            Cause::Reset(_) | Cause::Refused | Cause::Unreachable => true,
            // Тишина неотличима от потери пакета — только здесь повтор осмыслен.
            Cause::Timeout(_) => false,
            // Прочее не берёмся звать детерминированным: не знаем.
            Cause::Io(_) | Cause::Protocol(_) => false,
        }
    }
}

impl Phase {
    pub fn name(&self) -> &'static str {
        match self {
            Phase::Connect => "connect",
            Phase::Tls => "tls",
            Phase::Request => "request",
            Phase::Body => "body",
        }
    }
}

/// Классифицировать ошибку, случившуюся на названной фазе.
///
/// `rustls` и `hyper` заворачивают `io::Error` в свои типы, поэтому вид ищется
/// по цепочке `source()`, а не в верхнем звене: `ConnectionReset`, пришедший
/// как `hyper::Error`, обязан остаться сбросом.
pub fn classify(err: &(dyn std::error::Error + 'static), phase: Phase) -> Cause {
    let mut link = Some(err);
    while let Some(current) = link {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            return of_kind(io, phase);
        }
        link = current.source();
    }
    // Ни одного звена ввода-вывода в цепочке: провод жив, не сошлось выше.
    Cause::Protocol(phase)
}

/// Вид отказа по ошибке ядра. `ErrorKind` покрывает не всё (варианты вроде
/// `HostUnreachable` стабильны не во всяком тулчейне), поэтому там, где вид
/// назван неточно, спрашивается номер ошибки — он в ядре не менялся никогда.
fn of_kind(io: &std::io::Error, phase: Phase) -> Cause {
    use std::io::ErrorKind;
    match io.kind() {
        // ECONNRESET и ECONNABORTED: разговор оборван встречной стороной.
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => Cause::Reset(phase),
        ErrorKind::TimedOut => Cause::Timeout(phase),
        ErrorKind::ConnectionRefused => Cause::Refused,
        _ => match io.raw_os_error() {
            // EHOSTUNREACH, ENETUNREACH, ENETDOWN.
            Some(113) | Some(101) | Some(100) => Cause::Unreachable,
            // ECONNRESET, ECONNABORTED, EPIPE — на случай, если вид не назван.
            Some(104) | Some(103) | Some(32) => Cause::Reset(phase),
            Some(110) => Cause::Timeout(phase),
            _ => Cause::Io(phase),
        },
    }
}

/// Отметка достигнутой фазы. Нужна затем, что внешний `tokio::time::timeout`
/// срывает пробу, не сказав, где она стояла, — а без фазы таймаут неотличим:
/// чёрная дыра и тишина сливаются в одну букву.
#[derive(Debug, Clone)]
pub struct Reached(Arc<AtomicU8>);

impl Default for Reached {
    fn default() -> Self {
        Reached(Arc::new(AtomicU8::new(Phase::Connect as u8)))
    }
}

impl Reached {
    /// Отметить, что проба дошла до этой фазы.
    pub fn mark(&self, phase: Phase) {
        self.0.fetch_max(phase as u8, Ordering::Relaxed);
    }

    /// Самая дальняя достигнутая фаза.
    pub fn phase(&self) -> Phase {
        match self.0.load(Ordering::Relaxed) {
            0 => Phase::Connect,
            1 => Phase::Tls,
            2 => Phase::Request,
            _ => Phase::Body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// Обёртка вроде тех, что строят `rustls`/`hyper`: своя ошибка, а истинная
    /// причина — в `source()`.
    #[derive(Debug)]
    struct Wrapped(io::Error);

    impl std::fmt::Display for Wrapped {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "wrapped")
        }
    }

    impl std::error::Error for Wrapped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn a_reset_is_classified_as_a_reset_on_its_phase() {
        let err = io::Error::from(io::ErrorKind::ConnectionReset);
        assert_eq!(classify(&err, Phase::Tls), Cause::Reset(Phase::Tls));
    }

    #[test]
    fn a_reset_hidden_under_a_wrapper_is_still_a_reset() {
        let err = Wrapped(io::Error::from(io::ErrorKind::ConnectionReset));
        assert_eq!(classify(&err, Phase::Request), Cause::Reset(Phase::Request));
    }

    #[test]
    fn a_refused_connection_loses_its_phase_because_only_connect_can_refuse() {
        let err = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(classify(&err, Phase::Connect), Cause::Refused);
    }

    #[test]
    fn an_error_with_no_io_anywhere_in_the_chain_is_a_protocol_error() {
        #[derive(Debug)]
        struct Alert;
        impl std::fmt::Display for Alert {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "alert")
            }
        }
        impl std::error::Error for Alert {}
        assert_eq!(classify(&Alert, Phase::Tls), Cause::Protocol(Phase::Tls));
    }

    #[test]
    fn a_reset_is_deterministic_and_a_timeout_is_not() {
        assert!(Cause::Reset(Phase::Tls).deterministic());
        assert!(!Cause::Timeout(Phase::Tls).deterministic());
    }

    #[test]
    fn a_fresh_probe_has_reached_only_connect() {
        assert_eq!(Reached::default().phase(), Phase::Connect);
    }

    #[test]
    fn the_furthest_phase_is_kept_not_the_last_one_marked() {
        let reached = Reached::default();
        reached.mark(Phase::Request);
        reached.mark(Phase::Tls);
        assert_eq!(
            reached.phase(),
            Phase::Request,
            "отметка назад не смеет откатывать достигнутое: иначе таймаут на теле \
             припишется рукопожатию"
        );
    }

    #[test]
    fn a_clone_shares_the_mark_with_its_origin() {
        let reached = Reached::default();
        let handle = reached.clone();
        handle.mark(Phase::Body);
        assert_eq!(
            reached.phase(),
            Phase::Body,
            "отметку ставит внутренность пробы, а читает внешний таймаут — они \
             держат разные копии одного счёта"
        );
    }
}
