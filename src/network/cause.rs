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

use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Докуда дошла проба. Порядок — это порядок прохождения: каждая следующая
/// фаза достижима только через предыдущую.
///
/// Фазы двух транспортов живут в одном порядке и не смешиваются в одной пробе: TCP идёт
/// `Connect → Tls → Request → Body`, QUIC — `Initial → Handshake → Request → Body`.
/// Номера разведены так, чтобы оба пути были возрастающими, — отметка берёт максимум.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    /// TCP-соединение ещё не установлено.
    Connect = 0,
    /// QUIC: Initial с ClientHello ушёл, ответа сервера ещё нет. Аналог `Connect`: у UDP
    /// нет рукопожатия транспорта, и первый ответ цели приходит уже в криптографии —
    /// тишина здесь и есть чёрная дыра QUIC.
    Initial = 1,
    /// Соединение есть, идёт TLS-рукопожатие.
    Tls = 2,
    /// QUIC: сервер ответил своим Handshake, рукопожатие не завершено. Аналог `Tls`:
    /// цель слышит нас, и отказ здесь — уже не блок по адресу.
    Handshake = 3,
    /// Рукопожатие прошло, послан запрос, ждём заголовки.
    Request = 4,
    /// Заголовки получены, читаем тело.
    Body = 5,
}

/// Вид отказа вместе с фазой.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cause {
    /// Пришёл RST. Детерминированный отказ — повторять пробу незачем.
    Reset(Phase),
    /// Цель замолчала на этой фазе дольше порога тишины — `Expiry::Idle` оператора
    /// сроков reflex, либо ядро само сдалось ждать ответа (`ETIMEDOUT`). Вывод о мире,
    /// но недетерминированный: потеря пакета даёт то же самое, и только здесь повтор
    /// осмыслен.
    Idle(Phase),
    /// Мы перестали ждать, хотя цель ещё шла — `Expiry::Ceiling`. Утверждение о НАС:
    /// о цели оно не говорит ничего, и слить его с тишиной значило бы приписать миру
    /// наше нетерпение.
    Ceiling(Phase),
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
            Cause::Idle(p) => format!("idle/{}", p.name()),
            Cause::Ceiling(p) => format!("ceiling/{}", p.name()),
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
            Cause::Idle(_) | Cause::Ceiling(_) => false,
            // Прочее не берёмся звать детерминированным: не знаем.
            Cause::Io(_) | Cause::Protocol(_) => false,
        }
    }
}

impl Phase {
    pub fn name(&self) -> &'static str {
        match self {
            Phase::Connect => "connect",
            Phase::Initial => "initial",
            Phase::Tls => "tls",
            Phase::Handshake => "handshake",
            Phase::Request => "request",
            Phase::Body => "body",
        }
    }

    /// Ответила ли цель хоть чем-то до этой фазы. TCP — встал ли коннект, QUIC — пришёл
    /// ли от сервера хоть один пакет рукопожатия. Порядок номеров здесь не годится:
    /// `Initial` стоит выше `Connect`, но так же ничего о цели не знает.
    pub fn answered(&self) -> bool {
        match self {
            Phase::Connect | Phase::Initial => false,
            Phase::Tls | Phase::Handshake | Phase::Request | Phase::Body => true,
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
        ErrorKind::TimedOut => Cause::Idle(phase),
        ErrorKind::ConnectionRefused => Cause::Refused,
        _ => match io.raw_os_error() {
            // EHOSTUNREACH, ENETUNREACH, ENETDOWN.
            Some(113) | Some(101) | Some(100) => Cause::Unreachable,
            // ECONNRESET, ECONNABORTED, EPIPE — на случай, если вид не назван.
            Some(104) | Some(103) | Some(32) => Cause::Reset(phase),
            Some(110) => Cause::Idle(phase),
            _ => Cause::Io(phase),
        },
    }
}

/// Отметка достигнутой фазы и последнего ШАГА пробы. Фаза нужна затем, что сторож
/// срывает пробу, не зная, где она стояла, — а без фазы срок неотличим: чёрная дыра и
/// тишина сливаются в одну букву. Шаг нужен сторожу (`patience`): тишина считается от
/// последнего продвижения, а не от начала запроса.
///
/// Моменты — миллисекунды от рождения пробы в `AtomicU32`, а не `AtomicU64`: его нет на
/// mips, mipsel и ppc (`ebf597e`). `u32` миллисекунд кончается через 49 суток — проба
/// столько не живёт.
#[derive(Debug, Clone)]
pub struct Reached {
    phase: Arc<AtomicU8>,
    born: Instant,
    last_stride_ms: Arc<AtomicU32>,
    longest_silence_ms: Arc<AtomicU32>,
}

impl Default for Reached {
    fn default() -> Self {
        Reached {
            phase: Arc::new(AtomicU8::new(Phase::Connect as u8)),
            born: Instant::now(),
            last_stride_ms: Arc::new(AtomicU32::new(0)),
            longest_silence_ms: Arc::new(AtomicU32::new(0)),
        }
    }
}

impl Reached {
    /// Отметить, что проба дошла до этой фазы. Переход фазы — всегда шаг.
    pub fn mark(&self, phase: Phase) {
        self.phase.fetch_max(phase as u8, Ordering::Relaxed);
        self.stride();
    }

    /// Проба продвинулась: цель ответила чем-то новым (кадр тела, завершённая фаза).
    pub fn stride(&self) {
        let at = self.since_born(Instant::now());
        let previous = self.last_stride_ms.swap(at, Ordering::Relaxed);
        self.longest_silence_ms
            .fetch_max(at.saturating_sub(previous), Ordering::Relaxed);
    }

    /// Когда проба родилась — отсюда сторож считает потолок.
    pub fn born(&self) -> Instant {
        self.born
    }

    /// Момент последнего шага.
    pub fn last_stride(&self) -> Instant {
        self.born + Duration::from_millis(u64::from(self.last_stride_ms.load(Ordering::Relaxed)))
    }

    /// Самая длинная тишина между шагами. Мерило порога: здоровая проба показывает,
    /// сколько тишины живой разговор себе позволяет.
    pub fn longest_silence(&self) -> Duration {
        Duration::from_millis(u64::from(self.longest_silence_ms.load(Ordering::Relaxed)))
    }

    fn since_born(&self, at: Instant) -> u32 {
        u32::try_from(at.saturating_duration_since(self.born).as_millis()).unwrap_or(u32::MAX)
    }

    /// Самая дальняя достигнутая фаза.
    pub fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Relaxed) {
            0 => Phase::Connect,
            1 => Phase::Initial,
            2 => Phase::Tls,
            3 => Phase::Handshake,
            4 => Phase::Request,
            _body => Phase::Body,
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
        assert!(!Cause::Idle(Phase::Tls).deterministic());
        assert!(!Cause::Ceiling(Phase::Tls).deterministic());
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
    fn every_phase_survives_the_atomic_mark() {
        // Отметка хранит номер фазы; расшифровка, забывшая новый номер, приписала бы
        // тишину на Initial телу — и чёрная дыра QUIC читалась бы как обрыв данных.
        [
            Phase::Connect,
            Phase::Initial,
            Phase::Tls,
            Phase::Handshake,
            Phase::Request,
            Phase::Body,
        ]
        .into_iter()
        .for_each(|phase| {
            let reached = Reached::default();
            reached.mark(phase);
            assert_eq!(reached.phase(), phase);
        });
    }

    #[test]
    fn quic_phases_ascend_in_the_order_they_are_passed() {
        assert!(Phase::Initial < Phase::Handshake);
        assert!(Phase::Handshake < Phase::Request);
    }

    #[test]
    fn silence_on_initial_is_no_answer_and_on_handshake_is_one() {
        assert!(!Phase::Initial.answered());
        assert!(!Phase::Connect.answered());
        assert!(Phase::Handshake.answered());
        assert_eq!(Cause::Idle(Phase::Initial).name(), "idle/initial");
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
