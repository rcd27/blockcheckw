//! Наблюдения сокета, переведённые в буквы парка. Чистые функции: сеть остаётся у того,
//! кто ленту собирает, толкование живёт здесь и проверяется без неё.

use crate::network::cause::{Cause, Phase};
use crate::network::http_client::Ended;
use crate::pipeline::fate::Delivery;

/// Что доставило плечо. `Abandoned` — единственный честный ответ там, где ждать
/// перестали мы: окно не досмотрено, и о цели не установлено ничего.
pub fn delivery_of(bytes: u64, ended: Ended) -> Delivery {
    match (bytes, ended) {
        // Байты были — остальное неважно: факт о цели состоялся.
        (1.., _) => Delivery::Delivered,
        (0, Ended::WeStoppedWaiting | Ended::NeverStarted) => Delivery::Abandoned,
        // Лимит без единого байта недостижим (лимит считается от байтов), но разбор
        // тотален: ветка есть, и она честнее, чем `unreachable!()`.
        (0, Ended::LimitReached) => Delivery::Abandoned,
        (0, Ended::BodyComplete | Ended::BodyError) => Delivery::Silent,
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
}
