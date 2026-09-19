//! МАШИНОЧИТАЕМАЯ ВЫДАЧА для того, кто поднял подбор не руками.
//!
//! Две разные вещи, и обе — ndjson, по строке на событие:
//!
//! · ПОТОК РЕЗУЛЬТАТОВ (`stdout`) — подтверждённая стратегия отдаётся В МОМЕНТ подтверждения,
//!   а не в конце прогона. Пока идёт подбор, цель держат в карантине, и человек сидит под
//!   укрытием; первая же годная стратегия лечит, а всё время до конца `--take` он платит зря.
//!   Прежде продукт узнавал хоть что-то только по завершении процесса.
//!
//! · ПРОГРЕСС (`stderr`) — чтобы «встал» судилось СРОКОМ, а не гаданием по человекочитаемому
//!   выводу. Единственным ответом на «жив или завис» был наш собственный текст для глаз.
//!
//! Потоки разведены намеренно: результат и ход работы читают по-разному, и смешать их значило
//! бы заставить читателя разбирать одно из другого.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::dto::VerifiedStrategy;

static STREAM: AtomicBool = AtomicBool::new(false);
static PROGRESS: AtomicBool = AtomicBool::new(false);

/// Включить поток результатов в stdout.
pub fn set_stream(on: bool) {
    STREAM.store(on, Ordering::Relaxed);
}

/// Включить поток прогресса в stderr.
pub fn set_progress(on: bool) {
    PROGRESS.store(on, Ordering::Relaxed);
}

pub fn stream_is_on() -> bool {
    STREAM.load(Ordering::Relaxed)
}

/// Отдать подтверждённую стратегию НЕМЕДЛЕННО.
///
/// `flush` обязателен: без него строка осядет в буфере до конца процесса, и весь смысл
/// (лечить человека первой же годной стратегией) пропадёт — читатель получит всё разом, как
/// и раньше. Сломанная труба молчит: читатель вправе уйти, дочитав нужное ему.
pub fn emit_working(strategy: &VerifiedStrategy) {
    if !stream_is_on() {
        return;
    }
    let line = match serde_json::to_string(&StreamRow {
        event: "working",
        strategy,
    }) {
        Ok(json) => json,
        Err(_) => return,
    };
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

#[derive(serde::Serialize)]
struct StreamRow<'a> {
    event: &'a str,
    #[serde(flatten)]
    strategy: &'a VerifiedStrategy,
}

/// Отметить ход работы: фаза, сколько сделано из скольких, сколько секунд прошло.
pub fn emit_progress(phase: &str, done: usize, total: usize, elapsed_secs: f64) {
    if !PROGRESS.load(Ordering::Relaxed) {
        return;
    }
    let line = format!(
        r#"{{"event":"progress","phase":"{phase}","done":{done},"total":{total},"elapsed":{elapsed_secs:.1}}}"#
    );
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{line}");
    let _ = err.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> VerifiedStrategy {
        VerifiedStrategy {
            protocol: "HTTPS/TLS1.2".to_string(),
            args: "--payload=tls_client_hello".to_string(),
            coverage: 1,
            success_rate: 1.0,
            median_latency_ms: 700,
            median_speed_kbps: 140.0,
            passes_ok: 3,
            passes_total: 3,
            median_share: Some(1.0),
            longest_silence_ms: Some(370),
            observed: "Bytes".to_string(),
            admits: vec!["Good".to_string()],
            working: true,
        }
    }

    /// Строка потока несёт И событие, И саму стратегию плоско: читателю не нужно разбирать
    /// вложенный объект, чтобы поднять слот, — `args` и `protocol` лежат на верхнем уровне.
    #[test]
    fn a_streamed_row_carries_the_strategy_flat() {
        let strategy = row();
        let json = serde_json::to_string(&StreamRow {
            event: "working",
            strategy: &strategy,
        })
        .expect("строка потока сериализуема");

        let v: serde_json::Value = serde_json::from_str(&json).expect("это JSON");
        assert_eq!(v["event"], "working");
        assert_eq!(v["protocol"], "HTTPS/TLS1.2");
        assert_eq!(v["args"], "--payload=tls_client_hello");
        assert_eq!(v["working"], true);
        assert!(
            !json.contains('\n'),
            "строка потока обязана быть одной строкой"
        );
    }

    /// Выключенный поток молчит: одиночный запуск человеком не должен обрастать машинными
    /// строками поверх человекочитаемого вывода.
    #[test]
    fn the_stream_is_silent_until_asked() {
        set_stream(false);
        assert!(!stream_is_on());
        set_stream(true);
        assert!(stream_is_on());
        set_stream(false);
    }
}
