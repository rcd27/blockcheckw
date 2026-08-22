//! CLI-поведение бинаря: запускаем настоящий исполняемый файл.
//!
//! Root не требуется — эти проверки как раз о том, что справка выводится
//! до любых привилегированных действий.

use std::process::{Command, Stdio};

/// Запустить blockcheckw с аргументами, вернуть (stdout + stderr, успех).
fn run(args: &[&str]) -> (String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_blockcheckw"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("не удалось запустить blockcheckw");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (combined, out.status.success())
}

/// issue #66: `blockcheckw` без аргументов поднимал права через sudo и печатал
/// диагностику окружения вместо справки.
#[test]
fn bare_invocation_prints_help_only() {
    let (output, ok) = run(&[]);

    assert!(ok, "голый запуск должен завершаться успешно:\n{output}");
    assert!(output.contains("Usage:"), "ожидалась справка:\n{output}");
    assert!(
        !output.contains("Checking prerequisites"),
        "prereq-проверка не должна выполняться без команды:\n{output}"
    );
    assert!(
        !output.contains("elevating with sudo"),
        "справка не должна требовать root:\n{output}"
    );
}

/// bol-van (#66): «неясно, как менять другие параметры типа задержек.
/// Нет ни в --help, ни в доке в явном виде» — флаги живут в сабкомандах,
/// и верхнеуровневая справка обязана на это указывать.
#[test]
fn help_points_to_per_command_flags() {
    let (output, _) = run(&["--help"]);

    assert!(
        output.contains("Examples:"),
        "справке нужны примеры запуска:\n{output}"
    );
    assert!(
        output.contains("<command> --help"),
        "справка должна указывать, где искать флаги команд:\n{output}"
    );
}
