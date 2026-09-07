//! Корпус стратегий не смеет содержать разделитель профилей.
//!
//! Строка с `--new` внутри молча слилась бы с соседним профилем: стратегия-жертва
//! объявилась бы нерабочей, а её соседка — применённой не той. Ни движок, ни мы
//! об этом не сообщим. Корпус пополняется, поэтому проверка нужна постоянная.

use std::fs;

#[test]
fn no_strategy_line_contains_a_profile_separator_or_filter() {
    let mut checked = 0usize;
    for name in ["http.txt", "tls12.txt", "tls13.txt"] {
        let path = format!("strategies/{name}");
        let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        for (lineno, line) in body.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            checked += 1;
            for token in line.split_whitespace() {
                assert_ne!(
                    token,
                    "--new",
                    "{path}:{}: разделитель профилей",
                    lineno + 1
                );
                assert!(
                    !token.starts_with("--filter-mark"),
                    "{path}:{}: стратегия задаёт марку профиля сама",
                    lineno + 1
                );
            }
        }
    }
    assert!(
        checked > 13_000,
        "корпус подозрительно мал: {checked} строк"
    );
}
