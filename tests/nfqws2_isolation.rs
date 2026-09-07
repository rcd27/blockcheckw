//! Границы модуля `src/nfqws2/` — по образцу `tests/nft_isolation.rs`.
//!
//! Второй тест важнее первого. В `zond/src/desync/mod.rs` записано, как после
//! поглощения крейта граница «в хирургии нет сокетов» перестала быть фактом
//! сборки и стала дисциплиной, которую замечает только читатель. У нас та же
//! ситуация — модуль вместо крейта, — но она лечится grep'ом по дереву, и он же
//! гарантирует, что вынос в отдельный крейт останется механическим.
//!
//! Третий guard стережёт третью дыру: собрать argv движка руками (обойдя
//! `Plan::argv`) можно откуда угодно, если просто написать строку с нужным
//! флагом. `Plan::argv` существует именно для того, чтобы такой сборки нигде,
//! кроме `src/nfqws2/`, не было.
//!
//! Все три guard'а снимают строчные комментарии перед поиском: иначе они падают
//! на собственной документации (этот файл и `mod.rs`/`plan.rs` называют
//! запрещённые строки вслух, объясняя запрет) и на комментариях-упоминаниях в
//! `src/cmd/mod.rs` и `src/pipeline/runner.rs`. Снятие комментариев учитывает
//! строковые литералы: `//` внутри `"…"` (например, URL) не обрывает строку —
//! иначе пострадали бы `src/network/doh.rs`, `via.rs` и другие файлы с
//! `https://` в литералах.

use std::fs;
use std::path::Path;

/// Все `.rs` в каталоге, рекурсивно — путь и тело файла с уже снятыми
/// строчными комментариями.
fn rust_files(dir: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![Path::new(dir).to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path)
            .unwrap_or_else(|e| panic!("{path:?}: {e}"))
            .flatten()
        {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let body = fs::read_to_string(&p).unwrap_or_default();
                out.push((p.display().to_string(), strip_line_comments(&body)));
            }
        }
    }
    out
}

/// Снимает `//...` до конца строки, не трогая содержимое строковых литералов
/// (учитывает экранирование `\"`). Блочных комментариев `/* */` в дереве нет —
/// их эта функция не обрабатывает.
fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let mut in_string = false;
        let mut escaped = false;
        let mut chars = line.char_indices().peekable();
        let mut cut_at = line.len();
        while let Some((i, c)) = chars.next() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }
            if c == '"' {
                in_string = true;
                continue;
            }
            if c == '/' && chars.peek().map(|(_, n)| *n) == Some('/') {
                cut_at = i;
                break;
            }
        }
        out.push_str(&line[..cut_at]);
        out.push('\n');
    }
    out
}

#[test]
fn the_engine_is_started_only_from_the_nfqws2_module() {
    for (path, body) in rust_files("src") {
        // `BackgroundProcess::spawn` объявлен и легитимно вызывается своими
        // же тестами в определяющем модуле.
        if path.starts_with("src/nfqws2/") || path == "src/system/process.rs" {
            continue;
        }
        assert!(
            !body.contains("BackgroundProcess::spawn"),
            "{path}: фоновые процессы поднимает только src/nfqws2/run.rs"
        );
    }
}

#[test]
fn the_pure_core_stays_pure() {
    const FORBIDDEN: [&str; 4] = ["tokio", "std::process", "crate::config", "crate::error"];
    for (path, body) in rust_files("src/nfqws2") {
        if path.ends_with("run.rs") {
            continue;
        }
        for needle in FORBIDDEN {
            assert!(
                !body.contains(needle),
                "{path}: «{needle}» ломает переносимость ядра — \
                 второй потребитель (zond) блокирующий и на iptables"
            );
        }
    }
}

#[test]
fn the_engine_command_line_is_built_only_by_the_nfqws2_module() {
    // Флаги ищем как начало строкового литерала (сразу после открывающей
    // кавычки), а не как произвольную подстроку: `Plan::argv` собирает их
    // именно так — `format!("--filter-mark={...}")`, `"--new".to_string()` —
    // а строка пользовательского вывода вроде `con.ok("nfqws2 --filter-mark")`
    // называет флаг посреди предложения и argv не строит.
    const FORBIDDEN_FLAGS: [&str; 6] = [
        "--filter-mark",
        "--qnum",
        "--lua-init",
        "--fwmark",
        "--uid=",
        "--new",
    ];

    for (path, body) in rust_files("src") {
        if path.starts_with("src/nfqws2/") {
            continue;
        }
        for flag in FORBIDDEN_FLAGS {
            let needle = format!("\"{flag}");
            assert!(
                !body.contains(needle.as_str()),
                "{path}: строковый литерал начинается с «{flag}» — командную \
                 строку движка собирает только src/nfqws2/plan.rs (Plan::argv), \
                 а не код вокруг него"
            );
        }
    }
}
