//! Архитектурный барьер вокруг nft (issue #66).
//!
//! `blockcheckw` уничтожал firewall роутера: `nft flush ruleset` отдельной
//! командой, следом — загрузка текстового дампа, которая падала на
//! `ct helper ... protocol 17` (вывод `nft list ruleset` не является валидным
//! входом `nft -f`). Flush уже применён, загрузка не прошла — роутер остаётся
//! без правил.
//!
//! Корень был в том, что вызвать nft можно было откуда угодно и как угодно.
//! Этот тест держит единственную точку входа: всё общение с nft живёт в
//! `src/firewall/`, где операция выражается типами, а не строкой.

use std::path::{Path, PathBuf};

/// Все `.rs` в каталоге, рекурсивно.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Ищем именно ВЫЗОВЫ бинаря: `Command::new("nft")` и `run_process(&["nft", …])`.
/// Упоминание строки в выводе консоли безобидно и не запрещается.
fn calls_nft(line: &str) -> bool {
    line.contains(r#"Command::new("nft")"#) || line.contains(r#"["nft""#)
}
#[test]
fn nft_is_invoked_only_from_firewall_module() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let firewall = src.join("firewall");

    let mut files = Vec::new();
    rust_files(&src, &mut files);

    let offenders: Vec<String> = files
        .iter()
        .filter(|p| !p.starts_with(&firewall))
        .filter_map(|path| {
            let body = std::fs::read_to_string(path).ok()?;
            let hits: Vec<String> = body
                .lines()
                .enumerate()
                .filter(|(_, line)| calls_nft(line))
                .map(|(i, line)| format!("  {}:{}: {}", path.display(), i + 1, line.trim()))
                .collect();
            (!hits.is_empty()).then(|| hits.join("\n"))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "nft вызывается в обход src/firewall/ — именно так в #66 появился \
         `nft flush ruleset`, снёсший fw4 на роутере:\n{}",
        offenders.join("\n"),
    );
}
