//! Атомарная запись отчёта.
//!
//! Отчёт читает ЧУЖОЙ процесс — продукт, который поднял подбор, — и читает по завершении
//! нашего. Частично записанный файл даёт ему `Unreadable`, а `Unreadable` он в суждение о
//! цели не превращает: человек просто ждёт. Это лучшее из плохого, и оно наступало.
//!
//! `write` + `rename` внутри одного каталога атомарен на всех файловых системах, на которых
//! мы живём: читатель видит либо прежний отчёт целиком, либо новый целиком, и никогда — половину.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Имя временного файла рядом с целевым. Тот же каталог обязателен: `rename` атомарен только
/// в пределах одной файловой системы, а `/tmp` может оказаться другой.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}

/// Записать файл так, чтобы читатель не увидел его наполовину.
///
/// `sync_all` перед переименованием не косметика: без него содержимое может ещё лежать в
/// страничном кеше, и внезапная потеря питания оставит на месте отчёта файл нужной длины,
/// набитый нулями. Коробка стоит у человека дома, и питание у неё пропадает.
pub fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    let temp = temp_path(path);

    let write_result = (|| {
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()
    })();

    if let Err(e) = write_result {
        // Временный файл не должен переживать собственный отказ: иначе каталог отчётов
        // обрастает мусором, который никто никогда не прочитает.
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }

    crate::system::elevate::chown_to_caller(path.to_string_lossy().as_ref());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bcw-atomic-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("каталог теста");
        dir.join("report.json")
    }

    /// Читатель видит либо старый отчёт, либо новый — и никогда половину нового.
    #[test]
    fn a_reader_never_sees_a_half_written_report() {
        let path = scratch("replace");
        std::fs::write(&path, r#"{"old":true}"#).expect("прежний отчёт");

        write_atomic(&path, r#"{"new":true}"#).expect("атомарная запись");

        assert_eq!(
            std::fs::read_to_string(&path).expect("чтение"),
            r#"{"new":true}"#
        );
    }

    /// Временный файл не остаётся в каталоге: он рядом с отчётом, и продукт, читающий
    /// каталог по маске, наткнулся бы на него как на отчёт.
    #[test]
    fn no_temporary_file_is_left_behind() {
        let path = scratch("leftovers");
        write_atomic(&path, r#"{"a":1}"#).expect("запись");

        let dir = path.parent().expect("каталог");
        let leftovers: Vec<_> = std::fs::read_dir(dir)
            .expect("обход каталога")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();

        assert!(
            leftovers.is_empty(),
            "остался временный файл: {leftovers:?}"
        );
    }

    /// Запись в несуществующий каталог обязана вернуть отказ, а не создать мусор где-то ещё.
    #[test]
    fn writing_into_a_missing_directory_fails_without_leftovers() {
        let path = std::env::temp_dir()
            .join(format!("bcw-atomic-missing-{}", std::process::id()))
            .join("nested")
            .join("report.json");

        assert!(write_atomic(&path, "{}").is_err());
        assert!(!path.exists());
    }
}
