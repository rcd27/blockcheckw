use crate::nfqws2::plan::FilterMark;

pub fn grant_from_help(help: &str) -> Option<FilterMark> {
    const OPTION: &str = "--filter-mark";
    let named = help.match_indices(OPTION).any(|(at, _)| {
        match help[at + OPTION.len()..].chars().next() {
            // Имя опции кончилось вместе со справкой.
            None => true,
            // За именем идёт то, что его продолжает, — это ДРУГАЯ опция.
            Some(c) => !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        }
    });
    named.then(FilterMark::evidenced)
}

/// Почему движок вышел сразу.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartFailure {
    /// lua-скрипты собраны под другую версию движка.
    LuaVersion,
    /// Сборка старее v1.0.5 — не знает наших опций.
    UnknownOption,
    /// Всё прочее, дословно.
    Other(String),
}

pub fn classify_stderr(stderr: &str) -> StartFailure {
    if stderr.contains("NFQWS2_COMPAT_VER") {
        StartFailure::LuaVersion
    } else if stderr.contains("unrecognized option") || stderr.contains("unknown option") {
        // Строку печатает getopt_long_only из libc, а не движок: своей у него нет.
        // И glibc, и busybox говорят «unrecognized» — проверено запуском. Ветка,
        // ловившая только «unknown option», не срабатывала бы никогда.
        StartFailure::UnknownOption
    } else {
        StartFailure::Other(stderr.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELP_NEW: &str = " --filter-mark=<mark>[/<mask>]\t\t; filter by packet mark\n \
                             --new[=<name>]\t\t; begin new profile\n";
    const HELP_OLD: &str = " --new[=<name>]\t\t; begin new profile\n \
                             --filter-l7=<proto>\t\t; filter by L7 protocol\n";

    #[test]
    fn v1_0_5_help_grants_the_witness() {
        assert!(grant_from_help(HELP_NEW).is_some());
    }

    /// `--filter-l7` содержит подстроку «filter», но не «filter-mark»:
    /// проверка обязана смотреть на точное имя опции.
    #[test]
    fn older_help_grants_nothing_even_though_it_mentions_filters() {
        assert!(grant_from_help(HELP_OLD).is_none());
    }

    #[test]
    fn lua_version_mismatch_is_named() {
        let stderr = "LUA ERROR: Incompatible NFQWS2_COMPAT_VER: got 3, want 5\n";
        assert_eq!(classify_stderr(stderr), StartFailure::LuaVersion);
    }

    #[test]
    fn unknown_option_is_named() {
        let stderr = "nfqws2: unknown option -- filter-mark\n";
        assert_eq!(classify_stderr(stderr), StartFailure::UnknownOption);
    }

    /// Настоящий текст, который печатает getopt из libc. Проверен запуском на
    /// glibc и busybox — оба говорят «unrecognized», а не «unknown».
    #[test]
    fn the_real_getopt_message_is_recognised() {
        let stderr = "nfqws2: unrecognized option '--filter-mark'\n";
        assert_eq!(classify_stderr(stderr), StartFailure::UnknownOption);
    }

    /// Прецедент из самого движка: у него есть пара `--filter-ssid` /
    /// `--filter-ssid-neg`. Сборка, знающая только суффиксного соседа, не смеет
    /// выдать свидетельство — иначе скан пойдёт вхолостую и промолчит.
    #[test]
    fn a_suffixed_neighbour_option_does_not_grant_the_witness() {
        assert!(grant_from_help(" --filter-mark-neg=<mark>\t; отрицающий фильтр\n").is_none());
        assert!(grant_from_help(" --filter-marker=<x>\n").is_none());
    }

    #[test]
    fn the_real_option_grants_the_witness_in_any_spelling() {
        assert!(grant_from_help(" --filter-mark=<mark>[/<mask>]\n").is_some());
        assert!(grant_from_help(" --filter-mark <mark>\n").is_some());
        assert!(grant_from_help("--filter-mark").is_some());
    }

    /// Всё прочее отдаётся ДОСЛОВНО. Сегодня stderr движка уходит в /dev/null,
    /// и причина отказа не видна никогда — проглотить её здесь было бы
    /// повторением той же ошибки.
    #[test]
    fn anything_else_is_passed_through_verbatim() {
        let stderr = "bind: Address already in use\n";
        assert_eq!(
            classify_stderr(stderr),
            StartFailure::Other("bind: Address already in use".to_string())
        );
    }
}
