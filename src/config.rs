use std::fmt;

/// Имя нашей nft-таблицы. Не должно совпадать с чужими: "zapret" занято zapret1,
/// "zapret2" — zapret2 (см. common/nft.sh), иначе их таблицы попадают под наш
/// cleanup и при этом не видны детекту конфликтов.
pub const DEFAULT_NFT_TABLE: &str = "blockcheckw";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    Auto,
    System,
    Doh,
}

impl fmt::Display for DnsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsMode::Auto => write!(f, "auto"),
            DnsMode::System => write!(f, "system"),
            DnsMode::Doh => write!(f, "doh"),
        }
    }
}

pub fn parse_dns_mode(s: &str) -> Result<DnsMode, String> {
    match s.to_lowercase().as_str() {
        "auto" => Ok(DnsMode::Auto),
        "system" => Ok(DnsMode::System),
        "doh" => Ok(DnsMode::Doh),
        _ => Err(format!(
            "unknown dns mode: '{s}'. expected: auto, system, doh"
        )),
    }
}

#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub worker_count: usize,
    /// Сколько стратегий держать загруженными в одном процессе nfqws2 (#68).
    /// Не то же самое, что `worker_count`: это ёмкость плана, а `worker_count` —
    /// сколько проб этого плана летит одновременно.
    pub profiles_per_instance: usize,
    pub base_qnum: u16,
    pub nft_table: String,
    pub nfqws2_path: String,
    pub request_timeout: u64,
    pub zapret_base: String,
    pub nfqws2_uid: u32,
    pub nfqws2_gid: u32,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            worker_count: 8,
            profiles_per_instance: 1024,
            base_qnum: 200,
            nft_table: DEFAULT_NFT_TABLE.to_string(),
            nfqws2_path: nfqws2_path("/opt/zapret2"),
            request_timeout: 2,
            // FIXME: zapret_base is hardcoded; add CLI option to override
            zapret_base: "/opt/zapret2".to_string(),
            nfqws2_uid: detect_nobody_uid(),
            nfqws2_gid: detect_nobody_gid(),
        }
    }
}

/// Потолок числа профилей в одном плане: марка профиля — младшие биты под
/// `PROFILE_MASK`, и индекс, приведённый к `u16`, на границе маски даёт ноль —
/// то есть «марки нет» (см. `nfqws2::mark::ProfileMark`).
pub const MAX_PROFILES_PER_INSTANCE: usize = crate::nfqws2::mark::PROFILE_MASK as usize;

pub fn validate_parallelism(
    worker_count: usize,
    profiles_per_instance: usize,
) -> Result<(), String> {
    if worker_count == 0 {
        return Err(
            "--workers 0 (may have come from saved configuration, not just the flag): \
             the probe semaphore will never hand out a permit, and the process will hang \
             forever — AFTER the NFQUEUE rules are already in place"
                .to_string(),
        );
    }
    if profiles_per_instance == 0 {
        return Err(
            "--profiles-per-instance 0: a plan with no profiles cannot test anything".to_string(),
        );
    }
    if profiles_per_instance > MAX_PROFILES_PER_INSTANCE {
        return Err(format!(
            "--profiles-per-instance {profiles_per_instance} exceeds the ceiling of \
             {MAX_PROFILES_PER_INSTANCE}: the profile number does not fit in the mark"
        ));
    }
    if worker_count > profiles_per_instance {
        return Err(format!(
            "--workers {worker_count} exceeds --profiles-per-instance {profiles_per_instance} \
             (--workers may have come from saved configuration, not just the flag): \
             the plan cannot serve that many probes at once. Fix: raise \
             --profiles-per-instance to at least {worker_count} (ceiling {MAX_PROFILES_PER_INSTANCE}), \
             or pass -w to reset the saved --workers value"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod parallelism_tests {
    use super::validate_parallelism;

    #[test]
    fn workers_may_not_exceed_loaded_profiles() {
        assert!(validate_parallelism(1024, 512).is_err());
    }

    #[test]
    fn zero_workers_is_rejected() {
        let err = validate_parallelism(0, 1024).expect_err("0 воркеров обязано быть ошибкой");
        assert!(
            err.contains("0"),
            "сообщение должно называть нулевое значение: {err}"
        );
    }

    #[test]
    fn profiles_may_not_outgrow_the_mark() {
        use super::MAX_PROFILES_PER_INSTANCE;
        assert!(validate_parallelism(8, MAX_PROFILES_PER_INSTANCE).is_ok());
        assert!(validate_parallelism(8, MAX_PROFILES_PER_INSTANCE + 1).is_err());
        assert!(validate_parallelism(8, 0).is_err());
    }

    #[test]
    fn defaults_are_consistent() {
        let c = super::CoreConfig::default();
        assert!(validate_parallelism(c.worker_count, c.profiles_per_instance).is_ok());
        assert_eq!(c.profiles_per_instance, 1024);
    }
}

impl CoreConfig {
    /// Окружение для запуска движка.
    pub fn nfqws2_env(&self) -> crate::nfqws2::plan::Env {
        crate::nfqws2::plan::Env {
            binary: self.nfqws2_path.clone().into(),
            lua: vec![
                format!("{}/lua/zapret-lib.lua", self.zapret_base).into(),
                format!("{}/lua/zapret-antidpi.lua", self.zapret_base).into(),
            ],
            uid: self.nfqws2_uid,
            gid: self.nfqws2_gid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    HttpsTls12,
    HttpsTls13,
    /// HTTP/3 поверх QUIC. Отдельный протокол, а не «ещё один TLS»: человек, у которого
    /// режут QUIC, страдает на UDP, и страта, найденная на TCP, ему ничего не говорит.
    Quic,
}

/// Транспорт протокола. От него зависит правило nft (`tcp dport` против `udp dport`) —
/// и только от него: движку профиль всё равно, он принимает оба.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    /// Имя в синтаксисе nft.
    pub fn nft_name(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }
}

/// Собрана ли в бинарь QUIC-проба. Экзотические цели собираются без неё.
pub const QUIC_PROBE_BUILT: bool = cfg!(feature = "quic");

impl Protocol {
    pub fn all() -> Vec<Protocol> {
        vec![
            Protocol::Http,
            Protocol::HttpsTls12,
            Protocol::HttpsTls13,
            Protocol::Quic,
        ]
    }

    pub fn port(self) -> u16 {
        match self {
            Protocol::Http => 80,
            Protocol::HttpsTls12 | Protocol::HttpsTls13 | Protocol::Quic => 443,
        }
    }

    pub fn transport(self) -> Transport {
        match self {
            Protocol::Http | Protocol::HttpsTls12 | Protocol::HttpsTls13 => Transport::Tcp,
            Protocol::Quic => Transport::Udp,
        }
    }

    pub fn test_func_name(self) -> &'static str {
        match self {
            Protocol::Http => "http_test_http",
            Protocol::HttpsTls12 => "http_test_https_tls12",
            Protocol::HttpsTls13 => "http_test_https_tls13",
            Protocol::Quic => "http_test_http3",
        }
    }

    /// Имя в CLI (`-p`).
    pub fn cli_name(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::HttpsTls12 => "tls12",
            Protocol::HttpsTls13 => "tls13",
            Protocol::Quic => "quic",
        }
    }

    /// Имя функции пробы в ванильном отчёте blockcheck2 — там же, где его берёт
    /// `blockcheck2.sh` (`curl_test_http3` для QUIC).
    pub fn vanilla_test_name(self) -> &'static str {
        match self {
            Protocol::Http => "curl_test_http",
            Protocol::HttpsTls12 => "curl_test_https_tls12",
            Protocol::HttpsTls13 => "curl_test_https_tls13",
            Protocol::Quic => "curl_test_http3",
        }
    }

    /// Протокол по имени из JSON-отчёта (`Display`).
    pub fn from_report_name(name: &str) -> Option<Protocol> {
        Protocol::all().into_iter().find(|p| p.to_string() == name)
    }

    /// Протокол строки ванильного отчёта. Имя сверяется вместе с разделителем:
    /// `curl_test_http` — префикс `curl_test_http3`.
    pub fn of_vanilla_line(line: &str) -> Option<Protocol> {
        Protocol::all().into_iter().find(|p| {
            line.strip_prefix(p.vanilla_test_name())
                .is_some_and(|rest| rest.starts_with(' '))
        })
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Http => write!(f, "HTTP"),
            Protocol::HttpsTls12 => write!(f, "HTTPS/TLS1.2"),
            Protocol::HttpsTls13 => write!(f, "HTTPS/TLS1.3"),
            Protocol::Quic => write!(f, "QUIC/HTTP3"),
        }
    }
}

/// Detect uid for "nobody" user. Falls back to 65534 (standard on most Linux distros).
fn detect_nobody_uid() -> u32 {
    nix::unistd::User::from_name("nobody")
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
        .unwrap_or(65534)
}

/// Detect gid for "nobody" user. Falls back to 65534.
fn detect_nobody_gid() -> u32 {
    nix::unistd::User::from_name("nobody")
        .ok()
        .flatten()
        .map(|u| u.gid.as_raw())
        .unwrap_or(65534)
}

/// Путь к движку внутри zapret2 (#68).
///
/// Архитектуру выбирает install_bin.sh: он кладёт в `nfq2/` ссылку на
/// подходящий `binaries/<arch>/nfqws2` (или на `binaries/my`), а самосборка
/// оставляет бинарь прямо там. Свой перебор `binaries/linux-*` промахивался
/// мимо всего, что не релиз, — поэтому не выбираем, а берём выбранное.
pub fn nfqws2_path(zapret_base: &str) -> String {
    format!("{zapret_base}/nfq2/nfqws2")
}

pub fn parse_protocols(s: &str) -> Result<Vec<Protocol>, String> {
    let protocols = s
        .split(',')
        .map(str::trim)
        .map(|token| {
            Protocol::all()
                .into_iter()
                .find(|p| p.cli_name() == token)
                .ok_or_else(|| {
                    format!("unknown protocol: '{token}'. expected: http, tls12, tls13, quic")
                })
                .and_then(|p| match (p, QUIC_PROBE_BUILT) {
                    (Protocol::Quic, false) => Err(
                        "protocol 'quic': this build has no QUIC probe (built without feature `quic`)"
                            .to_string(),
                    ),
                    (known, _built) => Ok(known),
                })
        })
        .collect::<Result<Vec<Protocol>, String>>()?;
    match protocols.is_empty() {
        true => Err("no protocols specified".to_string()),
        false => Ok(protocols),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_nft_table_does_not_collide_with_foreign_ones() {
        // issue #66: имя "zapret" принадлежит zapret1
        for foreign in ["zapret", "zapret2", "fw4"] {
            assert_ne!(DEFAULT_NFT_TABLE, foreign);
        }
        assert_eq!(CoreConfig::default().nft_table, DEFAULT_NFT_TABLE);
    }

    #[test]
    fn test_parse_protocols_all() {
        let result = parse_protocols("http,tls12,tls13").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], Protocol::Http);
        assert_eq!(result[1], Protocol::HttpsTls12);
        assert_eq!(result[2], Protocol::HttpsTls13);
    }

    #[test]
    fn test_parse_protocols_single() {
        let result = parse_protocols("tls13").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], Protocol::HttpsTls13);
    }

    #[test]
    fn test_parse_protocols_with_spaces() {
        let result = parse_protocols("http, tls12").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], Protocol::Http);
        assert_eq!(result[1], Protocol::HttpsTls12);
    }

    #[test]
    fn test_parse_protocols_unknown() {
        let result = parse_protocols("http,spdy");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("spdy"));
    }

    #[test]
    fn test_protocol_all() {
        let all = Protocol::all();
        assert_eq!(all.len(), 4);
    }

    #[cfg(feature = "quic")]
    #[test]
    fn quic_is_parsed_by_its_cli_name() {
        assert_eq!(parse_protocols("tls12,quic").unwrap()[1], Protocol::Quic);
    }

    #[cfg(not(feature = "quic"))]
    #[test]
    fn quic_is_refused_by_a_build_without_the_probe() {
        // Сборка без пробы не смеет принять `quic` и молча мерить нулём: отказ обязан
        // прозвучать на разборе, до подъёма движка.
        let refused = parse_protocols("quic").unwrap_err();
        assert!(refused.contains("quic"), "{refused}");
    }

    #[test]
    fn quic_goes_over_udp_443_and_the_rest_over_tcp() {
        // Транспорт решает правило nft: страта QUIC, отданная очереди по `tcp dport`,
        // не увидит ни одной датаграммы — и проиграет не потому, что не пробивает.
        assert_eq!(Protocol::Quic.port(), 443);
        assert_eq!(Protocol::Quic.transport(), Transport::Udp);
        [Protocol::Http, Protocol::HttpsTls12, Protocol::HttpsTls13]
            .into_iter()
            .for_each(|p| assert_eq!(p.transport(), Transport::Tcp, "{p}"));
    }

    #[test]
    fn every_protocol_round_trips_through_its_report_names() {
        // Имя в JSON (`Display`) и имя строки ванильного отчёта — публичный контракт:
        // отчёт scan читает check. Протокол, не узнающий собственное имя, теряет
        // страты между командами молча.
        Protocol::all().into_iter().for_each(|p| {
            assert_eq!(Protocol::from_report_name(&p.to_string()), Some(p));
            let line = format!("{} ipv4 example.com : nfqws2 --a", p.vanilla_test_name());
            assert_eq!(Protocol::of_vanilla_line(&line), Some(p), "{line}");
        });
        assert_eq!(Protocol::Quic.to_string(), "QUIC/HTTP3");
        assert_eq!(Protocol::Quic.vanilla_test_name(), "curl_test_http3");
    }

    #[test]
    fn http3_line_is_not_taken_for_plain_http() {
        // `curl_test_http` — префикс `curl_test_http3`: без разделителя QUIC-страта
        // уехала бы в каталог HTTP на порт 80.
        assert_eq!(
            Protocol::of_vanilla_line("curl_test_http3 ipv4 x.org : nfqws2 --a"),
            Some(Protocol::Quic)
        );
        assert_eq!(
            Protocol::of_vanilla_line("curl_test_http ipv4 x.org : nfqws2 --a"),
            Some(Protocol::Http)
        );
    }

    #[test]
    fn test_parse_dns_mode_valid() {
        assert_eq!(parse_dns_mode("auto").unwrap(), DnsMode::Auto);
        assert_eq!(parse_dns_mode("system").unwrap(), DnsMode::System);
        assert_eq!(parse_dns_mode("doh").unwrap(), DnsMode::Doh);
        assert_eq!(parse_dns_mode("DOH").unwrap(), DnsMode::Doh);
        assert_eq!(parse_dns_mode("Auto").unwrap(), DnsMode::Auto);
    }

    #[test]
    fn test_parse_dns_mode_invalid() {
        assert!(parse_dns_mode("plain").is_err());
        assert!(parse_dns_mode("").is_err());
    }

    #[test]
    fn test_dns_mode_display() {
        assert_eq!(DnsMode::Auto.to_string(), "auto");
        assert_eq!(DnsMode::System.to_string(), "system");
        assert_eq!(DnsMode::Doh.to_string(), "doh");
    }

    #[test]
    fn env_carries_both_lua_scripts_and_the_binary() {
        let config = CoreConfig::default();
        let env = config.nfqws2_env();
        assert_eq!(env.lua.len(), 2, "движку нужны обе библиотеки");
        assert!(env.lua[0].to_string_lossy().ends_with("zapret-lib.lua"));
        assert!(env.lua[1].to_string_lossy().ends_with("zapret-antidpi.lua"));
        // binary — путь к самому бинарю, а не к каталогу zapret_base: если
        // конверсия перепутает поля, здесь бы прошёл каталог вместо файла.
        assert_eq!(
            env.binary,
            std::path::PathBuf::from(&config.nfqws2_path),
            "env.binary обязан быть путём к бинарю nfqws2, а не к zapret_base"
        );
        assert_eq!(env.uid, config.nfqws2_uid);
        assert_eq!(env.gid, config.nfqws2_gid);
    }
}

#[cfg(test)]
mod nfqws2_path_tests {
    use super::nfqws2_path;

    /// #68: движок берётся из `nfq2/`, где его оставил install_bin.sh, — не из
    /// `binaries/linux-*`, куда не попадает самосборка.
    #[test]
    fn engine_is_taken_from_nfq2() {
        assert_eq!(nfqws2_path("/opt/zapret2"), "/opt/zapret2/nfq2/nfqws2");
    }
}
