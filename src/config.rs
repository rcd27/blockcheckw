use std::fmt;

pub const DESYNC_MARK: u32 = 0x10000000;
pub const WORKER_MARK_BASE: u32 = 0x20000000;
pub const NFQWS2_INIT_DELAY_MS: u64 = 100;

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
            base_qnum: 200,
            nft_table: "zapret".to_string(),
            nfqws2_path: detect_nfqws2_path("/opt/zapret2"),
            request_timeout: 2,
            // FIXME: zapret_base is hardcoded; add CLI option to override
            zapret_base: "/opt/zapret2".to_string(),
            nfqws2_uid: detect_nobody_uid(),
            nfqws2_gid: detect_nobody_gid(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    HttpsTls12,
    HttpsTls13,
}

impl Protocol {
    pub fn all() -> Vec<Protocol> {
        vec![Protocol::Http, Protocol::HttpsTls12, Protocol::HttpsTls13]
    }

    pub fn port(self) -> u16 {
        match self {
            Protocol::Http => 80,
            Protocol::HttpsTls12 | Protocol::HttpsTls13 => 443,
        }
    }

    pub fn test_func_name(self) -> &'static str {
        match self {
            Protocol::Http => "http_test_http",
            Protocol::HttpsTls12 => "http_test_https_tls12",
            Protocol::HttpsTls13 => "http_test_https_tls13",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Http => write!(f, "HTTP"),
            Protocol::HttpsTls12 => write!(f, "HTTPS/TLS1.2"),
            Protocol::HttpsTls13 => write!(f, "HTTPS/TLS1.3"),
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

/// Каталоги в `binaries/`, которые собирает zapret2, в порядке приоритета его
/// install_bin.sh. "my" — самосборка под текущую машину, поэтому первая.
const ZAPRET_ARCH_DIRS: &[&str] = &[
    "my",
    "linux-x86_64",
    "linux-x86",
    "linux-arm64",
    "linux-arm",
    "linux-mips64",
    "linux-mipsel64",
    "linux-mipsel",
    "linux-mips",
    "linux-lexra",
    "linux-ppc",
    "linux-riscv64",
];

/// Имена каталогов zapret2, подходящие текущей архитектуре, в порядке предпочтения.
/// Пусто для архитектур, которых нет в релизах zapret2.
///
/// std::env::consts::ARCH не различает endianness, поэтому для mips её передают
/// отдельно: таргеты mipsel-* и mips-* оба дают ARCH == "mips".
fn arch_candidates(arch: &str, little_endian: bool) -> Vec<&'static str> {
    match (arch, little_endian) {
        ("x86_64", _) => vec!["linux-x86_64"],
        ("x86", _) => vec!["linux-x86"],
        ("aarch64", _) => vec!["linux-arm64"],
        ("arm", _) => vec!["linux-arm"],
        ("mips64", true) => vec!["linux-mipsel64", "linux-mips64"],
        ("mips64", false) => vec!["linux-mips64", "linux-mipsel64"],
        ("mips", true) => vec!["linux-mipsel", "linux-mips"],
        ("mips", false) => vec!["linux-mips", "linux-mipsel"],
        ("powerpc" | "powerpc64", _) => vec!["linux-ppc"],
        ("riscv64", _) => vec!["linux-riscv64"],
        _ => Vec::new(),
    }
}

/// Выбрать каталог внутри `binaries/`, в котором лежит `nfqws2`.
///
/// Источник истины — то, что реально установлено: на роутере обычно ровно один
/// каталог, и он же верный, даже если маппинг архитектуры промахнулся (issue #66).
/// Маппинг разрешает неоднозначность, когда каталогов несколько.
fn select_binary_dir(binaries_dir: &std::path::Path, candidates: &[&str]) -> Option<String> {
    let mut installed: Vec<String> = std::fs::read_dir(binaries_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("nfqws2").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    match installed.len() {
        0 => None,
        1 => installed.pop(),
        _ => candidates
            .iter()
            .find(|c| installed.iter().any(|i| i == *c))
            .or_else(|| {
                // маппинг не совпал ни с чем: держимся порядка install_bin.sh
                ZAPRET_ARCH_DIRS
                    .iter()
                    .find(|d| installed.iter().any(|i| i == *d))
            })
            .map(|s| s.to_string()),
    }
}

pub fn detect_nfqws2_path(zapret_base: &str) -> String {
    let candidates = arch_candidates(std::env::consts::ARCH, cfg!(target_endian = "little"));
    let binaries_dir = std::path::Path::new(zapret_base).join("binaries");

    let binary_arch = select_binary_dir(&binaries_dir, &candidates).unwrap_or_else(|| {
        // ничего не установлено: путь по маппингу, чтобы ошибка prereq
        // называла тот каталог, который здесь ожидается
        candidates
            .first()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("linux-{}", std::env::consts::ARCH))
    });

    format!("{zapret_base}/binaries/{binary_arch}/nfqws2")
}

pub fn parse_protocols(s: &str) -> Result<Vec<Protocol>, String> {
    let mut protocols = Vec::new();
    for token in s.split(',') {
        let token = token.trim();
        let protocol = match token {
            "http" => Protocol::Http,
            "tls12" => Protocol::HttpsTls12,
            "tls13" => Protocol::HttpsTls13,
            _ => {
                return Err(format!(
                    "unknown protocol: '{token}'. expected: http, tls12, tls13"
                ))
            }
        };
        protocols.push(protocol);
    }
    if protocols.is_empty() {
        return Err("no protocols specified".to_string());
    }
    Ok(protocols)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let result = parse_protocols("http,quic");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("quic"));
    }

    #[test]
    fn test_protocol_all() {
        let all = Protocol::all();
        assert_eq!(all.len(), 3);
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
}

#[cfg(test)]
mod arch_detect_tests {
    use super::{arch_candidates, detect_nfqws2_path, select_binary_dir};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn tmp_base(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bcw_arch_{tag}_{nanos}"));
        fs::create_dir_all(dir.join("binaries")).unwrap();
        dir
    }

    /// Каталог `binaries/<arch>` с бинарником nfqws2 внутри.
    fn with_nfqws2(base: &Path, arch: &str) {
        let dir = base.join("binaries").join(arch);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("nfqws2"), b"\x7fELF").unwrap();
    }

    /// Каталог `binaries/<arch>` без бинарника.
    fn empty_arch_dir(base: &Path, arch: &str) {
        fs::create_dir_all(base.join("binaries").join(arch)).unwrap();
    }

    #[test]
    fn single_installed_dir_wins_over_arch_mapping() {
        // issue #66: на mipsel-роутере стоит только linux-mipsel,
        // а маппинг предлагал linux-x86_64
        let base = tmp_base("single");
        with_nfqws2(&base, "linux-mipsel");
        let picked = select_binary_dir(&base.join("binaries"), &["linux-x86_64"]);
        assert_eq!(picked.as_deref(), Some("linux-mipsel"));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn mapping_picks_matching_dir_when_several_installed() {
        let base = tmp_base("several");
        with_nfqws2(&base, "linux-x86_64");
        with_nfqws2(&base, "linux-arm64");
        let picked = select_binary_dir(&base.join("binaries"), &["linux-arm64", "linux-arm"]);
        assert_eq!(picked.as_deref(), Some("linux-arm64"));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn self_built_my_dir_wins_when_mapping_matches_nothing() {
        let base = tmp_base("my");
        with_nfqws2(&base, "linux-x86_64");
        with_nfqws2(&base, "my");
        let picked = select_binary_dir(&base.join("binaries"), &["linux-riscv64"]);
        assert_eq!(picked.as_deref(), Some("my"));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn dir_without_nfqws2_is_ignored() {
        let base = tmp_base("empty_dir");
        empty_arch_dir(&base, "linux-mipsel");
        let picked = select_binary_dir(&base.join("binaries"), &["linux-x86_64"]);
        assert_eq!(picked, None);
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn missing_binaries_dir_selects_nothing() {
        let picked = select_binary_dir(Path::new("/nonexistent/bcw/binaries"), &["linux-x86_64"]);
        assert_eq!(picked, None);
    }

    #[test]
    fn mips_candidates_follow_endianness() {
        assert_eq!(
            arch_candidates("mips", true),
            vec!["linux-mipsel", "linux-mips"]
        );
        assert_eq!(
            arch_candidates("mips", false),
            vec!["linux-mips", "linux-mipsel"]
        );
        assert_eq!(
            arch_candidates("mips64", true),
            vec!["linux-mipsel64", "linux-mips64"]
        );
    }

    #[test]
    fn arm_candidates_are_bitness_correct() {
        assert_eq!(arch_candidates("aarch64", true), vec!["linux-arm64"]);
        assert_eq!(arch_candidates("arm", true), vec!["linux-arm"]);
    }

    #[test]
    fn unknown_arch_has_no_candidates() {
        assert!(arch_candidates("s390x", false).is_empty());
    }

    #[test]
    fn detect_returns_path_to_installed_binary() {
        let base = tmp_base("detect");
        with_nfqws2(&base, "linux-mipsel");
        let path = detect_nfqws2_path(base.to_str().unwrap());
        assert_eq!(
            path,
            format!("{}/binaries/linux-mipsel/nfqws2", base.display())
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn detect_falls_back_to_arch_mapping_when_nothing_installed() {
        let base = tmp_base("fallback");
        let path = detect_nfqws2_path(base.to_str().unwrap());
        let expected_arch = arch_candidates(std::env::consts::ARCH, cfg!(target_endian = "little"))
            .first()
            .copied()
            .map(str::to_string)
            .unwrap_or_else(|| format!("linux-{}", std::env::consts::ARCH));
        assert_eq!(
            path,
            format!("{}/binaries/{expected_arch}/nfqws2", base.display())
        );
        fs::remove_dir_all(&base).ok();
    }
}
