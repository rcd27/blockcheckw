use std::fmt;

pub const PORTS_PER_WORKER: u16 = 10;
pub const DESYNC_MARK: u32 = 0x10000000;
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
        _ => Err(format!("unknown dns mode: '{s}'. expected: auto, system, doh")),
    }
}

#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub worker_count: usize,
    pub base_qnum: u16,
    pub base_local_port: u16,
    pub nft_table: String,
    pub nfqws2_path: String,
    pub curl_max_time: String,
    pub zapret_base: String,
    pub nfqws2_uid: u32,
    pub nfqws2_gid: u32,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            worker_count: 8,
            base_qnum: 200,
            base_local_port: 30000,
            nft_table: "zapret".to_string(),
            nfqws2_path: detect_nfqws2_path("/opt/zapret2"),
            curl_max_time: "2".to_string(),
            zapret_base: "/opt/zapret2".to_string(),
            nfqws2_uid: 1,
            nfqws2_gid: 3003,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            Protocol::Http => "curl_test_http",
            Protocol::HttpsTls12 => "curl_test_https_tls12",
            Protocol::HttpsTls13 => "curl_test_https_tls13",
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

pub fn detect_nfqws2_path(zapret_base: &str) -> String {
    let arch = std::env::consts::ARCH;
    let binary_arch = match arch {
        "aarch64" | "arm" => "linux-arm64",
        _ => "linux-x86_64",
    };
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
            _ => return Err(format!("unknown protocol: '{token}'. expected: http, tls12, tls13")),
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
