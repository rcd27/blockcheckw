use std::fmt;

use crate::config::Protocol;
use crate::system::process::{run_process, ProcessResult};

/// Extra time beyond curl's --max-time before we force-kill the process.
/// Covers connect-timeout + TCP teardown overhead.
const CURL_TIMEOUT_MARGIN_MS: u64 = 3_000;

/// Minimum bytes downloaded to consider data transfer successful.
pub const DATA_TRANSFER_MIN_BYTES: u64 = 1024;

#[derive(Debug)]
pub struct CurlResult {
    pub exit_code: i32,
    pub http_code: Option<u16>,
    pub headers: String,
    pub size_download: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum CurlVerdict {
    Available,
    SuspiciousRedirect { code: u16, location: String },
    ServerReceivesFakes,
    Unavailable { curl_exit_code: i32 },
    DataTransferFailed { size_download: u64 },
}

impl fmt::Display for CurlVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CurlVerdict::Available => write!(f, "!!!!! AVAILABLE !!!!!"),
            CurlVerdict::SuspiciousRedirect { code, location } => {
                write!(f, "suspicious redirection {code} to : {location}")
            }
            CurlVerdict::ServerReceivesFakes => {
                write!(f, "http code 400. likely the server receives fakes.")
            }
            CurlVerdict::Unavailable { curl_exit_code } => {
                write!(f, "UNAVAILABLE code={curl_exit_code}")
            }
            CurlVerdict::DataTransferFailed { size_download } => {
                write!(f, "DATA TRANSFER FAILED ({size_download}B downloaded)")
            }
        }
    }
}

const REDIRECT_CODES: &[u16] = &[301, 302, 307, 308];

fn to_curl_result(pr: ProcessResult) -> CurlResult {
    let http_code = pr
        .stdout
        .lines()
        .find(|line| line.starts_with("HTTP/"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok());

    let size_download = pr
        .stdout
        .lines()
        .find(|line| line.starts_with("SIZE_DOWNLOAD:"))
        .and_then(|line| line.strip_prefix("SIZE_DOWNLOAD:"))
        .and_then(|val| val.trim().parse::<f64>().ok())
        .map(|v| v as u64);

    CurlResult {
        exit_code: pr.exit_code,
        http_code,
        headers: pr.stdout,
        size_download,
    }
}

fn process_timeout_ms(max_time: &str) -> u64 {
    // TODO: accept a numeric type instead of &str to avoid silent fallback on parse error
    let secs: f64 = max_time.parse().unwrap_or(1.0);
    (secs * 1000.0) as u64 + CURL_TIMEOUT_MARGIN_MS
}

fn local_port_args(local_port: Option<&str>) -> Vec<String> {
    match local_port {
        Some(port) => vec!["--local-port".to_string(), port.to_string()],
        None => vec![],
    }
}

/// Build `--connect-to` args that pin curl to a specific IP for the given domain.
/// Format: `--connect-to domain::ip:port` — tells curl to connect to `ip:port` instead of resolving.
pub fn connect_to_args(domain: &str, ip: Option<&str>, port: u16) -> Vec<String> {
    match ip {
        Some(ip) => vec!["--connect-to".to_string(), format!("{domain}::{ip}:{port}")],
        None => vec![],
    }
}

/// Pick a random IP from a slice using a fast, deterministic-per-call method.
/// Uses subsec_nanos to avoid pulling in the `rand` crate.
pub fn pick_random_ip(ips: &[String]) -> Option<&str> {
    if ips.is_empty() {
        return None;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize;
    Some(&ips[nanos % ips.len()])
}

/// Base curl args for HTTP test (without URL, local-port, connect-to).
fn base_http_args(max_time: &str) -> Vec<&str> {
    vec![
        "curl",
        "-4",
        "--noproxy",
        "*",
        "-SsD",
        "-",
        "-A",
        "Mozilla",
        "--max-time",
        max_time,
        "-o",
        "/dev/null",
    ]
}

// TODO: curl_test_http, curl_test_https_tls12, curl_test_https_tls13 are structurally
// identical — consider unifying into a single parametrized function
pub async fn curl_test_http(
    domain: &str,
    local_port: Option<&str>,
    max_time: &str,
    ip: Option<&str>,
) -> CurlResult {
    let url = format!("http://{domain}");
    let mut args = base_http_args(max_time);

    let port_args = local_port_args(local_port);
    let port_refs: Vec<&str> = port_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&port_refs);
    let ct_args = connect_to_args(domain, ip, 80);
    let ct_refs: Vec<&str> = ct_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&ct_refs);
    args.push(&url);

    match run_process(&args, process_timeout_ms(max_time)).await {
        Ok(pr) => to_curl_result(pr),
        Err(_) => CurlResult {
            exit_code: -1,
            http_code: None,
            headers: String::new(),
            size_download: None,
        },
    }
}

/// Base curl args for HTTPS TLS 1.2 test (HEAD request — fast handshake check).
fn base_https_tls12_args(max_time: &str) -> Vec<&str> {
    vec![
        "curl",
        "-4",
        "--noproxy",
        "*",
        "-Ss",
        "-I",
        "-A",
        "Mozilla",
        "--max-time",
        max_time,
        "--tlsv1.2",
        "--tls-max",
        "1.2",
        "-o",
        "/dev/null",
    ]
}

/// Base curl args for HTTPS TLS 1.3 test.
fn base_https_tls13_args(max_time: &str) -> Vec<&str> {
    vec![
        "curl",
        "-4",
        "--noproxy",
        "*",
        "-Ss",
        "-I",
        "-A",
        "Mozilla",
        "--max-time",
        max_time,
        "--tlsv1.3",
        "--tls-max",
        "1.3",
        "-o",
        "/dev/null",
    ]
}

pub async fn curl_test_https_tls12(
    domain: &str,
    local_port: Option<&str>,
    max_time: &str,
    ip: Option<&str>,
) -> CurlResult {
    let url = format!("https://{domain}");
    let mut args = base_https_tls12_args(max_time);

    let port_args = local_port_args(local_port);
    let port_refs: Vec<&str> = port_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&port_refs);
    let ct_args = connect_to_args(domain, ip, 443);
    let ct_refs: Vec<&str> = ct_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&ct_refs);
    args.push(&url);

    match run_process(&args, process_timeout_ms(max_time)).await {
        Ok(pr) => to_curl_result(pr),
        Err(_) => CurlResult {
            exit_code: -1,
            http_code: None,
            headers: String::new(),
            size_download: None,
        },
    }
}

pub async fn curl_test_https_tls13(
    domain: &str,
    local_port: Option<&str>,
    max_time: &str,
    ip: Option<&str>,
) -> CurlResult {
    let url = format!("https://{domain}");
    let mut args = base_https_tls13_args(max_time);

    let port_args = local_port_args(local_port);
    let port_refs: Vec<&str> = port_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&port_refs);
    let ct_args = connect_to_args(domain, ip, 443);
    let ct_refs: Vec<&str> = ct_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&ct_refs);
    args.push(&url);

    match run_process(&args, process_timeout_ms(max_time)).await {
        Ok(pr) => to_curl_result(pr),
        Err(_) => CurlResult {
            exit_code: -1,
            http_code: None,
            headers: String::new(),
            size_download: None,
        },
    }
}

pub async fn curl_test(
    protocol: Protocol,
    domain: &str,
    local_port: Option<&str>,
    max_time: &str,
    ip: Option<&str>,
) -> CurlResult {
    match protocol {
        Protocol::Http => curl_test_http(domain, local_port, max_time, ip).await,
        Protocol::HttpsTls12 => curl_test_https_tls12(domain, local_port, max_time, ip).await,
        Protocol::HttpsTls13 => curl_test_https_tls13(domain, local_port, max_time, ip).await,
    }
}

/// Base curl args for HTTPS TLS 1.2 data transfer test (GET, not HEAD).
/// Uses `-w` to output SIZE_DOWNLOAD marker for parsing.
fn base_https_tls12_data_args(max_time: &str) -> Vec<&str> {
    vec![
        "curl",
        "-4",
        "--noproxy",
        "*",
        "-SsD",
        "-",
        "-A",
        "Mozilla",
        "--max-time",
        max_time,
        "--tlsv1.2",
        "--tls-max",
        "1.2",
        "-o",
        "/dev/null",
        "-w",
        "\nSIZE_DOWNLOAD:%{size_download}",
    ]
}

/// Base curl args for HTTPS TLS 1.3 data transfer test (GET, not HEAD).
fn base_https_tls13_data_args(max_time: &str) -> Vec<&str> {
    vec![
        "curl",
        "-4",
        "--noproxy",
        "*",
        "-SsD",
        "-",
        "-A",
        "Mozilla",
        "--max-time",
        max_time,
        "--tlsv1.3",
        "--tls-max",
        "1.3",
        "-o",
        "/dev/null",
        "-w",
        "\nSIZE_DOWNLOAD:%{size_download}",
    ]
}

pub async fn curl_test_https_tls12_data(
    domain: &str,
    local_port: Option<&str>,
    max_time: &str,
    ip: Option<&str>,
) -> CurlResult {
    let url = format!("https://{domain}");
    let mut args = base_https_tls12_data_args(max_time);

    let port_args = local_port_args(local_port);
    let port_refs: Vec<&str> = port_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&port_refs);
    let ct_args = connect_to_args(domain, ip, 443);
    let ct_refs: Vec<&str> = ct_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&ct_refs);
    args.push(&url);

    match run_process(&args, process_timeout_ms(max_time)).await {
        Ok(pr) => to_curl_result(pr),
        Err(_) => CurlResult {
            exit_code: -1,
            http_code: None,
            headers: String::new(),
            size_download: None,
        },
    }
}

pub async fn curl_test_https_tls13_data(
    domain: &str,
    local_port: Option<&str>,
    max_time: &str,
    ip: Option<&str>,
) -> CurlResult {
    let url = format!("https://{domain}");
    let mut args = base_https_tls13_data_args(max_time);

    let port_args = local_port_args(local_port);
    let port_refs: Vec<&str> = port_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&port_refs);
    let ct_args = connect_to_args(domain, ip, 443);
    let ct_refs: Vec<&str> = ct_args.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&ct_refs);
    args.push(&url);

    match run_process(&args, process_timeout_ms(max_time)).await {
        Ok(pr) => to_curl_result(pr),
        Err(_) => CurlResult {
            exit_code: -1,
            http_code: None,
            headers: String::new(),
            size_download: None,
        },
    }
}

/// Dispatch data transfer test by protocol.
/// For HTTP, reuses the existing `curl_test_http` (already uses GET).
pub async fn curl_test_data(
    protocol: Protocol,
    domain: &str,
    local_port: Option<&str>,
    max_time: &str,
    ip: Option<&str>,
) -> CurlResult {
    match protocol {
        Protocol::Http => curl_test_http(domain, local_port, max_time, ip).await,
        Protocol::HttpsTls12 => curl_test_https_tls12_data(domain, local_port, max_time, ip).await,
        Protocol::HttpsTls13 => curl_test_https_tls13_data(domain, local_port, max_time, ip).await,
    }
}

/// Interpret data transfer result: first apply standard verdict, then check download size.
pub fn interpret_data_transfer_result(
    result: &CurlResult,
    domain: &str,
    min_bytes: u64,
) -> CurlVerdict {
    let base_verdict = interpret_curl_result(result, domain);
    match base_verdict {
        CurlVerdict::Available => {
            let downloaded = result.size_download.unwrap_or(0);
            if downloaded >= min_bytes {
                CurlVerdict::Available
            } else {
                CurlVerdict::DataTransferFailed {
                    size_download: downloaded,
                }
            }
        }
        other => other,
    }
}

pub fn interpret_curl_result(result: &CurlResult, domain: &str) -> CurlVerdict {
    if result.exit_code != 0 {
        return CurlVerdict::Unavailable {
            curl_exit_code: result.exit_code,
        };
    }

    if result.http_code == Some(400) {
        return CurlVerdict::ServerReceivesFakes;
    }

    if let Some(code) = result.http_code {
        if REDIRECT_CODES.contains(&code) {
            let location = result
                .headers
                .lines()
                .find(|line| line.to_lowercase().starts_with("location:"))
                .map(|line| {
                    line.split_once(':')
                        .map(|x| x.1)
                        .unwrap_or("")
                        .trim()
                        .to_string()
                })
                .unwrap_or_default();

            if location.to_lowercase().contains(&domain.to_lowercase()) {
                return CurlVerdict::Available;
            } else {
                return CurlVerdict::SuspiciousRedirect { code, location };
            }
        }

        return CurlVerdict::Available;
    }

    // HTTPS without -D: exit_code=0, http_code=None → successful connection
    if result.exit_code == 0 {
        return CurlVerdict::Available;
    }

    CurlVerdict::Unavailable {
        curl_exit_code: result.exit_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpret_available_200() {
        let result = CurlResult {
            exit_code: 0,
            http_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            size_download: None,
        };
        assert!(matches!(
            interpret_curl_result(&result, "example.com"),
            CurlVerdict::Available
        ));
    }

    #[test]
    fn test_interpret_unavailable() {
        let result = CurlResult {
            exit_code: 28,
            http_code: None,
            headers: String::new(),
            size_download: None,
        };
        assert!(matches!(
            interpret_curl_result(&result, "example.com"),
            CurlVerdict::Unavailable { curl_exit_code: 28 }
        ));
    }

    #[test]
    fn test_interpret_server_receives_fakes() {
        let result = CurlResult {
            exit_code: 0,
            http_code: Some(400),
            headers: "HTTP/1.1 400 Bad Request\r\n".to_string(),
            size_download: None,
        };
        assert!(matches!(
            interpret_curl_result(&result, "example.com"),
            CurlVerdict::ServerReceivesFakes
        ));
    }

    #[test]
    fn test_interpret_redirect_same_domain() {
        let result = CurlResult {
            exit_code: 0,
            http_code: Some(301),
            headers: "HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n".to_string(),
            size_download: None,
        };
        assert!(matches!(
            interpret_curl_result(&result, "example.com"),
            CurlVerdict::Available
        ));
    }

    #[test]
    fn test_interpret_suspicious_redirect() {
        let result = CurlResult {
            exit_code: 0,
            http_code: Some(302),
            headers: "HTTP/1.1 302 Found\r\nLocation: https://warning.isp.ru/blocked\r\n"
                .to_string(),
            size_download: None,
        };
        assert!(matches!(
            interpret_curl_result(&result, "example.com"),
            CurlVerdict::SuspiciousRedirect { .. }
        ));
    }

    #[test]
    fn test_connect_to_args_with_ip_http() {
        let args = connect_to_args("example.com", Some("1.2.3.4"), 80);
        assert_eq!(args, vec!["--connect-to", "example.com::1.2.3.4:80"]);
    }

    #[test]
    fn test_connect_to_args_with_ip_https() {
        let args = connect_to_args("example.com", Some("1.2.3.4"), 443);
        assert_eq!(args, vec!["--connect-to", "example.com::1.2.3.4:443"]);
    }

    #[test]
    fn test_connect_to_args_without_ip() {
        let args = connect_to_args("example.com", None, 80);
        assert!(args.is_empty());
    }

    #[test]
    fn test_pick_random_ip_empty() {
        let ips: Vec<String> = vec![];
        assert!(pick_random_ip(&ips).is_none());
    }

    #[test]
    fn test_pick_random_ip_single() {
        let ips = vec!["1.2.3.4".to_string()];
        assert_eq!(pick_random_ip(&ips), Some("1.2.3.4"));
    }

    #[test]
    fn test_pick_random_ip_multiple() {
        let ips = vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()];
        let picked = pick_random_ip(&ips);
        assert!(picked.is_some());
        assert!(ips.iter().any(|ip| ip.as_str() == picked.unwrap()));
    }

    #[test]
    fn test_interpret_https_no_headers() {
        let result = CurlResult {
            exit_code: 0,
            http_code: None,
            headers: String::new(),
            size_download: None,
        };
        assert!(matches!(
            interpret_curl_result(&result, "example.com"),
            CurlVerdict::Available
        ));
    }

    #[test]
    fn curl_http_args_no_connect_timeout() {
        let args = base_http_args("2");
        assert!(
            !args.contains(&"--connect-timeout"),
            "HTTP args must not contain --connect-timeout"
        );
    }

    #[test]
    fn curl_https_tls12_args_no_connect_timeout() {
        let args = base_https_tls12_args("2");
        assert!(
            !args.contains(&"--connect-timeout"),
            "HTTPS TLS1.2 args must not contain --connect-timeout"
        );
    }

    #[test]
    fn curl_https_tls13_args_no_connect_timeout() {
        let args = base_https_tls13_args("2");
        assert!(
            !args.contains(&"--connect-timeout"),
            "HTTPS TLS1.3 args must not contain --connect-timeout"
        );
    }

    #[test]
    fn curl_https_tls12_args_has_head_flag() {
        let args = base_https_tls12_args("2");
        assert!(
            args.contains(&"-I"),
            "HTTPS TLS1.2 args must contain -I (HEAD request)"
        );
    }

    #[test]
    fn curl_https_tls13_args_has_head_flag() {
        let args = base_https_tls13_args("2");
        assert!(
            args.contains(&"-I"),
            "HTTPS TLS1.3 args must contain -I (HEAD request)"
        );
    }

    #[test]
    fn curl_http_args_no_head_flag() {
        let args = base_http_args("2");
        assert!(!args.contains(&"-I"), "HTTP args must not contain -I");
    }

    #[test]
    fn curl_data_tls12_args_no_head_flag() {
        let args = base_https_tls12_data_args("8");
        assert!(
            !args.contains(&"-I"),
            "Data transfer TLS1.2 args must not contain -I"
        );
        assert!(
            args.contains(&"-w"),
            "Data transfer TLS1.2 args must contain -w"
        );
    }

    #[test]
    fn curl_data_tls13_args_no_head_flag() {
        let args = base_https_tls13_data_args("8");
        assert!(
            !args.contains(&"-I"),
            "Data transfer TLS1.3 args must not contain -I"
        );
        assert!(
            args.contains(&"-w"),
            "Data transfer TLS1.3 args must contain -w"
        );
    }

    #[test]
    fn test_interpret_data_transfer_success() {
        let result = CurlResult {
            exit_code: 0,
            http_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            size_download: Some(50_000),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            CurlVerdict::Available
        ));
    }

    #[test]
    fn test_interpret_data_transfer_too_small() {
        let result = CurlResult {
            exit_code: 0,
            http_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            size_download: Some(500),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            CurlVerdict::DataTransferFailed { size_download: 500 }
        ));
    }

    #[test]
    fn test_interpret_data_transfer_no_size() {
        let result = CurlResult {
            exit_code: 0,
            http_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            size_download: None,
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            CurlVerdict::DataTransferFailed { size_download: 0 }
        ));
    }

    #[test]
    fn test_interpret_data_transfer_curl_failed() {
        let result = CurlResult {
            exit_code: 28,
            http_code: None,
            headers: String::new(),
            size_download: None,
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            CurlVerdict::Unavailable { curl_exit_code: 28 }
        ));
    }

    #[test]
    fn test_interpret_data_transfer_exact_threshold() {
        let result = CurlResult {
            exit_code: 0,
            http_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            size_download: Some(1024),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            CurlVerdict::Available
        ));
    }

    #[test]
    fn test_to_curl_result_parses_size_download() {
        let pr = ProcessResult {
            exit_code: 0,
            stdout: "HTTP/1.1 200 OK\r\n\r\nSIZE_DOWNLOAD:54321.000".to_string(),
            stderr: String::new(),
        };
        let result = to_curl_result(pr);
        assert_eq!(result.size_download, Some(54321));
        assert_eq!(result.http_code, Some(200));
    }

    #[test]
    fn test_to_curl_result_no_size_marker() {
        let pr = ProcessResult {
            exit_code: 0,
            stdout: "HTTP/1.1 200 OK\r\n".to_string(),
            stderr: String::new(),
        };
        let result = to_curl_result(pr);
        assert_eq!(result.size_download, None);
    }
}
