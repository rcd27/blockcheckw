use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::Protocol;

/// Minimum bytes downloaded to consider data transfer successful.
pub const DATA_TRANSFER_MIN_BYTES: u64 = 1024;

const REDIRECT_CODES: &[u16] = &[301, 302, 307, 308];

#[derive(Debug)]
pub struct HttpResult {
    pub status_code: Option<u16>,
    pub headers: String,
    pub error: Option<String>,
    pub size_download: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum HttpVerdict {
    Available,
    SuspiciousRedirect { code: u16, location: String },
    ServerReceivesFakes,
    Unavailable { reason: String },
    DataTransferFailed { size_download: u64 },
}

impl fmt::Display for HttpVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpVerdict::Available => write!(f, "!!!!! AVAILABLE !!!!!"),
            HttpVerdict::SuspiciousRedirect { code, location } => {
                write!(f, "suspicious redirection {code} to : {location}")
            }
            HttpVerdict::ServerReceivesFakes => {
                write!(f, "http code 400. likely the server receives fakes.")
            }
            HttpVerdict::Unavailable { reason } => {
                write!(f, "UNAVAILABLE {reason}")
            }
            HttpVerdict::DataTransferFailed { size_download } => {
                write!(f, "DATA TRANSFER FAILED ({size_download}B downloaded)")
            }
        }
    }
}

// ── Marked TCP connect ──────────────────────────────────────────────────────
//
// Creates a TCP socket via socket2, sets SO_MARK before connect(),
// then converts to tokio::net::TcpStream. This ensures the SYN packet
// carries the fwmark so nftables can match and queue it to nfqws2.

/// Create a TCP connection with SO_MARK set before connect().
///
/// The fwmark is applied to the socket before the SYN is sent,
/// ensuring all packets (including SYN) carry the mark.
/// If fwmark == 0, no mark is set (used for baseline tests).
pub async fn marked_tcp_connect(addr: SocketAddr, fwmark: u32) -> io::Result<TcpStream> {
    use std::os::unix::io::{FromRawFd, IntoRawFd};

    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    if fwmark != 0 {
        socket.set_mark(fwmark)?;
    }

    socket.set_nonblocking(true)?;

    // Convert socket2::Socket → raw fd → tokio::net::TcpSocket
    let raw_fd = socket.into_raw_fd();
    let tokio_socket = unsafe { tokio::net::TcpSocket::from_raw_fd(raw_fd) };

    tokio_socket.connect(addr).await
}

// ── TLS configuration ───────────────────────────────────────────────────────

pub fn make_tls_config(protocol: Protocol) -> Arc<ClientConfig> {
    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Set TLS version constraints
    match protocol {
        Protocol::HttpsTls12 => {
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            // Only TLS 1.2
            let versions = &[&rustls::version::TLS12];
            config = ClientConfig::builder_with_protocol_versions(versions)
                .with_root_certificates(
                    rustls::RootCertStore::from_iter(
                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                    ),
                )
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        Protocol::HttpsTls13 => {
            let versions = &[&rustls::version::TLS13];
            config = ClientConfig::builder_with_protocol_versions(versions)
                .with_root_certificates(
                    rustls::RootCertStore::from_iter(
                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                    ),
                )
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        Protocol::Http => {} // no TLS
    }

    Arc::new(config)
}

// ── HTTP test functions ─────────────────────────────────────────────────────

/// Perform an HTTP(S) test request using a pre-marked TCP socket.
///
/// For HTTP: GET request (need to see response body/redirect).
/// For HTTPS: HEAD request (fast handshake check).
pub async fn http_test(
    protocol: Protocol,
    domain: &str,
    ip: &str,
    fwmark: u32,
    timeout_secs: u64,
) -> HttpResult {
    let timeout = Duration::from_secs(timeout_secs);

    match tokio::time::timeout(timeout, http_test_inner(protocol, domain, ip, fwmark, false)).await
    {
        Ok(result) => result,
        Err(_) => HttpResult {
            status_code: None,
            headers: String::new(),
            error: Some("timeout".to_string()),
            size_download: None,
        },
    }
}

/// Perform an HTTP(S) data transfer test (GET with streaming download).
pub async fn http_test_data(
    protocol: Protocol,
    domain: &str,
    ip: &str,
    fwmark: u32,
    timeout_secs: u64,
) -> HttpResult {
    let timeout = Duration::from_secs(timeout_secs);

    match tokio::time::timeout(timeout, http_test_inner(protocol, domain, ip, fwmark, true)).await {
        Ok(result) => result,
        Err(_) => HttpResult {
            status_code: None,
            headers: String::new(),
            error: Some("timeout".to_string()),
            size_download: None,
        },
    }
}

/// Inner implementation: connect, optional TLS, send HTTP request, parse response.
/// Follows one level of same-domain redirects (e.g. xnxx.com → www.xnxx.com).
async fn http_test_inner(
    protocol: Protocol,
    domain: &str,
    ip: &str,
    fwmark: u32,
    count_body: bool,
) -> HttpResult {
    let result = http_single_request(protocol, domain, ip, fwmark, count_body).await;

    // Follow one redirect if it points to the same domain
    if let Some(code) = result.status_code {
        if REDIRECT_CODES.contains(&code) {
            if let Some(location) = extract_location(&result.headers) {
                if location.to_lowercase().contains(&domain.to_lowercase()) {
                    // Extract redirect host (may differ: xnxx.com → www.xnxx.com)
                    if let Some(redirect_host) = extract_host_from_url(&location) {
                        return http_single_request(
                            protocol,
                            &redirect_host,
                            ip,
                            fwmark,
                            count_body,
                        )
                        .await;
                    }
                }
            }
        }
    }

    result
}

/// Perform a single HTTP(S) request without following redirects.
async fn http_single_request(
    protocol: Protocol,
    domain: &str,
    ip: &str,
    fwmark: u32,
    count_body: bool,
) -> HttpResult {
    let port = protocol.port();
    let addr: SocketAddr = match format!("{ip}:{port}").parse() {
        Ok(a) => a,
        Err(e) => {
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("invalid address: {e}")),
                size_download: None,
            };
        }
    };

    // Step 1: TCP connect with SO_MARK
    let tcp_stream = match marked_tcp_connect(addr, fwmark).await {
        Ok(s) => s,
        Err(e) => {
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("connect: {e}")),
                size_download: None,
            };
        }
    };

    // Step 2: Optionally wrap in TLS
    match protocol {
        Protocol::Http => {
            do_http_request(TokioIo::new(tcp_stream), domain, count_body).await
        }
        Protocol::HttpsTls12 | Protocol::HttpsTls13 => {
            let tls_config = make_tls_config(protocol);
            let connector = TlsConnector::from(tls_config);
            let server_name = match rustls::pki_types::ServerName::try_from(domain.to_string()) {
                Ok(sn) => sn,
                Err(e) => {
                    return HttpResult {
                        status_code: None,
                        headers: String::new(),
                        error: Some(format!("invalid server name: {e}")),
                        size_download: None,
                    };
                }
            };

            let tls_stream = match connector.connect(server_name, tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    return HttpResult {
                        status_code: None,
                        headers: String::new(),
                        error: Some(format!("tls: {e}")),
                        size_download: None,
                    };
                }
            };

            // For HTTPS: use HEAD (fast handshake check) unless counting body
            do_http_request_https(TokioIo::new(tls_stream), domain, count_body).await
        }
    }
}

/// Extract the Location header value from raw headers.
fn extract_location(headers: &str) -> Option<String> {
    headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("location:"))
        .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()))
}

/// Extract host from a URL like "https://www.xnxx.com/path".
fn extract_host_from_url(url: &str) -> Option<String> {
    // Strip scheme
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    // Take host part (before / or end)
    let host = without_scheme.split('/').next()?;
    // Strip port if present
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Send HTTP/1.1 request over a plain TCP connection (HTTP).
/// Always uses GET for HTTP (need to see redirects/body).
async fn do_http_request<IO>(io: IO, domain: &str, count_body: bool) -> HttpResult
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = match http1::handshake(io).await {
        Ok(h) => h,
        Err(e) => {
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("handshake: {e}")),
                size_download: None,
            };
        }
    };

    // Spawn connection driver
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::get("/")
        .header("Host", domain)
        .header("User-Agent", "Mozilla")
        .body(Empty::<Bytes>::new())
        .unwrap();

    send_and_parse(sender.send_request(req).await, domain, count_body).await
}

/// Send HTTP/1.1 request over a TLS connection (HTTPS).
/// Uses HEAD unless count_body is true (data transfer test).
async fn do_http_request_https<IO>(io: IO, domain: &str, count_body: bool) -> HttpResult
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = match http1::handshake(io).await {
        Ok(h) => h,
        Err(e) => {
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("handshake: {e}")),
                size_download: None,
            };
        }
    };

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let method = if count_body { "GET" } else { "HEAD" };
    let req = Request::builder()
        .method(method)
        .uri("/")
        .header("Host", domain)
        .header("User-Agent", "Mozilla")
        .body(Empty::<Bytes>::new())
        .unwrap();

    send_and_parse(sender.send_request(req).await, domain, count_body).await
}

/// Parse hyper response into HttpResult.
async fn send_and_parse(
    result: Result<hyper::Response<hyper::body::Incoming>, hyper::Error>,
    _domain: &str,
    count_body: bool,
) -> HttpResult {
    let response = match result {
        Ok(r) => r,
        Err(e) => {
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("request: {e}")),
                size_download: None,
            };
        }
    };

    let status_code = Some(response.status().as_u16());

    // Format headers
    let mut headers = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or(""),
    );
    for (key, value) in response.headers() {
        headers.push_str(&format!(
            "{}: {}\r\n",
            key,
            value.to_str().unwrap_or("<binary>"),
        ));
    }

    let size_download = if count_body {
        // Stream body and count bytes
        let mut total: u64 = 0;
        let mut body = response.into_body();
        while let Some(chunk) = body.frame().await {
            match chunk {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        total += data.len() as u64;
                    }
                }
                Err(_) => break,
            }
        }
        Some(total)
    } else {
        None
    };

    HttpResult {
        status_code,
        headers,
        error: None,
        size_download,
    }
}

// ── Interpret functions (unchanged) ─────────────────────────────────────────

pub fn interpret_http_result(result: &HttpResult, domain: &str) -> HttpVerdict {
    if result.error.is_some() {
        return HttpVerdict::Unavailable {
            reason: result.error.as_ref().unwrap().clone(),
        };
    }

    if result.status_code == Some(400) {
        return HttpVerdict::ServerReceivesFakes;
    }

    if let Some(code) = result.status_code {
        if REDIRECT_CODES.contains(&code) {
            let location = result
                .headers
                .lines()
                .find(|line| line.to_lowercase().starts_with("location:"))
                .map(|line| line.split_once(':').map(|x| x.1).unwrap_or("").trim().to_string())
                .unwrap_or_default();

            if location.to_lowercase().contains(&domain.to_lowercase()) {
                return HttpVerdict::Available;
            } else {
                return HttpVerdict::SuspiciousRedirect { code, location };
            }
        }

        return HttpVerdict::Available;
    }

    HttpVerdict::Available
}

/// Interpret data transfer result: first apply standard verdict, then check download size.
pub fn interpret_data_transfer_result(
    result: &HttpResult,
    domain: &str,
    min_bytes: u64,
) -> HttpVerdict {
    let base_verdict = interpret_http_result(result, domain);
    match base_verdict {
        HttpVerdict::Available => {
            let downloaded = result.size_download.unwrap_or(0);
            if downloaded >= min_bytes {
                HttpVerdict::Available
            } else {
                HttpVerdict::DataTransferFailed {
                    size_download: downloaded,
                }
            }
        }
        other => other,
    }
}

/// Pick a random IP from a slice using a fast, deterministic-per-call method.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpret_available_200() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: None,
        };
        assert!(matches!(
            interpret_http_result(&result, "example.com"),
            HttpVerdict::Available
        ));
    }

    #[test]
    fn test_interpret_unavailable() {
        let result = HttpResult {
            status_code: None,
            headers: String::new(),
            error: Some("timeout".to_string()),
            size_download: None,
        };
        assert!(matches!(
            interpret_http_result(&result, "example.com"),
            HttpVerdict::Unavailable { .. }
        ));
    }

    #[test]
    fn test_interpret_server_receives_fakes() {
        let result = HttpResult {
            status_code: Some(400),
            headers: "HTTP/1.1 400 Bad Request\r\n".to_string(),
            error: None,
            size_download: None,
        };
        assert!(matches!(
            interpret_http_result(&result, "example.com"),
            HttpVerdict::ServerReceivesFakes
        ));
    }

    #[test]
    fn test_interpret_redirect_same_domain() {
        let result = HttpResult {
            status_code: Some(301),
            headers: "HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n".to_string(),
            error: None,
            size_download: None,
        };
        assert!(matches!(
            interpret_http_result(&result, "example.com"),
            HttpVerdict::Available
        ));
    }

    #[test]
    fn test_interpret_suspicious_redirect() {
        let result = HttpResult {
            status_code: Some(302),
            headers: "HTTP/1.1 302 Found\r\nLocation: https://warning.isp.ru/blocked\r\n"
                .to_string(),
            error: None,
            size_download: None,
        };
        assert!(matches!(
            interpret_http_result(&result, "example.com"),
            HttpVerdict::SuspiciousRedirect { .. }
        ));
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
    fn test_interpret_data_transfer_success() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: Some(50_000),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            HttpVerdict::Available
        ));
    }

    #[test]
    fn test_interpret_data_transfer_too_small() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: Some(500),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            HttpVerdict::DataTransferFailed { size_download: 500 }
        ));
    }

    #[test]
    fn test_interpret_data_transfer_exact_threshold() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: Some(1024),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            HttpVerdict::Available
        ));
    }

    #[test]
    fn test_interpret_data_transfer_no_size() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: None,
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            HttpVerdict::DataTransferFailed { size_download: 0 }
        ));
    }

    #[test]
    fn test_interpret_data_transfer_request_failed() {
        let result = HttpResult {
            status_code: None,
            headers: String::new(),
            error: Some("connection refused".to_string()),
            size_download: None,
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", 1024),
            HttpVerdict::Unavailable { .. }
        ));
    }

    #[test]
    fn test_extract_location() {
        let headers = "HTTP/1.1 301 Moved\r\nLocation: https://www.xnxx.com/\r\nServer: nginx\r\n";
        assert_eq!(
            extract_location(headers),
            Some("https://www.xnxx.com/".to_string())
        );
    }

    #[test]
    fn test_extract_location_missing() {
        let headers = "HTTP/1.1 200 OK\r\nServer: nginx\r\n";
        assert_eq!(extract_location(headers), None);
    }

    #[test]
    fn test_extract_host_from_url() {
        assert_eq!(
            extract_host_from_url("https://www.xnxx.com/path"),
            Some("www.xnxx.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("https://host:8080/path"),
            Some("host".to_string())
        );
        assert_eq!(extract_host_from_url("/relative/path"), None);
    }
}
