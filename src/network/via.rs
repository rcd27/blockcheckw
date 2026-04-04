use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::LazyLock;

use console::style;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::system::process::run_process;
use crate::ui;

const ROUTE_TIMEOUT_MS: u64 = 5_000;

/// Global set of IPs whose routes we added (for cleanup on panic/Ctrl+C).
static ADDED_ROUTES: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Describes how traffic reaches the target: L3 gateway, HTTP proxy, or SOCKS5 proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// L3 gateway IP for `ip route add … via <gw>`
    Route(String),
    /// HTTP CONNECT tunnel
    HttpProxy { host: String, port: u16 },
    /// SOCKS5 tunnel
    Socks5Proxy { host: String, port: u16 },
}

impl Via {
    /// Auto-detect mode from the raw `--via` value.
    ///
    /// Formats:
    /// - `socks5://host:port` → Socks5Proxy
    /// - `http://host:port`   → HttpProxy
    /// - `https://…`          → error (TLS not supported, use http://)
    /// - `host:port`          → HttpProxy (bare host:port implies HTTP proxy)
    /// - bare IP / hostname   → Route (L3 gateway)
    pub fn parse(raw: &str) -> Result<Via, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("empty --via value".into());
        }

        if let Some(rest) = trimmed.strip_prefix("socks5://") {
            let (host, port) = parse_host_port(rest)?;
            Ok(Via::Socks5Proxy { host, port })
        } else if let Some(rest) = trimmed.strip_prefix("http://") {
            let (host, port) = parse_host_port(rest)?;
            Ok(Via::HttpProxy { host, port })
        } else if trimmed.starts_with("https://") {
            Err("HTTPS proxies are not supported; use http:// instead (the proxy tunnel itself does not need TLS)".into())
        } else if trimmed.contains(':') {
            // bare host:port → treat as HTTP proxy
            let (host, port) = parse_host_port(trimmed)?;
            Ok(Via::HttpProxy { host, port })
        } else {
            // bare IP or hostname → L3 route gateway
            Ok(Via::Route(trimmed.to_owned()))
        }
    }

    /// Returns `true` for proxy variants (HttpProxy, Socks5Proxy).
    pub fn is_proxy(&self) -> bool {
        matches!(self, Via::HttpProxy { .. } | Via::Socks5Proxy { .. })
    }

    // ── Reachability ─────────────────────────────────────────────

    /// Check that the gateway/proxy is reachable. Prints OK/FAIL to the console.
    pub async fn check_reachable(&self, con: &ui::Console) -> bool {
        match self {
            Via::Route(gw) => {
                let result = run_process(&["ip", "route", "get", gw], ROUTE_TIMEOUT_MS).await;
                let ok = result.is_ok_and(|r| r.exit_code == 0);
                let label = format!("Remote gateway {}", style(gw).bold());
                if ok {
                    con.println(&format!("  {label}: {}", style("OK").green().bold()));
                } else {
                    con.println(&format!(
                        "  {}{label}: {}",
                        ui::WARN,
                        style("FAIL (unreachable)").red().bold(),
                    ));
                }
                ok
            }
            Via::HttpProxy { host, port } | Via::Socks5Proxy { host, port } => {
                let addr = format!("{host}:{port}");
                let ok = tokio::time::timeout(
                    std::time::Duration::from_millis(ROUTE_TIMEOUT_MS),
                    TcpStream::connect(&addr),
                )
                .await
                .is_ok_and(|r| r.is_ok());
                let label = format!("Proxy {}", style(&addr).bold());
                if ok {
                    con.println(&format!(
                        "  {}{label}: {}",
                        ui::CHECKMARK,
                        style("OK").green().bold()
                    ));
                } else {
                    con.println(&format!(
                        "  {}{label}: {}",
                        ui::WARN,
                        style("FAIL (unreachable)").red().bold(),
                    ));
                }
                ok
            }
        }
    }

    // ── Route management ─────────────────────────────────────────

    /// Add `ip route add <ip> via <gw>` for each IP (Route mode).
    /// Proxy mode is a noop — returns all IPs unchanged.
    pub async fn add_routes(&self, ips: &[String]) -> Vec<String> {
        let Via::Route(gw) = self else {
            return ips.to_vec();
        };

        let mut global = ADDED_ROUTES.lock().await;
        let mut added = Vec::new();
        for ip in ips {
            if global.contains(ip) {
                added.push(ip.clone());
                continue;
            }
            let result =
                run_process(&["ip", "route", "add", ip, "via", gw], ROUTE_TIMEOUT_MS).await;
            if result.is_ok_and(|r| r.exit_code == 0) {
                global.insert(ip.clone());
                added.push(ip.clone());
            }
        }
        added
    }

    /// Remove routes for the given IPs (best-effort). Noop for proxy modes.
    pub async fn remove_routes(&self, ips: &[String]) {
        if !matches!(self, Via::Route(_)) {
            return;
        }
        let mut global = ADDED_ROUTES.lock().await;
        for ip in ips {
            if global.remove(ip) {
                let _ = run_process(&["ip", "route", "del", ip], ROUTE_TIMEOUT_MS).await;
            }
        }
    }

    /// Remove ALL routes we ever added (for cleanup handlers). Noop for proxy modes.
    pub async fn cleanup(&self) {
        if !matches!(self, Via::Route(_)) {
            return;
        }
        let mut global = ADDED_ROUTES.lock().await;
        for ip in global.drain() {
            let _ = run_process(&["ip", "route", "del", &ip], ROUTE_TIMEOUT_MS).await;
        }
    }

    /// Remove ALL routes we ever added (async, associated function).
    /// Called from signal handlers where no `Via` instance is available.
    pub async fn cleanup_all() {
        let mut global = ADDED_ROUTES.lock().await;
        for ip in global.drain() {
            let _ = run_process(&["ip", "route", "del", &ip], ROUTE_TIMEOUT_MS).await;
        }
    }

    /// Synchronous cleanup for panic hook — can't use async runtime.
    /// Associated function (no `&self`) so it can be called from any context.
    pub fn cleanup_sync() {
        if let Ok(mut global) = ADDED_ROUTES.try_lock() {
            for ip in global.drain() {
                let _ = std::process::Command::new("ip")
                    .args(["route", "del", &ip])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
    }

    // ── TCP tunnels ──────────────────────────────────────────────

    /// Open a TCP connection to `target`, tunnelling through the proxy if needed.
    pub async fn tcp_connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        match self {
            Via::Route(_) => TcpStream::connect(target).await,
            Via::HttpProxy { host, port } => http_connect_tunnel(host, port, target).await,
            Via::Socks5Proxy { host, port } => socks5_tunnel(host, port, target).await,
        }
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Via::Route(gw) => write!(f, "route via {gw}"),
            Via::HttpProxy { host, port } => write!(f, "http proxy {host}:{port}"),
            Via::Socks5Proxy { host, port } => write!(f, "socks5 proxy {host}:{port}"),
        }
    }
}

// ── Tunnel helpers ───────────────────────────────────────────────

/// Establish an HTTP CONNECT tunnel through `proxy_host:proxy_port` to `target`.
async fn http_connect_tunnel(
    proxy_host: &str,
    proxy_port: &u16,
    target: SocketAddr,
) -> io::Result<TcpStream> {
    let proxy_addr = format!("{proxy_host}:{proxy_port}");
    let mut stream = TcpStream::connect(&proxy_addr).await?;

    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Read response byte-by-byte until we see \r\n\r\n (max 4096 bytes).
    let mut buf = Vec::with_capacity(256);
    loop {
        if buf.len() >= 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT response too large",
            ));
        }
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
    }

    let response = String::from_utf8_lossy(&buf);
    if !response.contains(" 200 ") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "HTTP CONNECT failed: {}",
                response.lines().next().unwrap_or("")
            ),
        ));
    }

    Ok(stream)
}

/// Establish a SOCKS5 tunnel (RFC 1928, no-auth, IPv4 only) through `proxy_host:proxy_port`.
async fn socks5_tunnel(
    proxy_host: &str,
    proxy_port: &u16,
    target: SocketAddr,
) -> io::Result<TcpStream> {
    let ip4 = match target {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS5 tunnel: IPv6 targets not supported",
            ));
        }
    };

    let proxy_addr = format!("{proxy_host}:{proxy_port}");
    let mut stream = TcpStream::connect(&proxy_addr).await?;

    // Greeting: version 5, 1 auth method, no-auth (0x00)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut greeting_resp = [0u8; 2];
    stream.read_exact(&mut greeting_resp).await?;
    if greeting_resp != [0x05, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "SOCKS5 greeting rejected: [{:#04x}, {:#04x}]",
                greeting_resp[0], greeting_resp[1]
            ),
        ));
    }

    // CONNECT request: VER=5, CMD=CONNECT(1), RSV=0, ATYP=IPv4(1), DST.ADDR(4), DST.PORT(2)
    let octets = ip4.ip().octets();
    let port_be = ip4.port().to_be_bytes();
    let connect_req = [
        0x05, 0x01, 0x00, 0x01, octets[0], octets[1], octets[2], octets[3], port_be[0], port_be[1],
    ];
    stream.write_all(&connect_req).await?;

    let mut connect_resp = [0u8; 10];
    stream.read_exact(&mut connect_resp).await?;
    if connect_resp[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed: reply code {:#04x}", connect_resp[1]),
        ));
    }

    Ok(stream)
}

/// Parse `"host:port"` into `(host, port)`.
fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    // Handle IPv6 addresses in brackets: [::1]:8080
    if let Some(rest) = s.strip_prefix('[') {
        let bracket_end = rest
            .find(']')
            .ok_or_else(|| format!("missing closing ']' in address: {s}"))?;
        let host = &rest[..bracket_end];
        let after = &rest[bracket_end + 1..];
        let port_str = after
            .strip_prefix(':')
            .ok_or_else(|| format!("expected ':port' after ']' in address: {s}"))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|e| format!("invalid port in '{s}': {e}"))?;
        if port == 0 {
            return Err(format!("port must be 1-65535, got 0 in '{s}'"));
        }
        return Ok((host.to_owned(), port));
    }

    // Regular host:port
    let colon = s
        .rfind(':')
        .ok_or_else(|| format!("expected host:port, got '{s}'"))?;
    let host = &s[..colon];
    let port_str = &s[colon + 1..];

    if host.is_empty() {
        return Err(format!("empty host in '{s}'"));
    }

    let port = port_str
        .parse::<u16>()
        .map_err(|e| format!("invalid port in '{s}': {e}"))?;
    if port == 0 {
        return Err(format!("port must be 1-65535, got 0 in '{s}'"));
    }

    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse: socks5 ──────────────────────────────────────────

    #[test]
    fn parse_socks5() {
        let v = Via::parse("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(
            v,
            Via::Socks5Proxy {
                host: "127.0.0.1".into(),
                port: 1080
            }
        );
        assert!(v.is_proxy());
    }

    #[test]
    fn parse_socks5_hostname() {
        let v = Via::parse("socks5://proxy.example.com:9050").unwrap();
        assert_eq!(
            v,
            Via::Socks5Proxy {
                host: "proxy.example.com".into(),
                port: 9050
            }
        );
    }

    // ── parse: http ────────────────────────────────────────────

    #[test]
    fn parse_http() {
        let v = Via::parse("http://10.0.0.1:3128").unwrap();
        assert_eq!(
            v,
            Via::HttpProxy {
                host: "10.0.0.1".into(),
                port: 3128
            }
        );
        assert!(v.is_proxy());
    }

    // ── parse: bare host:port → HttpProxy ──────────────────────

    #[test]
    fn parse_bare_host_port() {
        let v = Via::parse("192.168.1.1:8080").unwrap();
        assert_eq!(
            v,
            Via::HttpProxy {
                host: "192.168.1.1".into(),
                port: 8080
            }
        );
    }

    #[test]
    fn parse_bare_hostname_port() {
        let v = Via::parse("proxy.local:3128").unwrap();
        assert_eq!(
            v,
            Via::HttpProxy {
                host: "proxy.local".into(),
                port: 3128
            }
        );
    }

    // ── parse: bare IP → Route ─────────────────────────────────

    #[test]
    fn parse_route_ip() {
        let v = Via::parse("10.0.0.1").unwrap();
        assert_eq!(v, Via::Route("10.0.0.1".into()));
        assert!(!v.is_proxy());
    }

    #[test]
    fn parse_route_hostname() {
        let v = Via::parse("gw.example.com").unwrap();
        assert_eq!(v, Via::Route("gw.example.com".into()));
    }

    // ── parse: whitespace trimming ─────────────────────────────

    #[test]
    fn parse_trims_whitespace() {
        let v = Via::parse("  10.0.0.1  ").unwrap();
        assert_eq!(v, Via::Route("10.0.0.1".into()));
    }

    // ── parse: error cases ─────────────────────────────────────

    #[test]
    fn parse_https_error() {
        let err = Via::parse("https://proxy:443").unwrap_err();
        assert!(
            err.contains("http://"),
            "error should suggest http://: {err}"
        );
    }

    #[test]
    fn parse_empty_error() {
        assert!(Via::parse("").is_err());
        assert!(Via::parse("   ").is_err());
    }

    #[test]
    fn parse_invalid_port() {
        assert!(Via::parse("http://host:notaport").is_err());
    }

    #[test]
    fn parse_zero_port() {
        assert!(Via::parse("http://host:0").is_err());
    }

    #[test]
    fn parse_port_overflow() {
        assert!(Via::parse("http://host:99999").is_err());
    }

    #[test]
    fn parse_empty_host_in_url() {
        assert!(Via::parse("http://:8080").is_err());
    }

    // ── parse: IPv6 ────────────────────────────────────────────

    #[test]
    fn parse_socks5_ipv6() {
        let v = Via::parse("socks5://[::1]:1080").unwrap();
        assert_eq!(
            v,
            Via::Socks5Proxy {
                host: "::1".into(),
                port: 1080
            }
        );
    }

    #[test]
    fn parse_http_ipv6() {
        let v = Via::parse("http://[fe80::1]:3128").unwrap();
        assert_eq!(
            v,
            Via::HttpProxy {
                host: "fe80::1".into(),
                port: 3128
            }
        );
    }

    // ── Display ────────────────────────────────────────────────

    #[test]
    fn display_route() {
        assert_eq!(
            Via::Route("10.0.0.1".into()).to_string(),
            "route via 10.0.0.1"
        );
    }

    #[test]
    fn display_http() {
        let v = Via::HttpProxy {
            host: "proxy".into(),
            port: 3128,
        };
        assert_eq!(v.to_string(), "http proxy proxy:3128");
    }

    #[test]
    fn display_socks5() {
        let v = Via::Socks5Proxy {
            host: "localhost".into(),
            port: 1080,
        };
        assert_eq!(v.to_string(), "socks5 proxy localhost:1080");
    }

    // ── is_proxy ───────────────────────────────────────────────

    #[test]
    fn is_proxy_variants() {
        assert!(!Via::Route("gw".into()).is_proxy());
        assert!(Via::HttpProxy {
            host: "h".into(),
            port: 1
        }
        .is_proxy());
        assert!(Via::Socks5Proxy {
            host: "h".into(),
            port: 1
        }
        .is_proxy());
    }

    // ── TCP tunnel tests ─────────────────────────────────────────

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn http_connect_sends_correct_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                total += n;
                if total >= 4 && buf[total - 4..total] == *b"\r\n\r\n" {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf[..total]).to_string();
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            request
        });

        let via = Via::HttpProxy {
            host: "127.0.0.1".into(),
            port: proxy_addr.port(),
        };
        let _stream = via.tcp_connect(target).await.unwrap();

        let request = server.await.unwrap();
        assert!(
            request.starts_with(&format!("CONNECT {target} HTTP/1.1\r\n")),
            "unexpected request: {request}"
        );
    }

    #[tokio::test]
    async fn http_connect_rejects_non_200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain the request
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                total += n;
                if total >= 4 && buf[total - 4..total] == *b"\r\n\r\n" {
                    break;
                }
            }
            sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        });

        let via = Via::HttpProxy {
            host: "127.0.0.1".into(),
            port: proxy_addr.port(),
        };
        let err = via.tcp_connect(target).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn socks5_sends_correct_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();

            // Read greeting (3 bytes)
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00], "bad SOCKS5 greeting");

            // Reply: version 5, no-auth accepted
            sock.write_all(&[0x05, 0x00]).await.unwrap();

            // Read CONNECT request (10 bytes)
            let mut connect = [0u8; 10];
            sock.read_exact(&mut connect).await.unwrap();
            assert_eq!(connect[0], 0x05, "VER");
            assert_eq!(connect[1], 0x01, "CMD=CONNECT");
            assert_eq!(connect[2], 0x00, "RSV");
            assert_eq!(connect[3], 0x01, "ATYP=IPv4");
            assert_eq!(&connect[4..8], &[93, 184, 216, 34], "DST.ADDR");
            assert_eq!(&connect[8..10], &443u16.to_be_bytes(), "DST.PORT");

            // Reply: success
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let via = Via::Socks5Proxy {
            host: "127.0.0.1".into(),
            port: proxy_addr.port(),
        };
        let _stream = via.tcp_connect(target).await.unwrap();
        server.await.unwrap();
    }
}
