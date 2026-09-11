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

use crate::network::cause::{classify, Cause, Phase, Reached};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::Protocol;

/// Minimum bytes downloaded to consider data transfer successful.
/// Set to 32KB to catch DPI systems that kill connections after ~16-20KB.
pub const DATA_TRANSFER_MIN_BYTES: u64 = 32_768;

/// DPI data-limit heuristic: connections killed in this byte range
/// suggest a DPI system that caps data transfer (typically ~16KB).
const DPI_LIMIT_RANGE: std::ops::Range<u64> = 10_240..25_600;

/// How much HTTP body to download.
#[derive(Debug, Clone, Copy)]
pub enum BodyMode {
    /// HEAD request — don't download body (fast handshake check)
    Head,
    /// GET request — download entire body
    Unlimited,
    /// GET request — stop after N bytes
    LimitedTo(u64),
}

impl BodyMode {
    fn is_get(self) -> bool {
        !matches!(self, BodyMode::Head)
    }

    fn max_bytes(self) -> u64 {
        match self {
            BodyMode::Head => 0,
            BodyMode::Unlimited => u64::MAX,
            BodyMode::LimitedTo(n) => n,
        }
    }
}

const REDIRECT_CODES: &[u16] = &[301, 302, 307, 308];

/// Корень сайта. Путь пробы стал параметром (спека §6-бис), и тем, кто мерит САМ САЙТ
/// (baseline, scan, status), корень по-прежнему нужен — но теперь это выбор вызывающего,
/// а не константа, вшитая в построение запроса.
pub const ROOT_PATH: &str = "/";

/// Привести путь пробы к виду, пригодному для строки запроса. Пустое и относительное
/// hyper отвергает построением URI, и отвергает уже ПОСЛЕ коннекта — то есть отказ
/// выглядел бы уликой против цензора.
pub fn normalize_probe_path(raw: &str) -> String {
    let trimmed = raw.trim();
    match trimmed {
        "" => ROOT_PATH.to_string(),
        p if p.starts_with('/') => p.to_string(),
        p => format!("/{p}"),
    }
}

/// Чем кончилось чтение. Различает ДОСМОТРЕННОЕ окно от брошенного — без этого
/// «цель молчала» неотличимо от «мы не дождались», и всякий наш промах становится
/// уликой против цензора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// Сервер закрыл поток — тело кончилось само.
    BodyComplete,
    /// Упёрлись в СВОЙ лимит (`BodyMode::LimitedTo`): брали, пока сами не прекратили.
    LimitReached,
    /// Ошибка чтения тела: сброс, TLS-алерт. Окно досмотрено, ответ получен.
    BodyError,
    /// Мы перестали ждать: `stall` или внешний таймаут. О цели НИЧЕГО.
    WeStoppedWaiting,
    /// До тела не дошло, и отказ ОПРЕДЕЛЁН: `ECONNREFUSED`, `EHOSTUNREACH`, `RST`.
    /// Цель (или цензор за неё) высказалась — это ОТВЕТ, а не его отсутствие, и
    /// повтор скажет то же самое (`Cause::deterministic`). Без этой ветки всякий
    /// доконтентный отказ уезжал в `NeverStarted`, то есть в «мы не досмотрели», и
    /// `Observed::NoConnect` с `Fate::Dead` не производились никогда.
    Denied,
    /// До тела не дошло вовсе (`HEAD`, провал раньше), и почему — не установлено.
    NeverStarted,
}

/// Чем кончилось чтение, когда до тела не дошло. Разбор тотален: определённый отказ
/// есть ответ цели, неопределённый — наша слепота, и слить их значит списать всякий
/// свой промах на цензора.
fn ended_before_body(cause: Cause) -> Ended {
    match cause {
        Cause::Refused | Cause::Unreachable | Cause::Reset(_) => Ended::Denied,
        Cause::Timeout(_) | Cause::Io(_) | Cause::Protocol(_) => Ended::NeverStarted,
    }
}

/// Добить ряд секундных окон нулями до фактической длительности чтения тела.
///
/// Окно закрывается ВРЕМЕНЕМ, а не приходом кадра (`sag.rs`: `Cadence::Own { 1000 }`,
/// «иначе прибор молчал бы, когда байты перестали идти совсем»). Замерший навсегда
/// поток — классический DPI-cap — не заводит новых окон сам, и секунды тишины подряд
/// в ряд не попадали вовсе: `Sag` оставался слеп ровно там, где он и нужен.
fn pad_windows(windows: &mut Vec<u64>, seconds: u64) {
    let needed = seconds as usize + 1;
    if windows.len() < needed {
        windows.resize(needed, 0);
    }
}

#[derive(Debug)]
pub struct HttpResult {
    pub status_code: Option<u16>,
    pub headers: String,
    pub error: Option<String>,
    pub size_download: Option<u64>,
    /// Причина провала — инструментовка замера (спайк #verify-histogram).
    pub cause: Option<Cause>,
    /// Чем кончилось чтение — см. [`Ended`].
    pub ended: Ended,
    /// Байт тела по СЕКУНДНЫМ окнам, индекс — номер секунды от первого байта тела.
    /// Материал для `Sag`; пусто, если тело не читали.
    pub windows: Vec<u64>,
}

impl HttpResult {
    /// Результат сорванной внешним таймаутом пробы. Отдельный конструктор, а не
    /// литерал на месте: только здесь известно, что фазу надо взять из отметки,
    /// — сам таймаут о ней не знает.
    pub fn timed_out(reached: &Reached) -> HttpResult {
        HttpResult {
            status_code: None,
            headers: String::new(),
            error: Some("timeout".to_string()),
            size_download: None,
            cause: Some(Cause::Timeout(reached.phase())),
            ended: Ended::WeStoppedWaiting,
            windows: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum HttpVerdict {
    Available,
    SuspiciousRedirect {
        code: u16,
        location: String,
    },
    ServerReceivesFakes,
    Unavailable {
        reason: String,
        cause: Option<Cause>,
    },
    DataTransferFailed {
        size_download: u64,
    },
    DpiDataLimit {
        size_download: u64,
    },
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
            HttpVerdict::Unavailable { reason, .. } => {
                write!(f, "UNAVAILABLE {reason}")
            }
            HttpVerdict::DataTransferFailed { size_download } => {
                write!(f, "DATA TRANSFER FAILED ({size_download}B downloaded)")
            }
            HttpVerdict::DpiDataLimit { size_download } => {
                write!(
                    f,
                    "DPI DATA LIMIT ({size_download}B downloaded, likely ~16KB cap)"
                )
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
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    if fwmark != 0 {
        socket.set_mark(fwmark)?;
    }

    socket.set_nonblocking(true)?;

    // socket2::Socket → OwnedFd → tokio::net::TcpSocket (safe conversion)
    let owned_fd: std::os::unix::io::OwnedFd = socket.into();
    let tokio_socket = tokio::net::TcpSocket::from_std_stream(std::net::TcpStream::from(owned_fd));

    tokio_socket.connect(addr).await
}

// ── TLS configuration ───────────────────────────────────────────────────────

pub fn make_tls_config(protocol: Protocol) -> Arc<ClientConfig> {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

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
                .with_root_certificates(rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                ))
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        Protocol::HttpsTls13 => {
            let versions = &[&rustls::version::TLS13];
            config = ClientConfig::builder_with_protocol_versions(versions)
                .with_root_certificates(rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                ))
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
    via: Option<&crate::network::via::Via>,
) -> HttpResult {
    let timeout = Duration::from_secs(timeout_secs);

    let reached = Reached::default();
    match tokio::time::timeout(
        timeout,
        http_test_inner(
            protocol,
            domain,
            ip,
            fwmark,
            ROOT_PATH,
            BodyMode::Head,
            via,
            None,
            &reached,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => HttpResult::timed_out(&reached),
    }
}

/// Perform an HTTP(S) data transfer test (GET with streaming download).
///
/// `path` — путь пробы. Корень годится там, где меряют сам сайт (`ROOT_PATH`); `check`
/// передаёт `--probe-path`, потому что от пути зависит СВЕРКА С ЭТАЛОНОМ, а не вердикт
/// о канале (спека §6-бис).
#[allow(clippy::too_many_arguments)] // путь пробы добавлен спекой §6-бис поверх уже широкого набора
pub async fn http_test_data(
    protocol: Protocol,
    domain: &str,
    ip: &str,
    fwmark: u32,
    timeout_secs: u64,
    mode: BodyMode,
    via: Option<&crate::network::via::Via>,
    path: &str,
) -> HttpResult {
    let timeout = Duration::from_secs(timeout_secs);

    let reached = Reached::default();
    match tokio::time::timeout(
        timeout,
        http_test_inner(
            protocol, domain, ip, fwmark, path, mode, via, None, &reached,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => HttpResult::timed_out(&reached),
    }
}

/// Perform an HTTP(S) GET that preserves the partial download size when the
/// transfer stalls (throttled or hard-capped by DPI) rather than discarding it
/// as a bare timeout. `stall_secs` bounds the wait between body chunks; connect
/// and handshake are bounded by `connect_timeout_secs`. Unlike `http_test_data`
/// (all-or-nothing), a capped transfer yields its partial byte count here, so a
/// caller can classify it as a DPI data limit. Baseline-only — strategy checks
/// keep the strict timeout. See #60.
pub async fn http_test_data_capturing(
    protocol: Protocol,
    domain: &str,
    ip: &str,
    fwmark: u32,
    connect_timeout_secs: u64,
    stall_secs: u64,
    limit: u64,
) -> HttpResult {
    // Outer bound protects against a hung connect/handshake; the body read
    // returns early via `stall`, so this rarely fires for a reachable host.
    let outer = Duration::from_secs(connect_timeout_secs + stall_secs + 1);
    let stall = Some(Duration::from_secs(stall_secs));

    let reached = Reached::default();
    match tokio::time::timeout(
        outer,
        http_test_inner(
            protocol,
            domain,
            ip,
            fwmark,
            ROOT_PATH,
            BodyMode::LimitedTo(limit),
            None,
            stall,
            &reached,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => HttpResult::timed_out(&reached),
    }
}

/// Inner implementation: connect, optional TLS, send HTTP request, parse response.
/// Follows one level of same-domain redirects (e.g. xnxx.com → www.xnxx.com).
#[allow(clippy::too_many_arguments)] // отметка фазы добавлена замером поверх уже широкого набора
async fn http_test_inner(
    protocol: Protocol,
    domain: &str,
    ip: &str,
    fwmark: u32,
    path: &str,
    mode: BodyMode,
    via: Option<&crate::network::via::Via>,
    stall: Option<Duration>,
    reached: &Reached,
) -> HttpResult {
    let result = http_single_request(
        protocol, domain, ip, fwmark, path, mode, via, stall, reached,
    )
    .await;

    // Follow one redirect if it points to the same domain — хостом И ПУТЁМ.
    if let Some(code) = result.status_code {
        if REDIRECT_CODES.contains(&code) {
            if let Some(location) = extract_location(&result.headers) {
                if let Some((host, target)) = redirect_target(&location, domain) {
                    return http_single_request(
                        protocol, &host, ip, fwmark, &target, mode, via, stall, reached,
                    )
                    .await;
                }
            }
        }
    }

    result
}

/// Perform a single HTTP(S) request without following redirects.
///
#[allow(clippy::too_many_arguments)] // отметка фазы добавлена замером поверх уже широкого набора
async fn http_single_request(
    protocol: Protocol,
    domain: &str,
    ip: &str,
    fwmark: u32,
    path: &str,
    mode: BodyMode,
    via: Option<&crate::network::via::Via>,
    stall: Option<Duration>,
    reached: &Reached,
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
                cause: None,
                ended: Ended::NeverStarted,
                windows: Vec::new(),
            };
        }
    };

    // TCP connect: via proxy tunnel or direct with SO_MARK
    let tcp_stream = match via.filter(|v| v.is_proxy()) {
        Some(v) => match v.tcp_connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                let cause = classify(&e, Phase::Connect);
                return HttpResult {
                    status_code: None,
                    headers: String::new(),
                    error: Some(format!("proxy connect: {e}")),
                    size_download: None,
                    cause: Some(cause),
                    ended: ended_before_body(cause),
                    windows: Vec::new(),
                };
            }
        },
        None => match marked_tcp_connect(addr, fwmark).await {
            Ok(s) => s,
            Err(e) => {
                let cause = classify(&e, Phase::Connect);
                return HttpResult {
                    status_code: None,
                    headers: String::new(),
                    error: Some(format!("connect: {e}")),
                    size_download: None,
                    cause: Some(cause),
                    ended: ended_before_body(cause),
                    windows: Vec::new(),
                };
            }
        },
    };

    // Соединение есть. Для простого HTTP следующая фаза — сразу запрос; для TLS
    // между ними стоит рукопожатие, и именно на нём цензор рвёт по имени.
    reached.mark(match protocol {
        Protocol::Http => Phase::Request,
        Protocol::HttpsTls12 | Protocol::HttpsTls13 => Phase::Tls,
    });

    // Step 2: Optionally wrap in TLS
    match protocol {
        Protocol::Http => {
            do_http_request(TokioIo::new(tcp_stream), domain, path, mode, stall, reached).await
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
                        cause: Some(Cause::Protocol(Phase::Tls)),
                        ended: Ended::NeverStarted,
                        windows: Vec::new(),
                    };
                }
            };

            let tls_stream = match connector.connect(server_name, tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    // Самый цензурно-значимый отказ (RST по SNI) — и он один уходил в
                    // гистограмму как `unknown`, а `Phase::Tls` не появлялась в замере
                    // никогда. Зовём `classify`, как все восемь соседних веток.
                    let cause = classify(&e, Phase::Tls);
                    return HttpResult {
                        status_code: None,
                        headers: String::new(),
                        error: Some(format!("tls: {e}")),
                        size_download: None,
                        cause: Some(cause),
                        ended: ended_before_body(cause),
                        windows: Vec::new(),
                    };
                }
            };

            // Рукопожатие состоялось — дальше молчание уже открытого разговора,
            // а не чёрная дыра.
            reached.mark(Phase::Request);
            do_http_request_https(TokioIo::new(tls_stream), domain, path, mode, stall, reached)
                .await
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

/// Куда ведёт редирект: хост И ПУТЬ. Прежде брался только хост, а путь снова просился
/// корневой — и `rutracker.org/` → `301` на `/forum/index.php` → снова `GET /` давал тот
/// же `301`: «ресурсом» меряли 529-байтовое тело редиректа вместо 96334-байтовой страницы.
///
/// `None` — идти некуда: чужой домен (блок-страница провайдера ловится именно так),
/// пустой или относительный без ведущей косой черты `Location`.
fn redirect_target(location: &str, domain: &str) -> Option<(String, String)> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    // Относительный `Location` — законная форма (RFC 9110 §10.2.2) и на самом же
    // `rutracker.org` встречается. Хост при нём прежний, значит и проверять нечего.
    if location.starts_with('/') {
        return Some((domain.to_string(), location.to_string()));
    }
    let host = extract_host_from_url(location)?;
    if !host.to_lowercase().contains(&domain.to_lowercase()) {
        return None;
    }
    let after_scheme = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"))?;
    let path = match after_scheme.find('/') {
        Some(at) => after_scheme[at..].to_string(),
        None => ROOT_PATH.to_string(),
    };
    Some((host, path))
}

/// Send HTTP/1.1 request over a plain TCP connection (HTTP).
/// Always uses GET for HTTP (need to see redirects/body).
async fn do_http_request<IO>(
    io: IO,
    domain: &str,
    path: &str,
    mode: BodyMode,
    stall: Option<Duration>,
    reached: &Reached,
) -> HttpResult
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = match http1::handshake(io).await {
        Ok(h) => h,
        Err(e) => {
            let cause = classify(&e, Phase::Request);
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("handshake: {e}")),
                size_download: None,
                cause: Some(cause),
                ended: ended_before_body(cause),
                windows: Vec::new(),
            };
        }
    };

    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Путь пришёл параметром и уже нормализован (`normalize_probe_path`): построение
    // URI может отказать только на пути, которого нормализация не выдаёт.
    let req = match Request::get(path)
        .header("Host", domain)
        .header("User-Agent", "Mozilla")
        .body(Empty::<Bytes>::new())
    {
        Ok(r) => r,
        Err(e) => {
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("bad probe path {path:?}: {e}")),
                size_download: None,
                cause: Some(Cause::Protocol(Phase::Request)),
                ended: Ended::NeverStarted,
                windows: Vec::new(),
            };
        }
    };

    send_and_parse(sender.send_request(req).await, mode, stall, reached).await
}

/// Send HTTP/1.1 request over a TLS connection (HTTPS).
/// Uses HEAD unless mode is GET (data transfer test).
async fn do_http_request_https<IO>(
    io: IO,
    domain: &str,
    path: &str,
    mode: BodyMode,
    stall: Option<Duration>,
    reached: &Reached,
) -> HttpResult
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = match http1::handshake(io).await {
        Ok(h) => h,
        Err(e) => {
            let cause = classify(&e, Phase::Request);
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("handshake: {e}")),
                size_download: None,
                cause: Some(cause),
                ended: ended_before_body(cause),
                windows: Vec::new(),
            };
        }
    };

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let method = if mode.is_get() { "GET" } else { "HEAD" };
    // Путь пришёл параметром и уже нормализован (`normalize_probe_path`): построение
    // URI может отказать только на пути, которого нормализация не выдаёт.
    let req = match Request::builder()
        .method(method)
        .uri(path)
        .header("Host", domain)
        .header("User-Agent", "Mozilla")
        .body(Empty::<Bytes>::new())
    {
        Ok(r) => r,
        Err(e) => {
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("bad probe path {path:?}: {e}")),
                size_download: None,
                cause: Some(Cause::Protocol(Phase::Request)),
                ended: Ended::NeverStarted,
                windows: Vec::new(),
            };
        }
    };

    send_and_parse(sender.send_request(req).await, mode, stall, reached).await
}

/// Parse hyper response into HttpResult.
///
async fn send_and_parse(
    result: Result<hyper::Response<hyper::body::Incoming>, hyper::Error>,
    mode: BodyMode,
    stall: Option<Duration>,
    reached: &Reached,
) -> HttpResult {
    let response = match result {
        Ok(r) => r,
        Err(e) => {
            let cause = classify(&e, Phase::Request);
            return HttpResult {
                status_code: None,
                headers: String::new(),
                error: Some(format!("request: {e}")),
                size_download: None,
                cause: Some(cause),
                ended: ended_before_body(cause),
                windows: Vec::new(),
            };
        }
    };

    // Заголовки на руках: всё, что случится дальше, случится на теле.
    reached.mark(Phase::Body);

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

    let mut body_cause: Option<Cause> = None;
    let mut ended = Ended::NeverStarted;
    // Материал для `Sag`; остаётся пустым, если тело не читали (не-GET).
    let mut windows: Vec<u64> = Vec::new();
    let size_download = if mode.is_get() {
        let limit = mode.max_bytes();
        let mut total: u64 = 0;
        let mut body = response.into_body();
        let body_started = std::time::Instant::now();
        loop {
            // With `stall` set, a body that hangs (throttled / capped by DPI)
            // stops the read and keeps the partial byte count, instead of
            // letting an outer timeout discard it. See #60.
            let next = match stall {
                Some(d) => match tokio::time::timeout(d, body.frame()).await {
                    Ok(chunk) => chunk,
                    // Сорвались по СВОЕМУ терпению — окно не досмотрено.
                    Err(_) => {
                        ended = Ended::WeStoppedWaiting;
                        break;
                    }
                },
                None => body.frame().await,
            };
            match next {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        // Окно ≥ секунды — требование прибора: короче пачки оно даёт
                        // нули между пачками и ложную просадку (`sag.rs`, ловушка 3).
                        let second = body_started.elapsed().as_secs() as usize;
                        if windows.len() <= second {
                            windows.resize(second + 1, 0);
                        }
                        windows[second] += data.len() as u64;
                        total += data.len() as u64;
                        if total >= limit {
                            ended = Ended::LimitReached;
                            break;
                        }
                    }
                }
                // Обрыв тела — та же улика, что и обрыв рукопожатия, и терять её
                // нельзя: цензор, режущий на данных, виден только здесь.
                Some(Err(e)) => {
                    body_cause = Some(classify(&e, Phase::Body));
                    ended = Ended::BodyError;
                    break;
                }
                None => {
                    ended = Ended::BodyComplete;
                    break;
                }
            }
        }
        // Хвостовая тишина — часть ряда, а не его отсутствие: см. `pad_windows`.
        pad_windows(&mut windows, body_started.elapsed().as_secs());
        Some(total)
    } else {
        None
    };

    HttpResult {
        status_code,
        headers,
        error: None,
        size_download,
        cause: body_cause,
        ended,
        windows,
    }
}

// ── Interpret functions (unchanged) ─────────────────────────────────────────

pub fn interpret_http_result(result: &HttpResult, domain: &str) -> HttpVerdict {
    if let Some(err) = &result.error {
        return HttpVerdict::Unavailable {
            reason: err.clone(),
            cause: result.cause,
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
                .map(|line| {
                    line.split_once(':')
                        .map(|x| x.1)
                        .unwrap_or("")
                        .trim()
                        .to_string()
                })
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
            match downloaded {
                n if n >= min_bytes => HttpVerdict::Available,
                n if DPI_LIMIT_RANGE.contains(&n) => HttpVerdict::DpiDataLimit { size_download: n },
                n => HttpVerdict::DataTransferFailed { size_download: n },
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
    // Mix thread id + timestamp for better distribution across concurrent workers
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize;
    let thread_id = std::thread::current().id();
    let hash = {
        use std::hash::{Hash, Hasher};
        let mut h = std::hash::DefaultHasher::new();
        thread_id.hash(&mut h);
        nanos.hash(&mut h);
        h.finish() as usize
    };
    Some(&ips[hash % ips.len()])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Реальный сокет, не выдумка: цепочку `io::Error` от tokio никакой макет не
    /// воспроизведёт, а сломаться она может именно в ней. Порт 80 на петле взят
    /// затем, что `Protocol::Http` берёт его сам; если на машине его кто-то
    /// занял, тест об этом честно скажет отказом, а не тихо позеленеет.
    #[tokio::test]
    async fn a_probe_into_a_closed_port_carries_a_refused_cause() {
        let result = http_test(Protocol::Http, "localhost", "127.0.0.1", 0, 2, None).await;
        assert_eq!(
            result.cause,
            Some(Cause::Refused),
            "проба обязана донести причину отказа наружу, а не только строку \
             (ошибка была: {:?})",
            result.error
        );
    }

    #[test]
    fn an_unavailable_verdict_carries_the_cause_that_produced_it() {
        let result = HttpResult {
            status_code: None,
            headers: String::new(),
            error: Some("tls: connection reset".to_string()),
            size_download: None,
            cause: Some(Cause::Reset(Phase::Tls)),
            ended: Ended::NeverStarted,
            windows: Vec::new(),
        };
        match interpret_http_result(&result, "example.com") {
            HttpVerdict::Unavailable { cause, .. } => assert_eq!(
                cause,
                Some(Cause::Reset(Phase::Tls)),
                "вердикт обязан донести причину до счётчика: без неё провал \
                 неотличим от любого другого и гистограмма не собирается"
            ),
            other => panic!("ожидался Unavailable, получен {other:?}"),
        }
    }

    #[test]
    fn a_definite_denial_before_the_body_is_an_answer_not_our_blindness() {
        // `Refused`, `Unreachable`, `Reset` — цель (или цензор за неё) высказалась.
        // Уезжая в `NeverStarted`, они давали `Delivery::Abandoned` и `Unobserved`:
        // `Observed::NoConnect` и `Fate::Dead` не производились никогда.
        assert_eq!(ended_before_body(Cause::Refused), Ended::Denied);
        assert_eq!(ended_before_body(Cause::Unreachable), Ended::Denied);
        assert_eq!(ended_before_body(Cause::Reset(Phase::Tls)), Ended::Denied);
    }

    #[test]
    fn an_indefinite_failure_before_the_body_stays_our_blindness() {
        // Тишина неотличима от потери пакета, а `Io`/`Protocol` мы не берёмся звать
        // определёнными: приговор за них выносить не за что.
        assert_eq!(
            ended_before_body(Cause::Timeout(Phase::Connect)),
            Ended::NeverStarted
        );
        assert_eq!(
            ended_before_body(Cause::Io(Phase::Tls)),
            Ended::NeverStarted
        );
        assert_eq!(
            ended_before_body(Cause::Protocol(Phase::Tls)),
            Ended::NeverStarted
        );
    }

    #[test]
    fn tail_silence_lands_in_the_series_instead_of_ending_it() {
        // Замерший навсегда поток (DPI-cap): два окна с байтами, дальше тишина до
        // пятой секунды. Без добивки ряд обрывался на приходе последнего кадра, и
        // `Sag` слеп ровно там, где он и нужен.
        let mut windows = vec![100_000, 100_000];
        pad_windows(&mut windows, 5);
        assert_eq!(windows, vec![100_000, 100_000, 0, 0, 0, 0]);
    }

    #[test]
    fn padding_never_shortens_a_series_it_already_covers() {
        // Кадр пришёл в ту же секунду, на которой чтение и кончилось: добивать нечего,
        // и отрезать уже посчитанное добивка не смеет.
        let mut windows = vec![1, 2, 3];
        pad_windows(&mut windows, 1);
        assert_eq!(windows, vec![1, 2, 3]);
    }

    #[test]
    fn an_expired_outer_timeout_is_a_timeout_on_the_phase_reached() {
        let reached = Reached::default();
        reached.mark(Phase::Tls);
        let result = HttpResult::timed_out(&reached);
        assert_eq!(
            result.cause,
            Some(Cause::Timeout(Phase::Tls)),
            "внешний таймаут обязан назвать фазу: таймаут на connect есть чёрная \
             дыра, таймаут после рукопожатия — тишина открытого разговора"
        );
    }

    #[test]
    fn test_interpret_available_200() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: None,
            cause: None,
            ended: Ended::NeverStarted,
            windows: Vec::new(),
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
            cause: None,
            ended: Ended::WeStoppedWaiting,
            windows: Vec::new(),
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
            cause: None,
            ended: Ended::NeverStarted,
            windows: Vec::new(),
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
            cause: None,
            ended: Ended::NeverStarted,
            windows: Vec::new(),
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
            cause: None,
            ended: Ended::NeverStarted,
            windows: Vec::new(),
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
            cause: None,
            ended: Ended::BodyComplete,
            windows: Vec::new(),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", DATA_TRANSFER_MIN_BYTES),
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
            cause: None,
            ended: Ended::BodyComplete,
            windows: Vec::new(),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", DATA_TRANSFER_MIN_BYTES),
            HttpVerdict::DataTransferFailed { size_download: 500 }
        ));
    }

    #[test]
    fn test_interpret_data_transfer_exact_threshold() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: Some(DATA_TRANSFER_MIN_BYTES),
            cause: None,
            ended: Ended::BodyComplete,
            windows: Vec::new(),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", DATA_TRANSFER_MIN_BYTES),
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
            cause: None,
            ended: Ended::NeverStarted,
            windows: Vec::new(),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", DATA_TRANSFER_MIN_BYTES),
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
            cause: None,
            ended: Ended::NeverStarted,
            windows: Vec::new(),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", DATA_TRANSFER_MIN_BYTES),
            HttpVerdict::Unavailable { .. }
        ));
    }

    #[test]
    fn test_interpret_data_transfer_dpi_limit() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: Some(16_384),
            cause: None,
            ended: Ended::BodyError,
            windows: Vec::new(),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result, "example.com", DATA_TRANSFER_MIN_BYTES),
            HttpVerdict::DpiDataLimit {
                size_download: 16_384
            }
        ));
    }

    #[test]
    fn test_interpret_data_transfer_dpi_limit_boundaries() {
        // 10240 — нижняя граница DPI range
        let result_low = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: Some(10_240),
            cause: None,
            ended: Ended::BodyError,
            windows: Vec::new(),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result_low, "example.com", DATA_TRANSFER_MIN_BYTES),
            HttpVerdict::DpiDataLimit {
                size_download: 10_240
            }
        ));

        // 26000 — выше DPI range, но ниже min_bytes → DataTransferFailed
        let result_above = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: Some(26_000),
            cause: None,
            ended: Ended::BodyComplete,
            windows: Vec::new(),
        };
        assert!(matches!(
            interpret_data_transfer_result(&result_above, "example.com", DATA_TRANSFER_MIN_BYTES),
            HttpVerdict::DataTransferFailed {
                size_download: 26_000
            }
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
    fn переход_по_редиректу_берёт_путь_а_не_только_хост() {
        // Замер на живой линии: `rutracker.org/` отдаёт `301` на `/forum/index.php`.
        // Прежний код брал из `Location` только ХОСТ и снова просил `/` — получал тот же
        // `301`, и 529-байтовое тело редиректа шло в сверку как «ресурс». Отсутствие
        // этого теста и есть причина, по которой баг дожил до живого замера.
        assert_eq!(
            redirect_target("https://rutracker.org/forum/index.php", "rutracker.org"),
            Some(("rutracker.org".to_string(), "/forum/index.php".to_string()))
        );
    }

    #[test]
    fn переход_по_редиректу_меняет_и_хост_и_путь() {
        assert_eq!(
            redirect_target("https://www.xnxx.com/some/page?a=1", "xnxx.com"),
            Some(("www.xnxx.com".to_string(), "/some/page?a=1".to_string()))
        );
    }

    #[test]
    fn редирект_без_пути_ведёт_в_корень() {
        assert_eq!(
            redirect_target("https://www.xnxx.com", "xnxx.com"),
            Some(("www.xnxx.com".to_string(), ROOT_PATH.to_string()))
        );
        assert_eq!(
            redirect_target("https://www.xnxx.com/", "xnxx.com"),
            Some(("www.xnxx.com".to_string(), "/".to_string()))
        );
    }

    #[test]
    fn относительный_редирект_сохраняет_хост_и_берёт_путь() {
        // `Location: /forum/index.php` — законная форма, и прежняя проверка
        // «`Location` содержит домен» отвергала её вовсе.
        assert_eq!(
            redirect_target("/forum/index.php", "rutracker.org"),
            Some(("rutracker.org".to_string(), "/forum/index.php".to_string()))
        );
    }

    #[test]
    fn редирект_на_чужой_домен_не_переход_а_улика() {
        // Блок-страница провайдера ловится именно так: идти туда незачем.
        assert_eq!(
            redirect_target("https://warning.rkn.gov.ru/blocked", "rutracker.org"),
            None
        );
        assert_eq!(redirect_target("", "rutracker.org"), None);
        assert_eq!(redirect_target("   ", "rutracker.org"), None);
    }

    #[test]
    fn путь_пробы_нормализуется_до_абсолютного() {
        assert_eq!(normalize_probe_path("/robots.txt"), "/robots.txt");
        assert_eq!(normalize_probe_path("robots.txt"), "/robots.txt");
        assert_eq!(normalize_probe_path(" /robots.txt "), "/robots.txt");
        // Пустой путь — корень: hyper отверг бы пустой URI уже ПОСЛЕ коннекта, и отказ
        // выглядел бы уликой против цензора.
        assert_eq!(normalize_probe_path(""), ROOT_PATH);
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
