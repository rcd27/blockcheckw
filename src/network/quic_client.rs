//! QUIC-проба: настоящий GET по HTTP/3, а не «ушёл ли Initial».
//!
//! Зачем своя проба, а не TCP с другим портом: человек, у которого режут QUIC, страдает
//! на UDP, и цензор режет его по другим признакам (Initial с SNI расшифровывается
//! каждым, кто видит Destination Connection ID). Страта, пробившая TLS на TCP, о QUIC не
//! говорит ничего — подбор обязан идти тем транспортом, на котором болит.
//!
//! Смысл вердикта тот же, что у TCP-пробы: [`HttpResult`], [`Ended`], порог байт тела и
//! терпение [`crate::network::patience`]. Различаются только фазы (`Initial` →
//! `Handshake` вместо `Connect` → `Tls`) и то, откуда берётся определённый отказ: у UDP
//! нет RST, и ответом цели служит ICMP unreachable, который ядро отдаёт только
//! подключённому сокету — отсюда `connect()` на UDP и свидетель ошибок сокета.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use futures_util::stream::{self, StreamExt};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ConnectionError, TokioRuntime, UdpPoller};
use tokio::sync::Notify;

use crate::config::Protocol;
use crate::network::cause::{classify, Cause, Phase, Reached};
use crate::network::http_client::{make_tls_config, BodyMode, Ended, HttpResult};

type Bidi = h3_quinn::BidiStream<Bytes>;
type RequestStream = h3::client::RequestStream<Bidi, Bytes>;
type SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type Driver = h3::client::Connection<h3_quinn::Connection, Bytes>;

/// Результат, до тела не дошедший. Один конструктор на все ранние выходы: строка ошибки
/// и причина — всё, чем они различаются.
fn failed(error: String, cause: Option<Cause>, ended: Ended) -> HttpResult {
    HttpResult {
        status_code: None,
        headers: String::new(),
        error: Some(error),
        size_download: None,
        cause,
        ended,
        windows: Vec::new(),
    }
}

/// Провал с причиной: `ended` выводится из неё так же, как у TCP-пробы.
fn failed_by(error: String, cause: Cause) -> HttpResult {
    failed(error, Some(cause), ended_before_body(cause))
}

/// Тот же разбор, что `http_client::ended_before_body`: определённый отказ — ответ цели,
/// неопределённый — наша слепота.
fn ended_before_body(cause: Cause) -> Ended {
    match cause {
        Cause::Refused | Cause::Unreachable | Cause::Reset(_) => Ended::Denied,
        Cause::Idle(_) | Cause::Ceiling(_) | Cause::Io(_) | Cause::Protocol(_) => {
            Ended::NeverStarted
        }
    }
}

/// Причина по отказу соединения QUIC. Разбор тотален, и каждая ветка отвечает на вопрос
/// «кто высказался»: `TimedOut` — тишина (quinn сам сдался ждать), `Reset` — stateless
/// reset, аналог RST; закрытие сервером и ошибки протокола — провод жив, не сошлось выше.
fn cause_of_connection(err: &ConnectionError, phase: Phase) -> Cause {
    match err {
        ConnectionError::TimedOut => Cause::Idle(phase),
        ConnectionError::Reset => Cause::Reset(phase),
        ConnectionError::VersionMismatch
        | ConnectionError::TransportError(_)
        | ConnectionError::ConnectionClosed(_)
        | ConnectionError::ApplicationClosed(_) => Cause::Protocol(phase),
        ConnectionError::LocallyClosed | ConnectionError::CidsExhausted => Cause::Io(phase),
    }
}

// ── Свидетель ошибок сокета ─────────────────────────────────────────────────────────
//
// quinn глотает ошибки сокета: `quinn-udp` логирует ошибку отправки и отвечает `Ok`, а
// приём на ошибке молча повторяется. ICMP port unreachable превращался бы в тишину — и
// ответ цели читался бы как чёрная дыра. Потому сокет свой: те же вызовы `quinn-udp`, что
// у `quinn::TokioRuntime`, но отправка без глотания ошибок, и отдельный сторож готовности
// `ERROR` — ядро будит по ICMP только его, приёму он не виден.

/// UDP-сокет quinn со свидетелем определённых отказов.
#[derive(Debug)]
struct Witnessed {
    io: tokio::net::UdpSocket,
    state: quinn::udp::UdpSocketState,
    /// Номер ошибки ядра первого определённого отказа, 0 — отказа не было.
    errno: AtomicI32,
    notify: Notify,
}

/// Определённый ли это отказ: ответ цели (или цензора за неё), а не наша беда вроде
/// `EMSGSIZE` на пробе MTU.
fn definite(err: &io::Error) -> bool {
    matches!(
        classify(err, Phase::Initial),
        Cause::Refused | Cause::Unreachable
    )
}

impl Witnessed {
    fn over(socket: std::net::UdpSocket) -> io::Result<Witnessed> {
        Ok(Witnessed {
            state: quinn::udp::UdpSocketState::new((&socket).into())?,
            io: tokio::net::UdpSocket::from_std(socket)?,
            errno: AtomicI32::new(0),
            notify: Notify::new(),
        })
    }

    /// Запомнить ошибку, если она определённый отказ.
    fn witness(&self, err: &io::Error) {
        if let (true, Some(errno)) = (definite(err), err.raw_os_error()) {
            if self
                .errno
                .compare_exchange(0, errno, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                // `notify_one` хранит разрешение: отказ, случившийся раньше, чем проба
                // начала ждать, не теряется.
                self.notify.notify_one();
            }
        }
    }

    /// Первый определённый отказ — увиденный ли отправкой, приёмом или сторожем `ERROR`.
    async fn denied(&self) -> io::Error {
        tokio::select! {
            () = self.notify.notified() => {
                io::Error::from_raw_os_error(self.errno.load(Ordering::Relaxed))
            }
            pending = self.pending_error() => pending,
        }
    }

    /// Ошибка, которую ядро держит на сокете (`SO_ERROR`). Не определённую — забираем и
    /// ждём дальше: `async_io` на `WouldBlock` снимает готовность и спит до следующей.
    async fn pending_error(&self) -> io::Error {
        self.io
            .async_io(tokio::io::Interest::ERROR, || match self.io.take_error() {
                Ok(Some(err)) if definite(&err) => Ok(err),
                Ok(Some(_indefinite)) => Err(io::ErrorKind::WouldBlock.into()),
                Ok(None) => Err(io::ErrorKind::WouldBlock.into()),
                Err(getsockopt) => Ok(getsockopt),
            })
            .await
            .unwrap_or_else(|watch| watch)
    }
}

/// Готовность к записи для quinn — та же, что у `TokioRuntime`.
#[derive(Debug)]
struct Writable(Arc<Witnessed>);

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for Witnessed {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable(self))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Разбор ошибок — как у `UdpSocketState::send`, но отказ сперва засвидетельствован:
        // подключённый UDP отдаёт ICMP-ошибку на следующей отправке.
        match self.io.try_io(tokio::io::Interest::WRITABLE, || {
            self.state.try_send((&self.io).into(), transmit)
        }) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => {
                self.witness(&e);
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.io.poll_recv_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            match self.io.try_io(tokio::io::Interest::READABLE, || {
                self.state.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(received) => return Poll::Ready(Ok(received)),
                // Как у `TokioRuntime`: ошибка приёма не рвёт эндпоинт, но свидетель её
                // видит.
                Err(e) => self.witness(&e),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }
}

/// UDP-сокет с `SO_MARK` до первой датаграммы и подключённый к цели. Марка ставится до
/// отправки по той же причине, что у TCP до SYN: правило nft узнаёт профиль по ней, и
/// Initial без марки ушёл бы мимо движка. `connect()` — ради ICMP: неподключённому
/// сокету ядро ошибку не отдаёт вовсе.
fn marked_udp_socket(addr: SocketAddr, fwmark: u32) -> io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    match fwmark {
        // Эталон и контроль: мимо диспетчеризации, марку не ставим вовсе.
        0 => Ok(()),
        mark => socket.set_mark(mark),
    }?;
    socket.connect(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Эндпоинт на отмеченном сокете со свидетелем отказов.
fn endpoint_at(addr: SocketAddr, fwmark: u32) -> io::Result<(quinn::Endpoint, Arc<Witnessed>)> {
    let socket = Arc::new(Witnessed::over(marked_udp_socket(addr, fwmark)?)?);
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket.clone(),
        Arc::new(TokioRuntime),
    )
    .map(|endpoint| (endpoint, socket))
}

fn client_config() -> Result<quinn::ClientConfig, String> {
    quinn::crypto::rustls::QuicClientConfig::try_from(make_tls_config(Protocol::Quic))
        .map(|crypto| quinn::ClientConfig::new(Arc::new(crypto)))
        .map_err(|e| format!("quic tls config: {e}"))
}

/// Один запрос HTTP/3 без редиректов — QUIC-двойник `http_single_request`.
#[allow(clippy::too_many_arguments)] // тот же набор, что у TCP-двойника
pub async fn quic_single_request(
    domain: &str,
    ip: &str,
    fwmark: u32,
    path: &str,
    mode: BodyMode,
    via: Option<&crate::network::via::Via>,
    stall: Option<Duration>,
    reached: &Reached,
) -> HttpResult {
    let port = Protocol::Quic.port();
    match (
        format!("{ip}:{port}").parse::<SocketAddr>(),
        via.filter(|v| v.is_proxy()),
    ) {
        (Err(e), _) => failed(format!("invalid address: {e}"), None, Ended::NeverStarted),
        // Прокси `Via` — туннель поверх TCP: датаграмму через него не провести, и
        // «эталон через прокси» для QUIC был бы эталоном другого транспорта.
        (Ok(_), Some(_)) => failed(
            "via proxy: QUIC cannot go through a TCP proxy tunnel".to_string(),
            None,
            Ended::NeverStarted,
        ),
        (Ok(addr), None) => exchange_at(addr, domain, fwmark, path, mode, stall, reached).await,
    }
}

/// Разговор с целью по адресу. Отдельно от разбора адреса затем, что тестам нужен порт,
/// отличный от 443.
#[allow(clippy::too_many_arguments)]
async fn exchange_at(
    addr: SocketAddr,
    domain: &str,
    fwmark: u32,
    path: &str,
    mode: BodyMode,
    stall: Option<Duration>,
    reached: &Reached,
) -> HttpResult {
    // Initial уходит сразу за созданием соединения: с этой отметки тишина — тишина на
    // первом пакете.
    reached.mark(Phase::Initial);
    let (endpoint, socket, config) = match (endpoint_at(addr, fwmark), client_config()) {
        (Err(e), _) => return failed_by(format!("udp socket: {e}"), classify(&e, Phase::Initial)),
        (Ok(_), Err(e)) => {
            return failed(
                e,
                Some(Cause::Protocol(Phase::Initial)),
                Ended::NeverStarted,
            )
        }
        (Ok((endpoint, socket)), Ok(config)) => (endpoint, socket, config),
    };
    tokio::select! {
        biased;
        result = converse(&endpoint, config, addr, domain, path, mode, stall, reached) => result,
        err = socket.denied() => {
            let cause = classify(&err, reached.phase());
            failed_by(format!("udp: {err}"), cause)
        }
    }
}

/// Рукопожатие, запрос, ответ, тело.
#[allow(clippy::too_many_arguments)]
async fn converse(
    endpoint: &quinn::Endpoint,
    config: quinn::ClientConfig,
    addr: SocketAddr,
    domain: &str,
    path: &str,
    mode: BodyMode,
    stall: Option<Duration>,
    reached: &Reached,
) -> HttpResult {
    let connecting = match endpoint.connect_with(config, addr, domain) {
        Ok(c) => c,
        Err(e) => {
            return failed(
                format!("quic connect: {e}"),
                Some(Cause::Protocol(Phase::Initial)),
                Ended::NeverStarted,
            )
        }
    };
    let connection = match handshaken(connecting, reached).await {
        Ok(c) => c,
        Err(e) => {
            return failed_by(
                format!("quic: {e}"),
                cause_of_connection(&e, reached.phase()),
            )
        }
    };
    // Рукопожатие состоялось — дальше молчание уже открытого разговора.
    reached.mark(Phase::Request);

    let (driver, send_request) =
        match h3::client::new(h3_quinn::Connection::new(connection.clone())).await {
            Ok(pair) => pair,
            Err(e) => return failed_by(format!("h3: {e}"), cause_after_h3(&connection, reached)),
        };

    // Драйвер соединения h3 обязан крутиться рядом с запросом: он читает управляющий
    // поток. Кончился раньше запроса — разговор оборван.
    tokio::select! {
        result = request(send_request, &connection, domain, path, mode, stall, reached) => result,
        closed = drive(driver) => failed_by(format!("h3 connection: {closed}"), cause_after_h3(&connection, reached)),
    }
}

/// Причина провала на уровне h3: у ошибок h3 истинная причина не в `source()`, а в
/// самом соединении QUIC — оно знает, почему закрылось. Не закрылось — не сошлось выше.
fn cause_after_h3(connection: &quinn::Connection, reached: &Reached) -> Cause {
    let phase = reached.phase();
    connection
        .close_reason()
        .map(|e| cause_of_connection(&e, phase))
        .unwrap_or(Cause::Protocol(phase))
}

async fn drive(mut driver: Driver) -> h3::error::ConnectionError {
    driver.wait_idle().await
}

/// Дождаться ответа сервера на Initial (`Handshake`), затем конца рукопожатия.
async fn handshaken(
    mut connecting: quinn::Connecting,
    reached: &Reached,
) -> Result<quinn::Connection, ConnectionError> {
    // Данные рукопожатия (ALPN) есть только после Handshake-пакетов сервера: с этого
    // момента цель нас слышит.
    connecting.handshake_data().await?;
    reached.mark(Phase::Handshake);
    connecting.await
}

#[allow(clippy::too_many_arguments)]
async fn request(
    mut send_request: SendRequest,
    connection: &quinn::Connection,
    domain: &str,
    path: &str,
    mode: BodyMode,
    stall: Option<Duration>,
    reached: &Reached,
) -> HttpResult {
    let method = match mode {
        BodyMode::Head => http::Method::HEAD,
        BodyMode::Unlimited | BodyMode::LimitedTo(_) => http::Method::GET,
    };
    let req = match http::Request::builder()
        .method(method)
        .uri(format!("https://{domain}{path}"))
        .header("user-agent", "Mozilla")
        .body(())
    {
        Ok(r) => r,
        Err(e) => {
            return failed(
                format!("bad probe path {path:?}: {e}"),
                Some(Cause::Protocol(Phase::Request)),
                Ended::NeverStarted,
            )
        }
    };
    match send_request.send_request(req).await {
        Ok(stream) => respond(stream, connection, mode, stall, reached).await,
        Err(e) => failed_by(format!("request: {e}"), cause_after_h3(connection, reached)),
    }
}

async fn respond(
    mut stream: RequestStream,
    connection: &quinn::Connection,
    mode: BodyMode,
    stall: Option<Duration>,
    reached: &Reached,
) -> HttpResult {
    let response = match stream.finish().await {
        Ok(()) => stream.recv_response().await,
        Err(e) => Err(e),
    };
    let response = match response {
        Ok(r) => r,
        Err(e) => return failed_by(format!("request: {e}"), cause_after_h3(connection, reached)),
    };
    // Заголовки на руках: всё, что случится дальше, случится на теле.
    reached.mark(Phase::Body);

    let status = response.status();
    let headers = std::iter::once(format!(
        "HTTP/3 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    ))
    .chain(
        response
            .headers()
            .iter()
            .map(|(key, value)| format!("{}: {}\r\n", key, value.to_str().unwrap_or("<binary>"))),
    )
    .collect::<String>();

    let tally = match mode {
        BodyMode::Head => None,
        BodyMode::Unlimited | BodyMode::LimitedTo(_) => {
            Some(read_body(stream, connection, mode.max_bytes(), stall, reached).await)
        }
    };
    match tally {
        None => HttpResult {
            status_code: Some(status.as_u16()),
            headers,
            error: None,
            size_download: None,
            cause: None,
            ended: Ended::NeverStarted,
            windows: Vec::new(),
        },
        Some(tally) => HttpResult {
            status_code: Some(status.as_u16()),
            headers,
            error: None,
            size_download: Some(tally.total),
            cause: tally.cause,
            ended: tally.ended,
            windows: tally.windows,
        },
    }
}

/// Кусок чтения тела: байты в своей секунде или конец.
enum Piece {
    Bytes { len: u64, second: usize },
    End { ended: Ended, cause: Option<Cause> },
}

/// Итог чтения тела.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tally {
    total: u64,
    windows: Vec<u64>,
    ended: Ended,
    cause: Option<Cause>,
}

impl Tally {
    fn opened() -> Tally {
        Tally {
            total: 0,
            windows: Vec::new(),
            ended: Ended::NeverStarted,
            cause: None,
        }
    }

    fn with(self, piece: Piece) -> Tally {
        match piece {
            Piece::Bytes { len, second } => Tally {
                total: self.total + len,
                windows: (0..self.windows.len().max(second + 1))
                    .map(|i| {
                        self.windows.get(i).copied().unwrap_or(0)
                            + match i == second {
                                true => len,
                                false => 0,
                            }
                    })
                    .collect(),
                ..self
            },
            Piece::End { ended, cause } => Tally {
                ended,
                cause,
                ..self
            },
        }
    }
}

/// Добить ряд окон нулями до длительности чтения — тот же закон, что
/// `http_client::pad_windows`: хвостовая тишина — часть ряда, а не его отсутствие.
fn padded(windows: Vec<u64>, seconds: u64) -> Vec<u64> {
    let needed = windows.len().max(seconds as usize + 1);
    (0..needed)
        .map(|i| windows.get(i).copied().unwrap_or(0))
        .collect()
}

/// Читать тело до своего лимита, конца потока, обрыва или `stall`.
async fn read_body(
    stream: RequestStream,
    connection: &quinn::Connection,
    limit: u64,
    stall: Option<Duration>,
    reached: &Reached,
) -> Tally {
    let started = Instant::now();
    let tally = stream::unfold(Some((stream, 0u64)), |state| async move {
        match state {
            None => None,
            Some((stream, total)) => {
                Some(next_piece(stream, total, connection, limit, stall, started, reached).await)
            }
        }
    })
    .fold(
        Tally::opened(),
        |tally, piece| async move { tally.with(piece) },
    )
    .await;
    Tally {
        windows: padded(tally.windows.clone(), started.elapsed().as_secs()),
        ..tally
    }
}

type Rest = Option<(RequestStream, u64)>;

#[allow(clippy::too_many_arguments)]
async fn next_piece(
    mut stream: RequestStream,
    total: u64,
    connection: &quinn::Connection,
    limit: u64,
    stall: Option<Duration>,
    started: Instant,
    reached: &Reached,
) -> (Piece, Rest) {
    let end = |ended, cause| (Piece::End { ended, cause }, None);
    if total >= limit {
        return end(Ended::LimitReached, None);
    }
    let next = match stall {
        // Сорвались по СВОЕМУ терпению — окно не досмотрено.
        Some(d) => match tokio::time::timeout(d, stream.recv_data()).await {
            Ok(chunk) => chunk.map(|c| c.map(|b| b.remaining() as u64)),
            Err(_) => return end(Ended::WeStoppedWaiting, None),
        },
        None => stream
            .recv_data()
            .await
            .map(|c| c.map(|b| b.remaining() as u64)),
    };
    match next {
        Ok(Some(len)) => {
            // Байты цели — шаг: сторож отодвигает тишину.
            reached.stride();
            let second = started.elapsed().as_secs() as usize;
            (Piece::Bytes { len, second }, Some((stream, total + len)))
        }
        Ok(None) => end(Ended::BodyComplete, None),
        // Обрыв тела — улика цензора, режущего на данных.
        Err(_) => end(Ended::BodyError, Some(cause_after_h3(connection, reached))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::patience::{self, Patience};

    /// Проба под сторожем — как `http_probe`, но на произвольный адрес.
    async fn probe_at(addr: SocketAddr, patience: Patience) -> HttpResult {
        let reached = Reached::default();
        tokio::select! {
            biased;
            result = exchange_at(addr, "localhost", 0, "/", BodyMode::LimitedTo(1024), None, &reached) => result,
            expiry = patience::expired(patience, &reached) => HttpResult::expired(&reached, expiry),
        }
    }

    /// Порт, на котором гарантированно никто не слушает: заняли и отпустили.
    fn a_closed_udp_port() -> SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .unwrap_or_else(|e| panic!("не удалось занять порт на петле: {e}"))
    }

    #[tokio::test]
    async fn a_quic_probe_into_a_closed_udp_port_carries_a_refused_cause() {
        // ICMP port unreachable — ответ цели, а не тишина. Без свидетеля сокета quinn
        // глотал его, и проба ждала до срока.
        let started = Instant::now();
        let result = probe_at(
            a_closed_udp_port(),
            Patience::new(Duration::from_secs(3), Duration::from_secs(5)),
        )
        .await;
        assert_eq!(
            result.cause,
            Some(Cause::Refused),
            "ошибка была: {:?}",
            result.error
        );
        assert_eq!(result.ended, Ended::Denied);
        assert!(
            started.elapsed() < Duration::from_millis(800),
            "отказ обязан прийти ответом, а не сроком: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn silence_after_the_initial_is_idle_on_initial() {
        // Слушатель есть, но молчит — ровно так выглядит QUIC, проглоченный цензором.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap_or_else(|e| panic!("не удалось занять порт на петле: {e}"));
        let addr = silent
            .local_addr()
            .unwrap_or_else(|e| panic!("адрес слушателя: {e}"));
        let result = probe_at(
            addr,
            Patience::new(Duration::from_millis(400), Duration::from_secs(5)),
        )
        .await;
        assert_eq!(result.cause, Some(Cause::Idle(Phase::Initial)));
        assert_eq!(result.ended, Ended::WeStoppedWaiting);
        drop(silent);
    }

    #[test]
    fn bytes_land_in_their_second_and_the_end_keeps_the_count() {
        let tally = [
            Piece::Bytes { len: 10, second: 0 },
            Piece::Bytes { len: 5, second: 2 },
            Piece::Bytes { len: 1, second: 2 },
            Piece::End {
                ended: Ended::BodyComplete,
                cause: None,
            },
        ]
        .into_iter()
        .fold(Tally::opened(), Tally::with);
        assert_eq!(tally.total, 16);
        assert_eq!(tally.windows, vec![10, 0, 6]);
        assert_eq!(tally.ended, Ended::BodyComplete);
    }

    #[test]
    fn tail_silence_is_padded_and_never_cut() {
        assert_eq!(padded(vec![7, 7], 4), vec![7, 7, 0, 0, 0]);
        assert_eq!(padded(vec![1, 2, 3], 1), vec![1, 2, 3]);
    }

    #[test]
    fn quinn_timeout_is_silence_and_stateless_reset_is_a_reset() {
        assert_eq!(
            cause_of_connection(&ConnectionError::TimedOut, Phase::Handshake),
            Cause::Idle(Phase::Handshake)
        );
        assert_eq!(
            cause_of_connection(&ConnectionError::Reset, Phase::Request),
            Cause::Reset(Phase::Request)
        );
    }
}
