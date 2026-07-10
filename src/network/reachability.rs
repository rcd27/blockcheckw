//! IP-reachability probe shared by the `scan` and `status` block-type
//! classifiers. A completed TCP handshake (SYN-ACK) means the IP is reachable;
//! a dropped SYN means IP-blackhole — the distinction `scan` reports so a
//! consumer knows desync can't help below the handshake.

use std::time::Duration;

use crate::network::via::Via;

/// Direct TCP connect to `ip:443`. True iff the handshake completes.
pub async fn tcp_reachable(ip: &str, timeout_secs: u64) -> bool {
    let addr = format!("{ip}:443");
    let timeout = Duration::from_secs(timeout_secs);
    tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

/// IP-reachability honoring an optional gateway: through the proxy when `via`
/// is a proxy, directly otherwise. A proxy egress reaching an IP the direct
/// line can't is exactly the TSPU-blackhole-vs-dead signal.
pub async fn ip_reachable(ip: &str, timeout_secs: u64, via: Option<&Via>) -> bool {
    match via {
        Some(v) if v.is_proxy() => {
            let addr = match format!("{ip}:443").parse() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let timeout = Duration::from_secs(timeout_secs);
            tokio::time::timeout(timeout, v.tcp_connect(addr))
                .await
                .is_ok_and(|r| r.is_ok())
        }
        _ => tcp_reachable(ip, timeout_secs).await,
    }
}
