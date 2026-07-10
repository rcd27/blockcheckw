use crate::config::Protocol;
use crate::network::http_client::{
    http_test, http_test_data_capturing, interpret_data_transfer_result, interpret_http_result,
    pick_random_ip, HttpResult, HttpVerdict, DATA_TRANSFER_MIN_BYTES,
};
use crate::ui;

/// Seconds to wait for the next HTTPS body chunk before declaring the transfer
/// stalled. A DPI hard-cap plateaus (no further data), so a short wait catches
/// it while tolerating normal chunk gaps on a working connection.
const BASELINE_STALL_SECS: u64 = 2;

/// Judge a baseline (no-bypass) probe result.
///
/// For HTTPS, baseline uses the same yardstick as strategy success (check/verify/
/// worker): a domain is "available without bypass" only if it actually transfers
/// data, not merely completes a handshake. See #60 — a DPI that permits the TLS
/// handshake but resets during data transfer is invisible to a headers-only probe.
///
/// For plain HTTP the data yardstick does not apply: a legitimate redirect to
/// HTTPS carries no body, so blocking is judged by redirect target / status code
/// (interpret_http_result), matching how verify limits its data check to HTTPS.
fn interpret_baseline(result: &HttpResult, domain: &str, protocol: Protocol) -> HttpVerdict {
    match protocol {
        Protocol::HttpsTls12 | Protocol::HttpsTls13 => {
            interpret_data_transfer_result(result, domain, DATA_TRANSFER_MIN_BYTES)
        }
        Protocol::Http => interpret_http_result(result, domain),
    }
}

pub struct BaselineResult {
    pub protocol: Protocol,
    pub verdict: HttpVerdict,
}

impl BaselineResult {
    pub fn is_blocked(&self) -> bool {
        !matches!(self.verdict, HttpVerdict::Available)
    }
}

pub async fn test_baseline(
    domain: &str,
    protocol: Protocol,
    timeout_secs: u64,
    ips: &[String],
) -> BaselineResult {
    let ip = match pick_random_ip(ips) {
        Some(ip) => ip,
        None => {
            return BaselineResult {
                protocol,
                verdict: HttpVerdict::Unavailable {
                    reason: "no IPs available".to_string(),
                },
            };
        }
    };

    // fwmark=0 — no marking for baseline (no bypass, no nftables rules).
    //
    // HTTPS: GET, downloading up to the threshold. A DPI that caps data transfer
    // (while passing the handshake) registers as blocked, same as check/verify/
    // status. The capturing probe keeps the partial byte count when the transfer
    // stalls, so a hard cap surfaces as "DPI data limit" rather than a bare
    // timeout — while a genuinely-available page reaches the threshold and passes.
    //
    // HTTP: headers-only probe (redirect/status is what matters; a redirect to
    // HTTPS legitimately carries no body, so the data threshold does not apply).
    let result = match protocol {
        Protocol::HttpsTls12 | Protocol::HttpsTls13 => {
            http_test_data_capturing(
                protocol,
                domain,
                ip,
                0,
                timeout_secs,
                BASELINE_STALL_SECS,
                DATA_TRANSFER_MIN_BYTES,
            )
            .await
        }
        Protocol::Http => http_test(protocol, domain, ip, 0, timeout_secs, None).await,
    };
    let verdict = interpret_baseline(&result, domain, protocol);
    BaselineResult { protocol, verdict }
}

/// True when a data-transfer verdict carries the DPI throttle signature: the
/// download is cut in the ~16-19KB DPI-cap range ([`HttpVerdict::DpiDataLimit`]).
/// Deliberately NOT [`HttpVerdict::DataTransferFailed`] — that also fires on a
/// legitimately small page (a 1.2KB site downloads fully in <32KB), which is not
/// throttled. Sub-cap stalls are missed; the cap range is the canonical signal.
pub fn is_throttle_verdict(verdict: &HttpVerdict) -> bool {
    matches!(verdict, HttpVerdict::DpiDataLimit { .. })
}

pub fn format_baseline_verdict(result: &BaselineResult) -> String {
    match &result.verdict {
        HttpVerdict::Available => {
            format!("{}: available without bypass", result.protocol)
        }
        other => {
            format!("{}: BLOCKED ({other})", result.protocol)
        }
    }
}

pub fn format_baseline_verdict_styled(result: &BaselineResult) -> String {
    let proto = result.protocol.to_string();
    match &result.verdict {
        HttpVerdict::Available => ui::verdict_available(&proto, "available without bypass"),
        HttpVerdict::SuspiciousRedirect { code, location } => {
            ui::verdict_warning(&proto, &format!("suspicious redirect {code} to {location}"))
        }
        HttpVerdict::ServerReceivesFakes => {
            ui::verdict_warning(&proto, "server receives fakes (HTTP 400)")
        }
        HttpVerdict::Unavailable { reason } => {
            ui::verdict_blocked(&proto, &format!("UNAVAILABLE {reason}"))
        }
        HttpVerdict::DataTransferFailed { size_download } => ui::verdict_warning(
            &proto,
            &format!("data transfer failed ({size_download}B downloaded)"),
        ),
        HttpVerdict::DpiDataLimit { size_download } => ui::verdict_blocked(
            &proto,
            &format!("DPI data limit ({size_download}B downloaded, likely ~16KB cap)"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(protocol: Protocol, verdict: HttpVerdict) -> BaselineResult {
        BaselineResult { protocol, verdict }
    }

    #[test]
    fn test_is_blocked_unavailable() {
        let r = make_result(
            Protocol::Http,
            HttpVerdict::Unavailable {
                reason: "timeout".to_string(),
            },
        );
        assert!(r.is_blocked());
    }

    #[test]
    fn test_is_blocked_available() {
        let r = make_result(Protocol::Http, HttpVerdict::Available);
        assert!(!r.is_blocked());
    }

    #[test]
    fn test_is_blocked_suspicious_redirect() {
        let r = make_result(
            Protocol::HttpsTls13,
            HttpVerdict::SuspiciousRedirect {
                code: 302,
                location: "https://warning.isp.ru".to_string(),
            },
        );
        assert!(r.is_blocked());
    }

    #[test]
    fn test_is_blocked_server_receives_fakes() {
        let r = make_result(Protocol::Http, HttpVerdict::ServerReceivesFakes);
        assert!(r.is_blocked());
    }

    #[test]
    fn test_format_verdict_blocked() {
        let r = make_result(
            Protocol::Http,
            HttpVerdict::Unavailable {
                reason: "timeout".to_string(),
            },
        );
        let s = format_baseline_verdict(&r);
        assert!(s.contains("BLOCKED"));
        assert!(s.contains("HTTP"));
    }

    #[test]
    fn test_format_verdict_available() {
        let r = make_result(Protocol::HttpsTls13, HttpVerdict::Available);
        let s = format_baseline_verdict(&r);
        assert!(s.contains("available without bypass"));
        assert!(s.contains("HTTPS/TLS1.3"));
    }

    // ── #60: baseline must catch DPI that passes headers but caps data ──

    /// DPI lets the handshake + response headers through (200 OK) but resets
    /// during the body — only ~12KB arrives. A headers-only probe calls this
    /// "available"; baseline must call it blocked, like check/verify/status do.
    #[test]
    fn baseline_treats_capped_data_as_blocked() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: Some(12_000),
        };
        let verdict = interpret_baseline(&result, "www.cloudflare.com", Protocol::HttpsTls12);
        assert!(
            !matches!(verdict, HttpVerdict::Available),
            "capped-data response must not be judged Available, got {verdict:?}"
        );
    }

    /// A domain that transfers a full page (>= min bytes) is genuinely available.
    #[test]
    fn baseline_treats_full_download_as_available() {
        let result = HttpResult {
            status_code: Some(200),
            headers: "HTTP/1.1 200 OK\r\n".to_string(),
            error: None,
            size_download: Some(64_000),
        };
        let verdict = interpret_baseline(&result, "www.cloudflare.com", Protocol::HttpsTls12);
        assert!(
            matches!(verdict, HttpVerdict::Available),
            "full download must be judged Available, got {verdict:?}"
        );
    }

    /// Plain HTTP that redirects to HTTPS carries no body — it is available,
    /// not blocked. The data-transfer threshold must not apply to HTTP.
    #[test]
    fn baseline_http_redirect_stays_available() {
        let result = HttpResult {
            status_code: Some(301),
            headers: "HTTP/1.1 301 Moved Permanently\r\nlocation: https://www.cloudflare.com/\r\n"
                .to_string(),
            error: None,
            size_download: Some(0),
        };
        let verdict = interpret_baseline(&result, "www.cloudflare.com", Protocol::Http);
        assert!(
            matches!(verdict, HttpVerdict::Available),
            "HTTP redirect to HTTPS must stay Available, got {verdict:?}"
        );
    }

    // ── is_throttle_verdict: only the DPI-cap range counts as throttling ──

    #[test]
    fn throttle_verdict_true_for_dpi_data_limit() {
        assert!(is_throttle_verdict(&HttpVerdict::DpiDataLimit {
            size_download: 15_000
        }));
    }

    #[test]
    fn throttle_verdict_false_for_data_transfer_failed() {
        assert!(!is_throttle_verdict(&HttpVerdict::DataTransferFailed {
            size_download: 1_200
        }));
    }

    #[test]
    fn throttle_verdict_false_for_unavailable_and_available() {
        assert!(!is_throttle_verdict(&HttpVerdict::Unavailable {
            reason: "timeout".to_string()
        }));
        assert!(!is_throttle_verdict(&HttpVerdict::Available));
    }
}
