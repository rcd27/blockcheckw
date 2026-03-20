use crate::config::Protocol;
use crate::network::http_client::{
    http_test, interpret_http_result, pick_random_ip, HttpVerdict,
};
use crate::ui;

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

    // fwmark=0 — no marking for baseline (no bypass, no nftables rules)
    let result = http_test(protocol, domain, ip, 0, timeout_secs).await;
    let verdict = interpret_http_result(&result, domain);
    BaselineResult { protocol, verdict }
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
        HttpVerdict::Available => {
            ui::verdict_available(&proto, "available without bypass")
        }
        HttpVerdict::SuspiciousRedirect { code, location } => {
            ui::verdict_warning(&proto, &format!("suspicious redirect {code} to {location}"))
        }
        HttpVerdict::ServerReceivesFakes => {
            ui::verdict_warning(&proto, "server receives fakes (HTTP 400)")
        }
        HttpVerdict::Unavailable { reason } => {
            ui::verdict_blocked(&proto, &format!("UNAVAILABLE {reason}"))
        }
        HttpVerdict::DataTransferFailed { size_download } => {
            ui::verdict_warning(&proto, &format!("data transfer failed ({size_download}B downloaded)"))
        }
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
            HttpVerdict::Unavailable { reason: "timeout".to_string() },
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
            HttpVerdict::Unavailable { reason: "timeout".to_string() },
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
}
