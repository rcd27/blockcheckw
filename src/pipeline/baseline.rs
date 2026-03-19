use crate::config::Protocol;
use crate::network::curl::{curl_test, interpret_curl_result, pick_random_ip, CurlVerdict};
use crate::ui;

pub struct BaselineResult {
    pub protocol: Protocol,
    pub verdict: CurlVerdict,
}

impl BaselineResult {
    pub fn is_blocked(&self) -> bool {
        !matches!(self.verdict, CurlVerdict::Available)
    }
}

pub async fn test_baseline(domain: &str, protocol: Protocol, max_time: &str, ips: &[String]) -> BaselineResult {
    let ip = pick_random_ip(ips);
    let curl_result = curl_test(protocol, domain, None, max_time, ip).await;
    let verdict = interpret_curl_result(&curl_result, domain);
    BaselineResult { protocol, verdict }
}

pub fn format_baseline_verdict(result: &BaselineResult) -> String {
    if result.is_blocked() {
        format!("{}: BLOCKED ({})", result.protocol, result.verdict)
    } else {
        format!("{}: available without bypass", result.protocol)
    }
}

pub fn format_baseline_verdict_styled(result: &BaselineResult) -> String {
    let proto = result.protocol.to_string();
    match &result.verdict {
        CurlVerdict::Available => {
            ui::verdict_available(&proto, "available without bypass")
        }
        CurlVerdict::SuspiciousRedirect { code, location } => {
            ui::verdict_warning(&proto, &format!("suspicious redirect {code} to {location}"))
        }
        CurlVerdict::ServerReceivesFakes => {
            ui::verdict_warning(&proto, "server receives fakes (HTTP 400)")
        }
        CurlVerdict::Unavailable { curl_exit_code } => {
            ui::verdict_blocked(&proto, &format!("UNAVAILABLE code={curl_exit_code}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(protocol: Protocol, verdict: CurlVerdict) -> BaselineResult {
        BaselineResult { protocol, verdict }
    }

    #[test]
    fn test_is_blocked_unavailable() {
        let r = make_result(Protocol::Http, CurlVerdict::Unavailable { curl_exit_code: 28 });
        assert!(r.is_blocked());
    }

    #[test]
    fn test_is_blocked_available() {
        let r = make_result(Protocol::Http, CurlVerdict::Available);
        assert!(!r.is_blocked());
    }

    #[test]
    fn test_is_blocked_suspicious_redirect() {
        let r = make_result(
            Protocol::HttpsTls13,
            CurlVerdict::SuspiciousRedirect {
                code: 302,
                location: "https://warning.isp.ru".to_string(),
            },
        );
        assert!(r.is_blocked());
    }

    #[test]
    fn test_is_blocked_server_receives_fakes() {
        let r = make_result(Protocol::Http, CurlVerdict::ServerReceivesFakes);
        assert!(r.is_blocked());
    }

    #[test]
    fn test_format_verdict_blocked() {
        let r = make_result(Protocol::Http, CurlVerdict::Unavailable { curl_exit_code: 28 });
        let s = format_baseline_verdict(&r);
        assert!(s.contains("BLOCKED"));
        assert!(s.contains("HTTP"));
    }

    #[test]
    fn test_format_verdict_available() {
        let r = make_result(Protocol::HttpsTls13, CurlVerdict::Available);
        let s = format_baseline_verdict(&r);
        assert!(s.contains("available without bypass"));
        assert!(s.contains("HTTPS/TLS1.3"));
    }
}
