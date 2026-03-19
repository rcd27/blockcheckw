use crate::error::BlockcheckError;
use crate::network::dns::is_ipv4;
use crate::system::process::run_process;

const DOH_TIMEOUT_MS: u64 = 6_000;

const DOH_SERVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
];

/// Resolve a domain to IPv4 addresses via DoH (DNS-over-HTTPS) JSON API.
pub async fn doh_resolve(domain: &str, server_url: &str) -> Option<Vec<String>> {
    let url = format!("{server_url}?name={domain}&type=A");
    let args = vec![
        "curl", "-4", "--noproxy", "*",
        "-s", "--max-time", "3",
        "-H", "Accept: application/dns-json",
        &url,
    ];

    let result = run_process(&args, DOH_TIMEOUT_MS).await.ok()?;
    if result.exit_code != 0 {
        return None;
    }

    Some(parse_doh_response(&result.stdout))
}

/// Parse DoH JSON response, extract IPv4 addresses from "data" fields.
fn parse_doh_response(json: &str) -> Vec<String> {
    let re = regex::Regex::new(r#""data"\s*:\s*"([^"]+)""#).unwrap();
    re.captures_iter(json)
        .filter_map(|cap| {
            let value = cap.get(1)?.as_str();
            if is_ipv4(value) {
                Some(value.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Try each DoH server with a test query (iana.org) and return the first working one.
pub async fn find_working_doh_server() -> Option<&'static str> {
    for &server in DOH_SERVERS {
        if let Some(ips) = doh_resolve("iana.org", server).await {
            if !ips.is_empty() {
                return Some(server);
            }
        }
    }
    None
}

/// Resolve domain via DoH. Finds a working server automatically, then resolves.
pub async fn resolve_ipv4_doh(domain: &str) -> Result<Vec<String>, BlockcheckError> {
    let server = find_working_doh_server().await.ok_or_else(|| {
        BlockcheckError::DnsResolveFailed {
            domain: domain.to_string(),
            reason: "no DoH servers reachable".to_string(),
        }
    })?;

    let ips = doh_resolve(domain, server).await.ok_or_else(|| {
        BlockcheckError::DnsResolveFailed {
            domain: domain.to_string(),
            reason: format!("DoH query to {server} failed"),
        }
    })?;

    if ips.is_empty() {
        return Err(BlockcheckError::DnsNoAddresses {
            domain: domain.to_string(),
        });
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_doh_response_cloudflare() {
        let json = r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"rutracker.org","type":1}],"Answer":[{"name":"rutracker.org","type":1,"TTL":300,"data":"172.67.182.217"},{"name":"rutracker.org","type":1,"TTL":300,"data":"104.21.32.39"}]}"#;
        let ips = parse_doh_response(json);
        assert_eq!(ips, vec!["172.67.182.217", "104.21.32.39"]);
    }

    #[test]
    fn test_parse_doh_response_cname() {
        // CNAME records have non-IP data, should be filtered out
        let json = r#"{"Answer":[{"name":"www.example.com","type":5,"TTL":300,"data":"example.com"},{"name":"example.com","type":1,"TTL":300,"data":"93.184.216.34"}]}"#;
        let ips = parse_doh_response(json);
        assert_eq!(ips, vec!["93.184.216.34"]);
    }

    #[test]
    fn test_parse_doh_response_empty() {
        let json = r#"{"Status":3,"Answer":[]}"#;
        let ips = parse_doh_response(json);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_parse_doh_response_no_answer() {
        let json = r#"{"Status":3}"#;
        let ips = parse_doh_response(json);
        assert!(ips.is_empty());
    }
}
