// Strategy loading from pre-generated files.
//
// Strategies are dumped from vanilla blockcheck2 scripts via:
//   bash tools/update_strategies.sh
//
// This produces strategies/{http,tls12,tls13}.txt — one strategy per line,
// each line is space-separated nfqws2 arguments.

use crate::config::Protocol;
use std::path::Path;

type Strategy = Vec<String>;

/// Strategy files baked into the binary at compile time.
const HTTP_STRATEGIES: &str = include_str!("../../strategies/http.txt");
const TLS12_STRATEGIES: &str = include_str!("../../strategies/tls12.txt");
const TLS13_STRATEGIES: &str = include_str!("../../strategies/tls13.txt");

/// Parse a strategy file: one strategy per line, each line split by whitespace.
fn parse_strategies(data: &str) -> Vec<Strategy> {
    data.lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_whitespace().map(String::from).collect())
        .collect()
}

/// Load all strategies for the given protocol.
pub fn generate_strategies(protocol: Protocol) -> Vec<Strategy> {
    match protocol {
        Protocol::Http => parse_strategies(HTTP_STRATEGIES),
        Protocol::HttpsTls12 => parse_strategies(TLS12_STRATEGIES),
        Protocol::HttpsTls13 => parse_strategies(TLS13_STRATEGIES),
    }
}

/// Load strategies from an external file.
/// Supports two formats:
/// 1. Plain: one strategy per line (`--payload=tls_client_hello --lua-desync=...`)
/// 2. Vanilla summary: `curl_test_https_tls12 ipv4 domain : nfqws2 <args>`
///
/// For vanilla format, filters by protocol.
pub fn load_strategies_from_file(path: &Path, protocol: Option<Protocol>) -> std::io::Result<Vec<Strategy>> {
    let data = std::fs::read_to_string(path)?;
    let is_vanilla = data.lines().any(|l| l.starts_with("* SUMMARY") || l.starts_with("curl_test_"));

    if is_vanilla {
        Ok(parse_vanilla_summary(&data, protocol))
    } else {
        Ok(parse_strategies(&data))
    }
}

/// Parse vanilla blockcheck2 summary format.
/// Each line: `curl_test_<proto> ipv4 <domain> : nfqws2 <args>`
fn parse_vanilla_summary(data: &str, protocol: Option<Protocol>) -> Vec<Strategy> {
    data.lines()
        .filter_map(|line| {
            if !line.starts_with("curl_test_") {
                return None;
            }
            // Check protocol filter
            if let Some(proto) = protocol {
                let prefix = match proto {
                    Protocol::Http => "curl_test_http ",
                    Protocol::HttpsTls12 => "curl_test_https_tls12 ",
                    Protocol::HttpsTls13 => "curl_test_https_tls13 ",
                };
                if !line.starts_with(prefix) {
                    return None;
                }
            }
            // Extract args after "nfqws2 "
            line.split_once(": nfqws2 ")
                .map(|(_, args)| args.split_whitespace().map(String::from).collect())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategies_load() {
        for protocol in [Protocol::Http, Protocol::HttpsTls12, Protocol::HttpsTls13] {
            let strategies = generate_strategies(protocol);
            assert!(!strategies.is_empty(), "no strategies for {protocol}");
            for (i, s) in strategies.iter().enumerate() {
                assert!(!s.is_empty(), "empty strategy at index {i} for {protocol}");
            }
        }
    }

    #[test]
    fn test_strategy_counts() {
        let http = generate_strategies(Protocol::Http).len();
        let tls12 = generate_strategies(Protocol::HttpsTls12).len();
        let tls13 = generate_strategies(Protocol::HttpsTls13).len();

        eprintln!("Strategy counts: HTTP={http}, TLS1.2={tls12}, TLS1.3={tls13}");

        assert!(http > 100, "HTTP too few: {http}");
        assert!(tls12 > 1000, "TLS1.2 too few: {tls12}");
        assert!(tls13 > 1000, "TLS1.3 too few: {tls13}");
    }

    #[test]
    fn test_no_duplicates() {
        for protocol in [Protocol::Http, Protocol::HttpsTls12, Protocol::HttpsTls13] {
            let strategies = generate_strategies(protocol);
            let mut seen = std::collections::HashSet::new();
            let mut dupes = 0;
            for s in &strategies {
                if !seen.insert(s.clone()) {
                    dupes += 1;
                }
            }
            assert_eq!(dupes, 0, "{protocol} has {dupes} duplicate strategies");
        }
    }

    /// Verify known-working vanilla strategies are present.
    #[test]
    fn test_vanilla_working_strategies_present() {
        let tls12 = generate_strategies(Protocol::HttpsTls12);
        let tls12_set: std::collections::HashSet<Vec<String>> =
            tls12.into_iter().collect();

        let parse = |s: &str| -> Strategy {
            s.split_whitespace().map(String::from).collect()
        };

        // 25-fake: multisplit:blob nodrop with TTL=1 (first TTL in vanilla loop)
        let s = parse("--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:ip_ttl=1:pos=2:nodrop:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "missing: multisplit:blob nodrop TTL+pktmod");

        // 25-fake: double fake
        let s = parse("--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_seq=-3000:repeats=1 --lua-desync=fake:blob=fake_default_tls:tcp_seq=-3000:tls_mod=rnd,dupsid:repeats=1");
        assert!(tls12_set.contains(&s), "missing: double fake tcp_seq");

        // 30-faked: fakedsplit with TTL=1
        let s = parse("--payload=tls_client_hello --lua-desync=fakedsplit:pos=sniext+4:ip_ttl=1:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "missing: fakedsplit TTL+pktmod");

        // 35-hostfake: hostfakesplit with tcp_md5
        let s = parse("--payload=tls_client_hello --lua-desync=hostfakesplit:tcp_md5:repeats=1");
        assert!(tls12_set.contains(&s), "missing: hostfakesplit tcp_md5");
    }
}
