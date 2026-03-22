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

/// A strategy paired with its protocol and optional metadata.
#[derive(Debug, Clone)]
pub struct TaggedStrategy {
    pub protocol: Protocol,
    pub args: Vec<String>,
    /// Domain coverage: 1 for scan/vanilla, N for universal.
    pub coverage: usize,
}

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
pub fn load_strategies_from_file(
    path: &Path,
    protocol: Option<Protocol>,
) -> std::io::Result<Vec<Strategy>> {
    let data = std::fs::read_to_string(path)?;
    let is_vanilla = data
        .lines()
        .any(|l| l.starts_with("* SUMMARY") || l.starts_with("curl_test_"));

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

/// Load strategies from a file. Auto-detects format:
/// - JSON with `strategies` field → parse as scan/universal report
/// - Text with `curl_test_*` lines → parse as vanilla blockcheck2 report
pub fn load_tagged_strategies(path: &Path) -> std::io::Result<Vec<TaggedStrategy>> {
    let data = std::fs::read_to_string(path)?;

    // Try JSON first
    if data.trim_start().starts_with('{') {
        if let Ok(strategies) = parse_json_strategies(&data) {
            if !strategies.is_empty() {
                return Ok(strategies);
            }
        }
    }

    // Fall back to vanilla format
    let strategies = parse_vanilla_tagged(&data);
    if strategies.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no strategies found (expected JSON with 'strategies' field or vanilla curl_test_* lines)",
        ));
    }
    Ok(strategies)
}

/// Parse JSON report containing flat `strategies` array with `{protocol, args}` entries.
fn parse_json_strategies(data: &str) -> Result<Vec<TaggedStrategy>, String> {
    use crate::pipeline::scan_report::StrategyEntry;

    #[derive(serde::Deserialize)]
    struct Report {
        strategies: Vec<StrategyEntry>,
    }

    let report: Report = serde_json::from_str(data).map_err(|e| e.to_string())?;

    let tagged = report
        .strategies
        .into_iter()
        .filter_map(|entry| {
            let protocol = match entry.protocol.as_str() {
                "HTTP" => Protocol::Http,
                "HTTPS/TLS1.2" => Protocol::HttpsTls12,
                "HTTPS/TLS1.3" => Protocol::HttpsTls13,
                _ => return None,
            };
            Some(TaggedStrategy {
                protocol,
                args: entry.args.split_whitespace().map(String::from).collect(),
                coverage: entry.coverage,
            })
        })
        .collect();

    Ok(tagged)
}

/// Parse vanilla summary, returning each strategy tagged with its protocol.
fn parse_vanilla_tagged(data: &str) -> Vec<TaggedStrategy> {
    data.lines()
        .filter_map(|line| {
            let protocol = if line.starts_with("curl_test_https_tls13 ") {
                Protocol::HttpsTls13
            } else if line.starts_with("curl_test_https_tls12 ") {
                Protocol::HttpsTls12
            } else if line.starts_with("curl_test_http ") {
                Protocol::Http
            } else {
                return None;
            };

            line.split_once(": nfqws2 ")
                .map(|(_, args)| TaggedStrategy {
                    protocol,
                    args: args.split_whitespace().map(String::from).collect(),
                    coverage: 1,
                })
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
        let tls12_set: std::collections::HashSet<Vec<String>> = tls12.into_iter().collect();

        let parse = |s: &str| -> Strategy { s.split_whitespace().map(String::from).collect() };

        // 25-fake: multisplit:blob nodrop with TTL=1 (first TTL in vanilla loop)
        let s = parse("--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:ip_ttl=1:pos=2:nodrop:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(
            tls12_set.contains(&s),
            "missing: multisplit:blob nodrop TTL+pktmod"
        );

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

    #[test]
    fn test_parse_vanilla_tagged() {
        let data = "\
* SUMMARY
curl_test_http ipv4 rutracker.org : nfqws2 --payload=http_req --lua-desync=fake:blob=0x00000000
curl_test_https_tls12 ipv4 rutracker.org : nfqws2 --payload=tls_client_hello --lua-desync=multisplit
curl_test_https_tls13 ipv4 rutracker.org : nfqws2 --payload=tls_client_hello --lua-desync=fake
";
        let tagged = parse_vanilla_tagged(data);
        assert_eq!(tagged.len(), 3);
        assert_eq!(tagged[0].protocol, Protocol::Http);
        assert_eq!(
            tagged[0].args,
            vec!["--payload=http_req", "--lua-desync=fake:blob=0x00000000"]
        );
        assert_eq!(tagged[1].protocol, Protocol::HttpsTls12);
        assert_eq!(tagged[2].protocol, Protocol::HttpsTls13);
    }

    #[test]
    fn test_parse_vanilla_tagged_empty() {
        let data = "* SUMMARY\n# just comments\n";
        let tagged = parse_vanilla_tagged(data);
        assert!(tagged.is_empty());
    }

    #[test]
    fn test_parse_vanilla_tagged_tls13_before_tls12() {
        // Ensure tls13 prefix doesn't accidentally match tls12
        let data = "curl_test_https_tls13 ipv4 x.org : nfqws2 --a\ncurl_test_https_tls12 ipv4 x.org : nfqws2 --b\n";
        let tagged = parse_vanilla_tagged(data);
        assert_eq!(tagged[0].protocol, Protocol::HttpsTls13);
        assert_eq!(tagged[1].protocol, Protocol::HttpsTls12);
    }
}
