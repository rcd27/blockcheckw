use std::collections::HashSet;

use crate::config::DnsMode;
use crate::error::BlockcheckError;
use crate::network::doh;
use crate::system::process::run_process;

const DNS_TIMEOUT_MS: u64 = 10_000;

const SPOOFING_CHECK_DOMAINS: &[&str] = &[
    "rutracker.org",
    "pornhub.com",
    "torproject.org",
];

#[derive(Debug, Clone)]
pub enum DnsSpoofResult {
    Clean,
    Spoofed { details: String },
    CheckFailed { reason: String },
}

#[derive(Debug)]
pub struct DnsResolution {
    pub ips: Vec<String>,
    pub method: &'static str,
    pub spoof_result: Option<DnsSpoofResult>,
}

pub(crate) fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
}

async fn resolve_with_getent(domain: &str) -> Option<Vec<String>> {
    let args = vec!["getent", "ahostsv4", domain];
    let result = run_process(&args, DNS_TIMEOUT_MS).await.ok()?;
    if result.exit_code != 0 {
        return None;
    }

    let ips: HashSet<String> = result
        .stdout
        .lines()
        .filter_map(|line| {
            let token = line.split_whitespace().next()?;
            if is_ipv4(token) {
                Some(token.to_string())
            } else {
                None
            }
        })
        .collect();

    Some(ips.into_iter().collect())
}

async fn resolve_with_nslookup(domain: &str) -> Option<Vec<String>> {
    let args = vec!["nslookup", domain];
    let result = run_process(&args, DNS_TIMEOUT_MS).await.ok()?;
    if result.exit_code != 0 {
        return None;
    }

    let answer_section = result.stdout.split_once("Name:")?;
    let ips: HashSet<String> = answer_section
        .1
        .split_whitespace()
        .filter(|token| is_ipv4(token))
        .map(|s| s.to_string())
        .collect();

    Some(ips.into_iter().collect())
}

pub async fn resolve_ipv4(domain: &str) -> Result<Vec<String>, BlockcheckError> {
    let ips = if let Some(ips) = resolve_with_getent(domain).await {
        Some(ips)
    } else {
        resolve_with_nslookup(domain).await
    };

    match ips {
        Some(ips) if !ips.is_empty() => Ok(ips),
        Some(_) => Err(BlockcheckError::DnsNoAddresses {
            domain: domain.to_string(),
        }),
        None => Err(BlockcheckError::DnsResolveFailed {
            domain: domain.to_string(),
            reason: "getent and nslookup both failed".to_string(),
        }),
    }
}

/// Check for DNS spoofing by comparing system DNS and DoH results for known blocked domains.
pub async fn check_dns_spoofing(doh_server_url: &str) -> DnsSpoofResult {
    let mut mismatches = Vec::new();

    for &domain in SPOOFING_CHECK_DOMAINS {
        let system_ips = resolve_ipv4(domain).await.ok();
        let doh_ips = doh::doh_resolve(domain, doh_server_url).await;

        match (system_ips, doh_ips) {
            (Some(sys), Some(doh_result)) if !doh_result.is_empty() => {
                let sys_set: HashSet<&str> = sys.iter().map(|s| s.as_str()).collect();
                let doh_set: HashSet<&str> = doh_result.iter().map(|s| s.as_str()).collect();

                if sys_set.is_disjoint(&doh_set) {
                    mismatches.push(format!(
                        "{domain}: system={} doh={}",
                        sys.join(","),
                        doh_result.join(","),
                    ));
                }
            }
            (None, _) | (_, None) => {
                // Can't compare — not a conclusive signal
            }
            _ => {}
        }
    }

    if mismatches.is_empty() {
        // Also check: are all system results for different domains the same IP?
        // That's a strong signal of a captive portal / block page.
        let mut all_sys_ips: Vec<String> = Vec::new();
        for &domain in SPOOFING_CHECK_DOMAINS {
            if let Ok(ips) = resolve_ipv4(domain).await {
                all_sys_ips.extend(ips);
            }
        }
        let unique: HashSet<&str> = all_sys_ips.iter().map(|s| s.as_str()).collect();
        if all_sys_ips.len() >= 2 && unique.len() == 1 {
            return DnsSpoofResult::Spoofed {
                details: format!(
                    "all {} domains resolve to same IP: {}",
                    SPOOFING_CHECK_DOMAINS.len(),
                    unique.into_iter().next().unwrap(),
                ),
            };
        }

        DnsSpoofResult::Clean
    } else {
        DnsSpoofResult::Spoofed {
            details: mismatches.join("; "),
        }
    }
}

/// Unified domain resolution with DNS mode support.
pub async fn resolve_domain(domain: &str, dns_mode: DnsMode) -> Result<DnsResolution, BlockcheckError> {
    match dns_mode {
        DnsMode::System => {
            let ips = resolve_ipv4(domain).await?;
            Ok(DnsResolution {
                ips,
                method: "system",
                spoof_result: None,
            })
        }
        DnsMode::Doh => {
            let ips = doh::resolve_ipv4_doh(domain).await?;
            Ok(DnsResolution {
                ips,
                method: "doh",
                spoof_result: None,
            })
        }
        DnsMode::Auto => {
            // Try system DNS first
            let sys_result = resolve_ipv4(domain).await;

            // Find a DoH server for spoofing check
            let doh_server = doh::find_working_doh_server().await;

            if let Some(server) = doh_server {
                let spoof_result = check_dns_spoofing(server).await;

                match &spoof_result {
                    DnsSpoofResult::Spoofed { .. } => {
                        // DNS is spoofed — use DoH for the actual domain
                        let ips = doh::doh_resolve(domain, server).await.ok_or_else(|| {
                            BlockcheckError::DnsResolveFailed {
                                domain: domain.to_string(),
                                reason: "DoH fallback failed after spoofing detected".to_string(),
                            }
                        })?;
                        if ips.is_empty() {
                            return Err(BlockcheckError::DnsNoAddresses {
                                domain: domain.to_string(),
                            });
                        }
                        Ok(DnsResolution {
                            ips,
                            method: "doh (auto-fallback)",
                            spoof_result: Some(spoof_result),
                        })
                    }
                    DnsSpoofResult::Clean | DnsSpoofResult::CheckFailed { .. } => {
                        // No spoofing detected — use system result
                        let ips = sys_result?;
                        Ok(DnsResolution {
                            ips,
                            method: "system",
                            spoof_result: Some(spoof_result),
                        })
                    }
                }
            } else {
                // No DoH servers available — use system DNS without spoofing check
                let ips = sys_result?;
                Ok(DnsResolution {
                    ips,
                    method: "system (no DoH available)",
                    spoof_result: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ipv4_valid() {
        assert!(is_ipv4("192.168.1.1"));
        assert!(is_ipv4("0.0.0.0"));
        assert!(is_ipv4("255.255.255.255"));
        assert!(is_ipv4("1.2.3.4"));
        assert!(is_ipv4("172.67.182.217"));
    }

    #[test]
    fn test_is_ipv4_invalid() {
        assert!(!is_ipv4("256.1.1.1"));
        assert!(!is_ipv4("1.2.3"));
        assert!(!is_ipv4("1.2.3.4.5"));
        assert!(!is_ipv4(""));
        assert!(!is_ipv4("abc.def.ghi.jkl"));
        assert!(!is_ipv4("192.168.1"));
        assert!(!is_ipv4("1.2.3."));
        assert!(!is_ipv4(".1.2.3"));
        assert!(!is_ipv4("rutracker.org"));
        assert!(!is_ipv4("STREAM"));
    }
}
