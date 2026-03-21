use crate::error::BlockcheckError;
use crate::network::dns::is_ipv4;
use crate::system::process::{run_process, run_process_stdin};

/// Validate and join IPs for nftables set. Rejects malformed IPs to prevent nft injection.
fn validate_ip_set(ips: &[String]) -> Result<String, BlockcheckError> {
    for ip in ips {
        if !is_ipv4(ip) {
            return Err(BlockcheckError::Nftables {
                command: "validate ip set".to_string(),
                stderr: format!("invalid IPv4 address: {ip}"),
            });
        }
    }
    Ok(ips.join(", "))
}

const CHAIN_POSTNAT: &str = "postnat";
const CHAIN_PREDEFRAG: &str = "predefrag";
const CHAIN_PRENAT: &str = "prenat";
const NFT_TIMEOUT_MS: u64 = 15_000;

/// vmap: packet mark → jump worker postnat chain
const POSTNAT_VMAP: &str = "postnat_qmap";
/// vmap: ct mark → jump worker prenat chain
const PRENAT_VMAP: &str = "prenat_qmap";

#[derive(Debug, Clone, Copy)]
pub struct RuleHandle(pub u32);

async fn run_nft(args: &[&str]) -> Result<String, BlockcheckError> {
    let mut cmd: Vec<&str> = vec!["nft"];
    cmd.extend_from_slice(args);

    let result = run_process(&cmd, NFT_TIMEOUT_MS).await?;

    if result.exit_code == 0 {
        Ok(result.stdout)
    } else {
        Err(BlockcheckError::Nftables {
            command: cmd.join(" "),
            stderr: result.stderr,
        })
    }
}

/// Create the nftables table, hook chains, vmaps, and static rules.
pub async fn prepare_table(table: &str) -> Result<(), BlockcheckError> {
    let desync_mark = format!("0x{:08X}", crate::config::DESYNC_MARK);

    let batch = format!(
        "\
add table inet {table}
add chain inet {table} {CHAIN_POSTNAT} {{ type filter hook postrouting priority 102; }}
add chain inet {table} {CHAIN_PREDEFRAG} {{ type filter hook output priority -402; }}
add rule inet {table} {CHAIN_PREDEFRAG} meta nfproto ipv4 mark and {desync_mark} !=0 notrack
add chain inet {table} {CHAIN_PRENAT} {{ type filter hook prerouting priority -102; }}
add rule inet {table} {CHAIN_PRENAT} icmp type time-exceeded ct mark and {desync_mark} != 0 drop
add rule inet {table} {CHAIN_PRENAT} icmp type time-exceeded ct state invalid drop
add map inet {table} {POSTNAT_VMAP} {{ type mark : verdict; }}
add map inet {table} {PRENAT_VMAP} {{ type mark : verdict; }}
"
    );

    let result = run_process_stdin(&["nft", "-f", "-"], &batch, NFT_TIMEOUT_MS).await?;
    if result.exit_code != 0 {
        return Err(BlockcheckError::Nftables {
            command: "nft -f - (prepare_table)".to_string(),
            stderr: result.stderr,
        });
    }
    Ok(())
}

/// Add per-worker chains, vmap elements, and dispatch rules for ALL slots.
///
/// For each worker slot creates:
/// - postnat chain `wp_{qnum}`:  ct mark set ... ; queue num {qnum}
/// - prenat chain `wi_{qnum}`:   queue num {qnum}
/// - postnat vmap element: packet mark → jump wp_{qnum}
/// - prenat vmap element:  ct mark → jump wi_{qnum}
///
/// Plus two dispatch rules (one per hook chain) that use the vmaps.
/// All lookups are O(1) hash — no linear scan regardless of worker count.
pub async fn add_all_worker_rules(
    table: &str,
    slots: &[crate::worker::slot::WorkerSlot],
    dport: u16,
    ips: &[String],
) -> Result<(), BlockcheckError> {
    if slots.is_empty() {
        return Ok(());
    }

    let ip_set = validate_ip_set(ips)?;
    let desync_mark = format!("0x{:08X}", crate::config::DESYNC_MARK);
    let worker_base = format!("0x{:08X}", crate::config::WORKER_MARK_BASE);

    // 1. Per-worker chains + vmap elements
    let worker_rules: String = slots
        .iter()
        .flat_map(|slot| {
            let worker_mark = format!("0x{:08X}", slot.fwmark);
            let ct_value = format!("0x{:08X}", crate::config::DESYNC_MARK | slot.fwmark);
            let pc = format!("wp_{}", slot.qnum);
            let ic = format!("wi_{}", slot.qnum);
            [
                format!("add chain inet {table} {pc}"),
                format!(
                    "add rule inet {table} {pc} ct mark set ct mark or {ct_value} queue num {}",
                    slot.qnum
                ),
                format!("add chain inet {table} {ic}"),
                format!("add rule inet {table} {ic} queue num {}", slot.qnum),
                format!("add element inet {table} {POSTNAT_VMAP} {{ {worker_mark} : jump {pc} }}"),
                format!("add element inet {table} {PRENAT_VMAP} {{ {ct_value} : jump {ic} }}"),
            ]
        })
        .collect::<Vec<_>>()
        .join("\n");

    // 2. Dispatch rules
    let batch = format!(
        "{worker_rules}\n\
         add rule inet {table} {CHAIN_POSTNAT} \
         meta nfproto ipv4 tcp dport {dport} \
         mark and {desync_mark} == 0 mark and {worker_base} != 0 \
         ip daddr {{ {ip_set} }} mark vmap @{POSTNAT_VMAP}\n\
         add rule inet {table} {CHAIN_PRENAT} \
         meta nfproto ipv4 tcp flags & (syn | ack) == (syn | ack) \
         ct mark and {worker_base} != 0 \
         ip saddr {{ {ip_set} }} ct mark vmap @{PRENAT_VMAP}\n"
    );

    let result = run_process_stdin(&["nft", "-f", "-"], &batch, NFT_TIMEOUT_MS).await?;
    if result.exit_code != 0 {
        return Err(BlockcheckError::Nftables {
            command: "nft -f - (add_all_worker_rules)".to_string(),
            stderr: result.stderr,
        });
    }

    Ok(())
}

/// Remove all worker chains, vmap elements, and dispatch rules.
/// Flushes vmaps and hook chains, re-adds static ICMP rules.
pub async fn remove_all_worker_rules(table: &str, slots: &[crate::worker::slot::WorkerSlot]) {
    let desync_mark = format!("0x{:08X}", crate::config::DESYNC_MARK);

    // Flush vmaps and hook chains
    let flush = [
        format!("flush map inet {table} {POSTNAT_VMAP}"),
        format!("flush map inet {table} {PRENAT_VMAP}"),
        format!("flush chain inet {table} {CHAIN_POSTNAT}"),
        format!("flush chain inet {table} {CHAIN_PRENAT}"),
    ];

    // Delete per-worker chains
    let worker_cleanup: Vec<String> = slots
        .iter()
        .flat_map(|slot| {
            let pc = format!("wp_{}", slot.qnum);
            let ic = format!("wi_{}", slot.qnum);
            [
                format!("flush chain inet {table} {pc}"),
                format!("delete chain inet {table} {pc}"),
                format!("flush chain inet {table} {ic}"),
                format!("delete chain inet {table} {ic}"),
            ]
        })
        .collect();

    // Re-add static ICMP drop rules in prenat
    let icmp = [
        format!("add rule inet {table} {CHAIN_PRENAT} icmp type time-exceeded ct mark and {desync_mark} != 0 drop"),
        format!("add rule inet {table} {CHAIN_PRENAT} icmp type time-exceeded ct state invalid drop"),
    ];

    let batch = flush
        .iter()
        .chain(&worker_cleanup)
        .chain(&icmp)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");

    // best-effort cleanup — errors are not actionable
    let _ = run_process_stdin(&["nft", "-f", "-"], &batch, NFT_TIMEOUT_MS).await;
}

/// Drop the entire nftables table. Ignores errors (cleanup).
pub async fn drop_table(table: &str) {
    // best-effort cleanup — table may not exist
    let _ = run_nft(&["delete", "table", "inet", table]).await;
}

// ── Legacy per-rule API (used by test_runner.rs sequential tests) ────────────

pub async fn add_worker_rule(
    table: &str,
    worker_fwmark: u32,
    dport: u16,
    qnum: u16,
    ips: &[String],
) -> Result<RuleHandle, BlockcheckError> {
    let ip_set = validate_ip_set(ips)?;
    let desync_mark = format!("0x{:08X}", crate::config::DESYNC_MARK);
    let worker_mark_str = format!("0x{:08X}", worker_fwmark);
    let ct_mark_value = format!("0x{:08X}", crate::config::DESYNC_MARK | worker_fwmark);
    let rule = format!(
        "add rule inet {table} {CHAIN_POSTNAT} \
         meta nfproto ipv4 \
         mark {worker_mark_str} \
         tcp dport {dport} \
         mark and {desync_mark} == 0 \
         ip daddr {{ {ip_set} }} \
         ct mark set ct mark or {ct_mark_value} \
         queue num {qnum}"
    );
    let stdout = run_nft(&["--echo", "--handle", &rule]).await?;
    parse_handle(&stdout)
}

pub async fn add_incoming_rule(
    table: &str,
    worker_fwmark: u32,
    dport: u16,
    qnum: u16,
    ips: &[String],
) -> Result<RuleHandle, BlockcheckError> {
    let ip_set = validate_ip_set(ips)?;
    let worker_mark_str = format!("0x{:08X}", worker_fwmark);
    let rule = format!(
        "add rule inet {table} {CHAIN_PRENAT} \
         meta nfproto ipv4 \
         tcp sport {dport} \
         ct mark and {worker_mark_str} == {worker_mark_str} \
         tcp flags & (syn | ack) == (syn | ack) \
         ip saddr {{ {ip_set} }} \
         queue num {qnum}"
    );
    let stdout = run_nft(&["--echo", "--handle", &rule]).await?;
    parse_handle(&stdout)
}

pub async fn remove_rule(table: &str, handle: RuleHandle) -> Result<(), BlockcheckError> {
    let h = handle.0.to_string();
    run_nft(&["delete", "rule", "inet", table, CHAIN_POSTNAT, "handle", &h]).await?;
    Ok(())
}

pub async fn remove_prenat_rule(table: &str, handle: RuleHandle) -> Result<(), BlockcheckError> {
    let h = handle.0.to_string();
    run_nft(&["delete", "rule", "inet", table, CHAIN_PRENAT, "handle", &h]).await?;
    Ok(())
}

pub async fn remove_worker_rules(
    table: &str,
    postnat_handle: RuleHandle,
    prenat_handle: RuleHandle,
) -> Result<(), BlockcheckError> {
    let batch = format!(
        "delete rule inet {table} {CHAIN_POSTNAT} handle {}\ndelete rule inet {table} {CHAIN_PRENAT} handle {}\n",
        postnat_handle.0, prenat_handle.0,
    );
    let result = run_process_stdin(&["nft", "-f", "-"], &batch, NFT_TIMEOUT_MS).await?;
    if result.exit_code != 0 {
        // best-effort fallback: try removing rules individually
        let _ = remove_rule(table, postnat_handle).await;
        let _ = remove_prenat_rule(table, prenat_handle).await;
    }
    Ok(())
}

fn parse_handle(stdout: &str) -> Result<RuleHandle, BlockcheckError> {
    let re_pattern = "# handle ";
    for line in stdout.lines() {
        if let Some(pos) = line.find(re_pattern) {
            let num_str = &line[pos + re_pattern.len()..];
            if let Ok(n) = num_str.trim().parse::<u32>() {
                return Ok(RuleHandle(n));
            }
        }
    }
    Err(BlockcheckError::NftHandleParse {
        output: stdout.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_handle() {
        let output = "add rule ... # handle 42\n";
        let handle = parse_handle(output).unwrap();
        assert_eq!(handle.0, 42);
    }

    #[test]
    fn test_parse_handle_missing() {
        let output = "some other output\n";
        assert!(parse_handle(output).is_err());
    }

    #[test]
    fn test_parse_handle_multiline() {
        let output = "table inet zapret {\n}\nadd rule ... # handle 137\n";
        let handle = parse_handle(output).unwrap();
        assert_eq!(handle.0, 137);
    }
}
