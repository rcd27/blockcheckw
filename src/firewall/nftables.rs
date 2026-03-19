use crate::error::BlockcheckError;
use crate::system::process::run_process;

const CHAIN_POSTNAT: &str = "postnat";
const CHAIN_PREDEFRAG: &str = "predefrag";
const CHAIN_PRENAT: &str = "prenat";
const NFT_TIMEOUT_MS: u64 = 5_000;

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

/// Build the list of nft commands for table preparation.
///
/// Returns 7 commands:
/// 1. add table inet <table>
/// 2. add chain postnat (postrouting priority 102)
/// 3. add chain predefrag (output priority -402)
/// 4. add rule predefrag notrack for marked packets
/// 5. add chain prenat (prerouting priority -102)
/// 6. add rule prenat: drop ICMP time-exceeded with ct mark
/// 7. add rule prenat: drop ICMP time-exceeded with ct state invalid
fn build_prepare_commands(table: &str) -> Vec<Vec<String>> {
    let mark = format!("0x{:08X}", crate::config::DESYNC_MARK);
    vec![
        // 1. create table
        vec_s(&["add", "table", "inet", table]),
        // 2. postnat chain (postrouting)
        vec_s(&[
            "add", "chain", "inet", table, CHAIN_POSTNAT,
            "{ type filter hook postrouting priority 102; }",
        ]),
        // 3. predefrag chain (output, before defragmentation)
        vec_s(&[
            "add", "chain", "inet", table, CHAIN_PREDEFRAG,
            "{ type filter hook output priority -402; }",
        ]),
        // 4. predefrag rule: notrack nfqws2-marked packets
        strs_and_owned(&[
            "add", "rule", "inet", table, CHAIN_PREDEFRAG,
            "meta", "nfproto", "ipv4", "mark", "and",
        ], &[&mark, "!=0", "notrack"]),
        // 5. prenat chain (prerouting, for autottl)
        vec_s(&[
            "add", "chain", "inet", table, CHAIN_PRENAT,
            "{ type filter hook prerouting priority -102; }",
        ]),
        // 6. prenat rule: drop ICMP time-exceeded with desync ct mark
        strs_and_owned(&[
            "add", "rule", "inet", table, CHAIN_PRENAT,
            "icmp", "type", "time-exceeded", "ct", "mark", "and",
        ], &[&mark, "!=", "0", "drop"]),
        // 7. prenat rule: drop ICMP time-exceeded with ct state invalid
        vec_s(&[
            "add", "rule", "inet", table, CHAIN_PRENAT,
            "icmp", "type", "time-exceeded", "ct", "state", "invalid", "drop",
        ]),
    ]
}

fn vec_s(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

fn strs_and_owned(prefix: &[&str], suffix: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
    v.extend(suffix.iter().map(|s| s.to_string()));
    v
}

/// Create the nftables table and all required chains.
pub async fn prepare_table(table: &str) -> Result<(), BlockcheckError> {
    for cmd in build_prepare_commands(table) {
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        run_nft(&refs).await?;
    }
    Ok(())
}

/// Build nft arguments for a per-worker postnat rule (pure function, testable without root).
fn build_worker_rule_args(
    table: &str,
    sport_range: &str,
    dport: u16,
    qnum: u16,
    ips: &[String],
) -> Vec<String> {
    let ip_set = ips.join(", ");
    let dport_str = dport.to_string();
    let qnum_str = qnum.to_string();
    let mark = format!("0x{:08X}", crate::config::DESYNC_MARK);
    let ip_expr = format!("{{ {ip_set} }}");

    vec_s(&["--echo", "--handle", "add", "rule", "inet", table, CHAIN_POSTNAT])
        .into_iter()
        .chain(vec_s(&["meta", "nfproto", "ipv4"]))
        .chain(vec_s(&["tcp", "sport", sport_range]))
        .chain(vec![
            "tcp".into(), "dport".into(), dport_str,
        ])
        .chain(vec![
            "mark".into(), "and".into(), mark.clone(), "==".into(), "0".into(),
        ])
        .chain(vec![
            "ip".into(), "daddr".into(), ip_expr,
        ])
        .chain(vec![
            "ct".into(), "mark".into(), "set".into(),
            "ct".into(), "mark".into(), "or".into(), mark,
        ])
        .chain(vec![
            "queue".into(), "num".into(), qnum_str,
        ])
        .collect()
}

/// Build nft arguments for a per-worker incoming SYN,ACK rule in prenat chain.
/// This directs server SYN,ACK responses into the nfqws2 queue so it can determine
/// the server's TTL (required for autottl strategies).
///
/// Unlike blockcheck2.sh (which runs one worker at a time), we run many workers in parallel.
/// Each worker uses a unique local port range (sport_range). In the server's SYN,ACK response,
/// the server's port is `sport` and our local port is `dport`. We filter on both to ensure
/// each worker's nfqws2 instance receives only its own SYN,ACK packets.
///
/// The rule is passed as a single string argument to nft (matching blockcheck2.sh behavior),
/// with `--echo --handle` as separate preceding args to get the handle back.
fn build_incoming_rule_args(
    table: &str,
    sport_range: &str,
    dport: u16,
    qnum: u16,
    ips: &[String],
) -> Vec<String> {
    let ip_set = ips.join(", ");
    let rule = format!(
        "add rule inet {table} {CHAIN_PRENAT} \
         meta nfproto ipv4 \
         tcp sport {dport} \
         tcp dport {sport_range} \
         tcp flags & (syn | ack) == (syn | ack) \
         ip saddr {{ {ip_set} }} \
         queue num {qnum}"
    );
    vec!["--echo".into(), "--handle".into(), rule]
}

/// Add a per-worker nftables rule and return its handle for later removal.
pub async fn add_worker_rule(
    table: &str,
    sport_range: &str,
    dport: u16,
    qnum: u16,
    ips: &[String],
) -> Result<RuleHandle, BlockcheckError> {
    let args = build_worker_rule_args(table, sport_range, dport, qnum, ips);
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let stdout = run_nft(&refs).await?;

    parse_handle(&stdout)
}

/// Add a per-worker incoming SYN,ACK rule in prenat and return its handle.
/// This allows nfqws2 to see server SYN,ACK responses for autottl detection.
pub async fn add_incoming_rule(
    table: &str,
    sport_range: &str,
    dport: u16,
    qnum: u16,
    ips: &[String],
) -> Result<RuleHandle, BlockcheckError> {
    let args = build_incoming_rule_args(table, sport_range, dport, qnum, ips);
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let stdout = run_nft(&refs).await?;

    parse_handle(&stdout)
}

/// Remove a specific rule from postnat by its handle.
pub async fn remove_rule(table: &str, handle: RuleHandle) -> Result<(), BlockcheckError> {
    let handle_str = handle.0.to_string();
    run_nft(&["delete", "rule", "inet", table, CHAIN_POSTNAT, "handle", &handle_str])
        .await?;
    Ok(())
}

/// Remove a specific rule from prenat by its handle.
pub async fn remove_prenat_rule(table: &str, handle: RuleHandle) -> Result<(), BlockcheckError> {
    let handle_str = handle.0.to_string();
    run_nft(&["delete", "rule", "inet", table, CHAIN_PRENAT, "handle", &handle_str])
        .await?;
    Ok(())
}

/// Drop the entire nftables table. Ignores errors (cleanup).
pub async fn drop_table(table: &str) {
    let _ = run_nft(&["delete", "table", "inet", table]).await;
}

fn parse_handle(stdout: &str) -> Result<RuleHandle, BlockcheckError> {
    // nft --echo --handle outputs lines like: "# handle 42"
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
        let output = "add rule inet zapret postnat meta nfproto ipv4 tcp sport 30000-30009 tcp dport 80 mark and 0x10000000 == 0 ip daddr { 1.2.3.4 } ct mark set ct mark or 0x10000000 queue num 200 # handle 42\n";
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

    #[test]
    fn prepare_commands_include_predefrag_and_prenat() {
        let cmds = build_prepare_commands("zapret");
        assert_eq!(cmds.len(), 7, "expected 7 nft commands, got {}", cmds.len());

        // 1. add table
        assert_eq!(cmds[0], vec_s(&["add", "table", "inet", "zapret"]));

        // 2. postnat chain
        let postnat = cmds[1].join(" ");
        assert!(postnat.contains("postnat"), "cmd[1] should create postnat chain");
        assert!(postnat.contains("postrouting"), "postnat should be postrouting");
        assert!(postnat.contains("102"), "postnat priority should be 102");

        // 3. predefrag chain
        let predefrag_chain = cmds[2].join(" ");
        assert!(predefrag_chain.contains("predefrag"), "cmd[2] should create predefrag chain");
        assert!(predefrag_chain.contains("output"), "predefrag should be output hook");
        assert!(predefrag_chain.contains("-402"), "predefrag priority should be -402");

        // 4. predefrag notrack rule
        let predefrag_rule = cmds[3].join(" ");
        assert!(predefrag_rule.contains("predefrag"), "cmd[3] should target predefrag chain");
        assert!(predefrag_rule.contains("notrack"), "predefrag rule should include notrack");
        assert!(predefrag_rule.contains("0x10000000"), "predefrag rule should check DESYNC_MARK");

        // 5. prenat chain
        let prenat_chain = cmds[4].join(" ");
        assert!(prenat_chain.contains("prenat"), "cmd[4] should create prenat chain");
        assert!(prenat_chain.contains("prerouting"), "prenat should be prerouting hook");
        assert!(prenat_chain.contains("-102"), "prenat priority should be -102");

        // 6. prenat icmp ct mark drop
        let prenat_rule1 = cmds[5].join(" ");
        assert!(prenat_rule1.contains("prenat"), "cmd[5] should target prenat chain");
        assert!(prenat_rule1.contains("icmp"), "cmd[5] should match icmp");
        assert!(prenat_rule1.contains("time-exceeded"), "cmd[5] should match time-exceeded");
        assert!(prenat_rule1.contains("ct mark"), "cmd[5] should check ct mark");
        assert!(prenat_rule1.contains("drop"), "cmd[5] should drop");

        // 7. prenat icmp ct state invalid drop
        let prenat_rule2 = cmds[6].join(" ");
        assert!(prenat_rule2.contains("prenat"), "cmd[6] should target prenat chain");
        assert!(prenat_rule2.contains("time-exceeded"), "cmd[6] should match time-exceeded");
        assert!(prenat_rule2.contains("invalid"), "cmd[6] should match ct state invalid");
        assert!(prenat_rule2.contains("drop"), "cmd[6] should drop");
    }

    #[test]
    fn worker_rule_args_structure() {
        let ips = vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()];
        let args = build_worker_rule_args("zapret", "30000-30009", 80, 200, &ips);
        let joined = args.join(" ");

        // Should start with --echo --handle
        assert_eq!(&args[0], "--echo");
        assert_eq!(&args[1], "--handle");

        // Should target postnat chain
        assert!(joined.contains("postnat"), "should target postnat chain");

        // Should have sport range
        assert!(joined.contains("30000-30009"), "should include sport range");

        // Should have dport
        assert!(joined.contains("dport 80"), "should include dport");

        // Should have queue num
        assert!(joined.contains("queue num 200"), "should include queue num");

        // Should have ip set
        assert!(joined.contains("1.2.3.4, 5.6.7.8"), "should include ip set");

        // Should have DESYNC_MARK
        assert!(joined.contains("0x10000000"), "should include DESYNC_MARK");

        // Should have ct mark set
        assert!(joined.contains("ct mark set ct mark or"), "should set ct mark");
    }

    #[test]
    fn worker_rule_args_single_ip() {
        let ips = vec!["10.0.0.1".to_string()];
        let args = build_worker_rule_args("zapret", "30010-30019", 443, 201, &ips);
        let joined = args.join(" ");
        assert!(joined.contains("10.0.0.1"), "should include single ip");
        assert!(joined.contains("dport 443"), "should include dport 443");
        assert!(joined.contains("queue num 201"), "should include queue 201");
    }

    #[test]
    fn incoming_rule_args_structure() {
        let ips = vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()];
        let args = build_incoming_rule_args("zapret", "30000-30009", 80, 200, &ips);

        // Should have 3 elements: --echo, --handle, and the rule string
        assert_eq!(args.len(), 3);
        assert_eq!(&args[0], "--echo");
        assert_eq!(&args[1], "--handle");

        let rule = &args[2];

        // Should target prenat chain (not postnat)
        assert!(rule.contains("prenat"), "should target prenat chain");
        assert!(!rule.contains("postnat"), "should NOT target postnat chain");

        // Server port becomes sport in response packets
        assert!(rule.contains("tcp sport 80"), "should have tcp sport = server port");

        // Our local port range becomes dport in response packets
        assert!(rule.contains("tcp dport 30000-30009"), "should have tcp dport = our local port range");

        // Should match SYN,ACK flags
        assert!(rule.contains("tcp flags & (syn | ack) == (syn | ack)"), "should match SYN,ACK flags");

        // Should use saddr (source = server IP in response)
        assert!(rule.contains("ip saddr"), "should match ip saddr");

        // Should have ip set
        assert!(rule.contains("1.2.3.4, 5.6.7.8"), "should include ip set");

        // Should have queue num
        assert!(rule.contains("queue num 200"), "should include queue num");
    }

    #[test]
    fn incoming_rule_args_single_ip() {
        let ips = vec!["10.0.0.1".to_string()];
        let args = build_incoming_rule_args("zapret", "30010-30019", 443, 201, &ips);
        let rule = &args[2];
        assert!(rule.contains("tcp sport 443"), "should have sport 443");
        assert!(rule.contains("tcp dport 30010-30019"), "should have dport = local port range");
        assert!(rule.contains("10.0.0.1"), "should include single ip");
        assert!(rule.contains("queue num 201"), "should include queue 201");
    }
}
