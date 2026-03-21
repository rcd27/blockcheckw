pub mod benchmark;
pub mod check;
pub mod completions;
pub mod scan;

use console::style;

// ── Bypass conflict detection & resolution ──────────────────────────────────

pub struct BypassConflicts {
    pub has_nfqws2_processes: bool,
    /// (family, table_name) pairs, e.g. ("inet", "zapret2")
    pub conflicting_tables: Vec<(String, String)>,
}

impl BypassConflicts {
    pub fn is_empty(&self) -> bool {
        !self.has_nfqws2_processes && self.conflicting_tables.is_empty()
    }
}

/// Detect conflicting DPI bypass processes and nftables tables.
pub async fn detect_bypass_conflicts(own_table: &str) -> BypassConflicts {
    use blockcheckw::system::process::run_process;

    let mut conflicts = BypassConflicts {
        has_nfqws2_processes: false,
        conflicting_tables: Vec::new(),
    };

    // Check for other nfqws2 processes
    if let Ok(result) = run_process(&["pgrep", "-c", "nfqws2"], 3_000).await {
        if result.exit_code == 0 {
            if let Ok(count) = result.stdout.trim().parse::<u32>() {
                if count > 0 {
                    conflicts.has_nfqws2_processes = true;
                }
            }
        }
    }

    // Check for other nftables tables with queue rules on ports 80/443
    if let Ok(result) = run_process(&["nft", "list", "tables"], 3_000).await {
        if result.exit_code == 0 {
            for line in result.stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0] == "table" {
                    let family = parts[1];
                    let table_name = parts[2];
                    if table_name != own_table && table_name != "fw4" {
                        if let Ok(table_content) =
                            run_process(&["nft", "list", "table", family, table_name], 3_000).await
                        {
                            if table_content.exit_code == 0
                                && table_content.stdout.contains("queue")
                                && (table_content.stdout.contains("dport 443")
                                    || table_content.stdout.contains("dport { 80, 443"))
                            {
                                conflicts
                                    .conflicting_tables
                                    .push((family.to_string(), table_name.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }

    conflicts
}

/// Kill all nfqws2 processes and drop conflicting nft tables.
pub async fn resolve_bypass_conflicts(conflicts: &BypassConflicts) {
    use blockcheckw::system::process::run_process;

    if conflicts.has_nfqws2_processes {
        // FIXME: killall kills ALL nfqws2 processes system-wide, including production ones
        let _ = run_process(&["killall", "nfqws2"], 5_000).await;
        // Give processes time to exit
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    for (family, table) in &conflicts.conflicting_tables {
        let _ = run_process(&["nft", "delete", "table", family, table], 5_000).await;
    }
}

/// Display conflicts and prompt user. Returns true if should proceed.
pub async fn handle_bypass_conflicts(own_table: &str) -> bool {
    let conflicts = detect_bypass_conflicts(own_table).await;
    if conflicts.is_empty() {
        return true;
    }

    eprintln!();
    eprintln!(
        "{} {}",
        style("WARNING").yellow().bold(),
        style("conflicting DPI bypass detected:").yellow()
    );
    if conflicts.has_nfqws2_processes {
        eprintln!(
            "  {} running nfqws2 processes found",
            style("!").yellow().bold(),
        );
    }
    for (family, table) in &conflicts.conflicting_tables {
        eprintln!(
            "  {} nft table '{} {}' has queue rules intercepting port 443",
            style("!").yellow().bold(),
            family,
            table
        );
    }

    // Prompt user
    eprintln!();
    eprint!(
        "  {} ",
        style("Kill nfqws2 and drop conflicting nft tables to proceed? [Y/n] ").bold()
    );

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        eprintln!("{}", style("Aborted.").red());
        return false;
    }

    resolve_bypass_conflicts(&conflicts).await;
    eprintln!(
        "  {} conflicting processes killed, nft tables dropped",
        style("OK").green().bold()
    );
    true
}

/// Generate a local-time prefix for report filenames: "2026-03-20_18-30"
pub fn chrono_local_prefix() -> String {
    use std::process::Command;
    let output = Command::new("date").arg("+%Y-%m-%d_%H-%M").output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("{secs}")
        }
    }
}
