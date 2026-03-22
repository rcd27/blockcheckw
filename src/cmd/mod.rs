pub mod benchmark;
pub mod check;
pub mod completions;
pub mod scan;
pub mod universal;

use std::sync::Arc;

use console::style;
use tokio::sync::Mutex;

use blockcheckw::ui::WARN;

// ── Zapret2 service management ──────────────────────────────────────────────

/// How zapret2 service is managed on this system.
#[derive(Debug, Clone)]
pub enum ServiceManager {
    /// systemd: `systemctl stop/start zapret2`
    Systemd { unit: String },
    /// OpenWrt / sysv init: `/etc/init.d/zapret2 stop/start`
    InitD { script: String },
}

impl std::fmt::Display for ServiceManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceManager::Systemd { unit } => write!(f, "systemd ({unit})"),
            ServiceManager::InitD { script } => write!(f, "init.d ({script})"),
        }
    }
}

/// Detect how zapret2 is managed. Returns None if no service found.
async fn detect_service_manager() -> Option<ServiceManager> {
    use blockcheckw::system::process::run_process;

    // Check systemd first (most common on desktop/server Linux)
    if let Ok(result) = run_process(&["systemctl", "is-active", "zapret2"], 3_000).await {
        // is-active returns 0 for "active", 3 for "inactive", etc.
        // Any successful execution means systemd is present and knows the unit
        if result.exit_code == 0 || result.stdout.trim() == "inactive" {
            return Some(ServiceManager::Systemd {
                unit: "zapret2".to_string(),
            });
        }
    }

    // Check OpenWrt / sysv init.d
    for script in &["/etc/init.d/zapret2"] {
        if std::path::Path::new(script).exists() {
            return Some(ServiceManager::InitD {
                script: script.to_string(),
            });
        }
    }

    None
}

/// Stop zapret2 service. Returns true on success.
async fn stop_service(mgr: &ServiceManager) -> bool {
    use blockcheckw::system::process::run_process;

    let result = match mgr {
        ServiceManager::Systemd { unit } => run_process(&["systemctl", "stop", unit], 10_000).await,
        ServiceManager::InitD { script } => run_process(&[script, "stop"], 10_000).await,
    };

    match result {
        Ok(r) => r.exit_code == 0,
        Err(_) => false,
    }
}

/// Start zapret2 service. Returns true on success.
pub async fn start_service(mgr: &ServiceManager) -> bool {
    use blockcheckw::system::process::run_process;

    let result = match mgr {
        ServiceManager::Systemd { unit } => {
            run_process(&["systemctl", "start", unit], 10_000).await
        }
        ServiceManager::InitD { script } => run_process(&[script, "start"], 10_000).await,
    };

    match result {
        Ok(r) => r.exit_code == 0,
        Err(_) => false,
    }
}

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

/// Display conflicts and handle them. Returns `Some((ServiceManager, nft_ruleset_backup))` if a
/// service was stopped (caller must restart it on graceful exit), or `None` if no service was
/// involved. Returns `Err(())` if user aborted.
pub async fn handle_bypass_conflicts(
    own_table: &str,
) -> Result<Option<(ServiceManager, Option<String>)>, ()> {
    let conflicts = detect_bypass_conflicts(own_table).await;
    if conflicts.is_empty() {
        return Ok(None);
    }

    eprintln!();
    eprintln!("{}", style("=== Conflicting DPI bypass ===").bold().cyan());
    if conflicts.has_nfqws2_processes {
        eprintln!("  {}running nfqws2 processes found", WARN,);
    }
    for (family, table) in &conflicts.conflicting_tables {
        eprintln!(
            "  {}nft table '{} {}' has queue rules on port 443",
            WARN, family, table
        );
    }

    // Try to detect service manager
    let service_mgr = detect_service_manager().await;

    if let Some(ref mgr) = service_mgr {
        eprintln!(
            "  detected service: {}",
            style(format!("{mgr}")).cyan().bold()
        );
        eprintln!();
        eprint!(
            "  Stop zapret2 via {mgr} for the duration of the scan? {} ",
            style("[Y/n]").bold()
        );

        if !prompt_yes_no() {
            eprintln!("  {}", style("Aborted.").red());
            return Err(());
        }

        // Backup entire nft ruleset BEFORE stopping zapret2 (stop drops tables)
        let nft_backup = backup_nft_ruleset().await;
        if nft_backup.is_some() {
            eprintln!("  {} nft ruleset backed up", style("OK").green().bold(),);
        }

        if stop_service(mgr).await {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            eprintln!("  {} zapret2 stopped via {mgr}", style("OK").green().bold());
            eprintln!(
                "  {} will restart automatically when blockcheckw finishes",
                style("→").dim(),
            );
            Ok(Some((mgr.clone(), nft_backup)))
        } else {
            eprintln!(
                "  {} failed to stop zapret2 via {mgr}",
                style("ERROR:").red().bold()
            );
            eprintln!(
                "  {} please stop it manually and re-run blockcheckw",
                style("→").dim(),
            );
            Err(())
        }
    } else {
        eprintln!(
            "  {}no systemd unit or init.d script found for zapret2",
            WARN,
        );
        eprintln!();
        eprint!(
            "  Kill nfqws2 processes and drop conflicting nft tables? {} ",
            style("[Y/n]").bold()
        );

        if !prompt_yes_no() {
            eprintln!("  {}", style("Aborted.").red());
            return Err(());
        }

        resolve_bypass_conflicts_manual(&conflicts).await;
        eprintln!(
            "  {} processes killed, nft tables dropped",
            style("OK").green().bold()
        );
        eprintln!(
            "  {}you will need to restart DPI bypass manually afterwards",
            WARN,
        );
        Ok(None)
    }
}

/// Fallback: kill nfqws2 by PID (not killall) and drop conflicting tables.
async fn resolve_bypass_conflicts_manual(conflicts: &BypassConflicts) {
    use blockcheckw::system::process::run_process;

    if conflicts.has_nfqws2_processes {
        // Kill by PID instead of killall — safer, only kills processes we detected
        if let Ok(result) = run_process(&["pgrep", "nfqws2"], 3_000).await {
            if result.exit_code == 0 {
                for pid in result.stdout.lines() {
                    let pid = pid.trim();
                    if !pid.is_empty() {
                        let _ = run_process(&["kill", pid], 3_000).await;
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    for (family, table) in &conflicts.conflicting_tables {
        let _ = run_process(&["nft", "delete", "table", family, table], 5_000).await;
    }
}

/// Re-check and resolve conflicts silently (used between protocol scans).
pub async fn resolve_bypass_conflicts_if_any(own_table: &str) {
    let conflicts = detect_bypass_conflicts(own_table).await;
    if !conflicts.is_empty() {
        resolve_bypass_conflicts_manual(&conflicts).await;
    }
}

fn prompt_yes_no() -> bool {
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    let input = input.trim().to_lowercase();
    input.is_empty() || input == "y" || input == "yes"
}

// ── nft ruleset backup/restore ────────────────────────────────────────────────

/// Backup the entire nft ruleset before stopping zapret2.
pub async fn backup_nft_ruleset() -> Option<String> {
    use blockcheckw::system::process::run_process;

    if let Ok(result) = run_process(&["nft", "list", "ruleset"], 5_000).await {
        if result.exit_code == 0 && !result.stdout.is_empty() {
            return Some(result.stdout);
        }
    }
    None
}

/// Restore entire nft ruleset from backup after zapret2 start.
/// Flushes whatever zapret2 start created, then loads the saved snapshot.
pub async fn restore_nft_ruleset(dump: &str) {
    // Flush current ruleset, then load backup
    let _ = std::process::Command::new("nft")
        .args(["flush", "ruleset"])
        .status();

    let status = nft_load_stdin(dump);
    match status {
        Ok(s) if s.success() => {
            eprintln!(
                "  {} nft ruleset restored from backup",
                style("OK").green().bold(),
            );
        }
        _ => {
            eprintln!("  {}failed to restore nft ruleset from backup", WARN);
        }
    }
}

/// Synchronous restore for panic hook (can't use async).
fn restore_nft_ruleset_sync(dump: &str) {
    let _ = std::process::Command::new("nft")
        .args(["flush", "ruleset"])
        .status();

    match nft_load_stdin(dump) {
        Ok(s) if s.success() => {
            eprintln!(
                "  {} nft ruleset restored after panic",
                style("OK").green().bold(),
            );
        }
        _ => {
            eprintln!("  {}failed to restore nft ruleset after panic", WARN);
        }
    }
}

/// Pipe `dump` into `nft -f -`.
fn nft_load_stdin(dump: &str) -> std::io::Result<std::process::ExitStatus> {
    use std::io::Write;

    let mut child = std::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(dump.as_bytes())?;
    }
    child.wait()
}

// ── Shared cleanup state ────────────────────────────────────────────────────

/// Shared state for Ctrl+C handler: nft table to drop + optional service to restart.
pub type CleanupState = Arc<Mutex<CleanupInfo>>;

pub struct CleanupInfo {
    pub nft_table: String,
    pub stopped_service: Option<ServiceManager>,
    /// Full nft ruleset backup taken before we stopped zapret2.
    pub nft_backup: Option<String>,
}

/// Create shared cleanup state and spawn Ctrl+C handler that will:
/// 1. Drop our nft table
/// 2. Restart zapret2 service if we stopped it
pub fn spawn_cleanup_handler(nft_table: &str) -> CleanupState {
    let state = Arc::new(Mutex::new(CleanupInfo {
        nft_table: nft_table.to_string(),
        stopped_service: None,
        nft_backup: None,
    }));

    // Panic hook: restore zapret2 synchronously if we crash.
    // We can't use async here, so we shell out directly.
    let panic_state = state.clone();
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Best-effort synchronous cleanup
        if let Ok(guard) = panic_state.try_lock() {
            // Drop our nft table
            let _ = std::process::Command::new("nft")
                .args(["delete", "table", "inet", &guard.nft_table])
                .status();
            // Restart zapret2
            if let Some(ref mgr) = guard.stopped_service {
                let _ = match mgr {
                    ServiceManager::Systemd { unit } => std::process::Command::new("systemctl")
                        .args(["start", unit])
                        .status(),
                    ServiceManager::InitD { script } => {
                        std::process::Command::new(script).arg("start").status()
                    }
                };
                eprintln!(
                    "\n  {} zapret2 restored after panic",
                    style("OK").green().bold(),
                );
            }
            // Restore nft ruleset from backup
            if let Some(ref dump) = guard.nft_backup {
                restore_nft_ruleset_sync(dump);
            }
        }
        prev_hook(info);
    }));

    let handler_state = state.clone();
    tokio::spawn(async move {
        // First Ctrl+C: graceful cleanup
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\n{}", style("=== Ctrl+C — cleaning up ===").bold().cyan());

            // Spawn force-quit listener + delayed hint
            tokio::spawn(async {
                // Show hint only if cleanup takes more than 1 second
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                eprintln!("  {} press Ctrl+C again to force quit", style("→").dim());
            });
            tokio::spawn(async {
                if tokio::signal::ctrl_c().await.is_ok() {
                    eprintln!("\n  force quit");
                    std::process::exit(137);
                }
            });

            let info = handler_state.lock().await;
            blockcheckw::firewall::nftables::drop_table(&info.nft_table).await;
            eprintln!(
                "  {} nft table '{}' dropped",
                style("OK").green().bold(),
                info.nft_table,
            );
            if let Some(ref mgr) = info.stopped_service {
                if start_service(mgr).await {
                    eprintln!(
                        "  {} zapret2 restarted via {mgr}",
                        style("OK").green().bold(),
                    );
                } else {
                    eprintln!(
                        "  {}failed to restart zapret2 via {mgr}, please start manually",
                        WARN,
                    );
                }
            }
            // Restore user's nft ruleset from backup
            if let Some(ref dump) = info.nft_backup {
                // Small delay to let zapret2 finish creating its tables
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                restore_nft_ruleset(dump).await;
            }
            std::process::exit(130);
        }
    });

    state
}

/// Record that we stopped a service, so Ctrl+C handler can restart it.
pub async fn set_stopped_service(state: &CleanupState, mgr: ServiceManager) {
    state.lock().await.stopped_service = Some(mgr);
}

/// Record nft ruleset backup, so cleanup handlers can restore it.
pub async fn set_nft_backup(state: &CleanupState, backup: Option<String>) {
    state.lock().await.nft_backup = backup;
}

/// Restart zapret2 service, then restore nft ruleset from backup. Call at graceful exit.
pub async fn restore_service(mgr: &ServiceManager, nft_backup: &Option<String>) {
    eprintln!();
    eprintln!("{}", style("=== Restoring zapret2 ===").bold().cyan());
    if start_service(mgr).await {
        eprintln!(
            "  {} zapret2 restarted via {mgr}",
            style("OK").green().bold(),
        );
    } else {
        eprintln!(
            "  {}failed to restart zapret2 via {mgr}, please start manually",
            WARN,
        );
    }
    if let Some(ref dump) = nft_backup {
        // Small delay to let zapret2 finish creating its tables
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        restore_nft_ruleset(dump).await;
    }
}

// ── Instance lock ───────────────────────────────────────────────────────────

const LOCK_PATH: &str = "/var/run/blockcheckw.lock";

/// Acquire an exclusive lock to prevent parallel blockcheckw execution.
/// Returns the lock file (must be kept alive for the duration of the process).
/// Exits if another instance is already running.
pub fn acquire_instance_lock() -> std::fs::File {
    use std::io::Write;

    // No truncate before flock — truncate would create a new file description
    // and bypass the existing lock held by another process
    #[allow(clippy::suspicious_open_options)]
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(LOCK_PATH);

    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "  {} cannot create lock file {}: {e}",
                style("ERROR:").red().bold(),
                LOCK_PATH,
            );
            std::process::exit(1);
        }
    };

    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        // Read PID from lock file for a helpful error message
        let held_pid = std::fs::read_to_string(LOCK_PATH).unwrap_or_default();
        let held_pid = held_pid.trim();
        eprintln!(
            "  {} another blockcheckw instance is already running (PID {held_pid})",
            style("ERROR:").red().bold(),
        );
        eprintln!("  To stop it: sudo kill {held_pid}");
        std::process::exit(1);
    }

    // Write PID for diagnostics (truncate after locking, not before)
    let _ = file.set_len(0);
    let _ = write!(file, "{}", std::process::id());
    file
}

// ── Prerequisites check ─────────────────────────────────────────────────────

/// Check that required binaries and kernel features are available.
/// Exits with code 6 (matching vanilla blockcheck2) if something is missing.
pub fn check_prerequisites() {
    use blockcheckw::config::CoreConfig;

    eprintln!("{}", style("=== Checking prerequisites ===").bold().cyan());

    let config = CoreConfig::default();
    let mut ok = true;

    // nfqws2 binary
    if std::path::Path::new(&config.nfqws2_path).is_file() {
        eprintln!(
            "  {} nfqws2: {}",
            style("OK").green().bold(),
            style(&config.nfqws2_path).dim(),
        );
    } else {
        eprintln!(
            "  {} nfqws2 not found at {}",
            style("FAIL").red().bold(),
            style(&config.nfqws2_path).cyan(),
        );
        eprintln!(
            "       run \"{}/install_bin.sh\" or check ZAPRET_BASE path",
            config.zapret_base,
        );
        ok = false;
    }

    // nft binary
    if which("nft") {
        eprintln!("  {} nft", style("OK").green().bold());
    } else {
        eprintln!("  {} nft not found in PATH", style("FAIL").red().bold(),);
        eprintln!("       install nftables: apt install nftables / opkg install nftables");
        ok = false;
    }

    // nft queue support (try creating a table with queue rule)
    if ok {
        if nft_has_queue_support() {
            eprintln!("  {} nft queue support", style("OK").green().bold());
        } else {
            eprintln!(
                "  {} nftables queue support not available",
                style("FAIL").red().bold(),
            );
            eprintln!("       install kernel module: modprobe nfnetlink_queue");
            ok = false;
        }
    }

    if !ok {
        std::process::exit(6);
    }
}

fn which(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn nft_has_queue_support() -> bool {
    // Try to list ruleset — if nft works and kernel has nf_tables, this succeeds
    std::process::Command::new("nft")
        .args(["list", "ruleset"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
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
