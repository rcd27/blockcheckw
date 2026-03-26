use std::collections::HashSet;
use std::sync::LazyLock;

use console::style;
use tokio::sync::Mutex;

use crate::system::process::run_process;
use crate::ui;

const ROUTE_TIMEOUT_MS: u64 = 5_000;

/// Global set of IPs whose routes we added (for cleanup on panic/Ctrl+C).
static ADDED_ROUTES: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Check that the gateway is reachable via `ip route get`.
/// Prints a status line to the console.
pub async fn check_gateway(via: &str, con: &ui::Console) -> bool {
    let result = run_process(&["ip", "route", "get", via], ROUTE_TIMEOUT_MS).await;
    match result {
        Ok(r) if r.exit_code == 0 => {
            con.println(&format!(
                "  {}Remote gateway {}: {}",
                ui::CHECKMARK,
                style(via).bold(),
                style("OK").green().bold(),
            ));
            true
        }
        _ => {
            con.println(&format!(
                "  {}Remote gateway {}: {}",
                ui::WARN,
                style(via).bold(),
                style("FAIL (unreachable)").red().bold(),
            ));
            false
        }
    }
}

/// Add `ip route add <ip> via <gateway>` for each IP.
/// Returns the list of IPs for which routes were successfully added.
pub async fn add_routes(via: &str, ips: &[String]) -> Vec<String> {
    let mut added = Vec::new();
    let mut global = ADDED_ROUTES.lock().await;

    for ip in ips {
        if global.contains(ip) {
            added.push(ip.clone());
            continue;
        }
        let result = run_process(&["ip", "route", "add", ip, "via", via], ROUTE_TIMEOUT_MS).await;
        if result.is_ok_and(|r| r.exit_code == 0) {
            global.insert(ip.clone());
            added.push(ip.clone());
        }
    }

    added
}

/// Remove routes for the given IPs (best-effort).
pub async fn remove_routes(ips: &[String]) {
    let mut global = ADDED_ROUTES.lock().await;

    for ip in ips {
        if global.remove(ip) {
            let _ = run_process(&["ip", "route", "del", ip], ROUTE_TIMEOUT_MS).await;
        }
    }
}

/// Remove ALL routes we ever added (for cleanup handlers).
pub async fn remove_all_routes() {
    let mut global = ADDED_ROUTES.lock().await;
    for ip in global.drain() {
        let _ = run_process(&["ip", "route", "del", &ip], ROUTE_TIMEOUT_MS).await;
    }
}

/// Synchronous cleanup for panic hook — can't use async runtime.
pub fn remove_all_routes_sync() {
    // Best-effort: try_lock to avoid deadlock in panic context
    if let Ok(mut global) = ADDED_ROUTES.try_lock() {
        for ip in global.drain() {
            let _ = std::process::Command::new("ip")
                .args(["route", "del", &ip])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}
