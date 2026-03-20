use std::os::unix::process::CommandExt;
use std::process::Command;

/// Check if running as root; if not, re-exec via sudo or su.
/// Mirrors `require_root()` from vanilla `elevate.sh`.
pub fn require_root() {
    // Already root
    if unsafe { libc::getuid() } == 0 {
        return;
    }

    eprintln!("* checking privileges");
    eprintln!("root is required");

    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .or_else(|| std::env::args().next())
        .expect("cannot determine executable path");

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Try sudo
    if has_command("sudo") {
        eprintln!("elevating with sudo");
        let err = Command::new("sudo")
            .arg("-E")
            .arg(&exe)
            .args(&args)
            .exec();
        eprintln!("exec sudo failed: {err}");
        std::process::exit(2);
    }

    // Try su
    if has_command("su") {
        eprintln!("elevating with su");
        let mut shell_cmd = shell_escape(&exe);
        for arg in &args {
            shell_cmd.push(' ');
            shell_cmd.push_str(&shell_escape(arg));
        }
        let err = Command::new("su")
            .args(["--preserve-environment", "root", "-c"])
            .arg(&shell_cmd)
            .exec();
        eprintln!("exec su failed: {err}");
        std::process::exit(2);
    }

    eprintln!("sudo or su not found");
    std::process::exit(2);
}

/// Enable tcp_tw_reuse so TIME_WAIT ports can be reused for new outgoing connections.
/// Without this, rapid sequential curl calls on --local-port ranges exhaust ports.
pub fn tune_tcp() {
    let _ = std::fs::write("/proc/sys/net/ipv4/tcp_tw_reuse", "1");
}

fn has_command(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn shell_escape(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
