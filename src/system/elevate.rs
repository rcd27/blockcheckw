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
        let err = Command::new("sudo").arg("-E").arg(&exe).args(&args).exec();
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
/// With fwmark-based routing (no fixed port ranges), TIME_WAIT is less of an issue,
/// but this still helps ephemeral port recycling under heavy load.
pub fn tune_tcp() {
    let _ = std::fs::write("/proc/sys/net/ipv4/tcp_tw_reuse", "1");
}

/// Raise RLIMIT_NOFILE so that many parallel workers don't hit "Too many open files".
/// Each worker needs ~6-8 fd (nfqws2 process + TCP socket + nft calls).
/// Default soft limit is often 1024 — not enough for 256+ workers.
pub fn raise_nofile_limit() {
    unsafe {
        let mut rlim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
            let target = rlim.rlim_max.min(1_048_576); // cap at 1M, use hard limit
            if rlim.rlim_cur < target {
                rlim.rlim_cur = target;
                libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
            }
        }
    }
}

/// Change file ownership to the original (pre-sudo) user.
/// When blockcheckw runs as root via sudo, created files belong to root.
/// This makes them undeletable by the normal user. We read SUDO_UID/SUDO_GID
/// and chown the file back to the caller.
pub fn chown_to_caller(path: &str) {
    let uid: u32 = match std::env::var("SUDO_UID") {
        Ok(v) => match v.parse() {
            Ok(n) => n,
            Err(_) => return,
        },
        Err(_) => return,
    };
    let gid: u32 = std::env::var("SUDO_GID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(uid);

    let c_path = match std::ffi::CString::new(path) {
        Ok(p) => p,
        Err(_) => return,
    };
    unsafe {
        libc::chown(c_path.as_ptr(), uid, gid);
    }
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
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./=:".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
