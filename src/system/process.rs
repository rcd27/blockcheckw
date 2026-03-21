use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use crate::error::BlockcheckError;

#[derive(Debug)]
pub struct ProcessResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run a command synchronously (blocking), capturing stdout/stderr.
/// Used for short-lived commands like nft, curl.
pub async fn run_process(args: &[&str], timeout_ms: u64) -> Result<ProcessResult, BlockcheckError> {
    let (program, cmd_args) = args
        .split_first()
        .ok_or_else(|| BlockcheckError::ProcessSpawn {
            reason: "empty command".to_string(),
        })?;

    let fut = Command::new(program)
        .args(cmd_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let output = timeout(Duration::from_millis(timeout_ms), fut)
        .await
        .map_err(|_| BlockcheckError::ProcessTimeout { timeout_ms })?
        .map_err(|e| BlockcheckError::ProcessSpawn {
            reason: e.to_string(),
        })?;

    Ok(ProcessResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Run a command with stdin input, capturing stdout/stderr.
pub async fn run_process_stdin(
    args: &[&str],
    stdin_data: &str,
    timeout_ms: u64,
) -> Result<ProcessResult, BlockcheckError> {
    use tokio::io::AsyncWriteExt;

    let (program, cmd_args) = args
        .split_first()
        .ok_or_else(|| BlockcheckError::ProcessSpawn {
            reason: "empty command".to_string(),
        })?;

    let mut child = Command::new(program)
        .args(cmd_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| BlockcheckError::ProcessSpawn {
            reason: e.to_string(),
        })?;

    let mut stdin = child.stdin.take().expect("stdin piped");
    let data = stdin_data.to_string();
    tokio::spawn(async move {
        // best-effort — pipe may be broken if process exited early
        let _ = stdin.write_all(data.as_bytes()).await;
        drop(stdin);
    });

    let output = timeout(Duration::from_millis(timeout_ms), child.wait_with_output())
        .await
        .map_err(|_| BlockcheckError::ProcessTimeout { timeout_ms })?
        .map_err(|e| BlockcheckError::ProcessSpawn {
            reason: e.to_string(),
        })?;

    Ok(ProcessResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// A background process handle. Wraps a tokio::process::Child.
pub struct BackgroundProcess {
    child: tokio::process::Child,
}

impl BackgroundProcess {
    /// Spawn a background process with stdout/stderr → /dev/null.
    pub fn spawn(args: &[&str]) -> Result<Self, BlockcheckError> {
        let (program, cmd_args) =
            args.split_first()
                .ok_or_else(|| BlockcheckError::ProcessSpawn {
                    reason: "empty command".to_string(),
                })?;

        let child = Command::new(program)
            .args(cmd_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| BlockcheckError::ProcessSpawn {
                reason: e.to_string(),
            })?;

        Ok(Self { child })
    }

    /// Kill the process (SIGKILL) and wait to reap the zombie.
    pub async fn kill(&mut self) {
        // best-effort — process may have already exited
        let _ = self.child.kill().await;
    }

    /// Check if the process is still running.
    pub fn try_wait(&mut self) -> Option<i32> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
            _ => None,
        }
    }

    /// Wait for the process to become ready (init delay), then verify it's still alive.
    /// Returns `Ok(())` if alive after delay, `Err(exit_code)` if it exited early.
    pub async fn wait_for_ready(&mut self, delay_ms: u64) -> Result<(), i32> {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        match self.try_wait() {
            Some(code) => Err(code),
            None => Ok(()),
        }
    }
}
