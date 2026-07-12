use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Mutex;
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

#[derive(Default)]
struct BackgroundRegistry {
    shutting_down: bool,
    children: Vec<Weak<Mutex<tokio::process::Child>>>,
}

fn background_registry() -> &'static StdMutex<BackgroundRegistry> {
    static REGISTRY: OnceLock<StdMutex<BackgroundRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| StdMutex::new(BackgroundRegistry::default()))
}

/// Prevent new background children from being spawned during shutdown.
pub fn begin_background_shutdown() {
    background_registry().lock().unwrap().shutting_down = true;
}

fn registered_children() -> Vec<Arc<Mutex<tokio::process::Child>>> {
    let mut registry = background_registry().lock().unwrap();
    registry.shutting_down = true;
    registry.children.retain(|child| child.strong_count() > 0);
    registry.children.iter().filter_map(Weak::upgrade).collect()
}

/// Kill and reap every live child spawned through [`BackgroundProcess`].
pub async fn kill_all_background_processes() {
    for child in registered_children() {
        let _ = child.lock().await.kill().await;
    }
}

/// Best-effort synchronous kill initiation for panic hooks.
pub fn start_kill_all_background_processes() {
    for child in registered_children() {
        if let Ok(mut child) = child.try_lock() {
            let _ = child.start_kill();
        }
    }
}

/// A registered background process handle. Wraps a tokio process child.
pub struct BackgroundProcess {
    child: Arc<Mutex<tokio::process::Child>>,
}

impl BackgroundProcess {
    /// Spawn a background process with stdout/stderr → /dev/null.
    pub fn spawn(args: &[&str]) -> Result<Self, BlockcheckError> {
        let (program, cmd_args) =
            args.split_first()
                .ok_or_else(|| BlockcheckError::ProcessSpawn {
                    reason: "empty command".to_string(),
                })?;

        // Holding the registry lock across spawn makes registration atomic with
        // begin_background_shutdown(): cleanup cannot miss a concurrently
        // created child, and no child can start after shutdown begins.
        let mut registry = background_registry().lock().unwrap();
        if registry.shutting_down {
            return Err(BlockcheckError::ProcessSpawn {
                reason: "shutdown in progress".to_string(),
            });
        }

        let child = Command::new(program)
            .args(cmd_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| BlockcheckError::ProcessSpawn {
                reason: e.to_string(),
            })?;

        let child = Arc::new(Mutex::new(child));
        registry.children.retain(|child| child.strong_count() > 0);
        registry.children.push(Arc::downgrade(&child));

        Ok(Self { child })
    }

    /// Kill the process (SIGKILL) and wait to reap the zombie.
    pub async fn kill(&mut self) {
        // best-effort — process may have already exited
        let _ = self.child.lock().await.kill().await;
    }

    /// Check if the process is still running.
    pub async fn try_wait(&mut self) -> Option<i32> {
        match self.child.lock().await.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
            _ => None,
        }
    }

    /// Wait for the process to become ready (init delay), then verify it's still alive.
    /// Returns `Ok(())` if alive after delay, `Err(exit_code)` if it exited early.
    pub async fn wait_for_ready(&mut self, delay_ms: u64) -> Result<(), i32> {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        match self.try_wait().await {
            Some(code) => Err(code),
            None => Ok(()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_kills_registered_children_and_blocks_new_spawns() {
        let mut process = BackgroundProcess::spawn(&["sleep", "30"]).expect("spawn sleep");
        assert!(process.try_wait().await.is_none());

        kill_all_background_processes().await;

        assert!(process.try_wait().await.is_some());
        let error = BackgroundProcess::spawn(&["sleep", "30"])
            .err()
            .expect("spawn during shutdown must fail");
        assert!(error.to_string().contains("shutdown in progress"));
    }
}
