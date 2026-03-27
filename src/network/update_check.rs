use std::time::Duration;

const GITHUB_API_URL: &str = "https://api.github.com/repos/rcd27/blockcheckw/releases/latest";
const TIMEOUT: Duration = Duration::from_secs(3);

/// Fetched release info from GitHub.
pub struct ReleaseInfo {
    pub tag: String,
}

/// Check GitHub for a newer release. Returns `Some(ReleaseInfo)` if a newer
/// version exists, `None` if current is up-to-date or the check failed.
pub async fn check_latest_release(current_version: &str) -> Option<ReleaseInfo> {
    let tag = fetch_latest_tag().await?;

    let remote = normalize_version(&tag);
    let local = normalize_version(current_version);

    if version_gt(&remote, &local) {
        Some(ReleaseInfo { tag })
    } else {
        None
    }
}

/// Fetch the `tag_name` field from GitHub releases/latest.
async fn fetch_latest_tag() -> Option<String> {
    use crate::system::process::run_process;

    // Use curl — available on all targets, no extra dependencies.
    let result = run_process(
        &[
            "curl",
            "-fsSL",
            "--max-time",
            "3",
            "-H",
            "Accept: application/vnd.github+json",
            GITHUB_API_URL,
        ],
        TIMEOUT.as_millis() as u64 + 500, // small buffer over curl's own timeout
    )
    .await
    .ok()?;

    if result.exit_code != 0 {
        return None;
    }

    // Minimal JSON parsing — avoid pulling in a JSON parser just for one field.
    // Looking for: "tag_name": "v0.9.0"
    result
        .stdout
        .lines()
        .find(|line| line.contains("\"tag_name\""))
        .and_then(|line| {
            let parts: Vec<&str> = line.split('"').collect();
            // "tag_name": "v0.9.0" → parts = ["", "tag_name", ": ", "v0.9.0", ","]
            parts.get(3).map(|s| s.to_string())
        })
}

/// Strip leading 'v' and split into numeric parts.
fn normalize_version(v: &str) -> Vec<u32> {
    v.trim_start_matches('v')
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// True if `a` is strictly greater than `b` (semantic version comparison).
fn version_gt(a: &[u32], b: &[u32]) -> bool {
    let len = a.len().max(b.len());
    for i in 0..len {
        let va = a.get(i).copied().unwrap_or(0);
        let vb = b.get(i).copied().unwrap_or(0);
        if va > vb {
            return true;
        }
        if va < vb {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version() {
        assert_eq!(normalize_version("v0.8.1"), vec![0, 8, 1]);
        assert_eq!(normalize_version("0.9.0"), vec![0, 9, 0]);
        assert_eq!(normalize_version("v1.0"), vec![1, 0]);
    }

    #[test]
    fn test_version_gt() {
        assert!(version_gt(&[0, 9, 0], &[0, 8, 1]));
        assert!(version_gt(&[1, 0, 0], &[0, 99, 99]));
        assert!(!version_gt(&[0, 8, 1], &[0, 8, 1]));
        assert!(!version_gt(&[0, 8, 0], &[0, 8, 1]));
        assert!(version_gt(&[0, 8, 1, 1], &[0, 8, 1]));
    }

    #[test]
    fn test_version_gt_equal() {
        assert!(!version_gt(&[1, 0], &[1, 0, 0]));
    }
}
