use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Remembered CLI defaults. All fields optional — missing = use hardcoded default.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PersistedConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workers: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
}

/// Resolve the real user's home directory (not /root when running under sudo).
fn real_home() -> Option<PathBuf> {
    std::env::var("SUDO_USER")
        .ok()
        .and_then(|user| {
            let c_user = std::ffi::CString::new(user).ok()?;
            // Safety: getpwnam is POSIX, returns null on failure.
            let pw = unsafe { libc::getpwnam(c_user.as_ptr()) };
            if pw.is_null() {
                return None;
            }
            let home = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
            Some(PathBuf::from(home.to_string_lossy().into_owned()))
        })
        .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
}

fn config_path() -> Option<PathBuf> {
    real_home().map(|h| h.join(".config/blockcheckw/config.json"))
}

/// Load persisted config. Returns default on any error.
pub fn load() -> PersistedConfig {
    let path = match config_path() {
        Some(p) => p,
        None => return PersistedConfig::default(),
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return PersistedConfig::default(),
    };
    serde_json::from_str(&data).unwrap_or_default()
}

/// Save persisted config. Non-fatal — logs warning on error.
pub fn save(config: &PersistedConfig) {
    let path = match config_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("  warning: cannot create config dir: {e}");
            return;
        }
    }
    let json = match serde_json::to_string_pretty(config) {
        Ok(j) => j,
        Err(_) => return,
    };
    // Atomic write: tmp file + rename
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, &json) {
        eprintln!("  warning: cannot write config: {e}");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        eprintln!("  warning: cannot save config: {e}");
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    // chown to real user if under sudo (both dir and file)
    if let Some(parent) = path.parent() {
        if let Some(dir_str) = parent.to_str() {
            crate::system::elevate::chown_to_caller(dir_str);
        }
    }
    if let Some(path_str) = path.to_str() {
        crate::system::elevate::chown_to_caller(path_str);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let config = PersistedConfig {
            workers: Some(1024),
            domain: Some("rutracker.org".to_string()),
            domain_list: None,
            dns: Some("doh".to_string()),
            protocols: Some(vec!["tls12".to_string()]),
        };
        let json = serde_json::to_string(&config).unwrap();
        let loaded: PersistedConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.workers, Some(1024));
        assert_eq!(loaded.domain.as_deref(), Some("rutracker.org"));
        assert!(loaded.domain_list.is_none());
        assert_eq!(loaded.dns.as_deref(), Some("doh"));
    }

    #[test]
    fn partial_config() {
        let json = r#"{"workers": 512}"#;
        let config: PersistedConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.workers, Some(512));
        assert!(config.domain.is_none());
        assert!(config.dns.is_none());
    }

    #[test]
    fn empty_json() {
        let config: PersistedConfig = serde_json::from_str("{}").unwrap();
        assert!(config.workers.is_none());
    }

    #[test]
    fn corrupt_json_returns_default() {
        let config: PersistedConfig = serde_json::from_str("not json").unwrap_or_default();
        assert!(config.workers.is_none());
    }

    #[test]
    fn skip_none_fields_in_json() {
        let config = PersistedConfig {
            workers: Some(1024),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("domain"));
        assert!(!json.contains("dns"));
        assert!(json.contains("1024"));
    }
}
