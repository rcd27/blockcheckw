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
            let u = nix::unistd::User::from_name(&user).ok()??;
            Some(u.dir)
        })
        .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
}

fn config_path() -> Option<PathBuf> {
    real_home().map(|h| h.join(".config/blockcheckw/config.json"))
}

/// ПАМЯТЬ ПРОШЛЫХ ЗАПУСКОВ ВО ВСТРОЕННОМ РЕЖИМЕ НЕ СУЩЕСТВУЕТ.
///
/// Глушится здесь, а не в точках вызова: их шесть, список полей открыт и растёт, и каждое
/// новое поле — новая молчаливая наследуемость, о которой вызывающий не узнает.
///
/// Оплачено 19.09.2026: подбор, поднятый продуктом, унаследовал `dns: doh` от ручного
/// прогона часом раньше. На коробке, где DoH-резолвер зовёт отсутствующий `curl`, это
/// означало падение на разрешении имени; продукт получил нечитаемый отчёт и молча ждал.
/// Человек в это время сидел под карантином.
fn memory_is_off() -> bool {
    crate::nfqws2::mark::is_embedded()
}

/// Load persisted config. Returns default on any error.
pub fn load() -> PersistedConfig {
    if memory_is_off() {
        return PersistedConfig::default();
    }
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
    if memory_is_off() {
        // Встроенный прогон не только не читает память, но и не пишет её: иначе ключи,
        // заданные продуктом, стали бы умолчанием следующего РУЧНОГО запуска человека.
        return;
    }
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

#[cfg(test)]
mod embedded_memory_tests {
    use super::*;

    /// Тот же замок, что у соседей по встроенности: режим — один статик на процесс.
    static EMBEDDED_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// ВО ВСТРОЕННОМ РЕЖИМЕ ПАМЯТИ НЕТ. Проверяется на ЗАВЕДОМО ПОРЧЕНОЙ памяти: `workers: 0`
    /// повесил бы прогон навсегда (семафор не выдаст ни одного разрешения) уже ПОСЛЕ того,
    /// как правила легли в ядро, а `dns: doh` на коробке без `curl` роняет разрешение имени.
    #[test]
    fn an_embedded_run_inherits_nothing_from_a_previous_one() {
        let _guard = EMBEDDED_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        crate::nfqws2::mark::set_embedded(true);
        let loaded = load();
        crate::nfqws2::mark::set_embedded(false);

        assert!(loaded.dns.is_none(), "режим DNS не наследуется");
        assert!(loaded.workers.is_none(), "число воркеров не наследуется");
        assert!(loaded.domain.is_none(), "домен не наследуется");
        assert!(loaded.domain_list.is_none());
        assert!(loaded.protocols.is_none());
    }

    /// И не пишет: ключи, заданные продуктом, не смеют стать умолчанием следующего ручного
    /// запуска человека.
    #[test]
    fn an_embedded_run_leaves_no_memory_behind() {
        let _guard = EMBEDDED_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let before = config_path().and_then(|p| std::fs::read_to_string(p).ok());

        crate::nfqws2::mark::set_embedded(true);
        save(&PersistedConfig {
            dns: Some("doh".to_string()),
            workers: Some(0),
            ..Default::default()
        });
        crate::nfqws2::mark::set_embedded(false);

        let after = config_path().and_then(|p| std::fs::read_to_string(p).ok());
        assert_eq!(
            before, after,
            "встроенный прогон не смеет трогать память человека"
        );
    }
}
