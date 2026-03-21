use std::fmt;

use crate::system::process::run_process;

pub struct IpInfo {
    pub ip: String,
    pub org: String,
    pub city: String,
    pub region: String,
    pub country: String,
}

impl fmt::Display for IpInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} | {} | {}, {}, {}",
            self.org, self.ip, self.city, self.region, self.country
        )
    }
}

/// Extract a string field from simple JSON without regex.
/// Matches `"field": "value"` or `"field":"value"`.
fn extract_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{field}\"");
    let key_pos = json.find(&key)?;
    let after_key = &json[key_pos + key.len()..];
    // Skip optional whitespace and colon
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_ws = after_colon.trim_start();
    // Extract quoted value
    let value_start = after_ws.strip_prefix('"')?;
    let end = value_start.find('"')?;
    Some(value_start[..end].to_string())
}

/// Detect ISP info via `curl -s ipinfo.io`.
/// Returns `None` on any error (timeout, parse failure, etc).
pub async fn detect_ip_info() -> Option<IpInfo> {
    let result = run_process(&["curl", "-s", "--max-time", "3", "ipinfo.io"], 6000)
        .await
        .ok()?;

    if result.exit_code != 0 {
        return None;
    }

    let json = &result.stdout;
    Some(IpInfo {
        ip: extract_field(json, "ip")?,
        org: extract_field(json, "org").unwrap_or_else(|| "unknown".to_string()),
        city: extract_field(json, "city").unwrap_or_else(|| "unknown".to_string()),
        region: extract_field(json, "region").unwrap_or_else(|| "unknown".to_string()),
        country: extract_field(json, "country").unwrap_or_else(|| "unknown".to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JSON: &str = r#"{
  "ip": "1.2.3.4",
  "hostname": "example.com",
  "city": "Moscow",
  "region": "Moscow",
  "country": "RU",
  "loc": "55.7558,37.6173",
  "org": "AS1234 Rostelecom",
  "postal": "101000",
  "timezone": "Europe/Moscow"
}"#;

    #[test]
    fn extract_field_ip() {
        assert_eq!(extract_field(SAMPLE_JSON, "ip").unwrap(), "1.2.3.4");
    }

    #[test]
    fn extract_field_org() {
        assert_eq!(
            extract_field(SAMPLE_JSON, "org").unwrap(),
            "AS1234 Rostelecom"
        );
    }

    #[test]
    fn extract_field_city() {
        assert_eq!(extract_field(SAMPLE_JSON, "city").unwrap(), "Moscow");
    }

    #[test]
    fn extract_field_missing() {
        assert!(extract_field(SAMPLE_JSON, "nonexistent").is_none());
    }

    #[test]
    fn display_format() {
        let info = IpInfo {
            ip: "1.2.3.4".to_string(),
            org: "AS1234 Rostelecom".to_string(),
            city: "Moscow".to_string(),
            region: "Moscow".to_string(),
            country: "RU".to_string(),
        };
        assert_eq!(
            info.to_string(),
            "AS1234 Rostelecom | 1.2.3.4 | Moscow, Moscow, RU"
        );
    }
}
