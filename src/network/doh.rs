use crate::error::BlockcheckError;
use crate::network::dns::is_ipv4;
use crate::network::http_client;
use crate::nfqws2::mark::ProbeMark;

const DOH_TIMEOUT_MS: u64 = 6_000;

/// Потолок ответа резолвера. Ответ на один вопрос типа A — сотни байт; всё, что больше,
/// мы читать не обязаны, а доверять чужому размеру не должны.
const DOH_BODY_LIMIT: usize = 64 * 1024;

/// DoH-резолвер: ИМЯ для SNI и АДРЕС, по которому к нему идти.
///
/// Адрес литералом, потому что иначе разрешение имени резолвера упёрлось бы в само себя —
/// а системного резолвера, которому можно верить, у нас по условию задачи нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DohServer {
    pub host: &'static str,
    pub ip: &'static str,
    pub path: &'static str,
}

const DOH_SERVERS: &[DohServer] = &[
    DohServer {
        host: "cloudflare-dns.com",
        ip: "1.1.1.1",
        path: "/dns-query",
    },
    DohServer {
        host: "dns.google",
        ip: "8.8.8.8",
        path: "/dns-query",
    },
    DohServer {
        host: "dns.quad9.net",
        ip: "9.9.9.9",
        path: "/dns-query",
    },
];

/// Разрешить имя через DoH СВОИМ помеченным сокетом.
///
/// Прежде здесь запускался внешний `curl`, и это было дважды неверно. Во-первых, чужому
/// процессу не поставить `SO_MARK`: запросы имени уходили немаркированными — тем же путём,
/// что трафик человека, то есть прямиком в карантин хозяина ядра, и прибор оказывался внутри
/// мира, который меряет. Во-вторых, на боевой коробке `curl` вообще нет (замер 20.09.2026:
/// есть `nslookup` и `uclient-fetch`), поэтому DoH там не работал НИКОГДА и молча — а вместе
/// с ним молча не работала и проверка подмены DNS, сообщая при этом «подмены нет».
///
/// `uclient-fetch` вместо `curl` не годится по первой же причине: он тоже чужой процесс.
pub async fn doh_resolve(domain: &str, server: &DohServer) -> Option<Vec<String>> {
    // Имя едет в URL, и кроме букв, цифр, точки и дефиса там взяться нечему (DNS-имена
    // ASCII). Проверка — не формальность: иначе домен с `&` подменил бы параметры запроса.
    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }

    let path = format!("{}?name={domain}&type=A", server.path);
    let body = http_client::fetch_https_body(
        server.ip,
        server.host,
        &path,
        "application/dns-json",
        ProbeMark::Control.so_mark(),
        std::time::Duration::from_millis(DOH_TIMEOUT_MS),
        DOH_BODY_LIMIT,
    )
    .await
    .ok()?;

    Some(parse_doh_response(&body))
}

/// Parse DoH JSON response, extract IPv4 addresses from "data" fields.
fn parse_doh_response(json: &str) -> Vec<String> {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#""data"\s*:\s*"([^"]+)""#).expect("static regex")
    });
    let re = &*RE;
    re.captures_iter(json)
        .filter_map(|cap| {
            let value = cap.get(1)?.as_str();
            if is_ipv4(value) {
                Some(value.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Try each DoH server with a test query (iana.org) and return the first working one.
pub async fn find_working_doh_server() -> Option<&'static DohServer> {
    for server in DOH_SERVERS {
        if let Some(ips) = doh_resolve("iana.org", server).await {
            if !ips.is_empty() {
                return Some(server);
            }
        }
    }
    None
}

/// Resolve domain via DoH. Finds a working server automatically, then resolves.
pub async fn resolve_ipv4_doh(domain: &str) -> Result<Vec<String>, BlockcheckError> {
    let server =
        find_working_doh_server()
            .await
            .ok_or_else(|| BlockcheckError::DnsResolveFailed {
                domain: domain.to_string(),
                reason: "no DoH servers reachable".to_string(),
            })?;

    let ips =
        doh_resolve(domain, server)
            .await
            .ok_or_else(|| BlockcheckError::DnsResolveFailed {
                domain: domain.to_string(),
                reason: format!("DoH query to {} failed", server.host),
            })?;

    if ips.is_empty() {
        return Err(BlockcheckError::DnsNoAddresses {
            domain: domain.to_string(),
        });
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// СТОРОЖ ПЕРЕЕЗДА. Резолв не смеет уходить чужому процессу: марку ему не поставить, и
    /// запросы имени пойдут тем же путём, что трафик человека, — в карантин хозяина ядра.
    /// Вдобавок на боевой коробке внешнего клиента может просто не быть (`curl` там нет), и
    /// тогда DoH отказывает молча, а вместе с ним молча отказывает проверка подмены DNS.
    ///
    /// ЦЕНА СТОРОЖА НАЗВАНА: он проверяет, что мы никого не ЗАПУСКАЕМ, а не что сокет
    /// помечен. Маркировку свидетельствует `so_mark_set_on_socket` в `tests/e2e_infra.rs`.
    #[test]
    fn the_resolver_never_shells_out() {
        const SOURCE: &str = include_str!("doh.rs");
        let body = SOURCE
            .split("mod tests {")
            .next()
            .expect("тестовый модуль отделён от тела");

        // Ищем МЕХАНИЗМЫ запуска, а не имена программ: первая редакция искала «curl» и
        // «uclient-fetch» и покраснела на собственном комментарии, где они упомянуты. Имя
        // программы — проза, а через эти два выражения проходит любой внешний вызов.
        for forbidden in ["run_process", "Command::new"] {
            assert!(
                !body.contains(forbidden),
                "резолвер зовёт внешнюю программу ({forbidden}): марку чужому процессу не \
                 поставить, и запрос имени уйдёт немаркированным"
            );
        }
    }

    /// Адреса резолверов — литералы: разрешать имя резолвера через резолвер значит
    /// упереться в само себя, а системному резолверу мы по условию задачи не верим.
    #[test]
    fn every_resolver_is_reachable_without_resolving_anything() {
        for server in DOH_SERVERS {
            assert!(
                crate::network::dns::is_ipv4(server.ip),
                "{}: адрес обязан быть литералом, а не именем",
                server.host
            );
            assert!(!server.host.is_empty(), "имя нужно для SNI");
        }
    }

    #[test]
    fn test_parse_doh_response_cloudflare() {
        let json = r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"rutracker.org","type":1}],"Answer":[{"name":"rutracker.org","type":1,"TTL":300,"data":"172.67.182.217"},{"name":"rutracker.org","type":1,"TTL":300,"data":"104.21.32.39"}]}"#;
        let ips = parse_doh_response(json);
        assert_eq!(ips, vec!["172.67.182.217", "104.21.32.39"]);
    }

    #[test]
    fn test_parse_doh_response_cname() {
        // CNAME records have non-IP data, should be filtered out
        let json = r#"{"Answer":[{"name":"www.example.com","type":5,"TTL":300,"data":"example.com"},{"name":"example.com","type":1,"TTL":300,"data":"93.184.216.34"}]}"#;
        let ips = parse_doh_response(json);
        assert_eq!(ips, vec!["93.184.216.34"]);
    }

    #[test]
    fn test_parse_doh_response_empty() {
        let json = r#"{"Status":3,"Answer":[]}"#;
        let ips = parse_doh_response(json);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_parse_doh_response_no_answer() {
        let json = r#"{"Status":3}"#;
        let ips = parse_doh_response(json);
        assert!(ips.is_empty());
    }
}
