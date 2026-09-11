use std::sync::Arc;

use crate::config::{CoreConfig, Protocol};
use crate::error::{BlockcheckError, HttpVerdictAvailable, TaskResult};
use crate::network::http_client::{
    http_test, http_test_data, interpret_data_transfer_result, interpret_http_result,
    pick_random_ip, BodyMode, HttpVerdict, ROOT_PATH,
};
use crate::nfqws2::mark::ProfileMark;

#[derive(Debug, Clone, Copy, Default)]
pub enum HttpTestMode {
    /// Standard mode: HEAD for HTTPS, GET for HTTP
    #[default]
    Standard,
    /// Data transfer mode: GET with size_download check
    DataTransfer { min_bytes: u64 },
}

/// Одна проба одного профиля внутри уже поднятого инстанса.
///
/// Марка профиля, не слот воркера: `#68` перешёл на схему «один процесс — K
/// профилей», и старт/остановка nfqws2, а также правила диспетчеризации живут
/// теперь на уровне плана (`pipeline::runner`), а не здесь.
#[derive(Debug)]
pub struct ProbeTask {
    pub mark: ProfileMark,
    pub domain: Arc<str>,
    pub strategy_args: Vec<String>,
    pub protocol: Protocol,
    pub ips: Arc<[String]>,
}

/// Прогнать одну пробу под уже поднятым инстансом и уже стоящими правилами
/// диспетчеризации.
///
/// Ни старта, ни остановки nfqws2 здесь больше нет — процесс общий на весь
/// план и живёт снаружи, в `pipeline::runner::run_parallel`.
pub async fn probe_profile(
    config: &CoreConfig,
    task: &ProbeTask,
    mode: HttpTestMode,
) -> TaskResult {
    let ip = match pick_random_ip(&task.ips) {
        Some(ip) => ip,
        None => {
            return TaskResult::Error {
                error: BlockcheckError::DnsNoAddresses {
                    domain: task.domain.to_string(),
                },
            };
        }
    };

    let verdict = match mode {
        HttpTestMode::Standard => {
            let result = http_test(
                task.protocol,
                &task.domain,
                ip,
                task.mark.so_mark(),
                config.request_timeout,
                None,
            )
            .await;
            interpret_http_result(&result, &task.domain)
        }
        HttpTestMode::DataTransfer { min_bytes } => {
            let result = http_test_data(
                task.protocol,
                &task.domain,
                ip,
                task.mark.so_mark(),
                config.request_timeout,
                BodyMode::Unlimited,
                None,
                ROOT_PATH,
            )
            .await;
            interpret_data_transfer_result(&result, &task.domain, min_bytes)
        }
    };

    match verdict {
        HttpVerdict::Available => TaskResult::Success {
            verdict: HttpVerdictAvailable,
            strategy_args: task.strategy_args.clone(),
        },
        other => TaskResult::Failed { verdict: other },
    }
}
