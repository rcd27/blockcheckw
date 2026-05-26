//! OTLP-трейсинг blockcheckw (край IO). Экспорт env-gated. Если демон прислал
//! `TRACEPARENT` — span'ы становятся детьми его контекста (единый trace пути
//! домена). Иначе blockcheckw сам себе корень (ручной `scan | check`).

use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

const SERVICE_NAME: &str = "blockcheckw";

/// Родительский контекст из строки `traceparent` (для тестов и из env).
pub fn parent_context_from_str(tp: Option<String>) -> opentelemetry::Context {
    let mut carrier = std::collections::HashMap::new();
    if let Some(tp) = tp {
        carrier.insert("traceparent".to_string(), tp);
    }
    TraceContextPropagator::new().extract(&carrier)
}

/// Родительский контекст из env `TRACEPARENT`.
pub fn parent_context_from_env() -> opentelemetry::Context {
    parent_context_from_str(std::env::var("TRACEPARENT").ok())
}

/// Привязывает span к родителю из `TRACEPARENT` — ТОЛЬКО если контекст валиден.
/// Пустой контекст (standalone, нет env) НЕ устанавливаем: `set_parent(empty)`
/// отвязывает span от его tracing-родителя и выдаёт новый trace_id → дерево
/// разлетается по отдельным одно-span'овым трейсам. Без вызова span остаётся
/// под своим естественным tracing-родителем (единый trace и в standalone).
pub fn set_parent_from_env(span: &tracing::Span) {
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let cx = parent_context_from_env();
    if cx.span().span_context().is_valid() {
        span.set_parent(cx);
    }
}

/// Инициализация: stderr-`fmt` всегда + OTLP-слой, если задан endpoint и
/// экспортёр собрался. Фильтры пер-слойные: stderr на унаследованном RUST_LOG
/// (тихий), OTLP форсит `blockcheckw=info`. Возвращает provider-guard; флаш —
/// явным `force_flush` в конце main (Drop провайдера НЕ флашит batch-буфер в
/// opentelemetry_sdk 0.27).
pub fn init() -> Option<opentelemetry_sdk::trace::TracerProvider> {
    use tracing_subscriber::Layer;

    // stderr остаётся на унаследованном RUST_LOG (дефолт warn) — интерактивный
    // вывод не зашумляем INFO-событиями blockcheckw.
    let stderr_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(stderr_filter);

    // Телеметрия best-effort: нет endpoint'а → без OTLP; ошибка сборки экспортёра
    // (битый endpoint) НЕ роняет процесс, а откатывает на stderr-only.
    let exporter = match std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok() {
        None => None,
        Some(_) => match opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .build()
        {
            Ok(e) => Some(e),
            Err(e) => {
                eprintln!("OTEL: OTLP-экспортёр не собрался ({e:?}); трейсинг отключён");
                None
            }
        },
    };

    match exporter {
        None => {
            tracing_subscriber::registry().with(fmt_layer).init();
            None
        }
        Some(exporter) => {
            opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
            let provider = opentelemetry_sdk::trace::TracerProvider::builder()
                .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
                .with_resource(opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", SERVICE_NAME),
                ]))
                .build();
            let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, SERVICE_NAME);
            // Форсим blockcheckw=info ТОЛЬКО для OTLP-слоя: демон отдаёт
            // RUST_LOG=nevod=debug,reflex_linux=info без директивы для target
            // `blockcheckw` → иначе span'ы режутся до экспорта. На stderr это
            // не влияет (у fmt-слоя свой фильтр).
            let otel_filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn"))
                .add_directive("blockcheckw=info".parse().unwrap());
            let otel_layer = tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_filter(otel_filter);
            tracing_subscriber::registry()
                .with(fmt_layer)
                .with(otel_layer)
                .init();
            Some(provider)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceContextExt;

    #[test]
    fn parent_extracted_from_traceparent_string() {
        let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let cx = parent_context_from_str(Some(tp.to_string()));
        let span = cx.span();
        let sc = span.span_context();
        assert!(sc.is_valid(), "валидный traceparent → валидный контекст");
        assert_eq!(
            format!("{:032x}", sc.trace_id()),
            "0af7651916cd43dd8448eb211c80319c"
        );
    }

    #[test]
    fn no_traceparent_yields_empty_context() {
        let cx = parent_context_from_str(None);
        assert!(!cx.span().span_context().is_valid());
    }
}
