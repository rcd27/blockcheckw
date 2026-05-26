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

/// Инициализация: stderr-`fmt` всегда + OTLP-слой, если задан endpoint.
/// Возвращает provider-guard (флаш при Drop).
pub fn init() -> Option<opentelemetry_sdk::trace::TracerProvider> {
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    match std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok() {
        None => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
            None
        }
        Some(_) => {
            opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .build()
                .expect("OTLP exporter");
            let provider = opentelemetry_sdk::trace::TracerProvider::builder()
                .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
                .with_resource(opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", SERVICE_NAME),
                ]))
                .build();
            let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, SERVICE_NAME);
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            tracing_subscriber::registry()
                .with(env_filter)
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
