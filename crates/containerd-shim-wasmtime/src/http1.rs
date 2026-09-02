//! HTTP/1.1 keep-alive outgoing connection pool — the REST middleware.
//!
//! Implements [`OutboundMiddleware`] for plaintext HTTP/1.1. Unlike h2c, HTTP/1
//! is **not** multiplexed: one connection carries one in-flight request at a
//! time, so the pool keeps several idle keep-alive connections per authority and
//! checks one out per request, returning it once the response body is fully
//! read.
//!
//! Rather than hand-roll that checkout / check-in-after-body dance, this wraps
//! [`hyper_util`]'s battle-tested legacy [`Client`], which pools by authority,
//! drives connections, and recycles a connection only when it is safely back at
//! a message boundary. We keep the [`IncomingResponse`] shape the rest of the
//! shim expects and apply the request's first-byte timeout.
//!
//! Socket tuning (`TCP_NODELAY`, `SO_KEEPALIVE`) and pool sizing
//! (`pool_max_idle_per_host`, `pool_idle_timeout`) come from the shim's
//! [`PoolTuning`](crate::outbound::PoolTuning).

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::sync::LazyLock;
use tokio::time::timeout;
use wasmtime_wasi_http::bindings::http::types as wasi_http_types;
use wasmtime_wasi_http::hyper_request_error;
use wasmtime_wasi_http::types::{
    HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig,
};

use crate::outbound::{self, OutboundMiddleware, OutgoingRequest, PoolTuning};

/// Boxed error so the request body satisfies the legacy `Client` body bound
/// (`B::Error: Into<Box<dyn Error>>`) without requiring `ErrorCode: Error`.
type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ClientBody = BoxBody<Bytes, BoxError>;

/// Process-global pooled HTTP/1.1 client. Built lazily from the shim's pool
/// tuning (installed before the first request is served).
static H1_CLIENT: LazyLock<Client<HttpConnector, ClientBody>> = LazyLock::new(|| {
    let t = outbound::tuning();
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_keepalive(Some(t.keepalive_time));
    // Plaintext only — TLS requests are routed to the default sender upstream.
    connector.enforce_http(true);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(t.idle_timeout)
        .pool_max_idle_per_host(t.max_idle_per_host)
        .build(connector)
});

/// Pooled HTTP/1.1 keep-alive middleware for plaintext REST traffic.
pub(crate) struct Http1Pool;

impl Http1Pool {
    pub(crate) fn new() -> Self {
        Http1Pool
    }
}

impl OutboundMiddleware for Http1Pool {
    fn send(
        &self,
        request: OutgoingRequest,
        config: OutgoingRequestConfig,
        _tuning: &PoolTuning,
    ) -> HostFutureIncomingResponse {
        let handle = wasmtime_wasi::runtime::spawn(async move {
            Ok(http1_send_handler(request, config).await)
        });
        HostFutureIncomingResponse::pending(handle)
    }
}

async fn http1_send_handler(
    request: OutgoingRequest,
    config: OutgoingRequestConfig,
) -> Result<IncomingResponse, wasi_http_types::ErrorCode> {
    // Map the request body's error to a boxed std error to satisfy the legacy
    // Client's body bound; the response body is mapped back to `ErrorCode`.
    let request = request.map(|body| {
        body.map_err(|e| -> BoxError { format!("{e:?}").into() }).boxed()
    });

    let resp = timeout(config.first_byte_timeout, H1_CLIENT.request(request))
        .await
        .map_err(|_| {
            log::error!(
                "http1 pool: request timeout (first_byte_timeout={:?})",
                config.first_byte_timeout
            );
            wasi_http_types::ErrorCode::ConnectionReadTimeout
        })?
        .map_err(|e| {
            log::error!("http1 pool: request error: {e}");
            if e.is_connect() {
                wasi_http_types::ErrorCode::ConnectionRefused
            } else {
                wasi_http_types::ErrorCode::InternalError(Some(e.to_string()))
            }
        })?
        .map(|body| body.map_err(hyper_request_error).boxed());

    // No worker — the legacy Client drives the connection and recycles it to the
    // pool once the response body is consumed.
    Ok(IncomingResponse {
        resp,
        worker: None,
        between_bytes_timeout: config.between_bytes_timeout,
    })
}
