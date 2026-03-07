/// HTTP/2 cleartext (h2c) outgoing request support.
///
/// This module provides an alternative `send_request` implementation that uses
/// HTTP/2 prior-knowledge (h2c) for outgoing plaintext connections, which is
/// required for gRPC communication between WASM components and backend services.
///
/// When `WASMTIME_HTTP_PROXY_SERVER_MODE` is set to `"http2"` or `"h2"`, the
/// shim switches outgoing requests to use this h2c handler. The default behavior
/// (HTTP/1.1) is preserved otherwise.
///
/// HTTP/2 connections are pooled per authority (host:port) so that multiple
/// requests to the same backend multiplex over a single TCP connection, avoiding
/// per-request handshake overhead and worker-task accumulation.
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use wasmtime_wasi::runtime::AbortOnDropJoinHandle;
use wasmtime_wasi_http::bindings::http::types as wasi_http_types;
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::types::{HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig};
use wasmtime_wasi_http::hyper_request_error;

/// A pooled HTTP/2 connection: the sender for multiplexing requests and the
/// background driver task that actually reads/writes on the TCP socket.
/// The driver handle MUST be kept alive — dropping it aborts the task and
/// kills the connection (`AbortOnDropJoinHandle`).
struct PooledConnection {
    sender: SendRequest<HyperOutgoingBody>,
    _driver: AbortOnDropJoinHandle<()>,
}

/// Global connection pool: maps authority (host:port) → reusable HTTP/2 connection.
static H2_POOL: LazyLock<Mutex<HashMap<String, PooledConnection>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Establish (or reuse) an h2c connection to `authority` and return a cloned sender.
async fn get_or_connect_h2(
    authority: &str,
    connect_timeout: Duration,
) -> Result<SendRequest<HyperOutgoingBody>, wasi_http_types::ErrorCode> {
    // Fast path: reuse an existing, still-ready connection.
    {
        let pool = H2_POOL.lock().await;
        if let Some(entry) = pool.get(authority) {
            if entry.sender.is_ready() {
                log::info!("h2c pool: reusing connection to {authority}");
                return Ok(entry.sender.clone());
            }
            // Connection is no longer usable; fall through to create a new one.
            log::info!("h2c pool: stale connection to {authority}, reconnecting");
        }
    }

    // Slow path: open a new TCP connection + HTTP/2 handshake.
    log::info!("h2c pool: opening new TCP connection to {authority}");
    let tcp_stream = timeout(connect_timeout, TcpStream::connect(authority))
        .await
        .map_err(|_| {
            log::error!("h2c: TCP connect timeout to {authority}");
            wasi_http_types::ErrorCode::ConnectionTimeout
        })?
        .map_err(|e| {
            log::error!("h2c: TCP connect error to {authority}: {e}");
            match e.kind() {
            std::io::ErrorKind::AddrNotAvailable => {
                wasi_http_types::ErrorCode::DnsError(wasi_http_types::DnsErrorPayload {
                    rcode: Some("address not available".to_string()),
                    info_code: Some(0),
                })
            }
            _ => {
                if e.to_string()
                    .starts_with("failed to lookup address information")
                {
                    wasi_http_types::ErrorCode::DnsError(wasi_http_types::DnsErrorPayload {
                        rcode: Some("address not available".to_string()),
                        info_code: Some(0),
                    })
                } else {
                    wasi_http_types::ErrorCode::ConnectionRefused
                }
            }
        }})?;

    log::info!("h2c: TCP connected to {authority} (peer={:?})", tcp_stream.peer_addr());

    // Disable Nagle's algorithm — critical for gRPC's small, latency-sensitive frames.
    tcp_stream.set_nodelay(true).ok();

    let stream = TokioIo::new(tcp_stream);
    log::info!("h2c: starting HTTP/2 handshake to {authority}");
    let (sender, conn) = timeout(
        connect_timeout,
        hyper::client::conn::http2::handshake(TokioExecutor::new(), stream),
    )
    .await
    .map_err(|_| {
        log::error!("h2c: HTTP/2 handshake timeout to {authority}");
        wasi_http_types::ErrorCode::ConnectionTimeout
    })?
    .map_err(|e| {
        log::error!("h2c: HTTP/2 handshake error to {authority}: {e:?}");
        hyper_request_error(e)
    })?;

    log::info!("h2c: HTTP/2 handshake complete to {authority}");

    // Drive the connection in the background; clean up pool entry on close.
    // IMPORTANT: The driver handle MUST be stored in the pool — dropping an
    // AbortOnDropJoinHandle aborts the task, which would kill the connection.
    let key = authority.to_string();
    let driver = wasmtime_wasi::runtime::spawn({
        let key = key.clone();
        async move {
            if let Err(e) = conn.await {
                log::warn!("h2c pool: connection to {key} closed with error: {e}");
            } else {
                log::info!("h2c pool: connection to {key} closed cleanly");
            }
            H2_POOL.lock().await.remove(&key);
        }
    });

    H2_POOL.lock().await.insert(
        key,
        PooledConnection {
            sender: sender.clone(),
            _driver: driver,
        },
    );

    log::debug!("h2c pool: new connection to {authority}");
    Ok(sender)
}

/// Send an outgoing HTTP request using h2c (HTTP/2 cleartext prior-knowledge).
///
/// This is the h2c counterpart to [`wasmtime_wasi_http::types::default_send_request`].
/// It spawns an async task that performs the actual request via [`h2c_send_request_handler`].
pub fn h2c_send_request(
    request: hyper::Request<HyperOutgoingBody>,
    config: OutgoingRequestConfig,
) -> HostFutureIncomingResponse {
    let handle = wasmtime_wasi::runtime::spawn(async move {
        Ok(h2c_send_request_handler(request, config).await)
    });
    HostFutureIncomingResponse::pending(handle)
}

/// The underlying h2c request handler. Should be spawned in a task.
///
/// For non-TLS connections, this reuses (or creates) a pooled HTTP/2
/// prior-knowledge connection to the target authority.
///
/// For TLS connections, falls back to HTTP/1.1 (same as default behavior),
/// since TLS+HTTP/2 typically negotiates via ALPN rather than prior-knowledge.
async fn h2c_send_request_handler(
    mut request: hyper::Request<HyperOutgoingBody>,
    OutgoingRequestConfig {
        use_tls,
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
    }: OutgoingRequestConfig,
) -> Result<IncomingResponse, wasi_http_types::ErrorCode> {
    let authority = if let Some(authority) = request.uri().authority() {
        if authority.port().is_some() {
            authority.to_string()
        } else {
            let port = if use_tls { 443 } else { 80 };
            format!("{}:{port}", authority)
        }
    } else {
        return Err(wasi_http_types::ErrorCode::HttpRequestUriInvalid);
    };

    log::info!("h2c_send_request_handler: authority={}, use_tls={}", authority, use_tls);

    // Strip scheme and authority from the URI — the HTTP packet should only
    // contain path+query when not addressing a proxy.
    *request.uri_mut() = http::Uri::builder()
        .path_and_query(
            request
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/"),
        )
        .build()
        .expect("comes from valid request");

    if use_tls {
        // For TLS, fall back to HTTP/1.1 (same as default wasmtime behavior).
        // TLS + HTTP/2 would require ALPN negotiation which is out of scope here.
        log::warn!(
            "h2c mode requested but connection uses TLS; falling back to HTTP/1.1 for {}",
            authority
        );

        let tcp_stream = timeout(connect_timeout, TcpStream::connect(&authority))
            .await
            .map_err(|_| wasi_http_types::ErrorCode::ConnectionTimeout)?
            .map_err(|_| wasi_http_types::ErrorCode::ConnectionRefused)?;

        // Disable Nagle for low-latency responses even on the TLS fallback path.
        tcp_stream.set_nodelay(true).ok();

        let stream = TokioIo::new(tcp_stream);
        let (mut sender, conn) = timeout(
            connect_timeout,
            hyper::client::conn::http1::handshake(stream),
        )
        .await
        .map_err(|_| wasi_http_types::ErrorCode::ConnectionTimeout)?
        .map_err(hyper_request_error)?;

        let worker = wasmtime_wasi::runtime::spawn(async move {
            if let Err(e) = conn.await {
                log::warn!("h2c: dropping HTTP/1.1 TLS connection error: {e}");
            }
        });

        let resp = timeout(first_byte_timeout, sender.send_request(request))
            .await
            .map_err(|_| wasi_http_types::ErrorCode::ConnectionReadTimeout)?
            .map_err(hyper_request_error)?
            .map(|body| body.map_err(hyper_request_error).boxed());

        Ok(IncomingResponse {
            resp,
            worker: Some(worker),
            between_bytes_timeout,
        })
    } else {
        // HTTP/2 prior-knowledge (h2c) with connection pooling.
        log::info!("h2c: getting/creating connection to {authority}");
        let mut sender = get_or_connect_h2(&authority, connect_timeout).await?;

        log::info!(
            "h2c: sending request to {authority}: method={}, uri={}, headers={:?}",
            request.method(),
            request.uri(),
            request.headers().keys().map(|k| k.as_str()).collect::<Vec<_>>(),
        );

        let resp = timeout(first_byte_timeout, sender.send_request(request))
            .await
            .map_err(|_| {
                log::error!("h2c: send_request timeout to {authority} (first_byte_timeout={first_byte_timeout:?})");
                wasi_http_types::ErrorCode::ConnectionReadTimeout
            })?
            .map_err(|e| {
                log::error!("h2c: send_request error to {authority}: {e:?}");
                hyper_request_error(e)
            })?
            .map(|body| body.map_err(hyper_request_error).boxed());

        log::info!("h2c: got response from {authority}: status={}", resp.status());

        // No per-request worker needed — the pool's background task drives the connection.
        Ok(IncomingResponse {
            resp,
            worker: None,
            between_bytes_timeout,
        })
    }
}
