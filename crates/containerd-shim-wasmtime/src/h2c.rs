//! HTTP/2 cleartext (h2c) outgoing connection pool — the gRPC middleware.
//!
//! Implements [`OutboundMiddleware`] for plaintext HTTP/2 prior-knowledge,
//! required for gRPC calls between WASM guests and backend services.
//!
//! Connections are pooled per authority (`host:port`) in a process-wide static
//! so they survive the per-request wasm instance teardown and multiplex many
//! requests over one TCP connection, avoiding per-request handshake overhead.
//!
//! ## Correctness properties (and the bugs they replace)
//!
//! * **Single-flight per authority.** Each authority has its own slot lock held
//!   across dialing, so N concurrent first-requests to a cold backend open
//!   exactly one connection. The previous code let them all dial and `insert`
//!   into a shared map; the losers' connection drivers were
//!   `AbortOnDropJoinHandle`s that aborted mid-flight, killing connections that
//!   other in-flight requests had already cloned a sender from.
//! * **Liveness via `is_closed()`, not `is_ready()`.** `is_ready()` is `false`
//!   while a connection is merely *busy* (at the peer's `MAX_CONCURRENT_STREAMS`),
//!   so the old check discarded healthy multiplexed connections under load.
//! * **Bounded lifetime.** Connections age out (`PoolTuning::max_lifetime`) and
//!   re-dial, so traffic periodically rebalances across backend pods —
//!   kube-proxy load balances per *connection*, and a pinned long-lived h2
//!   connection otherwise sends every request to one pod and starves new
//!   replicas.
//! * **Graceful eviction.** The connection driver is a *detached* task (not
//!   abort-on-drop). Dropping a stale/aged sender lets in-flight requests drain
//!   and the connection close cleanly instead of being aborted.
//! * **Dead-peer detection.** `SO_KEEPALIVE` reaps connections to a silently
//!   departed peer (pod restart / scale-down) even while idle in the pool.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Instant;

use http_body_util::BodyExt;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use wasmtime_wasi::runtime::with_ambient_tokio_runtime;
use wasmtime_wasi_http::bindings::http::types as wasi_http_types;
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::hyper_request_error;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::types::{
    HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig,
};

use crate::outbound::{OutboundMiddleware, OutgoingRequest, PoolTuning};

/// Per-authority pool slot. The inner mutex is held while dialing so concurrent
/// requests to the same backend single-flight on it.
struct Slot {
    conn: Mutex<Option<LiveConn>>,
}

/// A live pooled connection: the multiplexing sender plus its birth time (for
/// lifetime-based eviction). The connection's driver task runs detached; it is
/// not stored here, so dropping a `LiveConn` never aborts an in-flight request.
struct LiveConn {
    sender: SendRequest<HyperOutgoingBody>,
    born: Instant,
}

/// Global pool: authority (`host:port`) → reusable HTTP/2 connection slot.
static H2_POOL: LazyLock<Mutex<HashMap<String, Arc<Slot>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Pooled HTTP/2-cleartext (h2c) middleware for plaintext gRPC traffic.
pub(crate) struct H2cPool;

impl H2cPool {
    pub(crate) fn new() -> Self {
        H2cPool
    }
}

impl OutboundMiddleware for H2cPool {
    fn send(
        &self,
        request: OutgoingRequest,
        config: OutgoingRequestConfig,
        tuning: &PoolTuning,
    ) -> HostFutureIncomingResponse {
        let tuning = *tuning;
        let handle = wasmtime_wasi::runtime::spawn(async move {
            Ok(h2c_send_request_handler(request, config, tuning).await)
        });
        HostFutureIncomingResponse::pending(handle)
    }
}

/// Establish (or reuse) an h2c connection to `authority` and return a cloned
/// sender. Concurrent callers for the same authority single-flight on the slot
/// lock.
async fn get_or_connect_h2(
    authority: &str,
    connect_timeout: std::time::Duration,
    tuning: &PoolTuning,
) -> Result<SendRequest<HyperOutgoingBody>, wasi_http_types::ErrorCode> {
    // Look up (or create) the per-authority slot. The outer map lock is held
    // only briefly — just to clone the slot handle.
    let slot = {
        let mut map = H2_POOL.lock().await;
        map.entry(authority.to_string())
            .or_insert_with(|| Arc::new(Slot { conn: Mutex::new(None) }))
            .clone()
    };

    // Hold the per-authority lock across the dial: this is the single-flight
    // point. Requests to *different* authorities use different slots and never
    // contend here.
    let mut guard = slot.conn.lock().await;

    if let Some(live) = guard.as_ref() {
        if !live.sender.is_closed() && live.born.elapsed() < tuning.max_lifetime {
            log::debug!("h2c pool: reusing connection to {authority}");
            return Ok(live.sender.clone());
        }
        // Closed or aged out. Dropping the old sender here is graceful: in-flight
        // requests keep their own sender clones and the detached driver drives
        // the connection until they finish, then it closes on its own.
        log::debug!("h2c pool: stale/aged connection to {authority}, reconnecting");
    }

    let sender = dial_h2c(authority, connect_timeout, tuning).await?;
    *guard = Some(LiveConn {
        sender: sender.clone(),
        born: Instant::now(),
    });
    Ok(sender)
}

/// Open a new TCP connection, tune the socket, perform the HTTP/2 handshake, and
/// spawn the (detached) connection driver.
async fn dial_h2c(
    authority: &str,
    connect_timeout: std::time::Duration,
    tuning: &PoolTuning,
) -> Result<SendRequest<HyperOutgoingBody>, wasi_http_types::ErrorCode> {
    log::debug!("h2c pool: opening new TCP connection to {authority}");
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
            }
        })?;

    log::debug!(
        "h2c: TCP connected to {authority} (peer={:?})",
        tcp_stream.peer_addr()
    );

    // Disable Nagle's algorithm — critical for gRPC's small, latency-sensitive frames.
    tcp_stream.set_nodelay(true).ok();

    // Enable TCP keepalive so a connection to a silently departed peer (pod
    // restart / scale-down) is reaped even while idle in the pool, rather than
    // only failing on the next request.
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(tuning.keepalive_time)
        .with_interval(tuning.keepalive_interval);
    if let Err(e) = socket2::SockRef::from(&tcp_stream).set_tcp_keepalive(&keepalive) {
        log::debug!("h2c: could not set keepalive on {authority}: {e}");
    }

    let stream = TokioIo::new(tcp_stream);
    log::debug!("h2c: starting HTTP/2 handshake to {authority}");
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

    log::debug!("h2c: HTTP/2 handshake complete to {authority}");

    // Drive the connection in a *detached* task. Unlike the old
    // `AbortOnDropJoinHandle`, nothing here can abort it: it runs until the
    // connection closes (all senders dropped + streams drained, or error), so
    // stale/aged eviction is graceful. We deliberately do not store the handle —
    // `get_or_connect_h2` re-dials on the next `is_closed()` miss, and leaving a
    // closed entry in the (authority-keyed, bounded) map until then is harmless.
    let key = authority.to_string();
    with_ambient_tokio_runtime(|| {
        tokio::task::spawn(async move {
            match conn.await {
                Ok(()) => log::debug!("h2c pool: connection to {key} closed cleanly"),
                Err(e) => log::warn!("h2c pool: connection to {key} closed with error: {e}"),
            }
        })
    });

    log::debug!("h2c pool: new connection to {authority}");
    Ok(sender)
}

/// The underlying h2c request handler. Spawned in a task by [`H2cPool::send`].
///
/// For non-TLS connections, reuses (or creates) a pooled HTTP/2 prior-knowledge
/// connection to the target authority. TLS connections fall back to the default
/// sender (TLS+HTTP/2 negotiates via ALPN, not prior-knowledge).
async fn h2c_send_request_handler(
    mut request: OutgoingRequest,
    config @ OutgoingRequestConfig {
        use_tls,
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
    }: OutgoingRequestConfig,
    tuning: PoolTuning,
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

    log::debug!(
        "h2c_send_request_handler: authority={}, use_tls={}",
        authority,
        use_tls
    );

    if use_tls {
        log::debug!(
            "h2c mode requested with TLS for {}; delegating to default TLS request handler",
            authority
        );
        wasmtime_wasi_http::types::default_send_request_handler(request, config).await
    } else {
        log::debug!("h2c: getting/creating connection to {authority}");
        let mut sender = get_or_connect_h2(&authority, connect_timeout, &tuning).await?;

        // Strip scheme and authority from the URI — an origin-form request line
        // carries only path+query when not addressing a proxy.
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

        log::debug!(
            "h2c: sending request to {authority}: method={}, uri={}",
            request.method(),
            request.uri(),
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

        log::debug!("h2c: got response from {authority}: status={}", resp.status());

        // No per-request worker needed — the detached pool driver moves bytes.
        Ok(IncomingResponse {
            resp,
            worker: None,
            between_bytes_timeout,
        })
    }
}
