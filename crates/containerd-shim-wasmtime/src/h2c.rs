/// HTTP/2 cleartext (h2c) outgoing request support.
///
/// This module provides an alternative `send_request` implementation that uses
/// HTTP/2 prior-knowledge (h2c) for outgoing plaintext connections, which is
/// required for gRPC communication between WASM components and backend services.
///
/// When `WASMTIME_HTTP_PROXY_SERVER_MODE` is set to `"http2"` or `"h2"`, the
/// shim switches outgoing requests to use this h2c handler. The default behavior
/// (HTTP/1.1) is preserved otherwise.
use std::time::Duration;

use http_body_util::BodyExt;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpStream;
use tokio::time::timeout;
use wasmtime_wasi_http::bindings::http::types as wasi_http_types;
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::types::{HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig};
use wasmtime_wasi_http::hyper_request_error;

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
/// For non-TLS connections, this uses `hyper::client::conn::http2::handshake`
/// with `TokioExecutor` to establish HTTP/2 prior-knowledge connections (h2c).
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

    let tcp_stream = timeout(connect_timeout, TcpStream::connect(&authority))
        .await
        .map_err(|_| wasi_http_types::ErrorCode::ConnectionTimeout)?
        .map_err(|e| match e.kind() {
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
        })?;

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
        // HTTP/2 prior-knowledge (h2c) for plaintext connections.
        // This is the key difference: we use http2::handshake instead of http1::handshake.
        let stream = TokioIo::new(tcp_stream);
        let (mut sender, conn) = timeout(
            connect_timeout,
            hyper::client::conn::http2::handshake(TokioExecutor::new(), stream),
        )
        .await
        .map_err(|_| wasi_http_types::ErrorCode::ConnectionTimeout)?
        .map_err(hyper_request_error)?;

        let worker = wasmtime_wasi::runtime::spawn(async move {
            if let Err(e) = conn.await {
                log::warn!("h2c: dropping HTTP/2 connection error: {e}");
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
    }
}
