//! Outbound connection middleware registry.
//!
//! A guest service running under this shim makes outbound calls (HTTP/1 REST,
//! HTTP/2 gRPC, …) through the `wasi:http` outgoing-handler. Because the guest
//! instance is **ephemeral** — instantiated per request and torn down after —
//! any connection state the guest holds dies with it. The only way to keep a
//! connection warm for reuse across requests is to own it **host-side**, in
//! process-wide state that outlives any single wasm `Store`.
//!
//! Each outbound protocol is a small middleware ([`H2cPool`], [`Http1Pool`])
//! that owns a process-global connection pool. A per-shim [`OutboundConfig`]
//! routes each request to a middleware by target authority, falling back to the
//! upstream default sender (a fresh HTTP/1.1 connection per request, no pool).
//!
//! ## Why routing is config-driven, not sniffed
//!
//! HTTP is self-framing, so HTTP/1 and h2c pooling are always safe to apply.
//! But h2c uses *prior-knowledge* (no negotiation), so the shim must be told
//! which backends speak it — there is no safe way to guess. One shim runs one
//! service, so a single per-shim config (env-driven) is enough; it maps
//! `authority → protocol` with a default.
//!
//! [`H2cPool`]: crate::h2c::H2cPool
//! [`Http1Pool`]: crate::http1::Http1Pool

use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::types::{HostFutureIncomingResponse, OutgoingRequestConfig};

use crate::h2c::H2cPool;
use crate::http1::Http1Pool;

pub(crate) type OutgoingRequest = hyper::Request<HyperOutgoingBody>;

/// Outbound strategy for a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    /// Upstream default: a fresh HTTP/1.1 connection per request (no pool).
    Default,
    /// Pooled HTTP/1.1 keep-alive.
    Http1Pool,
    /// Pooled HTTP/2 cleartext, prior-knowledge (gRPC).
    H2cPool,
}

impl Protocol {
    fn parse(s: &str) -> Option<Protocol> {
        match s.trim().to_ascii_lowercase().as_str() {
            "default" | "" => Some(Protocol::Default),
            "http1" | "h1" | "http1-pool" => Some(Protocol::Http1Pool),
            "h2c" | "http2" | "h2" | "grpc" => Some(Protocol::H2cPool),
            _ => None,
        }
    }
}

/// Connection-pool tuning shared by the pooled middlewares. One shim → one
/// service → one set of values (env-driven, parsed once at startup).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PoolTuning {
    /// Max age of a pooled connection before it is re-dialed. Forces periodic
    /// rebalancing across backend pods (kube-proxy load-balances per
    /// connection, so a pinned long-lived connection starves new replicas).
    pub max_lifetime: Duration,
    /// TCP keepalive idle time before the first probe.
    pub keepalive_time: Duration,
    /// Interval between TCP keepalive probes.
    pub keepalive_interval: Duration,
    /// HTTP/1 pool: max idle keep-alive connections retained per authority.
    pub max_idle_per_host: usize,
    /// HTTP/1 pool: how long an idle keep-alive connection is retained.
    pub idle_timeout: Duration,
}

impl Default for PoolTuning {
    fn default() -> Self {
        PoolTuning {
            max_lifetime: Duration::from_secs(60),
            keepalive_time: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(10),
            max_idle_per_host: 32,
            idle_timeout: Duration::from_secs(90),
        }
    }
}

/// Per-shim outbound routing + tuning.
#[derive(Debug, Clone)]
pub(crate) struct OutboundConfig {
    default: Protocol,
    per_authority: HashMap<String, Protocol>,
    pub tuning: PoolTuning,
}

impl Default for OutboundConfig {
    fn default() -> Self {
        OutboundConfig {
            default: Protocol::Default,
            per_authority: HashMap::new(),
            tuning: PoolTuning::default(),
        }
    }
}

impl OutboundConfig {
    /// Resolve the protocol for a request's authority (`host:port`).
    fn protocol_for(&self, authority: Option<&str>) -> Protocol {
        authority
            .and_then(|a| self.per_authority.get(a).copied())
            .unwrap_or(self.default)
    }

    /// Parse config from the shim's environment map, **consuming** the keys it
    /// recognizes so they are not forwarded to the guest.
    ///
    /// * `WASMTIME_HTTP_PROXY_OUTBOUND_DEFAULT` = `default|http1|h2c`
    /// * `WASMTIME_HTTP_PROXY_OUTBOUND_RULES` = `authority=proto,authority=proto`
    ///   e.g. `productcatalogservice:3550=h2c,frontend:80=http1`
    /// * `WASMTIME_HTTP_PROXY_OUTGOING_H2C` (legacy, truthy) → default = h2c
    /// * `WASMTIME_HTTP_PROXY_POOL_{MAX_LIFETIME_MS,KEEPALIVE_MS,
    ///   KEEPALIVE_INTERVAL_MS,IDLE_TIMEOUT_MS,MAX_IDLE_PER_HOST}`
    pub fn from_env(env: &mut HashMap<String, String>) -> Self {
        let mut cfg = OutboundConfig::default();

        // Legacy flag: WASMTIME_HTTP_PROXY_OUTGOING_H2C → default h2c.
        if let Some(v) = env.remove("WASMTIME_HTTP_PROXY_OUTGOING_H2C") {
            if matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes") {
                cfg.default = Protocol::H2cPool;
            }
        }
        // Explicit default wins over the legacy flag.
        if let Some(v) = env.remove("WASMTIME_HTTP_PROXY_OUTBOUND_DEFAULT") {
            match Protocol::parse(&v) {
                Some(p) => cfg.default = p,
                None => log::warn!("outbound: unknown OUTBOUND_DEFAULT '{v}', keeping {:?}", cfg.default),
            }
        }

        if let Some(rules) = env.remove("WASMTIME_HTTP_PROXY_OUTBOUND_RULES") {
            for rule in rules.split(',').map(str::trim).filter(|r| !r.is_empty()) {
                match rule.split_once('=') {
                    Some((authority, proto)) => match Protocol::parse(proto) {
                        Some(p) => {
                            cfg.per_authority.insert(authority.trim().to_string(), p);
                        }
                        None => log::warn!("outbound: unknown protocol in rule '{rule}'"),
                    },
                    None => log::warn!("outbound: malformed rule '{rule}' (want authority=proto)"),
                }
            }
        }

        let ms = |env: &mut HashMap<String, String>, key: &str| -> Option<Duration> {
            env.remove(key)
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_millis)
        };
        if let Some(d) = ms(env, "WASMTIME_HTTP_PROXY_POOL_MAX_LIFETIME_MS") {
            cfg.tuning.max_lifetime = d;
        }
        if let Some(d) = ms(env, "WASMTIME_HTTP_PROXY_POOL_KEEPALIVE_MS") {
            cfg.tuning.keepalive_time = d;
        }
        if let Some(d) = ms(env, "WASMTIME_HTTP_PROXY_POOL_KEEPALIVE_INTERVAL_MS") {
            cfg.tuning.keepalive_interval = d;
        }
        if let Some(d) = ms(env, "WASMTIME_HTTP_PROXY_POOL_IDLE_TIMEOUT_MS") {
            cfg.tuning.idle_timeout = d;
        }
        if let Some(n) = env
            .remove("WASMTIME_HTTP_PROXY_POOL_MAX_IDLE_PER_HOST")
            .and_then(|v| v.parse::<usize>().ok())
        {
            cfg.tuning.max_idle_per_host = n;
        }

        log::info!(
            "outbound: default={:?}, rules={}, max_lifetime={:?}, idle_timeout={:?}, max_idle_per_host={}",
            cfg.default,
            cfg.per_authority.len(),
            cfg.tuning.max_lifetime,
            cfg.tuning.idle_timeout,
            cfg.tuning.max_idle_per_host,
        );
        cfg
    }
}

/// A pooled outbound middleware for one protocol class.
pub(crate) trait OutboundMiddleware: Send + Sync {
    /// Send `req`, reusing a pooled connection where possible. `tuning` is the
    /// per-shim pool configuration.
    fn send(
        &self,
        req: OutgoingRequest,
        cfg: OutgoingRequestConfig,
        tuning: &PoolTuning,
    ) -> HostFutureIncomingResponse;
}

/// Process-global config, set once by the HTTP server at startup. Reads fall
/// back to a default (e.g. for non-HTTP component targets that never call out).
static CONFIG: OnceLock<OutboundConfig> = OnceLock::new();

/// Install the per-shim outbound config. Called once before serving.
pub(crate) fn init_config(cfg: OutboundConfig) {
    if CONFIG.set(cfg).is_err() {
        log::warn!("outbound: config already initialized; ignoring re-init");
    }
}

fn config() -> &'static OutboundConfig {
    static DEFAULT: LazyLock<OutboundConfig> = LazyLock::new(OutboundConfig::default);
    CONFIG.get().unwrap_or(&DEFAULT)
}

/// The pool tuning for this shim — used by middlewares that build their pool
/// lazily (e.g. the HTTP/1 client).
pub(crate) fn tuning() -> PoolTuning {
    config().tuning
}

struct Registry {
    h2c: H2cPool,
    http1: Http1Pool,
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Registry {
    h2c: H2cPool::new(),
    http1: Http1Pool::new(),
});

/// Entry point used by [`WasiHttpView::send_request`]. Routes the request to a
/// pooled middleware per the shim's [`OutboundConfig`], or to the default
/// per-request sender.
///
/// [`WasiHttpView::send_request`]: wasmtime_wasi_http::WasiHttpView::send_request
pub(crate) fn send_request(
    req: OutgoingRequest,
    cfg: OutgoingRequestConfig,
) -> HostFutureIncomingResponse {
    let config = config();
    let tuning = config.tuning;

    // The pooled middlewares are plaintext prior-knowledge (h2c) / cleartext
    // keep-alive (http1). TLS always goes to the default sender, which does the
    // ALPN handshake and certificate validation.
    let protocol = if cfg.use_tls {
        Protocol::Default
    } else {
        config.protocol_for(req.uri().authority().map(|a| a.as_str()))
    };

    match protocol {
        Protocol::H2cPool => {
            log::debug!("outbound: h2c-pool {} {}", req.method(), req.uri());
            REGISTRY.h2c.send(req, cfg, &tuning)
        }
        Protocol::Http1Pool => {
            log::debug!("outbound: http1-pool {} {}", req.method(), req.uri());
            REGISTRY.http1.send(req, cfg, &tuning)
        }
        Protocol::Default => {
            log::debug!("outbound: default sender {} {}", req.method(), req.uri());
            wasmtime_wasi_http::types::default_send_request(req, cfg)
        }
    }
}
