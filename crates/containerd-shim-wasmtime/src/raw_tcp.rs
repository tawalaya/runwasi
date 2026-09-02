//! Pooled raw-TCP request/reply middleware (Redis, line protocols, …).
//!
//! A guest calls `pooled-tcp.request(upstream, bytes)` (WIT wiring in
//! [`instance`](crate::instance)); the host writes the request to a pooled
//! connection, **reads exactly one reply using a per-upstream framing rule**,
//! and returns it to the pool. Because the host owns the read loop, the
//! connection is always handed back at a clean message boundary — so pooling is
//! safe without parsing the guest's bytes or guessing idempotency.
//!
//! This is the WASI-free core: it depends only on `tokio` + `socket2` + `std`,
//! so the pool, framing, and request path are unit/integration testable without
//! a wasm runtime. Connections live in a process-global pool that outlives the
//! per-request wasm instance.
//!
//! ## Safety / reuse rules
//!
//! * The host reads to a framing boundary, so a checked-in connection is never
//!   mid-reply.
//! * Liveness is probed **before** writing (a non-blocking read): a dead pooled
//!   connection is discarded and a fresh one dialed, so the automatic retry
//!   happens only when no bytes have been sent — safe even for non-idempotent
//!   ops. Once the request is on the wire, errors propagate to the guest.
//! * Connections age out (`max_lifetime`) to rebalance across backend pods, and
//!   carry `SO_KEEPALIVE` to reap silently-departed peers.

// `request` and the pool internals are exercised by the `pooled-tcp` WIT
// binding (see instance.rs). Until that binding lands they are otherwise unused.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// How the host detects the end of one reply on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Redis serialization protocol (one complete RESP value).
    Resp,
    /// One `\n`-terminated line.
    Line,
}

impl Framing {
    fn parse(s: &str) -> Option<Framing> {
        match s.trim().to_ascii_lowercase().as_str() {
            "resp" | "redis" => Some(Framing::Resp),
            "line" => Some(Framing::Line),
            _ => None,
        }
    }
}

/// Errors surfaced to the guest. Mirrors the `tcp-error` WIT variant.
#[derive(Debug)]
pub enum RawTcpError {
    /// Upstream not present in the shim's raw-TCP config.
    UnknownUpstream(String),
    /// TCP connect failed.
    Connect(String),
    /// Connect/read/write exceeded its timeout.
    Timeout,
    /// Framing parse error or unexpected trailing data.
    Protocol(String),
    /// Socket I/O error after the request was sent.
    Io(String),
}

impl std::fmt::Display for RawTcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawTcpError::UnknownUpstream(u) => write!(f, "unknown upstream: {u}"),
            RawTcpError::Connect(e) => write!(f, "connect failed: {e}"),
            RawTcpError::Timeout => write!(f, "timeout"),
            RawTcpError::Protocol(e) => write!(f, "protocol error: {e}"),
            RawTcpError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

/// Pool / timeout knobs for raw-TCP upstreams.
#[derive(Debug, Clone, Copy)]
pub struct RawTcpTuning {
    pub connect_timeout: Duration,
    pub write_timeout: Duration,
    pub first_byte_timeout: Duration,
    pub between_bytes_timeout: Duration,
    pub max_idle_per_host: usize,
    pub max_lifetime: Duration,
    pub keepalive_time: Duration,
    pub keepalive_interval: Duration,
}

impl Default for RawTcpTuning {
    fn default() -> Self {
        RawTcpTuning {
            connect_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            first_byte_timeout: Duration::from_secs(10),
            between_bytes_timeout: Duration::from_secs(10),
            max_idle_per_host: 16,
            max_lifetime: Duration::from_secs(60),
            keepalive_time: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(10),
        }
    }
}

/// Per-shim raw-TCP config: which upstreams exist and how their replies are
/// framed, plus pool tuning.
#[derive(Debug, Clone, Default)]
pub struct RawTcpConfig {
    upstreams: HashMap<String, Framing>,
    tuning: RawTcpTuning,
}

impl RawTcpConfig {
    /// Parse from the shim env map, consuming recognized keys.
    ///
    /// * `WASMTIME_RAWTCP_UPSTREAMS` = `authority=framing,authority=framing`
    ///   e.g. `redis-cart:6379=resp`
    /// * `WASMTIME_RAWTCP_{CONNECT_MS,WRITE_MS,FIRST_BYTE_MS,BETWEEN_BYTES_MS,
    ///   MAX_LIFETIME_MS,KEEPALIVE_MS,KEEPALIVE_INTERVAL_MS,MAX_IDLE_PER_HOST}`
    pub fn from_env(env: &mut HashMap<String, String>) -> Self {
        let mut cfg = RawTcpConfig::default();

        if let Some(rules) = env.remove("WASMTIME_RAWTCP_UPSTREAMS") {
            for rule in rules.split(',').map(str::trim).filter(|r| !r.is_empty()) {
                match rule.split_once('=') {
                    Some((authority, framing)) => match Framing::parse(framing) {
                        Some(fr) => {
                            cfg.upstreams.insert(authority.trim().to_string(), fr);
                        }
                        None => log::warn!("raw-tcp: unknown framing in rule '{rule}'"),
                    },
                    None => log::warn!("raw-tcp: malformed rule '{rule}' (want authority=framing)"),
                }
            }
        }

        let ms = |env: &mut HashMap<String, String>, key: &str| -> Option<Duration> {
            env.remove(key)
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_millis)
        };
        if let Some(d) = ms(env, "WASMTIME_RAWTCP_CONNECT_MS") {
            cfg.tuning.connect_timeout = d;
        }
        if let Some(d) = ms(env, "WASMTIME_RAWTCP_WRITE_MS") {
            cfg.tuning.write_timeout = d;
        }
        if let Some(d) = ms(env, "WASMTIME_RAWTCP_FIRST_BYTE_MS") {
            cfg.tuning.first_byte_timeout = d;
        }
        if let Some(d) = ms(env, "WASMTIME_RAWTCP_BETWEEN_BYTES_MS") {
            cfg.tuning.between_bytes_timeout = d;
        }
        if let Some(d) = ms(env, "WASMTIME_RAWTCP_MAX_LIFETIME_MS") {
            cfg.tuning.max_lifetime = d;
        }
        if let Some(d) = ms(env, "WASMTIME_RAWTCP_KEEPALIVE_MS") {
            cfg.tuning.keepalive_time = d;
        }
        if let Some(d) = ms(env, "WASMTIME_RAWTCP_KEEPALIVE_INTERVAL_MS") {
            cfg.tuning.keepalive_interval = d;
        }
        if let Some(n) = env
            .remove("WASMTIME_RAWTCP_MAX_IDLE_PER_HOST")
            .and_then(|v| v.parse::<usize>().ok())
        {
            cfg.tuning.max_idle_per_host = n;
        }

        if !cfg.upstreams.is_empty() {
            log::info!(
                "raw-tcp: {} upstream(s), max_idle_per_host={}, max_lifetime={:?}",
                cfg.upstreams.len(),
                cfg.tuning.max_idle_per_host,
                cfg.tuning.max_lifetime
            );
        }
        cfg
    }
}

static CONFIG: OnceLock<RawTcpConfig> = OnceLock::new();

/// Install the per-shim raw-TCP config. Called once before serving.
pub fn init_config(cfg: RawTcpConfig) {
    if CONFIG.set(cfg).is_err() {
        log::warn!("raw-tcp: config already initialized; ignoring re-init");
    }
}

fn config() -> &'static RawTcpConfig {
    static DEFAULT: LazyLock<RawTcpConfig> = LazyLock::new(RawTcpConfig::default);
    CONFIG.get().unwrap_or(&DEFAULT)
}

/// A pooled raw-TCP connection plus its birth time (lifetime eviction).
struct PooledConn {
    stream: TcpStream,
    born: Instant,
}

#[derive(Default)]
struct Pool {
    idle: HashMap<String, Vec<PooledConn>>,
}

static POOL: LazyLock<Mutex<Pool>> = LazyLock::new(|| Mutex::new(Pool::default()));

/// Perform one request/reply round-trip to `upstream` over a pooled connection.
///
/// Returns the framed reply bytes. The connection is returned to the pool on
/// success (it is at a clean boundary) and dropped on any error.
pub async fn request(upstream: &str, payload: &[u8]) -> Result<Vec<u8>, RawTcpError> {
    let cfg = config();
    let framing = cfg
        .upstreams
        .get(upstream)
        .copied()
        .ok_or_else(|| RawTcpError::UnknownUpstream(upstream.to_string()))?;
    let t = &cfg.tuning;

    // Checkout probes liveness before returning, so a write below is the first
    // byte on a known-healthy connection — a transparent reconnect here never
    // double-sends.
    let mut conn = checkout(upstream, t).await?;

    match timeout(t.write_timeout, conn.stream.write_all(payload)).await {
        Err(_) => return Err(RawTcpError::Timeout),
        Ok(Err(e)) => return Err(RawTcpError::Io(e.to_string())),
        Ok(Ok(())) => {}
    }
    if let Err(e) = conn.stream.flush().await {
        return Err(RawTcpError::Io(e.to_string()));
    }

    match read_reply(&mut conn.stream, framing, t).await {
        Ok(reply) => {
            // Clean boundary — safe to reuse.
            checkin(upstream, conn, t).await;
            Ok(reply)
        }
        // `conn` is dropped here → socket closed, never pooled.
        Err(e) => Err(e),
    }
}

/// Borrow a connection: reuse a live, in-lifetime idle one, else dial fresh.
async fn checkout(upstream: &str, t: &RawTcpTuning) -> Result<PooledConn, RawTcpError> {
    loop {
        let candidate = {
            let mut pool = POOL.lock().await;
            pool.idle.get_mut(upstream).and_then(|v| v.pop())
        };
        match candidate {
            Some(conn) => {
                if conn.born.elapsed() < t.max_lifetime && is_live(&conn.stream) {
                    return Ok(conn);
                }
                // stale or dead → drop and try the next idle connection
            }
            None => break,
        }
    }
    dial(upstream, t).await
}

/// Non-blocking liveness probe for an idle pooled connection sitting at a
/// message boundary: no data should be pending, so `WouldBlock` means healthy,
/// EOF/data/error means discard.
fn is_live(stream: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    match stream.try_read(&mut b) {
        Ok(0) => false,
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

async fn dial(upstream: &str, t: &RawTcpTuning) -> Result<PooledConn, RawTcpError> {
    let stream = match timeout(t.connect_timeout, TcpStream::connect(upstream)).await {
        Err(_) => return Err(RawTcpError::Timeout),
        Ok(Err(e)) => return Err(RawTcpError::Connect(e.to_string())),
        Ok(Ok(s)) => s,
    };
    stream.set_nodelay(true).ok();
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(t.keepalive_time)
        .with_interval(t.keepalive_interval);
    if let Err(e) = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive) {
        log::debug!("raw-tcp: could not set keepalive on {upstream}: {e}");
    }
    Ok(PooledConn {
        stream,
        born: Instant::now(),
    })
}

async fn checkin(upstream: &str, conn: PooledConn, t: &RawTcpTuning) {
    if conn.born.elapsed() >= t.max_lifetime {
        return; // aged out → close
    }
    let mut pool = POOL.lock().await;
    let v = pool.idle.entry(upstream.to_string()).or_default();
    if v.len() < t.max_idle_per_host {
        v.push(conn);
    } // else drop → close (pool full)
}

/// Read exactly one framed reply from the stream.
async fn read_reply(
    stream: &mut TcpStream,
    framing: Framing,
    t: &RawTcpTuning,
) -> Result<Vec<u8>, RawTcpError> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut tmp = [0u8; 4096];
    let mut first = true;
    loop {
        match scan_reply(framing, &buf) {
            Scan::Complete(n) => {
                if n != buf.len() {
                    return Err(RawTcpError::Protocol(format!(
                        "{} unexpected trailing bytes after reply",
                        buf.len() - n
                    )));
                }
                return Ok(buf);
            }
            Scan::Invalid(e) => return Err(RawTcpError::Protocol(e)),
            Scan::Incomplete => {}
        }

        let to = if first {
            t.first_byte_timeout
        } else {
            t.between_bytes_timeout
        };
        let n = match timeout(to, stream.read(&mut tmp)).await {
            Err(_) => return Err(RawTcpError::Timeout),
            Ok(Ok(0)) => return Err(RawTcpError::Io("peer closed mid-reply".into())),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(RawTcpError::Io(e.to_string())),
        };
        buf.extend_from_slice(&tmp[..n]);
        first = false;
    }
}

// ---- framing (pure, unit-tested) --------------------------------------------

/// Result of scanning a buffer for one complete reply.
#[derive(Debug, PartialEq, Eq)]
enum Scan {
    /// One reply ends at this absolute byte index (exclusive).
    Complete(usize),
    /// Need more bytes.
    Incomplete,
    /// Malformed framing — connection is unusable.
    Invalid(String),
}

fn scan_reply(framing: Framing, buf: &[u8]) -> Scan {
    match framing {
        Framing::Resp => resp_value(buf, 0),
        Framing::Line => match find_lf(buf, 0) {
            Some(end) => Scan::Complete(end),
            None => Scan::Incomplete,
        },
    }
}

fn find_lf(buf: &[u8], start: usize) -> Option<usize> {
    (start..buf.len()).find(|&i| buf[i] == b'\n').map(|i| i + 1)
}

/// Absolute index one past the next `\r\n` at/after `start`, if present.
fn crlf_end(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

fn parse_int(b: &[u8]) -> Option<i64> {
    std::str::from_utf8(b).ok()?.trim().parse().ok()
}

/// Scan one complete RESP value starting at `pos`; returns its absolute end.
fn resp_value(buf: &[u8], pos: usize) -> Scan {
    let Some(&tag) = buf.get(pos) else {
        return Scan::Incomplete;
    };
    match tag {
        // Simple string / error / integer: one CRLF-terminated line.
        b'+' | b'-' | b':' => match crlf_end(buf, pos + 1) {
            Some(end) => Scan::Complete(end),
            None => Scan::Incomplete,
        },
        // Bulk string: $<len>\r\n<len bytes>\r\n, or $-1\r\n (null).
        b'$' => {
            let Some(hdr_end) = crlf_end(buf, pos + 1) else {
                return Scan::Incomplete;
            };
            let len = match parse_int(&buf[pos + 1..hdr_end - 2]) {
                Some(n) => n,
                None => return Scan::Invalid("bad bulk length".into()),
            };
            if len < 0 {
                return Scan::Complete(hdr_end); // null bulk
            }
            let need = hdr_end + len as usize + 2; // data + trailing CRLF
            if buf.len() >= need {
                Scan::Complete(need)
            } else {
                Scan::Incomplete
            }
        }
        // Array: *<count>\r\n then <count> values, or *-1\r\n (null).
        b'*' => {
            let Some(hdr_end) = crlf_end(buf, pos + 1) else {
                return Scan::Incomplete;
            };
            let count = match parse_int(&buf[pos + 1..hdr_end - 2]) {
                Some(n) => n,
                None => return Scan::Invalid("bad array count".into()),
            };
            if count < 0 {
                return Scan::Complete(hdr_end); // null array
            }
            let mut p = hdr_end;
            for _ in 0..count {
                match resp_value(buf, p) {
                    Scan::Complete(end) => p = end,
                    other => return other,
                }
            }
            Scan::Complete(p)
        }
        other => Scan::Invalid(format!("bad RESP type byte 0x{other:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(buf: &[u8]) -> Scan {
        scan_reply(Framing::Resp, buf)
    }

    #[test]
    fn resp_simple_string() {
        assert_eq!(resp(b"+OK\r\n"), Scan::Complete(5));
    }

    #[test]
    fn resp_error() {
        assert_eq!(resp(b"-ERR bad\r\n"), Scan::Complete(10));
    }

    #[test]
    fn resp_integer() {
        assert_eq!(resp(b":1000\r\n"), Scan::Complete(7));
    }

    #[test]
    fn resp_bulk() {
        assert_eq!(resp(b"$5\r\nhello\r\n"), Scan::Complete(11));
    }

    #[test]
    fn resp_null_bulk() {
        assert_eq!(resp(b"$-1\r\n"), Scan::Complete(5));
    }

    #[test]
    fn resp_array() {
        assert_eq!(
            resp(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"),
            Scan::Complete(22)
        );
    }

    #[test]
    fn resp_nested_array() {
        // *2\r\n :1\r\n *1\r\n +x\r\n
        assert_eq!(resp(b"*2\r\n:1\r\n*1\r\n+x\r\n"), Scan::Complete(16));
    }

    #[test]
    fn resp_null_array() {
        assert_eq!(resp(b"*-1\r\n"), Scan::Complete(5));
    }

    #[test]
    fn resp_incomplete_bulk_data() {
        assert_eq!(resp(b"$5\r\nhel"), Scan::Incomplete);
    }

    #[test]
    fn resp_incomplete_header() {
        assert_eq!(resp(b"$5\r"), Scan::Incomplete);
        assert_eq!(resp(b""), Scan::Incomplete);
        assert_eq!(resp(b"*2\r\n$3\r\nfoo\r\n"), Scan::Incomplete);
    }

    #[test]
    fn resp_trailing_after_one_reply_is_complete_at_first() {
        // One reply plus the start of another: complete at the first boundary.
        assert_eq!(resp(b"+OK\r\n+NEXT\r\n"), Scan::Complete(5));
    }

    #[test]
    fn resp_invalid_tag() {
        assert!(matches!(resp(b"?bad\r\n"), Scan::Invalid(_)));
    }

    #[test]
    fn line_framing() {
        assert_eq!(scan_reply(Framing::Line, b"hello\n"), Scan::Complete(6));
        assert_eq!(scan_reply(Framing::Line, b"hello"), Scan::Incomplete);
    }

    #[test]
    fn framing_parse() {
        assert_eq!(Framing::parse("resp"), Some(Framing::Resp));
        assert_eq!(Framing::parse("REDIS"), Some(Framing::Resp));
        assert_eq!(Framing::parse("line"), Some(Framing::Line));
        assert_eq!(Framing::parse("nope"), None);
    }
}
