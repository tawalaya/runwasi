// Heavily inspired by wasmtime serve command:
// https://github.com/bytecodealliance/wasmtime/blob/main/src/commands/serve.rs

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use containerd_shim_wasm::sandbox::context::RuntimeContext;
use hyper::server::conn::{http1, http2};
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use wasmtime::Store;
use wasmtime::component::ResourceTable;
use wasmtime_wasi_http::bindings::http::types::Scheme;
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpView};

use crate::instance::{WasiPreview2Ctx, ServicePre, envs_from_ctx, epoch_deadline_from_env, default_store_limits, max_memory_size};
use crate::outbound;
use crate::raw_tcp;

/// On Linux, enters a private mount namespace and bind-mounts the pod's
/// `/etc/resolv.conf` (injected by kubelet as an OCI spec mount) over the
/// shim process's `/etc/resolv.conf`.  This ensures libc's `getaddrinfo()`
/// uses kube-dns and the pod's search domains instead of the host resolver,
/// enabling WASI `ip-name-lookup` to resolve Kubernetes service names.
///
/// Failures are non-fatal — a warning is logged and the shim continues with
/// the host resolver (ClusterIP env-var addresses still work without DNS).
#[cfg(target_os = "linux")]
fn apply_pod_resolv_conf(ctx: &impl RuntimeContext) {
    use nix::mount::{MsFlags, mount};
    use nix::sched::{CloneFlags, unshare};

    let source = match ctx.resolv_conf_source() {
        Some(p) => p,
        None => {
            log::warn!("[dns] /etc/resolv.conf mount not found in OCI spec — using host resolver");
            return;
        }
    };

    if !source.exists() {
        log::warn!("[dns] pod resolv.conf source {source:?} does not exist — using host resolver");
        return;
    }

    // Detach from the shared mount namespace so the bind-mount only affects
    // this shim process and doesn't modify the host filesystem.
    if let Err(e) = unshare(CloneFlags::CLONE_NEWNS) {
        log::warn!("[dns] unshare(CLONE_NEWNS) failed: {e} — using host resolver");
        return;
    }

    if let Err(e) = mount(
        Some(&source),
        "/etc/resolv.conf",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    ) {
        log::warn!("[dns] bind-mount of {source:?} -> /etc/resolv.conf failed: {e} — using host resolver");
        return;
    }

    log::info!("[dns] applied pod resolv.conf from {source:?}");
}

#[cfg(not(target_os = "linux"))]
fn apply_pod_resolv_conf(_ctx: &impl RuntimeContext) {}

const DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 8080);

const DEFAULT_BACKLOG: u32 = 100;

/// Default wall-clock per-request timeout (ms). Override via
/// `WASMTIME_HTTP_PROXY_REQUEST_TIMEOUT_MS`.
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;

/// Fallback concurrency cap when the cgroup memory limit is unknown.
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 20;

/// Fraction of the cgroup memory limit budgeted for guest instances when
/// deriving the concurrency cap (the rest is headroom for host/runtime).
const MEMORY_BUDGET_FRACTION: f64 = 0.8;

type Request = hyper::Request<hyper::body::Incoming>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerMode {
    Http1,
    Http2,
    Auto,
}

fn parse_server_mode(mode: &str) -> ServerMode {
    match mode.to_ascii_lowercase().as_str() {
        "http1" => ServerMode::Http1,
        "http2" | "h2" => ServerMode::Http2,
        "auto" => ServerMode::Auto,
        _ => ServerMode::Auto,
    }
}

/// Best-effort read of this process's cgroup memory limit in bytes.
///
/// The runwasi shim process is placed in the pod's cgroup by containerd, so this
/// reflects the pod/container memory limit. Returns `None` when unlimited or
/// unreadable (non-Linux, no cgroup, or "max").
fn cgroup_memory_limit_bytes() -> Option<u64> {
    // cgroup v2 (unified hierarchy).
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        let s = s.trim();
        if s != "max" {
            if let Ok(v) = s.parse::<u64>() {
                return Some(v);
            }
        }
    }
    // cgroup v1.
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
        if let Ok(v) = s.trim().parse::<u64>() {
            // v1 reports a near-i64::MAX sentinel when unlimited.
            if v < i64::MAX as u64 / 2 {
                return Some(v);
            }
        }
    }
    None
}

/// Resolve the maximum number of concurrent in-flight Wasm instances.
///
/// Priority: explicit override → derive from cgroup memory limit
/// (`budget × limit / per-instance cap`) → fallback constant. Always ≥ 1.
fn resolve_max_concurrent(override_value: Option<usize>) -> usize {
    if let Some(v) = override_value {
        return v.max(1);
    }
    if let Some(limit) = cgroup_memory_limit_bytes() {
        let usable = (limit as f64 * MEMORY_BUDGET_FRACTION) as u64;
        let n = usable / max_memory_size() as u64;
        return (n as usize).max(1);
    }
    DEFAULT_MAX_CONCURRENT_REQUESTS
}

fn is_connection_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

// [From axum](https://github.com/tokio-rs/axum/blob/280d16a61059f57230819a79b15aa12a263e8cca/axum/src/serve.rs#L425)
async fn tcp_accept(listener: &TcpListener) -> Option<TcpStream> {
    match listener.accept().await {
        Ok((stream, _addr)) => {
            // Disable Nagle's algorithm for low-latency gRPC / HTTP responses.
            stream.set_nodelay(true).ok();
            Some(stream)
        }
        Err(e) => {
            if is_connection_error(&e) {
                return None;
            }

            // [From `hyper::Server` in 0.14](https://github.com/hyperium/hyper/blob/v0.14.27/src/server/tcp.rs#L186)
            //
            // > A possible scenario is that the process has hit the max open files
            // > allowed, and so trying to accept a new connection will fail with
            // > `EMFILE`. In some cases, it's preferable to just wait for some time, if
            // > the application will likely close some files (or connections), and try
            // > to accept the connection again. If this option is `true`, the error
            // > will be logged at the `error` level, since it is still a big deal,
            // > and then the listener will sleep for 1 second.
            log::error!("accept error: {e}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            None
        }
    }
}

pub(crate) async fn serve_conn(
    ctx: &impl RuntimeContext,
    instance: ServicePre<WasiPreview2Ctx>,
    cancel: CancellationToken,
) -> Result<()> {
    // Apply the pod's resolv.conf so that WASI ip-name-lookup (getaddrinfo)
    // uses kube-dns and pod search domains instead of the host resolver.
    apply_pod_resolv_conf(ctx);

    let mut env = envs_from_ctx(ctx).into_iter().collect::<HashMap<_, _>>();

    // Consume env variables for Proxy server settings before passing it to handler
    let addr = env
        .remove("WASMTIME_HTTP_PROXY_SOCKET_ADDR")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ADDR);
    let backlog = env
        .remove("WASMTIME_HTTP_PROXY_BACKLOG")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BACKLOG);

    // Wall-clock per-request timeout. Epoch interruption only preempts CPU-bound
    // guests; a guest suspended in a host call (socket connect/read) never trips
    // it, so without this a hung request pins its Wasm instance's memory forever.
    let request_timeout = Duration::from_millis(
        env.remove("WASMTIME_HTTP_PROXY_REQUEST_TIMEOUT_MS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS),
    );

    // Cap on concurrent in-flight Wasm instances. Each instance can grow to the
    // per-store memory limit, so bounding the count bounds worst-case RSS below
    // the cgroup budget. Explicit override wins; otherwise derive from cgroup.
    let max_concurrent_override = env
        .remove("WASMTIME_HTTP_PROXY_MAX_CONCURRENT_REQUESTS")
        .and_then(|v| v.parse().ok());
    let max_concurrent = resolve_max_concurrent(max_concurrent_override);

    let tracker = TaskTracker::new();

    // Determine server mode via env: "http1", "http2"/"h2" or "auto" (default = "auto")
    let mode = env
        .remove("WASMTIME_HTTP_PROXY_SERVER_MODE")
        .unwrap_or_else(|| "auto".to_string());
    let mode = parse_server_mode(&mode);

    // Outbound connection policy (pooled h2c / http1 / default, per target) is
    // parsed into a process-global config consumed by the outbound middleware
    // registry. `from_env` consumes its own env keys (incl. the legacy
    // WASMTIME_HTTP_PROXY_OUTGOING_H2C) so they are not forwarded to the guest.
    outbound::init_config(outbound::OutboundConfig::from_env(&mut env));

    // Raw-TCP (Redis/line) pooled-request config for the `pooled-tcp` WIT
    // interface. Consumes its own env keys so they aren't forwarded to the guest.
    raw_tcp::init_config(raw_tcp::RawTcpConfig::from_env(&mut env));

    // Number of SO_REUSEPORT acceptor tasks. The kernel load-balances incoming
    // connections across them, spreading accept + connection handling over
    // cores. Defaults to the cgroup CPU budget (capped); override via env.
    let acceptors = resolve_acceptors(&mut env);

    // Allow guest network access only when explicitly opted in (#5).
    let allow_network = env
        .remove("WASMTIME_HTTP_PROXY_ALLOW_NETWORK")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    let env: Vec<(String, String)> = env.into_iter().collect();
    let epoch_deadline = epoch_deadline_from_env(&env);
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let handler = Arc::new(ProxyHandler::new(instance, env, tracker.clone(), epoch_deadline, allow_network, request_timeout, semaphore));

    log::info!(
        "Serving HTTP on http://{} (mode: {:?}, acceptors: {}, max_concurrent: {}, request_timeout: {:?})",
        addr, mode, acceptors, max_concurrent, request_timeout
    );

    // Pre-build connection handlers once; cloned per acceptor / connection (#7).
    let http1_builder = {
        let mut b = http1::Builder::new();
        b.keep_alive(true);
        b
    };
    let http2_builder = {
        let mut b = http2::Builder::new(TokioExecutor::new());
        b.initial_stream_window_size(1024 * 1024)
         .initial_connection_window_size(2 * 1024 * 1024)
         .max_concurrent_streams(200);
        b
    };
    let auto_builder = AutoServerBuilder::new(TokioExecutor::new());

    // Spawn `acceptors` independent accept loops, each on its own SO_REUSEPORT
    // socket bound to the same address. The kernel load-balances incoming
    // connections across them, so accept + per-connection serving scale across
    // cores instead of funneling through a single accept loop.
    let mut acceptor_handles = Vec::with_capacity(acceptors);
    for i in 0..acceptors {
        let listener = bind_listener(addr, backlog, acceptors > 1)
            .with_context(|| format!("acceptor {i} failed to bind {addr}"))?;
        log::debug!("acceptor {i} listening on {}", listener.local_addr()?);
        acceptor_handles.push(tokio::spawn(accept_loop(
            listener,
            handler.clone(),
            mode,
            http1_builder.clone(),
            http2_builder.clone(),
            auto_builder.clone(),
            cancel.clone(),
            tracker.clone(),
        )));
    }

    // Wait for shutdown, then drain: acceptors stop on cancel; in-flight
    // connections (and their guest tasks, tracked on `tracker`) then finish.
    cancel.cancelled().await;
    for handle in acceptor_handles {
        let _ = handle.await;
    }
    tracker.close();
    tracker.wait().await;

    Ok(())
}

/// One accept loop. Owns a single (`SO_REUSEPORT`) listener and spawns a serving
/// task per accepted connection onto the shared `tracker`. Exits on `cancel`.
#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    handler: Arc<ProxyHandler>,
    mode: ServerMode,
    http1_builder: http1::Builder,
    http2_builder: http2::Builder<TokioExecutor>,
    auto_builder: AutoServerBuilder<TokioExecutor>,
    cancel: CancellationToken,
    tracker: TaskTracker,
) {
    loop {
        let stream = tokio::select! {
            conn = tcp_accept(&listener) => {
                match conn {
                    Some(conn) => conn,
                    None => continue,
                }
            }
            _ = cancel.cancelled() => {
                break;
            }
        };

        let stream = TokioIo::new(stream);
        let h = handler.clone();
        let h1b = http1_builder.clone();
        let h2b = http2_builder.clone();
        let ab = auto_builder.clone();

        tracker.spawn(async move {
            let svc = hyper::service::service_fn(move |req| h.clone().handle_request(req));
            match mode {
                ServerMode::Http1 => {
                    if let Err(e) = h1b.serve_connection(stream, svc).await {
                        log::error!("error: {e:?}");
                    }
                }
                ServerMode::Http2 => {
                    if let Err(e) = h2b.serve_connection(stream, svc).await {
                        log::error!("error: {e:?}");
                    }
                }
                ServerMode::Auto => {
                    if let Err(e) = ab.serve_connection(stream, svc).await {
                        log::error!("error: {e:?}");
                    }
                }
            }
        });
    }
}

/// Bind a TCP listener, optionally with `SO_REUSEPORT` so multiple acceptors can
/// share the same address and the kernel can spread connections across them.
fn bind_listener(addr: SocketAddr, backlog: u32, reuseport: bool) -> Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };

    // `SO_REUSEADDR`: rebind an address in `TIME_WAIT` after a restart with
    // active connections. Off on Windows, where it would let other processes
    // steal the port (deviates from Tokio's always-on default).
    socket.set_reuseaddr(!cfg!(windows))?;

    // `SO_REUSEPORT`: let every acceptor bind the same port; the kernel
    // load-balances accepted connections across the listening sockets.
    #[cfg(unix)]
    if reuseport {
        socket.set_reuseport(true)?;
    }
    #[cfg(not(unix))]
    let _ = reuseport;

    socket.bind(addr)?;
    Ok(socket.listen(backlog)?)
}

/// Resolve the number of `SO_REUSEPORT` acceptor tasks. Explicit override wins;
/// otherwise size to the cgroup CPU budget (capped), falling back to the host
/// parallelism. Always ≥ 1.
fn resolve_acceptors(env: &mut HashMap<String, String>) -> usize {
    if let Some(n) = env
        .remove("WASMTIME_HTTP_PROXY_ACCEPTORS")
        .and_then(|v| v.parse::<usize>().ok())
    {
        return n.max(1);
    }
    let cpus = cgroup_cpu_limit()
        .or_else(|| std::thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(1);
    cpus.clamp(1, 8)
}

/// Best-effort read of this process's cgroup CPU quota, rounded up to whole
/// CPUs. Returns `None` when unlimited or unreadable.
fn cgroup_cpu_limit() -> Option<usize> {
    // cgroup v2: "<quota> <period>" or "max <period>".
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
        let mut it = s.split_whitespace();
        if let (Some(q), Some(p)) = (it.next(), it.next()) {
            if q != "max" {
                if let (Ok(q), Ok(p)) = (q.parse::<u64>(), p.parse::<u64>()) {
                    if p > 0 {
                        return Some((q.div_ceil(p) as usize).max(1));
                    }
                }
            }
        }
    }
    // cgroup v1.
    if let (Ok(q), Ok(p)) = (
        std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"),
        std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us"),
    ) {
        if let (Ok(q), Ok(p)) = (q.trim().parse::<i64>(), p.trim().parse::<u64>()) {
            if q > 0 && p > 0 {
                return Some(((q as u64).div_ceil(p) as usize).max(1));
            }
        }
    }
    None
}

struct ProxyHandler {
    instance_pre: ServicePre<WasiPreview2Ctx>,
    next_id: AtomicU64,
    env: Vec<(String, String)>,
    tracker: TaskTracker,
    /// Per-request epoch deadline in ticks.
    epoch_deadline: u64,
    /// Whether the guest is allowed to make outgoing network connections.
    allow_network: bool,
    /// Wall-clock timeout applied to each guest invocation.
    request_timeout: Duration,
    /// Bounds the number of concurrently instantiated guests (and thus RSS).
    semaphore: Arc<Semaphore>,
}

impl ProxyHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        instance_pre: ServicePre<WasiPreview2Ctx>,
        env: Vec<(String, String)>,
        tracker: TaskTracker,
        epoch_deadline: u64,
        allow_network: bool,
        request_timeout: Duration,
        semaphore: Arc<Semaphore>,
    ) -> Self {
        ProxyHandler {
            instance_pre,
            env,
            tracker,
            next_id: AtomicU64::from(0),
            epoch_deadline,
            allow_network,
            request_timeout,
            semaphore,
        }
    }

    fn wasi_store_for_request(&self, req_id: u64) -> Store<WasiPreview2Ctx> {
        let engine = self.instance_pre.engine();
        let mut builder = wasmtime_wasi::p2::WasiCtxBuilder::new();

        builder.envs(&self.env);
        builder.env("REQUEST_ID", req_id.to_string());
        // Expose guest stdout/stderr so diagnostic logs reach containerd (#4).
        builder.inherit_stdio();
        // Pre-open /tmp so WASM components can use std::fs for scratch I/O.
        // Without this the HttpProxy path has no preopened directories at all,
        // causing std::fs calls to return ENOENT (WASI errno 44).
        let file_perms = wasmtime_wasi::FilePerms::all();
        let dir_perms  = wasmtime_wasi::DirPerms::all();
        if let Err(e) = builder.preopened_dir("/tmp", "/tmp", dir_perms, file_perms) {
            log::warn!("could not preopen /tmp for request {req_id}: {e} - IO stressor will be unavailable");
        }
        // Only grant network access when WASMTIME_HTTP_PROXY_ALLOW_NETWORK is set (#5).
        if self.allow_network {
            builder.inherit_network();
            builder.allow_tcp(true);
            builder.allow_udp(true);
            builder.allow_ip_name_lookup(true);
        }

        let ctx = WasiPreview2Ctx {
            wasi_ctx: builder.build(),
            wasi_http: WasiHttpCtx::new(),
            resource_table: ResourceTable::default(),
            store_limits: default_store_limits(),
        };

        let mut store = Store::new(engine, ctx);
        // Attach resource limiter to cap memory growth per request (#2).
        store.limiter(|state| &mut state.store_limits);
        // Set epoch deadline so runaway guests are interrupted (#1).
        store.epoch_deadline_async_yield_and_update(self.epoch_deadline);
        store
    }

    async fn handle_request(
        self: Arc<Self>,
        req: Request,
    ) -> Result<hyper::Response<HyperOutgoingBody>> {
        // Acquire a permit before building the instance so we never hold more
        // live Wasm instances than the memory budget allows. The permit is moved
        // into the guest task below and released only when the instance is fully
        // dropped (normal completion or abort), bounding worst-case RSS.
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore is never closed");

        let (sender, receiver) = tokio::sync::oneshot::channel();

        let req_id = self.next_req_id();

        log::trace!(
            "Request {req_id} handling {} to {}",
            req.method(),
            req.uri()
        );

        let mut store = self.wasi_store_for_request(req_id);

        let req = store.data_mut().new_incoming_request(Scheme::Http, req)?;
        let out = store.data_mut().new_response_outparam(sender)?;
        let proxy = self.instance_pre.instantiate_async(&mut store).await?;

        let task = self.tracker.spawn(async move {
            // Hold the permit for the full guest lifetime; dropped here on
            // completion or when the task is aborted on timeout.
            let _permit = permit;
            if let Err(e) = proxy
                .wasi_http_incoming_handler()
                .call_handle(store, req, out)
                .await
            {
                log::error!("[{req_id}] :: {:#?}", e);
                return Err(e);
            }

            Ok(())
        });

        match tokio::time::timeout(self.request_timeout, receiver).await {
            Ok(Ok(Ok(resp))) => Ok(resp),
            Ok(Ok(Err(e))) => Err(e.into()),
            Ok(Err(_)) => {
                // An error in the receiver (`RecvError`) only indicates that the
                // task exited before a response was sent (i.e., the sender was
                // dropped); it does not describe the underlying cause of failure.
                // Instead we retrieve and propagate the error from inside the task
                // which should more clearly tell the user what went wrong. Note
                // that we assume the task has already exited at this point so the
                // `await` should resolve immediately.
                let e = match task.await {
                    Ok(e) => {
                        e.expect_err("if the receiver has an error, the task must have failed")
                    }
                    Err(e) => e.into(),
                };

                bail!("guest never invoked `response-outparam::set` method: {e:?}")
            }
            Err(_elapsed) => {
                // Wall-clock timeout: abort the guest task so its Store — and the
                // instance's linear memory — is dropped and the permit released,
                // instead of a hung guest pinning memory until OOM.
                task.abort();
                log::error!("[{req_id}] :: request timed out after {:?}", self.request_timeout);
                bail!("request {req_id} timed out after {:?}", self.request_timeout)
            }
        }
    }

    fn next_req_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::{ServerMode, parse_server_mode};

    #[test]
    fn test_parse_server_mode_http1() {
        assert_eq!(parse_server_mode("http1"), ServerMode::Http1);
        assert_eq!(parse_server_mode("HTTP1"), ServerMode::Http1);
    }

    #[test]
    fn test_parse_server_mode_http2_and_h2_alias() {
        assert_eq!(parse_server_mode("http2"), ServerMode::Http2);
        assert_eq!(parse_server_mode("h2"), ServerMode::Http2);
        assert_eq!(parse_server_mode("H2"), ServerMode::Http2);
    }

    #[test]
    fn test_parse_server_mode_auto_and_default_fallback() {
        assert_eq!(parse_server_mode("auto"), ServerMode::Auto);
        assert_eq!(parse_server_mode("AUTO"), ServerMode::Auto);
        assert_eq!(parse_server_mode("unknown"), ServerMode::Auto);
        assert_eq!(parse_server_mode(""), ServerMode::Auto);
    }
}
