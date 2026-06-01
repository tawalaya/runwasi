// Heavily inspired by wasmtime serve command:
// https://github.com/bytecodealliance/wasmtime/blob/main/src/commands/serve.rs

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
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

use crate::instance::{WasiPreview2Ctx, ServicePre, envs_from_ctx, epoch_deadline_from_env, default_store_limits, DEFAULT_MAX_MEMORY_SIZE};

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
        let n = usable / DEFAULT_MAX_MEMORY_SIZE as u64;
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

    let socket = match addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };

    // Conditionally enable `SO_REUSEADDR` depending on the current
    // platform. On Unix we want this to be able to rebind an address in
    // the `TIME_WAIT` state which can happen then a server is killed with
    // active TCP connections and then restarted. On Windows though if
    // `SO_REUSEADDR` is specified then it enables multiple applications to
    // bind the port at the same time which is not something we want. Hence
    // this is conditionally set based on the platform (and deviates from
    // Tokio's default from always-on).
    socket.set_reuseaddr(!cfg!(windows))?;
    socket.bind(addr)?;

    let listener = socket.listen(backlog)?;
    let tracker = TaskTracker::new();

    // Determine server mode via env: "http1", "http2"/"h2" or "auto" (default = "auto")
    let mode = env
        .remove("WASMTIME_HTTP_PROXY_SERVER_MODE")
        .unwrap_or_else(|| "auto".to_string());
    #[derive(Debug, Clone, Copy)]
    enum ServerMode { Http1, Http2, Auto }
    let mode = match mode.to_ascii_lowercase().as_str() {
        "http1" => ServerMode::Http1,
        "http2" | "h2" => ServerMode::Http2,
        "auto" => ServerMode::Auto,
        _ => ServerMode::Auto,
    };

    // Outgoing h2c is independent from the incoming server mode.
    // Only enable when explicitly requested — the default upstream behavior (HTTP/1.1) is
    // more compatible with the variety of backends a guest might call.
    let outgoing_h2c = env
        .remove("WASMTIME_HTTP_PROXY_OUTGOING_H2C")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    // Allow guest network access only when explicitly opted in (#5).
    let allow_network = env
        .remove("WASMTIME_HTTP_PROXY_ALLOW_NETWORK")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    let env: Vec<(String, String)> = env.into_iter().collect();
    let epoch_deadline = epoch_deadline_from_env(&env);
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let handler = Arc::new(ProxyHandler::new(instance, env, tracker.clone(), outgoing_h2c, epoch_deadline, allow_network, request_timeout, semaphore));

    log::info!(
        "Serving HTTP on http://{} (mode: {:?}, max_concurrent: {}, request_timeout: {:?})",
        listener.local_addr()?, mode, max_concurrent, request_timeout
    );

    // Pre-build connection handlers outside the loop to avoid per-connection allocations (#7).
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

    tracker.close();
    tracker.wait().await;

    Ok(())
}

struct ProxyHandler {
    instance_pre: ServicePre<WasiPreview2Ctx>,
    next_id: AtomicU64,
    env: Vec<(String, String)>,
    tracker: TaskTracker,
    /// When true, outgoing plaintext HTTP requests use HTTP/2 prior-knowledge (h2c).
    outgoing_h2c: bool,
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
        outgoing_h2c: bool,
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
            outgoing_h2c,
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
            outgoing_h2c: self.outgoing_h2c,
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
