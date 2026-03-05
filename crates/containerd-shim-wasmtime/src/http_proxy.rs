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
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use wasmtime::Store;
use wasmtime::component::ResourceTable;
use wasmtime_wasi_http::bindings::ProxyPre;
use wasmtime_wasi_http::bindings::http::types::Scheme;
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpView};

use crate::instance::{WasiPreview2Ctx, envs_from_ctx, epoch_deadline_from_env, default_store_limits};

const DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 8080);

const DEFAULT_BACKLOG: u32 = 100;

type Request = hyper::Request<hyper::body::Incoming>;

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
    instance: ProxyPre<WasiPreview2Ctx>,
    cancel: CancellationToken,
) -> Result<()> {
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
    // When mode is "http2" or "h2", also enable h2c for outgoing requests (gRPC support)
    let outgoing_h2c = matches!(mode.to_ascii_lowercase().as_str(), "http2" | "h2");
    let mode = match mode.to_ascii_lowercase().as_str() {
        "http1" => ServerMode::Http1,
        "http2" | "h2" => ServerMode::Http2,
        "auto" => ServerMode::Auto,
        _ => ServerMode::Auto,
    };

    // Allow guest network access only when explicitly opted in (#5).
    let allow_network = env
        .remove("WASMTIME_HTTP_PROXY_ALLOW_NETWORK")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    let env: Vec<(String, String)> = env.into_iter().collect();
    let epoch_deadline = epoch_deadline_from_env(&env);
    let handler = Arc::new(ProxyHandler::new(instance, env, tracker.clone(), outgoing_h2c, epoch_deadline, allow_network));

    log::info!("Serving HTTP on http://{} (mode: {:?})", listener.local_addr()?, mode);

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
    instance_pre: ProxyPre<WasiPreview2Ctx>,
    next_id: AtomicU64,
    env: Vec<(String, String)>,
    tracker: TaskTracker,
    /// When true, outgoing plaintext HTTP requests use HTTP/2 prior-knowledge (h2c).
    outgoing_h2c: bool,
    /// Per-request epoch deadline in ticks.
    epoch_deadline: u64,
    /// Whether the guest is allowed to make outgoing network connections.
    allow_network: bool,
}

impl ProxyHandler {
    fn new(
        instance_pre: ProxyPre<WasiPreview2Ctx>,
        env: Vec<(String, String)>,
        tracker: TaskTracker,
        outgoing_h2c: bool,
        epoch_deadline: u64,
        allow_network: bool,
    ) -> Self {
        ProxyHandler {
            instance_pre,
            env,
            tracker,
            next_id: AtomicU64::from(0),
            outgoing_h2c,
            epoch_deadline,
            allow_network,
        }
    }

    fn wasi_store_for_request(&self, req_id: u64) -> Store<WasiPreview2Ctx> {
        let engine = self.instance_pre.engine();
        let mut builder = wasmtime_wasi::p2::WasiCtxBuilder::new();

        builder.envs(&self.env);
        builder.env("REQUEST_ID", req_id.to_string());
        // Expose guest stdout/stderr so diagnostic logs reach containerd (#4).
        builder.inherit_stdio();
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

        match receiver.await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => {
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
        }
    }

    fn next_req_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}
