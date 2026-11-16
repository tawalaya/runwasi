//! Serve one `wasi:http` component (0.3 handler, or 0.2 proxy) over HTTP/1.1 and h2c with
//! reused instances, and a pooled outbound client that speaks h2 prior-knowledge to the
//! authorities listed in `WASIHOST_H2C_AUTHORITIES`. Same machinery as `wasmtime serve`.
//!
//! Pod env knobs: `PORT` (or `WASMTIME_HTTP_PROXY_SOCKET_ADDR`), `WASMTIME_HTTP_BACKLOG`,
//! `WASIHOST_H2C_AUTHORITIES=host:port,...`, `WASIHOST_INSTANCE_REUSE` (0 = unbounded),
//! `WASIHOST_INSTANCE_CONCURRENCY`, `WASIHOST_REQUEST_TIMEOUT_S`, `WASIHOST_MAX_INSTANCES`
//! (unset or 0 = unbounded).

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use containerd_shim_wasm::sandbox::context::RuntimeContext;
use http_body_util::BodyExt;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use wasmtime::component::{Component, TaskGroupId, Linker, ResourceTable};
use wasmtime::{Engine, Store, StoreContextMut};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::handler::{
    HandlerState, Instance, ProxyHandler, ProxyPre, ShouldAccept, WorkerExpiration, WorkerState,
    WorkerStatus,
};
use wasmtime_wasi_http::{
    RequestOptions, WasiBody, WasiHttpCtx, WasiHttpCtxView, WasiHttpHooks, WasiHttpView,
};

use crate::instance::{envs_from_ctx, wasi_builder_from};

type Outbound = Client<HttpConnector, WasiBody>;
type HookFuture<T> = Box<dyn Future<Output = T> + Send>;
type IoResult = Result<(), wasmtime_wasi_http::Error>;

#[derive(Clone)]
struct Clients {
    h1: Outbound,
    h2: Outbound,
    h2c: Arc<Vec<String>>,
}

impl Clients {
    fn new(h2c: Vec<String>) -> Self {
        let connector = || {
            let mut c = HttpConnector::new();
            c.set_nodelay(true);
            c
        };
        let h1 = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(connector());
        let h2 = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .http2_only(true)
            .build(connector());
        Self {
            h1,
            h2,
            h2c: Arc::new(h2c),
        }
    }
}

struct Hooks(Clients);

/// The guest's `wasi:http` request options; `None` = no deadline (the worker's request
/// timeout still applies).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OutboundTimeouts {
    connect: Option<Duration>,
    first_byte: Option<Duration>,
    between_bytes: Option<Duration>,
}

impl OutboundTimeouts {
    /// The pooled client connects inside `request()`, so connect and first byte share one
    /// deadline; the first-byte timeout is the longer of the two by meaning, so it wins.
    /// `between_bytes` is not enforced: response bodies stream after the hook returns and
    /// every guest here makes unary calls.
    fn request_deadline(&self) -> Option<Duration> {
        self.first_byte.or(self.connect)
    }
}

fn outbound_timeouts(opts: Option<&RequestOptions>) -> OutboundTimeouts {
    opts.map(|o| OutboundTimeouts {
        connect: o.connect_timeout,
        first_byte: o.first_byte_timeout,
        between_bytes: o.between_bytes_timeout,
    })
    .unwrap_or_default()
}

impl WasiHttpHooks for Hooks {
    fn default_scheme(&mut self) -> Option<http::uri::Scheme> {
        Some(http::uri::Scheme::HTTP)
    }

    fn send_request(
        &mut self,
        request: http::Request<WasiBody>,
        options: Option<RequestOptions>,
        _fut: HookFuture<IoResult>,
    ) -> HookFuture<
        Result<(http::Response<WasiBody>, HookFuture<IoResult>), wasmtime_wasi_http::Error>,
    > {
        let timeouts = outbound_timeouts(options.as_ref());
        let authority = request
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let client = if self.0.h2c.iter().any(|a| *a == authority) {
            self.0.h2.clone()
        } else {
            self.0.h1.clone()
        };
        Box::new(async move {
            let sent = client.request(request);
            let sent = match timeouts.request_deadline() {
                Some(deadline) => match tokio::time::timeout(deadline, sent).await {
                    Ok(r) => r,
                    Err(_) => {
                        log::error!("outbound {authority}: no response within {deadline:?}");
                        return Err(wasmtime_wasi_http::Error::ConnectionReadTimeout);
                    }
                },
                None => sent.await,
            };
            let resp = sent.map_err(|e| {
                log::error!("outbound {authority}: {e}");
                if e.is_connect() {
                    wasmtime_wasi_http::Error::ConnectionRefused
                } else {
                    wasmtime_wasi_http::Error::HttpProtocolError
                }
            })?;
            let resp = resp.map(|b| b.map_err(wasmtime_wasi_http::Error::from).boxed_unsync());
            // Ok, not a stand-in: the pooled client drives each connection in its own task,
            // so there is no per-request connection future to hand back (unlike wasmtime's
            // default_send_request), and the request side is complete once the response
            // head arrived; an earlier failure already came back as `Err` above.
            let done: HookFuture<IoResult> = Box::new(async { Ok(()) });
            Ok((resp, done))
        })
    }
}

pub(crate) struct Host {
    table: ResourceTable,
    ctx: WasiCtx,
    http: WasiHttpCtx,
    hooks: Hooks,
}

impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for Host {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.hooks,
        }
    }
}

struct Expiration {
    idle: Duration,
    request: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl WorkerExpiration for Expiration {
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        status: WorkerStatus,
        start: Instant,
    ) -> Poll<()> {
        let me = self.get_mut();
        let timeout = match status {
            WorkerStatus::Idle => me.idle,
            WorkerStatus::Requests | WorkerStatus::PostReturn => me.request,
        };
        match start.checked_add(timeout) {
            Some(deadline) => {
                let deadline = deadline.into();
                if deadline != me.sleep.deadline() {
                    me.sleep.as_mut().reset(deadline);
                }
                me.sleep.as_mut().poll(cx)
            }
            None => Poll::Pending,
        }
    }
}

struct Worker {
    reuse: usize,
    concurrency: usize,
    request_timeout: Duration,
}

impl WorkerState for Worker {
    type StoreData = Host;
    type RequestData = u64;

    fn should_accept_request(&self, concurrent: usize, total: usize) -> ShouldAccept {
        if self.reuse != 0 && total >= self.reuse {
            ShouldAccept::Never
        } else if concurrent >= self.concurrency {
            ShouldAccept::No
        } else {
            ShouldAccept::Yes
        }
    }

    fn on_request_start(
        &self,
        _store: StoreContextMut<'_, Host>,
        _request_id: u64,
        _task: TaskGroupId,
    ) -> Pin<Box<dyn Future<Output = ()> + 'static + Send + Sync>> {
        Box::pin(tokio::time::sleep(self.request_timeout))
    }

    fn drop(&self, store: Store<Host>, result: Result<(), wasmtime::Error>) {
        if let Err(e) = result {
            log::error!("worker failed: {e:?}");
        }
        drop(store);
    }
}

struct State {
    engine: Engine,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    pre: ProxyPre<Host>,
    clients: Clients,
    reuse: usize,
    concurrency: usize,
    request_timeout: Duration,
    limit: Option<Arc<Semaphore>>,
    next_instance: AtomicU64,
    next_request: AtomicU64,
}

impl HandlerState for State {
    type StoreData = Host;
    type WorkerExpiration = Expiration;
    type WorkerState = Worker;

    async fn instantiate(&self) -> wasmtime::Result<Instance<Host, Expiration, Worker>> {
        let id = self.next_instance.fetch_add(1, Relaxed);
        let mut builder = wasi_builder_from(&self.args, &self.envs)?;
        builder.env("INSTANCE_ID", id.to_string());
        let host = Host {
            table: ResourceTable::new(),
            ctx: builder.build(),
            http: WasiHttpCtx::new(),
            hooks: Hooks(self.clients.clone()),
        };
        let mut store = Store::new(&self.engine, host);
        let proxy = self.pre.instantiate_async(&mut store).await?;
        Ok(Instance {
            store,
            proxy,
            view: WasiHttpView::http,
            expiration: Expiration {
                idle: Duration::from_secs(3600),
                request: self.request_timeout,
                sleep: Box::pin(tokio::time::sleep(Duration::MAX)),
            },
            state: Worker {
                reuse: self.reuse,
                concurrency: self.concurrency,
                request_timeout: self.request_timeout,
            },
        })
    }
}

fn env_usize(env: &HashMap<String, String>, name: &str, default: usize) -> usize {
    env.get(name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

const DEFAULT_INSTANCE_CONCURRENCY: usize = 16;

/// `WASIHOST_MAX_INSTANCES` as a cap on in-flight requests: instances × per-instance concurrency.
///
/// Without a cap the handler starts another instance whenever every live one is at its
/// concurrency, so a burst grows guest linear memory until the pod is OOMKilled (the P3
/// pods at their failing step, September). The cap sits around `ProxyHandler::handle`, not
/// in `instantiate`: a request handed to a new worker waits for that worker's instantiate,
/// and with instance reuse unbounded a permit held by an instance is only released when it
/// idles out (an hour), so a permit wait there strands the request. Capping requests bounds
/// instances too, because a new worker starts only when all existing ones are full.
fn instance_limit(env: &HashMap<String, String>) -> Option<Arc<Semaphore>> {
    let raw = env.get("WASIHOST_MAX_INSTANCES")?;
    match raw.parse::<usize>() {
        Ok(0) => None,
        Ok(max) => {
            let per = env_usize(env, "WASIHOST_INSTANCE_CONCURRENCY", DEFAULT_INSTANCE_CONCURRENCY);
            Some(Arc::new(Semaphore::new(max * per)))
        }
        Err(_) => {
            log::warn!("WASIHOST_MAX_INSTANCES={raw:?} is not a number; instances stay unbounded");
            None
        }
    }
}

async fn handle(
    handler: ProxyHandler<State>,
    req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<WasiBody>, std::convert::Infallible> {
    let id = handler.state().next_request.fetch_add(1, Relaxed);
    // Held until the guest has produced the response; excess requests queue here.
    let _permit = match &handler.state().limit {
        Some(limit) => Some(limit.clone().acquire_owned().await.expect("never closed")),
        None => None,
    };
    let req = req.map(|b| b.map_err(wasmtime_wasi_http::Error::from).boxed_unsync());
    match handler.handle(id, req).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            log::error!("request {id}: {e:?}");
            let body = http_body_util::Full::new(Bytes::from_static(b"guest error"))
                .map_err(wasmtime_wasi_http::Error::from)
                .boxed_unsync();
            Ok(hyper::Response::builder().status(500).body(body).unwrap())
        }
    }
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
        Ok((stream, _addr)) => Some(stream),
        Err(e) => {
            if is_connection_error(&e) {
                return None;
            }
            // EMFILE and friends: log, back off a second, retry.
            log::error!("accept error: {e}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            None
        }
    }
}

pub(crate) async fn serve_conn(
    ctx: &impl RuntimeContext,
    engine: &Engine,
    component: &Component,
    cancel: CancellationToken,
) -> Result<()> {
    let envs = envs_from_ctx(ctx);
    let env: HashMap<String, String> = envs.iter().cloned().collect();

    let addr: SocketAddr = match env.get("WASMTIME_HTTP_PROXY_SOCKET_ADDR") {
        Some(v) => v.parse()?,
        None => {
            let port: u16 = env.get("PORT").map(|p| p.parse()).transpose()?.unwrap_or(8080);
            SocketAddr::from(([0, 0, 0, 0], port))
        }
    };
    let backlog = env_usize(&env, "WASMTIME_HTTP_BACKLOG", 100) as u32;

    let mut linker = Linker::<Host>::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;
    wasmtime_wasi::p3::add_to_linker(&mut linker)?;
    wasmtime_wasi_http::p3::add_to_linker(&mut linker)?;
    let instance = linker.instantiate_pre(component)?;
    let pre = match wasmtime_wasi_http::p3::bindings::ServicePre::new(instance.clone()) {
        Ok(p) => {
            log::info!("component exports wasi:http/handler@0.3");
            ProxyPre::P3(p)
        }
        Err(_) => {
            log::info!("component exports wasi:http/incoming-handler@0.2");
            ProxyPre::P2(wasmtime_wasi_http::p2::bindings::ProxyPre::new(instance)?)
        }
    };

    let h2c: Vec<String> = env
        .get("WASIHOST_H2C_AUTHORITIES")
        .map(String::as_str)
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let state = State {
        engine: engine.clone(),
        args: ctx.args().to_vec(),
        envs,
        pre,
        clients: Clients::new(h2c),
        reuse: env_usize(&env, "WASIHOST_INSTANCE_REUSE", 0),
        concurrency: env_usize(&env, "WASIHOST_INSTANCE_CONCURRENCY", DEFAULT_INSTANCE_CONCURRENCY),
        request_timeout: Duration::from_secs(
            env_usize(&env, "WASIHOST_REQUEST_TIMEOUT_S", 30) as u64,
        ),
        limit: instance_limit(&env),
        next_instance: AtomicU64::new(0),
        next_request: AtomicU64::new(0),
    };
    let handler = ProxyHandler::new(state);

    let socket = match addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(!cfg!(windows))?;
    socket.bind(addr)?;
    let listener = socket.listen(backlog)?;
    let tracker = TaskTracker::new();
    log::info!("Serving HTTP on http://{}/", listener.local_addr()?);

    loop {
        let stream = tokio::select! {
            conn = tcp_accept(&listener) => match conn {
                Some(conn) => conn,
                None => continue,
            },
            _ = cancel.cancelled() => break,
        };
        if let Err(e) = stream.set_nodelay(true) {
            log::warn!("set_nodelay: {e}");
        }
        let handler = handler.clone();
        tracker.spawn(async move {
            let svc = hyper::service::service_fn(move |req| handle(handler.clone(), req));
            if let Err(e) = AutoBuilder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                log::error!("connection: {e}");
            }
        });
    }

    tracker.close();
    tracker.wait().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Serial like the wasmtime_tests, which start sandboxed containers in this process: run
    // alongside them, send_request_reports_refused_connections hung for over 60 s.
    use serial_test::serial;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    #[serial]
    fn instance_limit_unset_or_zero_is_unbounded() {
        assert!(instance_limit(&HashMap::new()).is_none());
        assert!(instance_limit(&env(&[("WASIHOST_MAX_INSTANCES", "0")])).is_none());
    }

    #[test]
    #[serial]
    fn instance_limit_permits_are_instances_times_concurrency() {
        let limit = instance_limit(&env(&[
            ("WASIHOST_MAX_INSTANCES", "4"),
            ("WASIHOST_INSTANCE_CONCURRENCY", "2"),
        ]))
        .unwrap();
        assert_eq!(limit.available_permits(), 8);
    }

    #[test]
    #[serial]
    fn instance_limit_uses_default_concurrency() {
        let limit = instance_limit(&env(&[("WASIHOST_MAX_INSTANCES", "4")])).unwrap();
        assert_eq!(limit.available_permits(), 4 * DEFAULT_INSTANCE_CONCURRENCY);
    }

    #[test]
    #[serial]
    fn instance_limit_garbage_is_unbounded() {
        assert!(instance_limit(&env(&[("WASIHOST_MAX_INSTANCES", "four")])).is_none());
    }

    #[test]
    #[serial]
    fn outbound_timeouts_without_options_are_unset() {
        assert_eq!(outbound_timeouts(None), OutboundTimeouts::default());
        assert_eq!(outbound_timeouts(None).request_deadline(), None);
    }

    #[test]
    #[serial]
    fn outbound_timeouts_map_guest_options() {
        let opts = RequestOptions {
            connect_timeout: Some(Duration::from_secs(2)),
            first_byte_timeout: Some(Duration::from_secs(5)),
            between_bytes_timeout: None,
        };
        let t = outbound_timeouts(Some(&opts));
        assert_eq!(t.connect, Some(Duration::from_secs(2)));
        assert_eq!(t.first_byte, Some(Duration::from_secs(5)));
        assert_eq!(t.between_bytes, None);
        // first byte includes connecting on a pooled client, so it is the deadline
        assert_eq!(t.request_deadline(), Some(Duration::from_secs(5)));
        let only_connect = OutboundTimeouts { connect: Some(Duration::from_secs(2)), ..Default::default() };
        assert_eq!(only_connect.request_deadline(), Some(Duration::from_secs(2)));
    }

    fn get(authority: &str) -> http::Request<WasiBody> {
        let body = http_body_util::Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync();
        http::Request::get(format!("http://{authority}/")).body(body).unwrap()
    }

    #[tokio::test]
    #[serial]
    async fn send_request_times_out_on_a_silent_downstream() {
        // accepts, never answers: without the first-byte deadline the guest waits for the
        // shim's 30 s request timeout instead of seeing its own timeout
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let _hold = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let (s, _) = listener.accept().await.unwrap();
                held.push(s);
            }
        });
        let mut hooks = Hooks(Clients::new(Vec::new()));
        let opts = RequestOptions { first_byte_timeout: Some(Duration::from_millis(200)), ..Default::default() };
        let done: HookFuture<IoResult> = Box::new(async { Ok(()) });
        let start = Instant::now();
        let res = tokio::time::timeout(
            Duration::from_secs(10),
            Pin::from(hooks.send_request(get(&addr), Some(opts), done)),
        )
        .await
        .expect("hook ignored the guest's first-byte timeout");
        assert!(matches!(res, Err(wasmtime_wasi_http::Error::ConnectionReadTimeout)), "{:?}", res.err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    #[serial]
    async fn send_request_reports_refused_connections() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let mut hooks = Hooks(Clients::new(Vec::new()));
        let done: HookFuture<IoResult> = Box::new(async { Ok(()) });
        let res = Pin::from(hooks.send_request(get(&addr), None, done)).await;
        assert!(matches!(res, Err(wasmtime_wasi_http::Error::ConnectionRefused)), "{:?}", res.err());
    }
}
