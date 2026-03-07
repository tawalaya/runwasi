use std::hash::Hash;
use std::sync::LazyLock;

use std::time::Duration;

use anyhow::{Context, Result, bail};
use containerd_shim_wasm::sandbox::Sandbox;
use containerd_shim_wasm::sandbox::context::{
    Entrypoint, RuntimeContext, WasmBinaryType, WasmLayer,
};
use containerd_shim_wasm::shim::{Compiler, Shim, Version, version};
use tokio_util::sync::CancellationToken;
use wasi_preview1::WasiP1Ctx;
use wasi_preview2::bindings::Command;
use wasmtime::component::types::ComponentItem;
use wasmtime::component::{self, Component, ResourceTable};
use wasmtime::{Config, Module, Precompiled, StoreLimits, StoreLimitsBuilder, Store};
use wasmtime_wasi::p2::{self as wasi_preview2};
use wasmtime_wasi::preview1::{self as wasi_preview1};
use wasmtime_wasi_http::bindings::ProxyPre;
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::types::{HostFutureIncomingResponse, OutgoingRequestConfig};
use wasmtime_wasi_http::{HttpResult, WasiHttpCtx, WasiHttpView};

use crate::h2c::h2c_send_request;

use crate::http_proxy::serve_conn;

/// Represents the WASI API that the component is targeting.
enum ComponentTarget<'a> {
    /// A component that targets WASI command-line interface.
    Command,
    /// A component that targets WASI http/proxy  interface.
    HttpProxy,
    /// Core function. The `&'a str` represents function to call.
    Core(&'a str),
}

impl<'a> ComponentTarget<'a> {
    fn new<'b, I>(exports: I, func: &'a str) -> Self
    where
        I: IntoIterator<Item = (&'b str, ComponentItem)> + 'b,
    {
        // This is heuristic but seems to work
        exports
            .into_iter()
            .find_map(|(name, _)| {
                if name.starts_with("wasi:http/incoming-handler") {
                    Some(Self::HttpProxy)
                } else if name.starts_with("wasi:cli/run") {
                    Some(Self::Command)
                } else {
                    None
                }
            })
            .unwrap_or(Self::Core(func))
    }
}

pub struct WasmtimeShim;

pub struct WasmtimeCompiler(wasmtime::Engine);

/// Default per-instance Wasm linear memory limit (128 MiB).
/// Override via `WASMTIME_MAX_MEMORY_SIZE` env var (bytes).
const DEFAULT_MAX_MEMORY_SIZE: usize = 128 * 1024 * 1024;

/// Default epoch-tick interval for the background ticker (10 ms).
const EPOCH_TICK_INTERVAL: Duration = Duration::from_millis(10);

/// Default per-request epoch deadline in ticks.
/// 3000 ticks × 10 ms = 30 s.
/// Override via `WASMTIME_EPOCH_TIMEOUT_MS` env var.
const DEFAULT_EPOCH_DEADLINE_TICKS: u64 = 3000;

pub struct WasmtimeSandbox {
    engine: wasmtime::Engine,
    cancel: CancellationToken,
}

impl Default for WasmtimeSandbox {
    fn default() -> Self {
        let mut config = wasmtime::Config::new();

        // Disable Wasmtime parallel compilation for the tests
        // see https://github.com/containerd/runwasi/pull/405#issuecomment-1928468714 for details
        config.parallel_compilation(!cfg!(test));
        config.wasm_component_model(true); // enable component linking
        config.async_support(true); // must be on

        // Enable epoch-based interruption so runaway guests can be preempted.
        config.epoch_interruption(true);

        if use_pooling_allocator_by_default() {
            let mut cfg = wasmtime::PoolingAllocationConfig::default();
            // Bound per-instance memory to match StoreLimits.
            cfg.max_memory_size(DEFAULT_MAX_MEMORY_SIZE);
            // Cap the total pools to reasonable values for a container workload.
            cfg.total_memories(200);
            cfg.total_tables(200);
            cfg.total_stacks(200);
            cfg.total_component_instances(200);
            cfg.total_core_instances(500);
            config.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(cfg));
        }

        let engine = wasmtime::Engine::new(&config)
            .context("failed to create wasmtime engine")
            .unwrap();

        // Spawn a background task that increments the epoch on a fixed interval.
        // This drives the epoch-interruption deadlines set on individual Stores.
        let ticker_engine = engine.clone();
        std::thread::Builder::new()
            .name("epoch-ticker".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(EPOCH_TICK_INTERVAL);
                    ticker_engine.increment_epoch();
                }
            })
            .expect("failed to spawn epoch ticker thread");

        Self {
            engine,
            cancel: CancellationToken::new(),
        }
    }
}

pub struct WasiPreview2Ctx {
    pub(crate) wasi_ctx: wasi_preview2::WasiCtx,
    pub(crate) wasi_http: WasiHttpCtx,
    pub(crate) resource_table: ResourceTable,
    /// Wasmtime resource limits (memory, tables, instances).
    pub(crate) store_limits: StoreLimits,
    /// When true, outgoing plaintext HTTP requests use HTTP/2 prior-knowledge (h2c)
    /// instead of HTTP/1.1. Required for gRPC communication.
    pub(crate) outgoing_h2c: bool,
}

impl WasiPreview2Ctx {
    pub fn new(ctx: &impl RuntimeContext) -> Result<Self> {
        log::debug!("Creating new WasiPreview2Ctx");
        Ok(Self {
            wasi_ctx: wasi_builder(ctx)?.build(),
            wasi_http: WasiHttpCtx::new(),
            resource_table: ResourceTable::default(),
            store_limits: default_store_limits(),
            outgoing_h2c: false,
        })
    }
}

/// Build the default `StoreLimits` used for every Wasm instance.
///
/// Caps linear memory growth to `DEFAULT_MAX_MEMORY_SIZE` (128 MiB) so a single
/// misbehaving guest cannot OOM the entire shim process.
pub(crate) fn default_store_limits() -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(DEFAULT_MAX_MEMORY_SIZE)
        .instances(100)
        .tables(20)
        .memories(20)
        .trap_on_grow_failure(false)
        .build()
}

/// Compute the epoch deadline (in ticks) from env or fall back to the default.
pub(crate) fn epoch_deadline_from_env(env: &[(String, String)]) -> u64 {
    env.iter()
        .find(|(k, _)| k == "WASMTIME_EPOCH_TIMEOUT_MS")
        .and_then(|(_, v)| v.parse::<u64>().ok())
        .map(|ms| ms / EPOCH_TICK_INTERVAL.as_millis() as u64)
        .unwrap_or(DEFAULT_EPOCH_DEADLINE_TICKS)
}

/// This impl is required to use wasmtime_wasi::preview2::WasiView trait.
impl wasi_preview2::WasiView for WasiPreview2Ctx {
    fn ctx(&mut self) -> &mut wasi_preview2::WasiCtx {
        &mut self.wasi_ctx
    }
}

impl wasi_preview2::IoView for WasiPreview2Ctx {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.resource_table
    }
}

impl WasiHttpView for WasiPreview2Ctx {
    fn ctx(&mut self) -> &mut wasmtime_wasi_http::WasiHttpCtx {
        &mut self.wasi_http
    }

    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        log::debug!(
            "send_request: outgoing_h2c={}, method={}, uri={}, use_tls={}",
            self.outgoing_h2c,
            request.method(),
            request.uri(),
            config.use_tls,
        );
        if self.outgoing_h2c {
            log::debug!("Using h2c (HTTP/2 prior-knowledge) for outgoing request");
            Ok(h2c_send_request(request, config))
        } else {
            log::debug!("Using default_send_request (HTTP/1.1) for outgoing request");
            Ok(wasmtime_wasi_http::types::default_send_request(request, config))
        }
    }
}

impl Shim for WasmtimeShim {
    fn name() -> &'static str {
        "wasmtime"
    }

    fn version() -> Version {
        version!()
    }

    type Sandbox = WasmtimeSandbox;

    #[allow(refining_impl_trait)]
    async fn compiler() -> Option<WasmtimeCompiler> {
        let mut config = wasmtime::Config::new();

        // Disable Wasmtime parallel compilation for the tests
        // see https://github.com/containerd/runwasi/pull/405#issuecomment-1928468714 for details
        config.parallel_compilation(!cfg!(test));
        config.wasm_component_model(true); // enable component linking
        config.async_support(true); // must be on
        // Must match the sandbox engine — epoch_interruption is baked into
        // precompiled artifacts and wasmtime rejects a mismatch at load time.
        config.epoch_interruption(true);

        let engine = wasmtime::Engine::new(&config)
            .expect("failed to create wasmtime precompilation engine");

        Some(WasmtimeCompiler(engine))
    }
}

impl Sandbox for WasmtimeSandbox {
    async fn run_wasi(&self, ctx: &impl RuntimeContext) -> Result<i32> {
        log::info!("setting up wasi");

        let Entrypoint {
            source,
            func,
            arg0: _,
            name: _,
        } = ctx.entrypoint();

        let wasm_bytes = &source.as_bytes()?;

        self.execute(ctx, wasm_bytes, func).await.into_error_code()
    }
}

impl Compiler for WasmtimeCompiler {
    fn cache_key(&self) -> impl Hash {
        self.0.precompile_compatibility_hash()
    }

    async fn compile(&self, layers: &[WasmLayer]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut compiled_layers = Vec::<Option<Vec<u8>>>::with_capacity(layers.len());

        for layer in layers {
            if wasmtime::Engine::detect_precompiled(&layer.layer).is_some() {
                log::info!("Already precompiled");
                compiled_layers.push(None);
                continue;
            }

            let compiled_layer = match WasmBinaryType::from_bytes(&layer.layer) {
                Some(WasmBinaryType::Module) => self.0.precompile_module(&layer.layer)?,
                Some(WasmBinaryType::Component) => self.0.precompile_component(&layer.layer)?,
                None => {
                    log::warn!("Unknown WASM binary type");
                    continue;
                }
            };

            compiled_layers.push(Some(compiled_layer));
        }

        Ok(compiled_layers)
    }
}

impl WasmtimeSandbox {
    /// Execute a wasm module.
    ///
    /// This function adds wasi_preview1 to the linker and can be utilized
    /// to execute a wasm module that uses wasi_preview1.
    async fn execute_module(
        &self,
        ctx: &impl RuntimeContext,
        module: Module,
        func: &String,
    ) -> Result<i32> {
        log::debug!("execute module");

        let ctx_p1 = wasi_builder(ctx)?.build_p1();
        let mut store = Store::new(&self.engine, ctx_p1);
        // Set a generous epoch deadline for long-running command modules.
        store.set_epoch_deadline(DEFAULT_EPOCH_DEADLINE_TICKS * 10);
        let mut module_linker = wasmtime::Linker::new(&self.engine);

        log::debug!("init linker");
        wasi_preview1::add_to_linker_async(&mut module_linker, |wasi_ctx: &mut WasiP1Ctx| {
            wasi_ctx
        })?;

        log::info!("instantiating instance");
        let instance: wasmtime::Instance =
            module_linker.instantiate_async(&mut store, &module).await?;

        log::debug!("getting start function");
        let start_func = instance
            .get_func(&mut store, func)
            .context("module does not have a WASI start function")?;

        log::info!("running start function {func:?}");

        start_func
            .call_async(&mut store, &[], &mut [])
            .await
            .into_error_code()
    }

    async fn execute_component_async(
        &self,
        ctx: &impl RuntimeContext,
        component: Component,
        func: String,
    ) -> Result<i32> {
        log::info!("instantiating component");

        let target = ComponentTarget::new(
            component.component_type().exports(&self.engine),
            func.as_str(),
        );

        // This is a adapter logic that converts wasip1 `_start` function to wasip2 `run` function.
        let status = match target {
            ComponentTarget::HttpProxy => {
                log::info!("Found HTTP proxy target");
                let mut linker = component::Linker::new(&self.engine);
                wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
                wasmtime_wasi_http::add_only_http_to_linker_async(&mut linker)?;

                let pre = linker.instantiate_pre(&component)?;
                log::info!("pre-instantiate_pre");
                let instance = ProxyPre::new(pre)?;

                log::info!("starting HTTP server");
                let cancel = self.cancel.clone();
                serve_conn(ctx, instance, cancel).await
            }
            ComponentTarget::Command => {
                log::info!("Found command target");
                let wasi_ctx = WasiPreview2Ctx::new(ctx)?;
                let (mut store, linker) = store_for_context(&self.engine, wasi_ctx)?;

                let command = Command::instantiate_async(&mut store, &component, &linker).await?;

                command
                    .wasi_cli_run()
                    .call_run(&mut store)
                    .await?
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "failed to run component targeting `wasi:cli/command` world"
                        )
                    })
            }
            ComponentTarget::Core(func) => {
                log::info!("Found Core target");
                let wasi_ctx = WasiPreview2Ctx::new(ctx)?;
                let (mut store, linker) = store_for_context(&self.engine, wasi_ctx)?;

                let pre = linker.instantiate_pre(&component)?;
                let instance = pre.instantiate_async(&mut store).await?;

                log::info!("getting component exported function {func:?}");
                let start_func = instance.get_func(&mut store, func).context(format!(
                    "component does not have exported function {func:?}"
                ))?;

                log::debug!("running exported function {func:?} {start_func:?}");
                start_func.call_async(&mut store, &[], &mut []).await
            }
        };

        status.into_error_code()
    }

    /// Execute a wasm component.
    ///
    /// This function adds wasi_preview2 to the linker and can be utilized
    /// to execute a wasm component that uses wasi_preview2.
    async fn execute_component(
        &self,
        ctx: &impl RuntimeContext,
        component: Component,
        func: String,
    ) -> Result<i32> {
        log::debug!("loading wasm component");
        tokio::select! {
            status = self.execute_component_async(ctx, component, func) => {
                status
            }
            status = self.handle_signals() => {
                status
            }
        }
    }

    async fn handle_signals(&self) -> Result<i32> {
        match wait_for_signal().await? {
            libc::SIGINT => {
                // Request graceful shutdown;
                self.cancel.cancel();
            }
            sig => {
                // On other signal, terminate the process without waiting for spawned tasks to finish.
                return Ok(128 + sig);
            }
        }

        // On a second SIGINT, terminate the process as well
        wait_for_signal().await
    }

    async fn execute(
        &self,
        ctx: &impl RuntimeContext,
        wasm_binary: &[u8],
        func: String,
    ) -> Result<i32> {
        match WasmBinaryType::from_bytes(wasm_binary) {
            Some(WasmBinaryType::Module) => {
                log::debug!("loading wasm module");
                let module = Module::from_binary(&self.engine, wasm_binary)?;
                self.execute_module(ctx, module, &func).await
            }
            Some(WasmBinaryType::Component) => {
                let component = Component::from_binary(&self.engine, wasm_binary)?;
                self.execute_component(ctx, component, func).await
            }
            None => match wasmtime::Engine::detect_precompiled(wasm_binary) {
                Some(Precompiled::Module) => {
                    log::info!("using precompiled module");
                    let module = unsafe { Module::deserialize(&self.engine, wasm_binary) }?;
                    self.execute_module(ctx, module, &func).await
                }
                Some(Precompiled::Component) => {
                    log::info!("using precompiled component");
                    let component = unsafe { Component::deserialize(&self.engine, wasm_binary) }?;
                    self.execute_component(ctx, component, func).await
                }
                None => {
                    bail!("invalid precompiled module")
                }
            },
        }
    }
}

pub(crate) fn envs_from_ctx(ctx: &impl RuntimeContext) -> Vec<(String, String)> {
    ctx.envs()
        .iter()
        .map(|v| {
            let (key, value) = v.split_once('=').unwrap_or((v.as_str(), ""));
            (key.to_string(), value.to_string())
        })
        .collect()
}

fn store_for_context(
    engine: &wasmtime::Engine,
    ctx: WasiPreview2Ctx,
) -> Result<(Store<WasiPreview2Ctx>, component::Linker<WasiPreview2Ctx>)> {
    let mut store = Store::new(engine, ctx);
    // Attach resource limiter (bounds memory growth).
    store.limiter(|state| &mut state.store_limits);
    // Set a generous epoch deadline for command / core components.
    store.set_epoch_deadline(DEFAULT_EPOCH_DEADLINE_TICKS * 10);

    log::debug!("init linker");
    let mut linker = component::Linker::new(engine);
    wasi_preview2::add_to_linker_async(&mut linker)?;

    Ok((store, linker))
}

fn wasi_builder(ctx: &impl RuntimeContext) -> Result<wasi_preview2::WasiCtxBuilder, anyhow::Error> {
    // TODO: make this more configurable (e.g. allow the user to specify the
    // preopened directories and their permissions)
    // https://github.com/containerd/runwasi/issues/413
    log::debug!("building WASI context");

    let file_perms = wasmtime_wasi::FilePerms::all();
    let dir_perms = wasmtime_wasi::DirPerms::all();
    let envs = envs_from_ctx(ctx);

    let mut builder = wasi_preview2::WasiCtxBuilder::new();
    builder
        .args(ctx.args())
        .envs(&envs)
        .inherit_stdio()
        .inherit_network()
        .allow_tcp(true)
        .allow_udp(true)
        .allow_ip_name_lookup(true)
        .preopened_dir("/", "/", dir_perms, file_perms)?;

    log::debug!("WASI context built successfully");
    Ok(builder)
}

async fn wait_for_signal() -> Result<i32> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigquit = signal(SignalKind::quit())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        tokio::select! {
            _ = sigquit.recv() => { Ok(libc::SIGQUIT) }
            _ = sigterm.recv() => { Ok(libc::SIGTERM) }
            _ = tokio::signal::ctrl_c() => { Ok(libc::SIGINT) }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await;
        Ok(1)
    }
}

/// The pooling allocator is tailor made for the `wasi/http` use case. Check if we can use it.
///
/// For more details refer to: <https://github.com/bytecodealliance/wasmtime/blob/v27.0.0/src/commands/serve.rs#L641>
fn use_pooling_allocator_by_default() -> bool {
    static SUPPORTS_POOLING_ALLOCATOR: LazyLock<bool> = LazyLock::new(|| {
        const BITS_TO_TEST: u32 = 42;
        let mut config = Config::new();
        config.wasm_memory64(true);
        config.memory_reservation(1 << BITS_TO_TEST);
        let Ok(engine) = wasmtime::Engine::new(&config) else {
            return false;
        };
        let mut store = Store::new(&engine, ());
        let ty = wasmtime::MemoryType::new64(0, Some(1 << (BITS_TO_TEST - 16)));
        wasmtime::Memory::new(&mut store, ty).is_ok()
    });
    *SUPPORTS_POOLING_ALLOCATOR
}

pub trait IntoErrorCode {
    fn into_error_code(self) -> Result<i32>;
}

impl IntoErrorCode for Result<i32> {
    fn into_error_code(self) -> Result<i32> {
        self.or_else(|err| match err.downcast_ref::<wasmtime_wasi::I32Exit>() {
            Some(exit) => Ok(exit.0),
            _ => Err(err),
        })
    }
}

impl IntoErrorCode for Result<()> {
    fn into_error_code(self) -> Result<i32> {
        self.map(|_| 0).into_error_code()
    }
}
