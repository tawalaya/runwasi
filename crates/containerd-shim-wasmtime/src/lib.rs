pub(crate) mod h2c;
pub(crate) mod http1;
mod http_proxy;
pub mod instance;
pub(crate) mod outbound;
pub(crate) mod raw_tcp;

pub use instance::WasmtimeShim;

#[cfg(unix)]
#[cfg(test)]
#[path = "tests.rs"]
mod wasmtime_tests;
