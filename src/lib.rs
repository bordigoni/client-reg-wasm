use log::info;
use proxy_wasm::traits::{Context, HttpContext};
use proxy_wasm::types::*;

mod cash;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(AuthFilter) });
}}

struct AuthFilter;

impl HttpContext for AuthFilter {}

impl Context for AuthFilter {}
