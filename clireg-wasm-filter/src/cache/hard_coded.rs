use log;
use proxy_wasm::types::Bytes;

use super::WritableCache;

pub fn _init(cache: &mut dyn WritableCache) {
    log::info!("init hard coded cache");
    cache.put(
        String::from("filter1.api_key.ABCDEF"),
        Some(Bytes::from("ABCDEF".as_bytes())),
    );
    cache.put(
        String::from("filter2.basic.admin"),
        Some(Bytes::from("changeme".as_bytes())),
    );
}
