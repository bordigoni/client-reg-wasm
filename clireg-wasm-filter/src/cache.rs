use proxy_wasm::types::Bytes;

pub mod hard_coded;
pub mod shared;

pub trait ReadableCache {
    fn get(&self, key: &String) -> Option<Bytes>;
}

pub trait WritableCache: Sync + Send {
    fn put(&mut self, key: String, value: Option<Bytes>);
    fn delete(&mut self, key: String);
}

pub(crate) fn format_key(api_id: &String, kind: &str, client_id: &String) -> String {
    let mut res = String::new();
    res.push_str(api_id);
    res.push('.');
    res.push_str(kind);
    res.push('.');
    res.push_str(client_id);
    res
}
