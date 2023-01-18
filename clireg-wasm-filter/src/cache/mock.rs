use std::collections::HashMap;

use proxy_wasm::types::Bytes;

use crate::cache::{ReadableCache, WritableCache};

pub struct MockCache {
    data: HashMap<String, Bytes>,
}

#[cfg(test)]
impl MockCache {
    pub fn new() -> MockCache {
        MockCache {
            data: HashMap::new(),
        }
    }
}

impl ReadableCache for MockCache {
    fn get(&self, key: &String) -> Option<Bytes> {
        self.data.get(key.as_str()).map(|d| d.clone())
    }
}

impl WritableCache for MockCache {
    fn put(&mut self, key: String, value: Option<Bytes>) {
        if let Some(value) = value {
            self.data.insert(key, value);
        }
    }

    fn delete(&mut self, key: String) {
        self.data.remove(key.as_str());
    }
}
