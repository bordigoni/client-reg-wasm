use super::ReadableCache;
use crate::cache::WritableCache;
use crate::{AuthFilter, AuthFilterConfig};
use proxy_wasm::traits::Context;
use proxy_wasm::types::Bytes;

impl ReadableCache for AuthFilter {
    fn get(&self, id: &String) -> Option<Bytes> {
        self.get_shared_data(id).0
    }
}

impl WritableCache for AuthFilterConfig {
    fn put(&mut self, key: String, value: Option<Bytes>) {
        if let Some(bytes) = value {
            let res = self.set_shared_data(key.as_str(), Some(&bytes), None);
            if let Err(err) = res {
                log::error!(
                    "[CACHE] Error while putting key {} to shared cache: {:?}",
                    key,
                    err
                );
            } else {
                log::debug!("[CACHE] Entry {} added", key)
            }
        }
    }

    fn delete(&mut self, key: String) {
        let res = self.set_shared_data(key.as_str(), None, None);
        match res {
            Ok(..) => {
                log::debug!("[CACHE] Entry {} deleted", key)
            }
            Err(s) => match s {
                err => {
                    log::debug!(
                        "[CACHE] Error setting None to shared cache key '{}': {:?}",
                        key,
                        err
                    )
                }
            },
        }
    }
}
