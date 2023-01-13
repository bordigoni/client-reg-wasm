use log;
use proxy_wasm::types::Bytes;

use crate::cache;
use crate::cache::ReadableCache;
use crate::hash::Hasher;

pub const API_KEY_KIND: &'static str = "api_key";
pub const BASIC_KIND: &'static str = "basic";
pub const JWT_KIND: &'static str = "jwt";

// TODO replace with bool
pub type AuthError = ();

pub trait Credential {
    fn check(&self, cache: &dyn ReadableCache, hasher: &dyn Hasher) -> Result<(), AuthError>;
    fn to_cache_key(&self, hasher: &dyn Hasher) -> String;
}

pub struct ClientId {
    pub api_id: String,
    pub id: String,
}

pub struct ApiKeyCredentials {
    pub client_id: ClientId,
}

pub struct JWTCredentials {
    pub client_id: ClientId,
}

pub struct BasicAuthCredentials {
    pub client_id: ClientId,
    pub secret: Bytes,
}

impl Credential for ApiKeyCredentials {
    fn check(&self, cache: &dyn ReadableCache, hasher: &dyn Hasher) -> Result<(), AuthError> {
        check(
            cache,
            &self.to_cache_key(hasher),
            hasher.hash(self.client_id.id.as_bytes().to_vec()),
        )
    }
    fn to_cache_key(&self, hasher: &dyn Hasher) -> String {
        cache::format_key(
            &self.client_id.api_id,
            API_KEY_KIND,
            &hasher.hash_base64(self.client_id.id.as_bytes().to_vec()),
        )
    }
}

impl Credential for BasicAuthCredentials {
    fn check(&self, cache: &dyn ReadableCache, hasher: &dyn Hasher) -> Result<(), AuthError> {
        check(
            cache,
            &self.to_cache_key(hasher),
            hasher.hash(self.secret.to_vec()),
        )
    }
    fn to_cache_key(&self, _hasher: &dyn Hasher) -> String {
        cache::format_key(&self.client_id.api_id, BASIC_KIND, &self.client_id.id)
    }
}

impl Credential for JWTCredentials {
    fn check(&self, cache: &dyn ReadableCache, hasher: &dyn Hasher) -> Result<(), AuthError> {
        check(
            cache,
            &self.to_cache_key(hasher),
            self.client_id.id.as_bytes().to_vec(),
        )
    }

    fn to_cache_key(&self, _: &dyn Hasher) -> String {
        cache::format_key(&self.client_id.api_id, JWT_KIND, &self.client_id.id)
    }
}

fn check(cache: &dyn ReadableCache, key: &String, expected: Bytes) -> Result<(), AuthError> {
    let actual = cache.get(key);
    if let Some(actual) = actual {
        if actual.eq(&expected) {
            Ok(())
        } else {
            log::warn!("mismatch {:?} != {:?}", expected, actual);
            Err(())
        }
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ops::Deref;

    use proxy_wasm::types::Bytes;

    use crate::auth::{
        ApiKeyCredentials,
        BasicAuthCredentials,
        ClientId,
        Credential,
        JWTCredentials,
    };
    use crate::cache::{ReadableCache, WritableCache};
    use crate::hash::HashAlg::SHA256;

    struct MockCache {
        data: HashMap<String, Bytes>,
    }

    fn new_cache() -> MockCache {
        MockCache {
            data: HashMap::new(),
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

    #[test]
    fn check() {
        let mut cache = new_cache();
        cache.put("foo".to_string(), Some("bar".as_bytes().to_vec()));
        super::check(&cache, &"foo".to_string(), "bar".as_bytes().to_vec()).unwrap()
    }

    #[test]
    #[should_panic]
    fn fail_check_key() {
        let mut cache = new_cache();
        cache.put("foo".to_string(), Some("bar".as_bytes().to_vec()));
        super::check(&cache, &"baz".to_string(), "bar".as_bytes().to_vec()).unwrap()
    }
    #[test]
    #[should_panic]
    fn fail_check_value() {
        let mut cache = new_cache();
        cache.put("foo".to_string(), Some("bar".as_bytes().to_vec()));
        super::check(&cache, &"foo".to_string(), "baz".as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn check_api_key() {
        let mut cache = new_cache();
        let creds = ApiKeyCredentials {
            client_id: ClientId {
                api_id: "foo".to_string(),
                id: "123456789".to_string(),
            },
        };
        let hasher = SHA256.new();
        cache.put(
            creds.to_cache_key(hasher.deref()),
            Some(hasher.hash("123456789".to_string().into_bytes().to_vec())),
        );
        creds.check(&cache, hasher.deref()).unwrap()
    }

    #[test]
    fn check_basic() {
        let mut cache = new_cache();
        let creds = BasicAuthCredentials {
            client_id: ClientId {
                api_id: "foo".to_string(),
                id: "admin".to_string(),
            },
            secret: "changeme".to_string().into_bytes().to_vec(),
        };
        let hasher = SHA256.new();
        cache.put(
            creds.to_cache_key(hasher.deref()),
            Some(hasher.hash("changeme".to_string().into_bytes().to_vec())),
        );
        creds.check(&cache, hasher.deref()).unwrap()
    }

    #[test]
    fn check_jwt() {
        let mut cache = new_cache();
        let creds = JWTCredentials {
            client_id: ClientId {
                api_id: "foo".to_string(),
                id: "benoit".to_string(),
            },
        };
        let hasher = SHA256.new();
        cache.put(
            creds.to_cache_key(hasher.deref()),
            Some("benoit".to_string().into_bytes().to_vec()),
        );
        creds.check(&cache, hasher.deref()).unwrap()
    }
}
