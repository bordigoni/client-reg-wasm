use log;
use proxy_wasm::types::Bytes;

use crate::cache;
use crate::cache::ReadableCache;
use crate::hash::Hasher;

pub const API_KEY_KIND: &'static str = "api_key";
pub const BASIC_KIND: &'static str = "basic";
pub const JWT_KIND: &'static str = "jwt";

pub trait Credential {
    fn check(&self, cache: &dyn ReadableCache, hasher: &dyn Hasher) -> bool;
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
    fn check(&self, cache: &dyn ReadableCache, hasher: &dyn Hasher) -> bool {
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
    fn check(&self, cache: &dyn ReadableCache, hasher: &dyn Hasher) -> bool {
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
    fn check(&self, cache: &dyn ReadableCache, hasher: &dyn Hasher) -> bool {
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

fn check(cache: &dyn ReadableCache, key: &String, expected: Bytes) -> bool {
    let actual = cache.get(key);
    if let Some(actual) = actual {
        if actual.eq(&expected) {
            true
        } else {
            log::warn!("mismatch {:?} != {:?}", expected, actual);
            false
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use crate::auth::{
        ApiKeyCredentials,
        BasicAuthCredentials,
        ClientId,
        Credential,
        JWTCredentials,
    };
    use crate::cache::mock::MockCache;
    use crate::cache::WritableCache;
    use crate::hash::HashAlg::SHA256;

    #[test]
    fn check() {
        let mut cache = MockCache::new();
        cache.put("foo".to_string(), Some("bar".as_bytes().to_vec()));
        assert_eq!(
            true,
            super::check(&cache, &"foo".to_string(), "bar".as_bytes().to_vec())
        )
    }

    #[test]
    fn fail_check_key() {
        let mut cache = MockCache::new();
        cache.put("foo".to_string(), Some("bar".as_bytes().to_vec()));
        assert_eq!(
            false,
            super::check(&cache, &"baz".to_string(), "bar".as_bytes().to_vec())
        )
    }
    #[test]
    fn fail_check_value() {
        let mut cache = MockCache::new();
        cache.put("foo".to_string(), Some("bar".as_bytes().to_vec()));
        assert_eq!(
            false,
            super::check(&cache, &"foo".to_string(), "baz".as_bytes().to_vec())
        )
    }

    #[test]
    fn check_api_key() {
        let mut cache = MockCache::new();
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
        assert_eq!(true, creds.check(&cache, hasher.deref()))
    }

    #[test]
    fn check_basic() {
        let mut cache = MockCache::new();
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
        assert_eq!(true, creds.check(&cache, hasher.deref()))
    }

    #[test]
    fn check_jwt() {
        let mut cache = MockCache::new();
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
        assert_eq!(true, creds.check(&cache, hasher.deref()))
    }
}
