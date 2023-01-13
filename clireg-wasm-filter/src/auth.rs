use log;
use proxy_wasm::types::Bytes;

use crate::cache;
use crate::cache::ReadableCache;
use crate::hash::Hasher;

pub const API_KEY_KIND: &'static str = "api_key";
pub const BASIC_KIND: &'static str = "basic";
pub const _JWT_KIND: &'static str = "jwt";

pub enum AuthError {
    Unauthorized = 401,
    Forbidden = 403,
}

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

pub fn check(cache: &dyn ReadableCache, key: &String, expected: Bytes) -> Result<(), AuthError> {
    let actual = cache.get(key);
    if let Some(actual) = actual {
        if actual.eq(&expected) {
            Ok(())
        } else {
            log::warn!("mismatch {:?} != {:?}", expected, actual);
            Err(AuthError::Forbidden)
        }
    } else {
        Err(AuthError::Unauthorized)
    }
}
