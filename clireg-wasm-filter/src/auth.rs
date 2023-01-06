use std::fmt::{Display, Formatter};
use crate::cache::ReadableCache;
use log;
use proxy_wasm::types::Bytes;
use serde::{Serialize, Deserialize};
use crate::hash::Hasher;


pub enum AuthError {
    Unauthorized = 401,
    Forbidden = 403,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum AuthKind {
    Unknown,
    ApiKey,
    Basic,
    _JWT,
}

impl Default for AuthKind {
    fn default() -> Self {
        AuthKind::Unknown
    }
}

impl Display for AuthKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthKind::Unknown => { f.write_str("Unknown") }
            AuthKind::ApiKey => { f.write_str("ApiKey") }
            AuthKind::Basic => { f.write_str("Basic") }
            AuthKind::_JWT => { f.write_str("JWT") }
        }
    }
}

impl AuthKind {
    pub const API_KEY_KIND: &'static str = "api_key";
    pub const BASIC_KIND: &'static str = "basic";

    pub fn from(s: &str) -> AuthKind {
        match s {
            Self::API_KEY_KIND => {
                Self::ApiKey
            }
            Self::BASIC_KIND => {
                Self::Basic
            }
            _ => {
                Self::Unknown
            }
        }
    }

    fn format_key(&self, api_id: &String, client_id: &String) -> String {
        match self {
            AuthKind::ApiKey => Self::format(api_id, Self::API_KEY_KIND, client_id),
            AuthKind::Basic => Self::format(api_id, Self::BASIC_KIND, client_id),
            AuthKind::Unknown => {
                todo!()
            }
            AuthKind::_JWT => {
                todo!()
            }
        }
    }

    pub fn format(api_id: &String, kind: &str, client_id: &String) -> String {
        let mut res = String::new();
        res.push_str(api_id);
        res.push('.');
        res.push_str(kind);
        res.push('.');
        res.push_str(client_id);
        res
    }
}

pub fn check_api_key(
    cache: &dyn ReadableCache<String, Bytes>,
    api_id: &String,
    api_key: &String,
    hasher: &dyn Hasher,
) -> Result<(), AuthError> {
    check(
        cache,
        &AuthKind::ApiKey.format_key(api_id, &hasher.hash_base64(api_key.as_bytes().to_vec())),
        hasher.hash(api_key.as_bytes().to_vec())
    )
}

pub fn check_basic_auth(
    cache: &dyn ReadableCache<String, Bytes>,
    api_id: &String,
    user: &String,
    pass: Bytes,
    hasher: &dyn Hasher,
) -> Result<(), AuthError> {
    check(cache, &AuthKind::Basic.format_key(api_id, user), hasher.hash(pass))
}

fn check(
    cache: &dyn ReadableCache<String, Bytes>,
    key: &String,
    expected: Bytes,
) -> Result<(), AuthError> {
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
