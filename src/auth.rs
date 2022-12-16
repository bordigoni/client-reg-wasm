use proxy_wasm::types::Bytes;

use crate::AuthFilter;
use crate::cache::ReadableCache;

use super::API_KEY_KIND;
use super::BASIC_KIND;

pub enum AuthError {
    Unauthorized = 401,
    Forbidden = 403,
}

pub enum AuthKind {
    ApiKey,
    Basic,
    _JWT,
}

impl AuthKind {
    fn format_key(&self, api_id: &String, client_id: &String) -> String {
        match self {
            AuthKind::ApiKey => Self::format(api_id, client_id, API_KEY_KIND),
            AuthKind::Basic => Self::format(api_id, client_id, BASIC_KIND),
            AuthKind::_JWT => {
                todo!()
            }
        }
    }

    fn format(api_id: &String, client_id: &String, kind: &str) -> String {
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
    cache: &AuthFilter,
    api_id: &String,
    api_key: &String,
) -> Result<(), AuthError> {
    check(
        cache,
        &AuthKind::ApiKey.format_key(api_id, api_key),
        Bytes::from(api_key.as_bytes()),
    )
}

pub fn check_basic_auth(
    cache: &AuthFilter,
    api_id: &String,
    user: &String,
    pass: Bytes,
) -> Result<(), AuthError> {
    check(cache, &AuthKind::Basic.format_key(api_id, user), pass)
}

fn check(cache: &AuthFilter, key: &String, expected: Bytes) -> Result<(), AuthError> {
    let actual = cache.get(key);
    if let Some(actual) = actual {
        if actual.eq(&expected) {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    } else {
        Err(AuthError::Unauthorized)
    }
}
