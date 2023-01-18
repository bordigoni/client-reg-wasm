use std::borrow::Borrow;
use std::time::Duration;

use auth::Credential;
use conf::{ApiKeyLocation, ConfigType, CredSpec, CredsConfig, ServiceConfig};
use grpc::GRPC;
use jwt::{Claims, Header, Token};
use log;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, Bytes, LogLevel};
use serde_json::Value;

mod auth;
mod cache;
mod conf;
mod grpc;
mod hash;

proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|context_id| -> Box<dyn RootContext> {
        Box::new(AuthFilterConfig{
            context_id,
            grpc_token:grpc::DISCONNECTED,
            config: Default::default()})
    });
    proxy_wasm::set_http_context(|_context_id, root_context_id| -> Box<dyn HttpContext> {
        Box::new(AuthFilter{
            root_context_id,
            config: Default::default(),
            ready: false
        })
    });

}}

pub struct AuthFilterConfig {
    context_id: u32,
    grpc_token: u32,
    config: ServiceConfig,
}

pub struct AuthFilter {
    root_context_id: u32,
    config: CredsConfig,
    ready: bool,
}

impl Context for AuthFilter {}

impl HttpContext for AuthFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _stream_code: bool) -> Action {
        log::debug!("checking cred for root_context_id {}", self.root_context_id);

        // config has never been read, we set it of fail reading
        if !self.ready {
            match conf::pull_filter_config(self, self.root_context_id) {
                Ok(config) => {
                    self.config = config;
                    self.ready = true;
                }
                Err(err) => log::error!("error reading config from the cache: {}", err),
            }
        }

        // base on config, extract creds
        let creds = self.extract_credentials();

        if let Some(creds) = creds {
            let hasher = self.config.hash_alg.borrow().new();
            if !creds.check(self, hasher.as_ref()) {
                self.send_forbidden();
            }
        } else {
            // no client_id extracted
            log::debug!("Authentication: no credentials found in request");
            self.send_unauthorized()
        }
        return Action::Continue;
    }
}

impl AuthFilter {
    fn extract_credentials(&self) -> Option<Box<dyn Credential>> {
        let api_id = self.config.api_id.clone();
        log::debug!(
            "auth kind for {} is {}. ctx:{}",
            &api_id,
            &self.config.kind(),
            self.root_context_id
        );
        match &self.config.spec {
            CredSpec::ApiKey(spec) => match &spec.is_in {
                ApiKeyLocation::Header => {
                    let header =
                        self.get_http_request_header(spec.name.to_ascii_lowercase().as_str());
                    Self::api_key_creds(api_id, header)
                }
                ApiKeyLocation::QueryParam => {
                    let request_path = self.get_http_request_header(":path");
                    Self::api_key_creds(
                        api_id,
                        Self::extract_from_query_string(request_path, spec.name.as_str()),
                    )
                }
            },
            CredSpec::Basic => {
                // ugly as hell won't keep it so...
                if let Some(auth_header) =
                    self.get_http_request_header(http::header::AUTHORIZATION.as_str())
                {
                    if let Ok(creds) = http_auth_basic::Credentials::from_header(auth_header) {
                        return Some(Box::new(auth::BasicAuthCredentials {
                            client_id: auth::ClientId {
                                id: creds.user_id,
                                api_id,
                            },
                            secret: creds.password.into_bytes(),
                        }));
                    }
                }
                None
            }
            CredSpec::JWT(spec) => {
                if let Some(auth_header) =
                    self.get_http_request_header(http::header::AUTHORIZATION.as_str())
                {
                    if let Some(client_id) = Self::extract_jwt_claim(auth_header, &spec.claim) {
                        return Some(Box::new(auth::JWTCredentials {
                            client_id: auth::ClientId {
                                api_id,
                                id: client_id,
                            },
                        }));
                    }
                }
                None
            }
        }
    }

    fn api_key_creds(api_id: String, param: Option<String>) -> Option<Box<dyn Credential>> {
        if let Some(api_key) = param {
            return Some(Box::new(auth::ApiKeyCredentials {
                client_id: auth::ClientId {
                    api_id: api_id.clone(),
                    id: api_key,
                },
            }));
        }
        None
    }

    fn extract_from_query_string(request_path: Option<String>, name: &str) -> Option<String> {
        if let Some(path) = request_path {
            if let Some((_, query_string)) = path.split_once('?') {
                querystring::querify(query_string)
                    .iter()
                    .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                    .next()
                    .map(|(_, value)| value.to_string())
            } else {
                None
            }
        } else {
            None
        }
    }

    fn extract_jwt_claim(auth_header: String, claim: &String) -> Option<String> {
        if let Some(token) = Self::extract_token(auth_header) {
            let res = Token::<Header, Claims, _>::parse_unverified(token.as_str()).map(|token| {
                let claims = token.claims();
                claims.private.get(claim).map(|val| match val {
                    Value::String(string) => string.clone(),
                    _ => "".to_string(),
                })
            });
            if let Ok(claim_opt) = res {
                return claim_opt.map(|s| s.clone());
            }
        }
        None
    }

    fn extract_token(auth_header: String) -> Option<String> {
        let mut map = http::HeaderMap::new();
        if let Ok(header) = http::HeaderValue::from_str(auth_header.as_str()) {
            map.insert(http::header::AUTHORIZATION, header);
            if let Ok(auth_header) = auth_headers::AuthorizationHeader::try_from(map) {
                return match auth_header {
                    auth_headers::AuthorizationHeader::Bearer { token } => Some(token),
                    _ => None,
                };
            }
        }
        None
    }

    fn send_unauthorized(&self) {
        self.send_http_response(http::StatusCode::UNAUTHORIZED.as_u16() as u32, vec![], None)
    }

    fn send_forbidden(&self) {
        self.send_http_response(http::StatusCode::FORBIDDEN.as_u16() as u32, vec![], None);
    }
}

impl AuthFilterConfig {
    fn read_plugin_config(&self) -> Result<Bytes, String> {
        self.get_plugin_configuration()
            .ok_or(format!("no config found for context: {}", self.context_id))
    }
}

impl RootContext for AuthFilterConfig {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        log::info!("VM starts for context_id: {}", self.context_id);

        match self.read_plugin_config() {
            Err(e) => {
                log::error!("cannot read config: {}", e);
                return false;
            }
            Ok(proto_struct_bytes) => {
                let context_id = self.context_id;
                conf::parse_config(proto_struct_bytes, context_id)
                    .map(|config_type| {
                        return match config_type {
                            ConfigType::Service(conf) => {
                                self.config = conf;
                                if self.grpc_token == grpc::DISCONNECTED {
                                    self.grpc_token = self.grpc_connect();
                                    // unwrap is safe since  value is set by default
                                    self.set_tick_period(Duration::from_secs(self.config.tick_period_secs as u64))
                                }
                                true
                            }
                            ConfigType::Creds(creds) => {
                                log::info!(
                                    "binding api_id: {} with kind: {} and hash alg: {} to context: {}",
                                    creds.api_id,
                                    creds.kind(),
                                    creds.hash_alg,
                                    self.context_id
                                );
                                conf::store_filter_config(self, context_id, creds)
                            }
                        };
                    })
                    .map_err(|err| {
                        log::error!("error parsing config: {}", err);
                        return false;
                    })
                    .unwrap()
            }
        }
    }

    fn on_tick(&mut self) {
        if self.grpc_token == grpc::DISCONNECTED {
            log::debug!("[GRPC] Attempting re-connection");
            self.grpc_token = self.grpc_connect()
        } else {
            grpc::renew_request(self, self.grpc_token)
        }
    }
}

#[cfg(test)]
mod lib {
    use crate::AuthFilter;

    #[test]
    fn extract_from_query_string() {
        for (path, name, key, ok) in vec![
            ("/headers?x-api-key=123", "x-api-key", "123", true),
            ("/headers?x-api-key=123", "X-API-KEY", "123", true),
            ("/headers?X-API-KEY=123", "x-api-key", "123", true),
            ("/headers?foo=bar&X-API-KEY=123", "x-api-key", "123", true),
            ("/headers?X-API-KEY=123&foo=bar&", "x-api-key", "123", true),
            ("/headers", "x-api-key", "123", false),
            ("/headers?", "x-api-key", "123", false),
            ("/headers?foo=bar", "x-api-key", "123", false),
        ] {
            let api_key = AuthFilter::extract_from_query_string(Some(path.to_string()), name)
                .unwrap_or("<unknown api key>".to_string());
            if ok {
                assert_eq!(key, api_key.as_str())
            } else {
                assert_eq!("<unknown api key>", api_key.as_str())
            }
        }
    }

    #[test]
    fn extract_jwt() {
        for (header, claim_name, expected_claim_value, case) in vec![
            // HS256
            ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjbGllbnRfaWQiOiJiZW5vaXQifQ.wrdsdXeH5tPDmM4alg9jiVNOTXSW1YV_SPCUwKdQPC4","client_id","benoit",1),
            // HS384
            ("Bearer eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjbGllbnRfaWQiOiJiZW5vaXQifQ.ZPsSPKVm58PFcIcC0TmiN2T61OneavsHNrkkjEGaaMtK3_6HlfSNTu8FaOFg8xTZ","client_id","benoit",1),
            // HS512
            ("Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjbGllbnRfaWQiOiJiZW5vaXQifQ.Ej9uVy2z4hYSeGwx5d37MYmQpVdJGCK9bqmQfxClXiezmxghlRQvsKAD16v1ktLR9jqfEXZcxYGJYB5II6x94w","client_id","benoit",1),
            ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjbGllbnRfaWQiOiJiZW5vaXQifQ.wrdsdXeH5tPDmM4alg9jiVNOTXSW1YV_SPCUwKdQPC4","foo","benoit",3),
            ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjbGllbnRfaWQiOiJiZW5vaXQifQ.wrdsdXeH5tPDmM4alg9jiVNOTXSW1YV_SPCUwKdQPC4","client_id","foo",2)
        ] {
            let claim_value = AuthFilter::extract_jwt_claim(header.to_string(), &claim_name.to_string()).unwrap_or("<unknown claim>".to_string());
            if case == 1 {
                assert_eq!(expected_claim_value, claim_value)
            } else if case == 2 {
                assert_ne!(expected_claim_value, claim_value)
            } else if case == 3 {
                assert_eq!("<unknown claim>", claim_value)
            }
        }
    }
}
