extern crate core;

use auth::{AuthError, Credential};
use conf::{ApiKeyLocation, CredSpec, CredsConfig, ServiceConfig, Type};
use grpc::GRPC;
use hash::Hasher;
use log;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, LogLevel};

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
            hasher: hash::HashAlg::SHA256.new(),
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
    hasher: Box<dyn Hasher>,
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
            let res = creds.check(self, self.hasher.as_ref());
            self.on_failed_send_forbidden(res);
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
            &self.config.kind,
            self.root_context_id
        );
        match &self.config.spec {
            CredSpec::ApiKey(spec) => match &spec.is_in {
                ApiKeyLocation::Header => {
                    let header =
                        self.get_http_request_header(spec.name.to_ascii_lowercase().as_str());
                    Self::api_key_creds(&api_id, header)
                }
                ApiKeyLocation::QueryParam => {
                    let request_path = self.get_http_request_header(":path");
                    Self::api_key_creds(
                        &api_id,
                        Self::extract_from_query_string(request_path, spec.name.as_str()),
                    )
                }
                ApiKeyLocation::Unknown(location) => {
                    log::warn!("Api-Key Location unknown: {}", location);
                    None
                }
            },
            CredSpec::Basic => {
                // ugly as hell won't keep it so...
                if let Some(auth_header) = self.get_http_request_header("Authorization") {
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
                log::debug!("no authorization header found kind for api_id:{}", &api_id);
                None
            }
            _ => {
                log::debug!(
                    "auth kind is could not be determined for api_id:{}",
                    &api_id
                );
                None
            }
        }
    }

    fn api_key_creds(api_id: &String, param: Option<String>) -> Option<Box<dyn Credential>> {
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

    fn send_unauthorized(&self) {
        self.send_http_response(401, vec![], None)
    }

    fn on_failed_send_forbidden(&mut self, res: Result<(), AuthError>) {
        if let Err(_) = res {
            log::error!("Authentication: check failed");
            self.send_http_response(403, vec![], None);
        }
    }
}

impl AuthFilterConfig {
    fn read_plugin_config(&self) -> Result<String, String> {
        if let Some(conf) = self.get_plugin_configuration() {
            match String::from_utf8(conf.to_vec()) {
                Err(err) => Err(err.utf8_error().to_string()),
                Ok(json) => Ok(json),
            }
        } else {
            Err(format!("no config found for context: {}", self.context_id))
        }
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
            Ok(json) => {
                let context_id = self.context_id;
                conf::parse_config(&json, context_id)
                    .map(|config_type| {
                        return match config_type {
                            Type::Service(conf) => {
                                self.config = conf;
                                if self.grpc_token == grpc::DISCONNECTED {
                                    self.grpc_token = self.grpc_connect();
                                    self.set_tick_period(self.config.tick_period)
                                }
                                true
                            }
                            Type::Creds(creds) => {
                                log::info!(
                                    "binding api_id: {} with kind: {} to context: {}",
                                    creds.api_id,
                                    creds.kind,
                                    self.context_id
                                );
                                conf::store_filter_config(self, context_id, creds)
                            }
                            Type::Unknown => {
                                log::error!("unknown config type: {}", &json);
                                false
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
        for (path, name, key, eq) in vec![
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
            if eq {
                assert_eq!(key, api_key.as_str())
            } else {
                assert_eq!("<unknown api key>", api_key.as_str())
            }
        }
    }
}
