extern crate core;

use log;
use std::task::ready;

use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, Bytes, LogLevel};

use auth::{AuthError, AuthKind};
use conf::{ApiKeyLocation, CredSpec, CredsConfig, ServiceConfig, Type};
use grpc::GRPC;
use hash::Hasher;

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

struct RequestCredentials {
    kind: AuthKind,
    api_id: String,
    client_id: String,
    secret: Option<Bytes>,
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
            // check it according to what it is
            match creds.kind {
                AuthKind::ApiKey => {
                    let res = auth::check_api_key(
                        self,
                        &creds.api_id,
                        &creds.client_id,
                        self.hasher.as_ref(),
                    );
                    self.on_failed_send_forbidden(res)
                }
                AuthKind::Basic => {
                    let res = auth::check_basic_auth(
                        self,
                        &creds.api_id,
                        &creds.client_id,
                        creds.secret.unwrap(),
                        self.hasher.as_ref(),
                    );
                    self.on_failed_send_forbidden(res)
                }
                // any other situation is a fatal error => it should not happen though as unknown kind leads to 401
                other => {
                    log::info!("auth type unsupported: {}", other);
                    self.send_internal_server_error()
                }
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
    fn extract_credentials(&self) -> Option<RequestCredentials> {
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
                    return self
                        .get_http_request_header(spec.name.to_ascii_lowercase().as_str())
                        .map(|client_id| RequestCredentials {
                            kind: AuthKind::ApiKey,
                            api_id: api_id.clone(),
                            client_id,
                            secret: None,
                        });
                }
                ApiKeyLocation::QueryParam => {
                    log::warn!("Api-Key Location 'query_param' not handled yet.");
                    None
                }
                ApiKeyLocation::Unknown(location) => {
                    log::warn!("Api-Key Location unknown: {}", location);
                    None
                }
            },
            CredSpec::Basic => {
                // ugly as hell won't keep it so...
                if let Some(auth_header) = self.get_http_request_header("Authorization") {
                    if let Some((basic, user_pwd_b64)) = auth_header.split_once(' ') {
                        if basic.to_ascii_lowercase().eq("basic") {
                            let user_pwd_bytes = base64::decode(user_pwd_b64);
                            if let Ok(user_pwd) = String::from_utf8(user_pwd_bytes.unwrap()) {
                                if let Some((user, pass)) = user_pwd.split_once(':') {
                                    return Some(RequestCredentials {
                                        kind: AuthKind::Basic,
                                        api_id: api_id.clone(),
                                        client_id: String::from(user),
                                        secret: Some(Vec::from(pass)),
                                    });
                                }
                            }
                        }
                    }
                    log::debug!(
                        "basic auth for api_id:{} could not properly parse user and password",
                        &api_id
                    );
                    return None;
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

    fn send_unauthorized(&self) {
        self.send_http_response(401, vec![], None)
    }

    fn send_internal_server_error(&self) {
        self.send_http_response(500, vec![], None)
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
