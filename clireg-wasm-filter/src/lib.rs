extern crate core;

use std::time::Duration;

use log;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, Bytes, LogLevel};

use auth::{AuthError, AuthKind};
use conf::{ApiKeyLocation, ServiceConfig, Type};

use grpc::GRPC;
use crate::hash::Hasher;

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
            hasher: hash::HashAlg::SHA256.new()
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
    hasher:  Box<dyn Hasher>
}

struct RequestCredentials {
    kind: AuthKind,
    api_id: String,
    client_id: String,
    secret: Option<Bytes>,
}

impl Context for AuthFilter {

}

impl HttpContext for AuthFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _stream_code: bool) -> Action {
        log::debug!("checking cred for root_context_id {}", self.root_context_id);

        // base on config, extract client id
        let creds = self.extract_credentials();

        if let Some(creds) = creds {
            // check it according to what it is
            match creds.kind {
                AuthKind::ApiKey => {
                    let res = auth::check_api_key(self, &creds.api_id, &creds.client_id, self.hasher.as_ref());
                    self.on_failed_send_forbidden(res)
                }
                AuthKind::Basic => {
                    let res = auth::check_basic_auth(
                        self,
                        &creds.api_id,
                        &creds.client_id,
                        creds.secret.unwrap(),
                        self.hasher.as_ref() );
                    self.on_failed_send_forbidden(res)
                }
                // any other situation is a fatal error
                _ => {
                    log::info!("Cannot infer auth type");
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

        let (is_api_key, api_id) = conf::is_api_key(self, self.root_context_id);
        if is_api_key {
            // safe to unwrap if true
            let api_id_string = &api_id.unwrap();
            log::debug!(
                "auth kind for {} is ApiKey. ctx:{}",
                &api_id_string,
                self.root_context_id
            );
            let res = conf::get_api_key_spec(self, api_id_string.as_str());
            match res {
                Ok(spec) => match spec.is_in {
                    ApiKeyLocation::Header => {
                        return self
                            .get_http_request_header(spec.name.to_ascii_lowercase().as_str())
                            .map(|client_id| RequestCredentials {
                                kind: AuthKind::ApiKey,
                                api_id: api_id_string.clone(),
                                client_id,
                                secret: None,
                            });
                    }
                    ApiKeyLocation::QueryParam => {
                        log::warn!("Api-Key Location 'query_param' not handled yet.");
                        return None;
                    }
                    ApiKeyLocation::Unknown(location) => {
                        log::warn!("Api-Key Location unknown: {}", location);
                    }
                },
                Err(err) => {
                    log::error!("Got error retrieving Api-Key spec: {}", err);
                }
            }
        }

        let (is_basic, api_id) = conf::is_basic(self, self.root_context_id);
        if is_basic {
            // safe to unwrap if true
            let api_id_string = &api_id.unwrap();
            log::debug!(
                "auth kind for {} is Basic. ctx:{}",
                api_id_string,
                self.root_context_id
            );
            if let Some(auth_header) = self.get_http_request_header("Authorization") {
                if let Some((basic, user_pwd_b64)) = auth_header.split_once(' ') {
                    if basic.to_ascii_lowercase().eq("basic") {
                        let user_pwd_bytes = base64::decode(user_pwd_b64);
                        if let Err(_) = user_pwd_bytes {
                            log::debug!("Authentication: fail to decode basic auth");
                        }

                        if let Ok(user_pwd) = String::from_utf8(user_pwd_bytes.unwrap()) {
                            if let Some((user, pass)) = user_pwd.split_once(':') {
                                return Some(RequestCredentials {
                                    kind: AuthKind::Basic,
                                    api_id: api_id_string.clone(),
                                    client_id: String::from(user),
                                    secret: Some(Vec::from(pass)),
                                });
                            }
                        }
                    }
                }
            }
            log::debug!(
                "basic auth for api_id:{} could not properly parse user and password",
                &api_id_string
            );
            return None;
        }
        log::debug!(
            "auth kind for ctx:{} could not be determined",
            self.root_context_id
        );
        None
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

impl RootContext for AuthFilterConfig {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        log::info!("VM starts for context_id: {}", self.context_id);
        let conf = self.get_plugin_configuration();

        if let Some(conf) = conf {
            match String::from_utf8(conf.to_vec()) {
                Ok(json) => {
                    let id = self.context_id;
                    match conf::parse_and_store(self, json, id) {
                        Ok(config_type) => {
                            if let Type::Service(conf) = config_type {
                                self.config = conf;
                                if self.grpc_token == grpc::DISCONNECTED {
                                    self.grpc_token = self.grpc_connect();
                                    self.set_tick_period(Duration::from_secs(60))
                                }
                            }
                            true
                        }
                        Err(err) => {
                            log::error!("error parsing config: {}", err);
                            false
                        }
                    }
                }
                Err(err) => {
                    log::error!("cannot read config: {}", err);
                    false
                }
            }
        } else {
            log::error!("no config found for context: {}", self.context_id);
            false
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
