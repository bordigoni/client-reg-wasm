extern crate core;

use log;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, Bytes, LogLevel, Status};

use auth::AuthKind;
use cache::hard_coded;

use crate::conf::ApiKeyLocation;
use cache::{ReadableCache, WritableCache};

mod auth;
mod cache;
mod conf;

const API_KEY_KIND: &'static str = "api_key";
const BASIC_KIND: &'static str = "basic";

proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|context_id| -> Box<dyn RootContext> {
        Box::new(AuthFilterConfig{context_id : context_id})
    });
    proxy_wasm::set_http_context(|_context_id, root_context_id| -> Box<dyn HttpContext> {
        Box::new(AuthFilter{root_context_id: root_context_id})
    });

}}

pub struct AuthFilterConfig {
    context_id: u32,
}

pub struct AuthFilter {
    root_context_id: u32,
}

impl Context for AuthFilter {}

impl HttpContext for AuthFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _stream_code: bool) -> Action {
        log::info!("checking cred for root_context_id {}", self.root_context_id);

        // base on config, extract client id
        let creds = self.extract_credentials();

        if let Some(creds) = creds {
            // check it according to what it is
            match creds.kind {
                AuthKind::ApiKey => {
                    self.check_api_key(creds.api_id, creds.client_id);
                }
                AuthKind::Basic => {
                    self.check_basic_auth(creds.api_id, creds.client_id, creds.secret.unwrap());
                }
                // any other situation is a fatal error
                _ => {
                    log::error!("Cannot infer auth type");
                    self.send_internal_server_error()
                }
            }
        } else {
            // no client_id extracted
            log::error!("Authentication: no credentials found in request");
            self.send_unauthorized()
        }
        return Action::Continue;
    }
}

struct RequestCredentials {
    kind: AuthKind,
    api_id: String,
    client_id: String,
    secret: Option<Bytes>,
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
                Ok(spec) => {
                    match spec.is_in {
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
                            log::warn!("Api-Key Location 'query_param' not handled yet, 401 will be returned");
                            return None;
                        }
                        ApiKeyLocation::Unknown(location) => {
                            log::error!("Api-Key Location unknown: {}", location);
                        }
                    }
                }
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
                            log::error!("Authentication: fail to decode basic auth");
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
            log::warn!("basic auth for api_id:{} could not properly parse user and password", &api_id_string);
            return None;
        }
        log::warn!(
            "auth kind for ctx:{} could not be determined",
            self.root_context_id
        );
        None
    }

    fn check_api_key(&mut self, api_id: String, api_key: String) {
        let res = auth::check_api_key(&self, &api_id, &api_key);
        if let Err(_) = res {
            log::error!("Authentication: check failed");
            self.send_forbidden();
        }
    }

    fn check_basic_auth(&self, api_id: String, user: String, pass: Bytes) {

        let res = auth::check_basic_auth(&self, &api_id, &user, pass);
        if let Err(_) = res {
            log::error!("Authentication: check failed");
            self.send_forbidden();
        }
    }

    fn send_forbidden(&self) {
        self.send_http_response(403, vec![], None)
    }

    fn send_unauthorized(&self) {
        self.send_http_response(401, vec![], None)
    }
    pub fn send_internal_server_error(&self) {
        self.send_http_response(500, vec![], None)
    }
}

impl ReadableCache<String, Bytes> for AuthFilter {
    fn get(&self, id: &String) -> Option<Bytes> {
        self.get_shared_data(&id[..]).0
    }
}

impl Context for AuthFilterConfig {}

impl WritableCache<String, Bytes> for AuthFilterConfig {
    fn put(&mut self, key: String, value: Option<Bytes>) {
        if let Some(bytes) = value {
            let res = self.set_shared_data(key.as_str(), Some(&bytes), None);
            if let Err(err) = res {
                log::error!(
                    "[CACHE] Error while putting key {} to shared cache: {:?}",
                    key,
                    err
                );
            }
        }
    }

    fn _delete(&self, key: String) {
        let res = self.set_shared_data(key.as_str(), None, None);
        if let Err(s) = res {
            match s {
                Status::Ok => {
                    log::debug!("[CACHE] Entry {} deleted", key)
                }
                err => {
                    log::error!("[CACHE] Error setting None to shared cache: {:?}", err)
                }
            }
        }
    }
}

impl RootContext for AuthFilterConfig {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        log::info!("VM starts fir context_id: {}", self.context_id);
        let conf = self.get_plugin_configuration();

        // here call the gRPC to update the cache
        hard_coded::init(self);

        if let Some(conf) = conf {
            let res = String::from_utf8(conf.to_vec());
            if let Ok(json) = res {
                let id = self.context_id;
                conf::parse_and_store(self, json, id)
            } else if let Err(err) = res {
                log::error!("cannot read config: {}", err);
                return false;
            }
        } else {
            log::error!("no config found for context: {}", self.context_id);
            return false;
        }
        true
    }
}
