use log;
use prost::Message;
use proxy_wasm::traits::Context;
use proxy_wasm::types::Bytes;

use crate::auth::AuthKind;
use crate::AuthFilterConfig;
use registry::RegistryRequest;

use crate::cache::WritableCache;
use crate::grpc::registry::RegistryResponse;

pub mod registry;

const RETRY_GRPC_CODES: &[u32] = &[2, 5, 8, 9, 10, 13, 14, 15];

pub const DISCONNECTED: u32 = 0;

pub trait GRPC {
    fn grpc_connect(&mut self) -> u32;
}

impl Context for AuthFilterConfig {
    fn on_grpc_stream_message(&mut self, token_id: u32, message_size: usize) {
        log::debug!(
            "[GRPC] message for token:{}, size:{}",
            token_id,
            message_size
        );
        let message = self.get_grpc_stream_message(0, message_size);
        handle_receive(self, message);
    }

    fn on_grpc_stream_close(&mut self, token_id: u32, status_code: u32) {
        if self.grpc_token == token_id && RETRY_GRPC_CODES.contains(&status_code) {
            log::info!(
                "[GRPC] close for token:{} with status:{}: will retry",
                token_id,
                status_code
            );
            self.grpc_token = DISCONNECTED;
        } else {
            log::error!("[GRPC] close for token:{} with status:{}: fatal error, no retry, check logs for more details", token_id, status_code);
        }
    }
}

impl GRPC for AuthFilterConfig {
    fn grpc_connect(&mut self) -> u32 {
        let conf = &self.config;
        return match self.open_grpc_stream(&conf.cluster, "registry.Registry", "Sync", vec![]) {
            Ok(token) => {
                log::debug!("grpc connected with token: {}", token);
                send_request(self, token, true);
                token
            }
            Err(err) => {
                log::error!("error connecting to grpc service: {:?}", err);
                DISCONNECTED
            }
        };
    }
}

pub fn handle_receive(cache: &mut dyn WritableCache<String, Bytes>, message: Option<Bytes>) {
    if let Some(bytes) = message {
        let res = RegistryResponse::decode(bytes.as_slice());
        match res {
            Ok(response) => {
                for cred in &response.removals {
                    cache.delete(AuthKind::format(&cred.owner, &cred.kind, &cred.client_id))
                }
                for cred in &response.credentials {
                    cache.put(
                        AuthKind::format(&cred.owner, &cred.kind, &cred.client_id),
                        Some(cred.secret.clone()),
                    );
                }
                log::info!("Auth cache updated: new/updated: {}, removed: {}", &response.credentials.len(), &response.removals.len())
            }
            Err(err) => log::error!("cannot decode gRPC message: {}", err),
        }
    } else {
        log::debug!("Got empty gRPC message")
    }
}

pub fn renew_request(context: &dyn Context, token: u32) {
    send_request(context, token, false);
}

fn send_request(context: &dyn Context, token: u32, full_sync: bool) {
    let req = RegistryRequest {
        full_sync,
        nonce: 0,
    };
    context.send_grpc_stream_message(token, Some(req.encode_to_vec().as_slice()), false)
}
