use log;
use prost::Message;
use proxy_wasm::traits::Context;
use proxy_wasm::types::Bytes;

use registry::RegistryRequest;
use crate::auth::AuthKind;

use crate::cache::WritableCache;
use crate::conf::ServiceConfig;
use crate::grpc::registry::RegistryResponse;

pub mod registry;

pub fn open_sync_stream(context: &dyn Context, conf: &ServiceConfig) -> Option<u32> {

    match context.open_grpc_stream(
        &conf.cluster,
        "registry.Registry",
        "Sync",
        vec![]) {
        Ok(token) => {
            log::debug!("grpc connected with token: {}",token);
            send_request(context, token, true);
            Some(token)
        }
        Err(err) => {
            log::error!("error opening grpc service: {:?}", err);
            None
        }
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
                    cache.put(AuthKind::format(&cred.owner, &cred.kind, &cred.client_id), Some(cred.secret.clone()));
                }

            }
            Err(err) =>
                log::error!("cannot decode gRPC message: {}", err)
        }
    } else {
        log::warn!("no gRPC message")
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