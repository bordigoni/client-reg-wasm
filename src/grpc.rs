use std::thread;
use std::time::Duration;
use log;
use prost::{Message};
use proxy_wasm::traits::{Context};

use proxy_wasm::types::Bytes;
use registry::RegistryRequest;

use crate::cache::WritableCache;
use crate::conf::ServiceConfig;
use crate::grpc::registry::registry_response::Credential;
use crate::grpc::registry::RegistryResponse;

pub mod registry;

pub fn call_sync(context: &dyn Context, conf: ServiceConfig) {

    // TODO refactor and use conf instead of hard coded values
    let cluster = "clireg";
    let attempts = 10;
    let time_between_attempts = 10;

    let req = RegistryRequest {
        full_sync: false,
        nonce: 0,
    };

    for i in 1..attempts {
        // match context.open_grpc_stream(
        //     cluster,
        //     "registry.Registry",
        //     "Sync",
        //     vec![]) {
        //     Ok(_) => {
        //         log::info!("grpc open successful");
        match context.dispatch_grpc_call(
                    cluster,
                    "registry.Registry",
                    "Sync",
                    vec![],
                    Some(req.encode_to_vec().as_slice()),
                    Duration::from_secs(10)) {
                    Ok(_) => {
                        log::info!("grpc call successful");
                        break;
                    }

                    Err(err) => log::error!("Error connecting to client on attempt: #{}, err: {:?}", i, err)
                }
            // }
            // Err(err) => log::error!("Error connecting to grpc on attempt: #{}, err: {:?}", i, err)
        //}
        thread::sleep(Duration::from_secs(time_between_attempts))
    }
}

pub fn handle_receive(cache: &mut dyn WritableCache<String, Bytes>, message: Option<Bytes>) {
    if let Some(bytes) = message {
        let res = RegistryResponse::decode(bytes.as_slice());
        match res {
            Ok(response) => {
                for credential in &response.credentials {
                    cache.put(to_key(credential), Some(credential.secret.clone()));
                }
                for credential in &response.credentials {
                    cache.delete(to_key(credential))
                }
            }
            Err(err) =>
                log::error!("cannot decode gRPC message: {}", err)
        }
    }
}

fn to_key(cred: &Credential) -> String {
    let mut key = String::new();
    key.push_str(cred.client_id.as_str());
    key.push_str(cred.kind.as_str());
    key.push_str(cred.client_id.as_str());
    key
}