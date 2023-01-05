use sha2::{Digest, Sha256};

use crate::registry::registry_response::Credential;
use crate::registry::RegistryResponse;

pub fn load() -> Vec<RegistryResponse> {
    vec![
        RegistryResponse {
            credentials: vec![
                Credential {
                    kind: String::from("api_key"),
                    owner: String::from("filter1"),
                    client_id: hash_base64(String::from("ABCDEF")),
                    secret: hash(String::from("ABCDEF")),
                },
                Credential {
                    kind: String::from("basic"),
                    owner: String::from("filter2"),
                    client_id: String::from("admin"),
                    secret: hash(String::from("changeme")),
                },
            ],
            removals: vec![Credential {
                kind: String::from("api_key"),
                owner: String::from("filter1"),
                client_id: hash_base64(String::from("GHIJKL")),
                secret: Vec::new(),
            }],
        },
        RegistryResponse {
            credentials: vec![Credential {
                kind: String::from("api_key"),
                owner: String::from("filter1"),
                client_id: hash_base64(String::from("GHIJKL")),
                secret: hash(String::from("GHIJKL")),
            }],
            removals: vec![
                Credential {
                    kind: String::from("basic"),
                    owner: String::from("filter2"),
                    client_id: String::from("admin"),
                    secret: Vec::new(),
                },
                Credential {
                    kind: String::from("api_key"),
                    owner: String::from("filter1"),
                    client_id: hash_base64(String::from("ABCDEF")),
                    secret: Vec::new(),
                },
            ],
        },
    ]
}

fn hash(s: String) -> Vec<u8> {
    Sha256::digest(s.into_bytes()).to_vec()
}

fn hash_base64(s: String) -> String {
    base64::encode(hash(s))
}