use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::registry::registry_response::Credential;
use crate::registry::RegistryResponse;

pub fn load() -> Vec<RegistryResponse> {
    simple_case()
}

fn _many_creds() -> Vec<RegistryResponse> {
    let mut data = vec![
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
    ];

    for i in 1..500000 {
        let id = Uuid::new_v4();
        let mut user = String::from("admin");
        user.push_str(i.to_string().as_str());
        let mut pass = String::from("changeme");
        pass.push_str(i.to_string().as_str());
        data.push(Credential {
            kind: String::from("api_key"),
            owner: String::from("filter1"),
            client_id: hash_base64(id.to_string()),
            secret: hash(id.to_string()),
        });
        data.push(Credential {
            kind: String::from("basic"),
            owner: String::from("filter2"),
            client_id: user,
            secret: hash(pass),
        });
    }

    vec![RegistryResponse {
        credentials: data,
        removals: vec![Credential {
            kind: String::from("api_key"),
            owner: String::from("filter1"),
            client_id: hash_base64(String::from("GHIJKL")),
            secret: Vec::new(),
        }],
    }]
}

fn simple_case() -> Vec<RegistryResponse> {
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
