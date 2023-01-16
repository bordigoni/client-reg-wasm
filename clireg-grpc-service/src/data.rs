use base64::Engine;
use sha2::{Digest, Sha256, Sha512};
use uuid::Uuid;

use crate::registry::registry_response::Credential;
use crate::registry::RegistryResponse;

pub fn load() -> Vec<RegistryResponse> {
    simple_case()
}

const API_KEY_KIND: &str = "api_key";
const BASIC_KIND: &str = "basic";
const JWT_KIND: &str = "jwt";

const SHA_256: &str = "sha-256";
const SHA_512: &str = "SHA-512";

const API_ID1: &str = "filter1";
const API_ID2: &str = "filter2";
const API_ID3: &str = "filter3";

const API_KEY1: &str = "ABCDEF";
const API_KEY2: &str = "GHIJKL";

const USER: &str = "admin";
const PASS: &str = "changeme";

const JWT_CLIENT_ID: &str = "benoit";

fn simple_case() -> Vec<RegistryResponse> {
    vec![
        RegistryResponse {
            credentials: vec![
                Credential {
                    kind: API_KEY_KIND.to_string(),
                    owner: API_ID1.to_string(),
                    client_id: hash256_base64(API_KEY1.to_string()),
                    secret: hash256(API_KEY1.to_string()),
                },
                Credential {
                    kind: BASIC_KIND.to_string(),
                    owner: API_ID2.to_string(),
                    client_id: USER.to_string(),
                    secret: hash512(PASS.to_string()),
                },
                Credential {
                    kind: JWT_KIND.to_string(),
                    owner: API_ID3.to_string(),
                    client_id: JWT_CLIENT_ID.to_string(),
                    secret: JWT_CLIENT_ID.as_bytes().to_vec(),
                },
            ],
            removals: vec![Credential {
                kind: API_KEY_KIND.to_string(),
                owner: API_ID1.to_string(),
                client_id: hash256_base64(API_KEY2.to_string()),
                secret: Vec::new(),
            }],
        },
        RegistryResponse {
            credentials: vec![Credential {
                kind: API_KEY_KIND.to_string(),
                owner: API_ID1.to_string(),
                client_id: hash256_base64(API_KEY2.to_string()),
                secret: hash256(API_KEY2.to_string()),
            }],
            removals: vec![
                Credential {
                    kind: BASIC_KIND.to_string(),
                    owner: API_ID2.to_string(),
                    client_id: USER.to_string(),
                    secret: Vec::new(),
                },
                Credential {
                    kind: API_KEY_KIND.to_string(),
                    owner: API_ID1.to_string(),
                    client_id: hash256_base64(API_KEY1.to_string()),
                    secret: Vec::new(),
                },
                Credential {
                    kind: JWT_KIND.to_string(),
                    owner: API_ID3.to_string(),
                    client_id: JWT_CLIENT_ID.to_string(),
                    secret: Vec::new(),
                },
            ],
        },
    ]
}

fn _many_creds() -> Vec<RegistryResponse> {
    let mut data = vec![
        Credential {
            kind: API_KEY_KIND.to_string(),
            owner: API_ID1.to_string(),
            client_id: hash256_base64(API_KEY1.to_string()),
            secret: hash256(API_KEY1.to_string()),
        },
        Credential {
            kind: BASIC_KIND.to_string(),
            owner: API_ID2.to_string(),
            client_id: USER.to_string(),
            secret: hash512(PASS.to_string()),
        },
    ];

    for i in 1..500000 {
        let id = Uuid::new_v4();
        let mut user = USER.to_string();
        user.push_str(i.to_string().as_str());
        let mut pass = PASS.to_string();
        pass.push_str(i.to_string().as_str());
        data.push(Credential {
            kind: API_KEY_KIND.to_string(),
            owner: API_ID1.to_string(),
            client_id: hash256_base64(id.to_string()),
            secret: hash256(id.to_string()),
        });
        data.push(Credential {
            kind: BASIC_KIND.to_string(),
            owner: API_ID2.to_string(),
            client_id: user,
            secret: hash512(pass),
        });
    }

    vec![RegistryResponse {
        credentials: data,
        removals: vec![Credential {
            kind: API_KEY_KIND.to_string(),
            owner: API_ID1.to_string(),
            client_id: hash256_base64(API_KEY2.to_string()),
            secret: Vec::new(),
        }],
    }]
}

fn hash256(s: String) -> Vec<u8> {
    Sha256::digest(s.into_bytes()).to_vec()
}

fn hash512(s: String) -> Vec<u8> {
    Sha512::digest(s.into_bytes()).to_vec()
}

fn hash256_base64(s: String) -> String {
    base64::engine::general_purpose::STANDARD.encode(hash256(s))
}
fn _hash512_base64(s: String) -> String {
    base64::engine::general_purpose::STANDARD.encode(hash512(s))
}
