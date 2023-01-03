use crate::registry::registry_response::Credential;
use crate::registry::RegistryResponse;

pub fn load() -> Vec<RegistryResponse> {
    vec![
        RegistryResponse {
            credentials: vec![Credential {
                kind: String::from("api_key"),
                owner: String::from("filter1"),
                client_id: String::from("ABCDEF"),
                secret: String::from("ABCDEF").into_bytes(),
            }, Credential {
                kind: String::from("basic"),
                owner: String::from("filter2"),
                client_id: String::from("admin"),
                secret: String::from("changeme").into_bytes(),
            }],
            removals: vec![Credential {
                kind: String::from("api_key"),
                owner: String::from("filter1"),
                client_id: String::from("GHIJKL"),
                secret: Vec::new(),
            }],
        },
        RegistryResponse {
            credentials: vec![Credential {
                kind: String::from("api_key"),
                owner: String::from("filter1"),
                client_id: String::from("GHIJKL"),
                secret: String::from("GHIJKL").into_bytes(),
            }],
            removals: vec![Credential {
                kind: String::from("basic"),
                owner: String::from("filter2"),
                client_id: String::from("admin"),
                secret: Vec::new(),
            }, Credential {
                kind: String::from("api_key"),
                owner: String::from("filter1"),
                client_id: String::from("ABCDEF"),
                secret: Vec::new(),
            }],
        },
    ]
}