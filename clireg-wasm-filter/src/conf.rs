use protobuf::well_known_types::struct_::Struct;
use protobuf::Message;
use proxy_wasm::types::Bytes;
use serde::{Deserialize, Serialize};
use validator::Validate;
use {serde_cbor, serde_json};

use crate::auth;
use crate::cache::{ReadableCache, WritableCache};
use crate::hash::HashAlg;

const DEFAULT_TICK_PERIOD_SEC: f32 = 60.0;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigType {
    Service(ServiceConfig),
    Creds(CredsConfig),
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize, Validate)]
pub struct ServiceConfig {
    #[validate(length(min = 1))]
    pub cluster: String,
    #[serde(default = "default_tick_period")]
    #[validate(range(min = 1))]
    pub tick_period_secs: f32,
}

fn default_tick_period() -> f32 {
    DEFAULT_TICK_PERIOD_SEC
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize, Validate)]
pub struct CredsConfig {
    #[validate(length(min = 1))]
    pub api_id: String,
    #[serde(default = "default_hash_alg")]
    pub hash_alg: HashAlg,
    pub spec: CredSpec,
}

impl CredsConfig {
    pub fn kind(&self) -> String {
        match self.spec {
            CredSpec::Basic => auth::BASIC_KIND.to_string(),
            CredSpec::ApiKey(_) => auth::API_KEY_KIND.to_string(),
            CredSpec::JWT(_) => auth::JWT_KIND.to_string(),
        }
    }
}

fn default_hash_alg() -> HashAlg {
    HashAlg::SHA256
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredSpec {
    Basic,
    ApiKey(ApiKeySpec),
    #[serde(rename = "jwt")]
    JWT(JWTSpec),
}

impl Default for CredSpec {
    fn default() -> Self {
        Self::Basic // we need one for init the filter, it will be overridden
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Validate)]
pub struct ApiKeySpec {
    #[serde(rename = "in")]
    pub is_in: ApiKeyLocation,
    #[validate(length(min = 1))]
    pub name: String,
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyLocation {
    Header,
    QueryParam,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct JWTSpec {
    pub claim: String,
}

pub fn parse_config(proto_struct_bytes: Bytes, _context_id: u32) -> Result<ConfigType, String> {
    // parse protobuf
    let from_bytes = Struct::parse_from_bytes(proto_struct_bytes.as_slice()).unwrap();
    // to json
    let json = protobuf_json_mapping::print_to_string(&from_bytes).unwrap();
    // to Rust struct
    let result: serde_json::Result<ConfigType> = serde_json::from_str(json.as_str());

    // validate if parsed
    match result {
        Ok(config) => match config {
            ConfigType::Service(svc_cfg) => svc_cfg
                .validate()
                .map(|_| ConfigType::Service(svc_cfg))
                .map_err(|e| e.to_string()),
            ConfigType::Creds(creds_cfg) => creds_cfg
                .validate()
                .map(|_| ConfigType::Creds(creds_cfg))
                .map_err(|e| e.to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

pub fn pull_filter_config(
    cache: &dyn ReadableCache,
    context_id: u32,
) -> Result<CredsConfig, String> {
    if let Some(bytes) = cache.get(&to_cache_key(context_id)) {
        match serde_cbor::from_slice(bytes.as_slice()) {
            Ok(config) => Ok(config),
            Err(e) => Err(e.to_string()),
        }
    } else {
        Err(format!(
            "no filter config found for context: {}",
            context_id
        ))
    }
}

pub fn store_filter_config(
    cache: &mut dyn WritableCache,
    context_id: u32,
    creds: CredsConfig,
) -> bool {
    return match serde_cbor::to_vec(&creds) {
        Ok(bytes) => {
            cache.put(to_cache_key(context_id), Some(bytes));
            true
        }
        Err(err) => {
            log::error!("could not serialize the config: {}", err);
            false
        }
    };
}

fn to_cache_key(context_id: u32) -> String {
    let mut key = String::from("context.");
    key.push_str(context_id.to_string().as_str());
    key.push_str(".config");
    key
}

#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use protobuf::well_known_types::struct_::Struct;
    use protobuf::Message;
    use proxy_wasm::types::Bytes;

    use crate::cache::mock::MockCache;
    use crate::conf;
    use crate::conf::CredSpec::Basic;
    use crate::conf::{
        ApiKeyLocation,
        ApiKeySpec,
        ConfigType,
        CredSpec,
        CredsConfig,
        JWTSpec,
        ServiceConfig,
    };
    use crate::hash::HashAlg;

    #[test]
    fn serialization() {
        let ser = CredsConfig {
            api_id: "foo".to_string(),
            spec: Basic,
            hash_alg: Default::default(),
        };

        let bytes = serde_cbor::to_vec(&ser).unwrap();
        assert_ne!(0, bytes.len());

        let des: CredsConfig = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(&ser.api_id, &des.api_id);
        assert_eq!(&ser.spec, &des.spec);
        assert_eq!(&ser.hash_alg, &des.hash_alg);
    }

    #[test]
    fn store_pull() {
        let mut cache = MockCache::new();
        let conf = new_cred_config();
        assert_eq!(
            true,
            super::store_filter_config(cache.borrow_mut(), 0, conf)
        );
        assert_eq!(
            new_cred_config(),
            super::pull_filter_config(&cache, 0).unwrap()
        )
    }

    fn new_cred_config() -> CredsConfig {
        CredsConfig {
            api_id: "foo".to_string(),
            spec: CredSpec::ApiKey(ApiKeySpec {
                is_in: ApiKeyLocation::Header,
                name: "api-key".to_string(),
            }),
            hash_alg: Default::default(),
        }
    }

    fn json_to_proto(json: &str) -> Bytes {
        let s: Struct = protobuf_json_mapping::parse_from_str(json).unwrap();
        s.write_to_bytes().unwrap()
    }

    #[test]
    fn api_key_conf_test() {
        let payload = r#"
    {
        "creds": {
            "api_id": "filter2",
            "spec": {
                "api_key": {
                    "in": "header",
                    "name": "x-api-key"
                }
            }   
        }
    }
    "#;
        let config = conf::parse_config(json_to_proto(payload), 0).unwrap();
        assert_eq!(
            config,
            ConfigType::Creds(CredsConfig {
                api_id: "filter2".to_string(),
                spec: CredSpec::ApiKey(ApiKeySpec {
                    is_in: ApiKeyLocation::Header,
                    name: "x-api-key".to_string()
                }),
                hash_alg: Default::default()
            })
        );
    }

    #[test]
    fn basic_conf_test() {
        let payload = r#"
    {
        "creds": {
            "api_id": "filter1",
            "hash_alg": "SHA512",
            "spec": "basic"
        }
    }
    "#;

        let config = conf::parse_config(json_to_proto(payload), 0).unwrap();
        assert_eq!(
            config,
            ConfigType::Creds(CredsConfig {
                api_id: "filter1".to_string(),
                spec: Basic,
                hash_alg: HashAlg::SHA512
            })
        );
    }

    #[test]
    fn jwt_conf_test() {
        let payload = r#"
    {
        "creds": {
            "api_id": "filter1",
            "spec": {
                "jwt" : {
                    "claim": "azp"
                }
            }
        }
    }
    "#;

        let config = conf::parse_config(json_to_proto(payload), 0).unwrap();
        assert_eq!(
            config,
            ConfigType::Creds(CredsConfig {
                api_id: "filter1".to_string(),
                spec: CredSpec::JWT(JWTSpec {
                    claim: "azp".to_string()
                }),
                hash_alg: Default::default()
            })
        );
    }

    #[test]
    fn service_conf_test_default() {
        let payload = r#"
    {
      "service": {
        "cluster": "test"
      }
    }
    "#;
        let config = conf::parse_config(json_to_proto(payload), 0).unwrap();
        assert_eq!(
            config,
            ConfigType::Service(ServiceConfig {
                cluster: "test".to_string(),
                tick_period_secs: 60.0
            })
        );
    }

    #[test]
    fn service_conf_test() {
        let payload = r#"
    {
      "service": {
        "cluster": "test",
        "tick_period_secs": 30
      }
    }
    "#;
        let config = conf::parse_config(json_to_proto(payload), 0).unwrap();
        assert_eq!(
            config,
            ConfigType::Service(ServiceConfig {
                cluster: "test".to_string(),
                tick_period_secs: 30.0
            })
        );
    }

    #[test]
    #[should_panic]
    fn unknown_type() {
        let payload = r#"
    {
        "foo": {
            "api_id": "filter2",
            "api_key": {
                "in": "header",
                "name": "x-api-key"
            }
        }
    }
    "#;
        conf::parse_config(json_to_proto(payload), 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn unknown_kind() {
        let payload = r#"
    {
        "creds": {
            "api_id": "filter2",
            "in": "header",
            "name": "x-api-key"
        }
    }
    "#;
        conf::parse_config(json_to_proto(payload), 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn unknown_header_location() {
        let payload = r#"
    {
        "creds": {
            "kind":"api_key",
            "api_id": "filter2",
            "spec": {
                "api_key": {
                    "in": "foo",
                    "name": "x-api-key"
                }
            }
        }
    }
    "#;
        conf::parse_config(json_to_proto(payload), 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn wrong_config4() {
        let payload = r#"
    {
        "creds": {
    
        }
    }
    "#;
        conf::parse_config(json_to_proto(payload), 0).unwrap();
    }
}
