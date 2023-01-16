use std::fmt::{Display, Formatter};
use std::time::Duration;

use json::JsonValue;
use serde::{Deserialize, Serialize};
use {json, serde_cbor};

use super::auth;
use crate::cache::{ReadableCache, WritableCache};
use crate::hash::HashAlg;

const DEFAULT_TICK_PERIOD_SEC: u64 = 60;

#[derive(Debug, PartialEq)]
pub enum Type {
    Service(ServiceConfig),
    Creds(CredsConfig),
    Unknown,
}

impl Type {
    const SERVICE_VALUE: &'static str = "service";
    const CREDS_VALUE: &'static str = "creds";

    fn from(type_str: &str) -> Type {
        if type_str == Self::SERVICE_VALUE {
            Type::Service(Default::default())
        } else if type_str == Self::CREDS_VALUE {
            Type::Creds(Default::default())
        } else {
            Type::Unknown
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ServiceConfig {
    pub cluster: String,
    pub tick_period: Duration,
}

impl ServiceConfig {
    pub const CLUSTER_FIELD: &'static str = "cluster";
    pub const TICK_PERIOD_FIELD: &'static str = "tick_period";
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            cluster: String::default(),
            tick_period: Duration::from_secs(DEFAULT_TICK_PERIOD_SEC),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum AuthKind {
    Unknown,
    ApiKey,
    Basic,
    JWT,
}

impl From<&str> for AuthKind {
    fn from(kind: &str) -> Self {
        match kind.to_ascii_lowercase().as_str() {
            auth::API_KEY_KIND => AuthKind::ApiKey,
            auth::BASIC_KIND => AuthKind::Basic,
            auth::JWT_KIND => AuthKind::JWT,
            _ => AuthKind::Unknown,
        }
    }
}

impl Default for AuthKind {
    fn default() -> Self {
        AuthKind::Unknown
    }
}

impl Display for AuthKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthKind::Unknown => f.write_str("Unknown"),
            AuthKind::ApiKey => f.write_str("ApiKey"),
            AuthKind::Basic => f.write_str("Basic"),
            AuthKind::JWT => f.write_str("JWT"),
        }
    }
}

#[derive(Default, Debug, PartialEq, Deserialize, Serialize)]
pub struct CredsConfig {
    pub api_id: String,
    pub kind: AuthKind,
    pub hash_alg: HashAlg,
    pub spec: CredSpec,
}

impl CredSpec {
    pub const KIND_FIELD: &'static str = "kind";
    pub const API_ID_FIELD: &'static str = "api_id";
    pub const HASH_ALG_FIELD: &'static str = "hash_alg";
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum CredSpec {
    Unknown,
    Basic,
    ApiKey(ApiKeySpec),
    JWT(JWTSpec),
}

impl Default for CredSpec {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApiKeySpec {
    pub is_in: ApiKeyLocation,
    pub name: String,
}

impl ApiKeySpec {
    pub const IN_FIELD: &'static str = "in";
    pub const NAME_FIELD: &'static str = "name";
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum ApiKeyLocation {
    Header,
    QueryParam,
    Unknown(String),
}

impl ApiKeyLocation {
    const HEADER: &'static str = "header";
    const QUERY_PARAM: &'static str = "query_param";
    fn from(loc: String) -> Self {
        if loc.eq(Self::HEADER) {
            ApiKeyLocation::Header
        } else if loc.eq(Self::QUERY_PARAM) {
            ApiKeyLocation::QueryParam
        } else {
            ApiKeyLocation::Unknown(loc)
        }
    }
}
impl Default for ApiKeyLocation {
    fn default() -> Self {
        ApiKeyLocation::Unknown(String::default())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct JWTSpec {
    pub claim: String,
}

impl JWTSpec {
    pub const CLAIM_FIELD: &'static str = "claim";
}

pub const CONFIG_FIELD: &'static str = "config";
pub const SERVICE_FIELD: &'static str = "service";
pub const CREDS_FIELD: &'static str = "creds";

pub fn parse_config(config: &str, context_id: u32) -> Result<Type, String> {
    let json = json::parse(config);
    match json {
        Err(err) => {
            return Err(format!(
                "config for context {context_id} cannot be parsed: {err}"
            ));
        }
        Ok(json) => {
            if let JsonValue::Short(config_type) = &json[CONFIG_FIELD] {
                match Type::from(config_type) {
                    Type::Service(_) => parse_service_config(&json[SERVICE_FIELD]),
                    Type::Creds(_) => parse_creds_config(&json[CREDS_FIELD], context_id),
                    Type::Unknown => Err(format!(
                        "config with value '{config_type}' is not supported",
                    )),
                }
            } else {
                Err(format!(
                    "\"{}\" attribute cannot be found for context:{context_id} in config: {config}",
                    CONFIG_FIELD
                ))
            }
        }
    }
}

fn parse_service_config(conf: &JsonValue) -> Result<Type, String> {
    let mut config = ServiceConfig::default();

    // gRPC cluster
    if let JsonValue::Short(cluster_short) = &conf[ServiceConfig::CLUSTER_FIELD] {
        config.cluster = cluster_short.to_string();
    } else {
        return Err(format!(
            "{}.{} is missing or not a string",
            SERVICE_FIELD,
            ServiceConfig::CLUSTER_FIELD
        ));
    }

    // non default duration
    if let JsonValue::Number(tick_period) = &conf[ServiceConfig::TICK_PERIOD_FIELD] {
        if let Some(duration) = tick_period
            .as_fixed_point_u64(0)
            .map(|d| Duration::from_secs(d))
        {
            config.tick_period = duration;
        }
    }

    Ok(Type::Service(config))
}

fn parse_creds_config(conf: &JsonValue, context_id: u32) -> Result<Type, String> {
    let mut api_id = String::new();
    if let JsonValue::Short(api_id_short) = &conf[CredSpec::API_ID_FIELD] {
        api_id.push_str(api_id_short.as_str());
    } else {
        return Err(format!(
            "{}.{} is missing or not a string for context: {context_id}",
            CREDS_FIELD,
            CredSpec::API_ID_FIELD,
        ));
    }

    let mut kind = String::new();
    if let JsonValue::Short(kind_str) = &conf[CredSpec::KIND_FIELD] {
        kind.push_str(kind_str);
    } else {
        return Err(format!(
            "{}.{} is missing or not a string for context: {context_id}",
            CREDS_FIELD,
            CredSpec::KIND_FIELD
        ));
    }

    let hash_alg: HashAlg;
    if let JsonValue::Short(alg) = &conf[CredSpec::HASH_ALG_FIELD] {
        hash_alg = HashAlg::from(alg.as_str());
        if let HashAlg::Unknown(alg) = hash_alg {
            return Err(format!(
                "'{alg}' for {}.{} do not match a supported hash algorithm for context: {context_id}",
                CREDS_FIELD,
                CredSpec::HASH_ALG_FIELD
            ));
        }
    } else {
        hash_alg = Default::default();
    }

    let mut config = CredsConfig {
        api_id,
        kind: AuthKind::from(kind.as_str()),
        hash_alg,
        spec: CredSpec::Unknown,
    };
    match config.kind {
        AuthKind::ApiKey => {
            let mut api_key_spec = ApiKeySpec::default();
            if let JsonValue::Short(is_in) = &conf[ApiKeySpec::IN_FIELD] {
                api_key_spec.is_in = ApiKeyLocation::from(is_in.to_string());
            } else {
                return Err(format!(
                    "{}.{} is missing or not a string for context: {}",
                    CREDS_FIELD,
                    ApiKeySpec::IN_FIELD,
                    context_id
                ));
            }
            if let JsonValue::Short(name) = &conf[ApiKeySpec::NAME_FIELD] {
                api_key_spec.name = name.to_string()
            } else {
                return Err(format!(
                    "{}.{} is missing or not a string for context: {}",
                    CREDS_FIELD,
                    ApiKeySpec::NAME_FIELD,
                    context_id
                ));
            }
            config.spec = CredSpec::ApiKey(api_key_spec);
            Ok(Type::Creds(config))
        }
        AuthKind::JWT => {
            let mut jwt_spec = JWTSpec::default();
            if let JsonValue::Short(claim) = &conf[JWTSpec::CLAIM_FIELD] {
                jwt_spec.claim = claim.to_string()
            } else {
                return Err(format!(
                    "{}.{} is missing or not a string for context: {}",
                    CREDS_FIELD,
                    JWTSpec::CLAIM_FIELD,
                    context_id
                ));
            }
            config.spec = CredSpec::JWT(jwt_spec);
            Ok(Type::Creds(config))
        }
        AuthKind::Basic => {
            config.spec = CredSpec::Basic;
            Ok(Type::Creds(config))
        }

        AuthKind::Unknown => Err(format!(
            "{}.{} is not expected or supported: {}",
            CREDS_FIELD,
            CredSpec::KIND_FIELD,
            kind
        )),
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
    use std::collections::HashMap;
    use std::time::Duration;

    use proxy_wasm::types::Bytes;

    use crate::cache::{ReadableCache, WritableCache};
    use crate::conf;
    use crate::conf::Type::{Creds, Service, Unknown};
    use crate::conf::{
        ApiKeyLocation,
        ApiKeySpec,
        AuthKind,
        CredSpec,
        CredsConfig,
        JWTSpec,
        ServiceConfig,
    };
    use crate::hash::HashAlg::SHA512;

    struct MockCache {
        data: HashMap<String, Bytes>,
    }

    fn new_cache() -> MockCache {
        MockCache {
            data: HashMap::new(),
        }
    }

    impl ReadableCache for MockCache {
        fn get(&self, key: &String) -> Option<Bytes> {
            self.data.get(key.as_str()).map(|d| d.clone())
        }
    }

    impl WritableCache for MockCache {
        fn put(&mut self, key: String, value: Option<Bytes>) {
            if let Some(value) = value {
                self.data.insert(key, value);
            }
        }

        fn delete(&mut self, key: String) {
            self.data.remove(key.as_str());
        }
    }

    #[test]
    fn serialization() {
        let ser = new_cred_config();

        let bytes = serde_cbor::to_vec(&ser).unwrap();
        assert_ne!(0, bytes.len());

        let des: CredsConfig = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(&ser.api_id, &des.api_id);
        assert_eq!(&ser.kind, &des.kind);
        assert_eq!(&ser.spec, &des.spec);
        assert_eq!(&ser.hash_alg, &des.hash_alg);
    }

    #[test]
    fn store_pull() {
        let mut cache = new_cache();
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
            kind: AuthKind::ApiKey,
            spec: CredSpec::ApiKey(ApiKeySpec {
                is_in: ApiKeyLocation::Header,
                name: "api-key".to_string(),
            }),
            hash_alg: Default::default(),
        }
    }

    #[test]
    fn api_key_conf_test() {
        let payload = r#"
{
    "config": "creds",
    "creds": {
        "kind": "api_key",
        "api_id": "filter2",
        "in": "header",
        "name": "x-api-key"
    }
}
"#;
        let config = conf::parse_config(payload, 0).unwrap();
        assert_eq!(
            config,
            Creds(CredsConfig {
                api_id: "filter2".to_string(),
                kind: AuthKind::ApiKey,
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
    "config": "creds",
    "creds": {
        "kind": "basic",
        "api_id": "filter1",
        "hash_alg": "SHA-512"
    }
}
"#;

        let config = conf::parse_config(payload, 0).unwrap();
        assert_eq!(
            config,
            Creds(CredsConfig {
                api_id: "filter1".to_string(),
                kind: AuthKind::Basic,
                spec: CredSpec::Basic,
                hash_alg: SHA512
            })
        );
    }

    #[test]
    fn jwt_conf_test() {
        let payload = r#"
{
    "config": "creds",
    "creds": {
        "kind": "jwt",
        "api_id": "filter1",
        "claim": "azp"
    }
}
"#;

        let config = conf::parse_config(payload, 0).unwrap();
        assert_eq!(
            config,
            Creds(CredsConfig {
                api_id: "filter1".to_string(),
                kind: AuthKind::JWT,
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
  "config": "service",
  "service": {
    "cluster": "test"
  }
}
"#;
        let config = conf::parse_config(payload, 0).unwrap();
        assert_eq!(
            config,
            Service(ServiceConfig {
                cluster: "test".to_string(),
                tick_period: Duration::from_secs(60)
            })
        );
    }

    #[test]
    fn service_conf_test() {
        let payload = r#"
{
  "config": "service",
  "service": {
    "cluster": "test",
    "tick_period": 30
  }
}
"#;
        let config = conf::parse_config(payload, 0).unwrap();
        assert_eq!(
            config,
            Service(ServiceConfig {
                cluster: "test".to_string(),
                tick_period: Duration::from_secs(30)
            })
        );
    }

    #[test]
    #[should_panic]
    fn unknown_type() {
        let payload = r#"
{
    "config": "foo",
    "creds": {
        "kind":"api_key",
        "api_id": "filter2",
        "in": "header",
        "name": "x-api-key"
    }
}
"#;
        let config = conf::parse_config(payload, 0).unwrap();
        assert_eq!(config, Unknown);
    }

    #[test]
    #[should_panic]
    fn unknown_kind() {
        let payload = r#"
{
    "config": "creds",
    "creds": {
        "kind":"foo",
        "api_id": "filter2",
        "in": "header",
        "name": "x-api-key"
    }
}
"#;
        conf::parse_config(payload, 0).unwrap();
    }

    #[test]
    fn unknown_header_location() {
        let payload = r#"
{
    "config": "creds",
    "creds": {
        "kind":"api_key",
        "api_id": "filter2",
        "in": "foo",
        "name": "x-api-key"
    }
}
"#;
        let config = conf::parse_config(payload, 0).unwrap();
        assert_eq!(
            config,
            Creds(CredsConfig {
                api_id: "filter2".to_string(),
                kind: AuthKind::ApiKey,
                spec: CredSpec::ApiKey(ApiKeySpec {
                    is_in: ApiKeyLocation::Unknown("foo".to_string()),
                    name: "x-api-key".to_string()
                }),
                hash_alg: Default::default()
            })
        );
    }

    #[test]
    #[should_panic]
    fn wrong_config() {
        let payload = r#"
{
    "config": true,
    "creds": {
        "kind": "api_key",
        "api_id": "filter2",
        "in": "header",
        "name": "x-api-key"
    }
}
"#;
        conf::parse_config(payload, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn wrong_config2() {
        let payload = r#"
{
    "config": "creds",
    "creds": {
        "kind":true,
        "api_id": "filter2",
        "in": "header",
        "name": "x-api-key"
    }
}
"#;
        conf::parse_config(payload, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn wrong_config3() {
        let payload = r#"
{
    "config": "service",
    "creds": {
        "kind":"api_key",
        "api_id": "filter2",
        "in": "header",
        "name": "x-api-key"
    }
}
"#;
        conf::parse_config(payload, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn wrong_config4() {
        let payload = r#"
{
    "config": "creds",
    "creds": {
        
    }
}
"#;
        conf::parse_config(payload, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn wrong_config5() {
        let payload = r#"
{
    "config": "creds",
    "creds": {
        "kind": "jwt",
        "api_id": "filter1"
        "claim": "azp"
    }
}
"#;
        conf::parse_config(payload, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn bad_json() {
        let payload = "{this is not JSON !!}[}";
        conf::parse_config(payload, 0).unwrap();
    }
}
