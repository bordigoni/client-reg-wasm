use std::time::Duration;

use json;
use json::JsonValue;
use proxy_wasm::types::Bytes;
use serde::{Deserialize, Serialize};
use serde_cbor;

use crate::auth::AuthKind;
use crate::cache::{ReadableCache, WritableCache};

const DEFAULT_TICK_PERIOD_SEC: u64 = 60;

#[derive(Debug, PartialEq)]
pub enum Type {
    Service(ServiceConfig),
    Creds(CredsConfig),
    Unknown,
}

impl Type {
    fn from(type_str: &str) -> Type {
        if type_str == "service" {
            Type::Service(Default::default())
        } else if type_str == "creds" {
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

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            cluster: String::default(),
            tick_period: Duration::from_secs(DEFAULT_TICK_PERIOD_SEC),
        }
    }
}

#[derive(Default, Debug, PartialEq, Deserialize, Serialize)]
pub struct CredsConfig {
    pub api_id: String,
    pub kind: AuthKind,
    pub spec: CredSpec,
}

impl CredsConfig {
    pub fn has_values(&self) -> bool {
        match self.spec {
            CredSpec::Unknown => false,
            _ => true,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum CredSpec {
    Unknown,
    Basic,
    ApiKey(ApiKeySpec),
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

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum ApiKeyLocation {
    Header,
    QueryParam,
    Unknown(String),
}

impl ApiKeyLocation {
    fn from(loc: String) -> Self {
        if loc.eq("header") {
            ApiKeyLocation::Header
        } else if loc.eq("query_param") {
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

pub fn parse_config(config: &str, context_id: u32) -> Result<Type, String> {
    let json = json::parse(config);
    match json {
        Err(err) => {
            return Err(format!(
                "config for context {} cannot be parsed: {}",
                context_id, err
            ));
        }
        Ok(json) => {
            if let JsonValue::Short(config_type) = &json["config"] {
                match Type::from(config_type) {
                    Type::Service(_) => parse_service_config(&json["service"]),
                    Type::Creds(_) => parse_creds_config(&json["creds"], context_id),
                    Type::Unknown => Err(format!(
                        "config with value '{}' is not supported",
                        config_type
                    )),
                }
            } else {
                Err(format!(
                    "\"config\" attribute cannot be found for context:{} in config: {}",
                    context_id, config
                ))
            }
        }
    }
}

fn parse_service_config(conf: &JsonValue) -> Result<Type, String> {
    let mut config = ServiceConfig::default();

    // gRPC cluster
    if let JsonValue::Short(cluster_short) = &conf["cluster"] {
        config.cluster = cluster_short.to_string();
    } else {
        return Err(format!("service.cluster not found or not a String"));
    }

    // non default duration
    if let JsonValue::Number(tick_period) = &conf["tick_period"] {
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
    if let JsonValue::Short(api_id_short) = &conf["api_id"] {
        api_id.push_str(api_id_short.as_str());
    } else {
        return Err(format!(
            "creds.api_id is missing or not a string for context: {}",
            context_id
        ));
    }

    let mut kind = String::new();
    if let JsonValue::Short(kind_str) = &conf["kind"] {
        kind.push_str(kind_str);
    } else {
        return Err(format!(
            "creds.kind is missing or not a string for context: {}",
            context_id
        ));
    }

    let mut config = CredsConfig {
        api_id,
        kind: AuthKind::from(kind.as_str()),
        spec: CredSpec::Unknown,
    };
    match config.kind {
        AuthKind::ApiKey => {
            let mut api_key_spec = ApiKeySpec::default();
            if let JsonValue::Short(is_in) = &conf["in"] {
                api_key_spec.is_in = ApiKeyLocation::from(is_in.to_string());
            } else {
                return Err(format!(
                    "creds.in is missing or not a string for context: {}",
                    context_id
                ));
            }
            if let JsonValue::Short(name) = &conf["name"] {
                api_key_spec.name = name.to_string()
            } else {
                return Err(format!(
                    "creds.name is missing or not a string for context: {}",
                    context_id
                ));
            }
            config.spec = CredSpec::ApiKey(api_key_spec);
            Ok(Type::Creds(config))
        }
        AuthKind::Basic => {
            config.spec = CredSpec::Basic;
            Ok(Type::Creds(config))
        }
        _ => Err(format!("creds.kind is not expected or supported: {}", kind)),
    }
}

pub fn pull_filter_config(
    cache: &dyn ReadableCache<String, Bytes>,
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
    cache: &mut dyn WritableCache<String, Bytes>,
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
    use std::time::Duration;

    use crate::auth::AuthKind;
    use crate::conf;
    use crate::conf::Type::{Creds, Service, Unknown};
    use crate::conf::{ApiKeyLocation, ApiKeySpec, CredSpec, CredsConfig, ServiceConfig};

    #[test]
    fn serialization() {
        let ser = CredsConfig {
            api_id: "foo".to_string(),
            kind: AuthKind::ApiKey,
            spec: CredSpec::ApiKey(ApiKeySpec {
                is_in: ApiKeyLocation::Header,
                name: "api-key".to_string(),
            }),
        };

        let bytes = serde_cbor::to_vec(&ser).unwrap();
        assert_ne!(0, bytes.len());

        let des: CredsConfig = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(&ser.api_id, &des.api_id);
        assert_eq!(&ser.kind, &des.kind);
        assert_eq!(&ser.spec, &des.spec);
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
                })
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
        "api_id": "filter1"
    }
}
"#;

        let config = conf::parse_config(payload, 0).unwrap();
        assert_eq!(
            config,
            Creds(CredsConfig {
                api_id: "filter1".to_string(),
                kind: AuthKind::Basic,
                spec: CredSpec::Basic
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
                })
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
    fn bad_json() {
        let payload = "{this is not JSON !!}[}";
        conf::parse_config(payload, 0).unwrap();
    }
}
