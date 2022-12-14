use super::API_KEY_KIND;
use super::BASIC_KIND;
use crate::cache::{ReadableCache, WritableCache};
use json;
use json::JsonValue;
use proxy_wasm::types::Bytes;


pub fn parse_and_store(cache: &mut dyn WritableCache<String, Bytes>, config: String, context_id: u32) {
    let json = json::parse(config.as_str()).unwrap_or_else(|err| {
        panic!(
            "config for context {} cannot be parsed: {}",
            context_id, err
        )
    });
    if let JsonValue::Short(config_type) = &json["config"] {
        match from(config_type) {
            Type::Service => parse_and_store_service_config(cache, &json["service"]),
            Type::Creds => parse_and_store_creds_config(cache, &json["creds"], context_id),
            Type::Unknown => panic!("config with value '{}' is not supported", config_type),
        }
    } else {
        panic!("\"config\" attribute cannot be found for context:{} in config: {}", context_id, config)
    }
}

const CONF_SERVICE_HOST_KEY: &'static str = "conf.service.host";
const CONF_SERVICE_PORT_KEY: &'static str = "conf.service.port";

fn parse_and_store_service_config(cache: &mut dyn WritableCache<String, Bytes>, conf: &JsonValue) {
    // gRPC host
    if let JsonValue::Short(host) = &conf["host"] {
        cache.put(
            String::from(CONF_SERVICE_HOST_KEY),
            Some(String::from(*host).into_bytes()),
        );
    } else {
        panic!("service.host not found or not a String")
    }

    // gRPC port
    if let JsonValue::Number(port) = &conf["port"] {
        let (pos, number, exp) = port.as_parts();
        if !pos {
            panic!("service.port must be positive")
        }
        if exp > 0 {
            panic!("service.port must be an integer")
        }
        if number > u16::MAX as u64 {
            panic!("service.port must below {}", u16::MAX)
        }

        cache.put(
            String::from(CONF_SERVICE_PORT_KEY),
            Some(format!("{}", number).into_bytes()),
        );
    } else {
        panic!("service.port not found or not a (positive) Number")
    }
}

fn parse_and_store_creds_config(
    cache: &mut dyn WritableCache<String, Bytes>,
    conf: &JsonValue,
    context_id: u32,
) {
    let mut api_id = String::new();

    // set mapping from context to api_id
    if let JsonValue::Short(api_id_short) = &conf["api_id"] {
        log::debug!("binding api_id {} to ctx {}", api_id_short, context_id);
        api_id.push_str(String::from(*api_id_short).as_str());
        cache.put(
            as_context_key(context_id),
            Some(api_id.clone().into_bytes()),
        );
    } else {
        panic!("creds.api_id is missing for context: {}", context_id)
    }

    let mut kind = String::new();
    // set mapping from api_id to to cred kind

    if let JsonValue::Short(kind_str) = &conf["kind"] {
        kind.push_str(kind_str);
        log::debug!("binding api_id {} to kind {}",api_id, &kind);
        cache.put(
            as_api_id_key(api_id.as_str()),
            Some(kind.clone().into_bytes()),
        );
    } else {
        panic!("creds.kind is missing for context: {}", context_id)
    }
    if kind.eq(API_KEY_KIND) {
        if let JsonValue::Short(is_in) = &conf["in"] {
            let in_key = as_api_key_in_key(api_id.as_str());
            cache.put(in_key, Some(String::from(*is_in).into_bytes()));
        }
        if let JsonValue::Short(name) = &conf["name"] {
            let name_key = as_api_key_name_key(api_id.as_str());
            cache.put(name_key, Some(String::from(*name).into_bytes()));
        }
    }

    if kind.eq(BASIC_KIND) {
        let key = as_basic_key(api_id.as_str());
        cache.put(key, Some(vec![]));
    }
}

pub fn is_api_key(
    cache: &dyn ReadableCache<String, Bytes>,
    context_id: u32,
) -> (bool, Option<String>) {
    is_auth_of_kind(cache, context_id, API_KEY_KIND)
}

pub fn is_basic(
    cache: &dyn ReadableCache<String, Bytes>,
    context_id: u32,
) -> (bool, Option<String>) {
    is_auth_of_kind(cache, context_id, BASIC_KIND)
}

fn is_auth_of_kind(
    cache: &dyn ReadableCache<String, Bytes>,
    context_id: u32,
    expected_kind: &str,
) -> (bool, Option<String>) {
    if let Some(api_id_bytes) = cache.get(&as_context_key(context_id)) {
        let api_id = String::from_utf8(api_id_bytes.to_vec()).unwrap();
        if let Some(kind) = cache.get(&as_api_id_key(api_id.as_str())) {
            return (kind.as_slice().eq(expected_kind.as_bytes()), Some(api_id));
        } else {
            log::error!("no cache entry for {}", as_api_id_key(api_id.as_str()))
        }
    } else {
        log::error!("no cache entry for {}", as_context_key(context_id))
    }
    (false, None)
}

#[derive(PartialEq, Debug)]
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

pub struct ApiKeySpec {
    pub is_in: ApiKeyLocation,
    pub name: String,
}

pub fn get_api_key_spec(
    cache: &dyn ReadableCache<String, Bytes>,
    api_id: &str,
) -> Result<ApiKeySpec, String> {
    let is_in = cache.get(&as_api_key_in_key(api_id));
    let name = cache.get(&as_api_key_name_key(api_id));

    if let Some(is_in) = is_in {
        if let Some(name) = name {
            // we set it our self no need to check
            let name_str = String::from_utf8(name).unwrap();
            let is_in_str = String::from_utf8(is_in).unwrap();
            Ok(ApiKeySpec {
                is_in: ApiKeyLocation::from(is_in_str),
                name: name_str,
            })
        } else {
            Err(format!("cannot find entry 'name' for {}.api_key'", api_id))
        }
    } else {
        Err(format!("cannot find entry 'in' for {}.api_key'", api_id))
    }
}

enum Type {
    Service,
    Creds,
    Unknown,
}

fn from(type_str: &str) -> Type {
    if type_str == "service" {
        Type::Service
    } else if type_str == "creds" {
        Type::Creds
    } else {
        Type::Unknown
    }
}

fn as_api_key_in_key(api_id: &str) -> String {
    as_api_key_key(api_id, "in")
}

fn as_api_key_name_key(api_id: &str) -> String {
    as_api_key_key(api_id, "name")
}

fn as_basic_key(api_id: &str) -> String {
    let mut key = String::new();
    key.push_str(api_id);
    key.push_str(".");
    key.push_str(BASIC_KIND);
    key
}

fn as_api_key_key(api_id: &str, field_name: &str) -> String {
    let mut key = String::new();
    key.push_str(api_id);
    key.push_str(".");
    key.push_str(API_KEY_KIND);
    key.push_str(".");
    key.push_str(field_name);
    key
}

fn as_context_key(id: u32) -> String {
    let mut key = String::from("context.");
    key.push_str(id.to_string().as_str());
    key
}

fn as_api_id_key(api_id: &str) -> String {
    let mut key = String::from("api_id.");
    key.push_str(api_id);
    key
}



#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;
    use std::collections::HashMap;
    use proxy_wasm::types::Bytes;
    use crate::cache::{ReadableCache, WritableCache};
    use crate::conf;
    use crate::conf::{ApiKeyLocation, CONF_SERVICE_HOST_KEY, CONF_SERVICE_PORT_KEY, get_api_key_spec, is_api_key, is_basic};

    struct MockCache {
        data: HashMap<String, Bytes>
    }

    impl MockCache {
        fn new() -> MockCache {
            MockCache {
                data : HashMap::new()
            }
        }
    }

    impl WritableCache<String, Bytes> for MockCache {
        fn put(&mut self, key: String, value: Option<Bytes>) {
            self.data.insert(key, value.unwrap());
        }

        fn _delete(&self, _key: String) {
            todo!()
        }
    }

    impl ReadableCache<String, Bytes> for MockCache {
        fn get(&self, key: &String) -> Option<Bytes> {
            self.data.get(key).map(|bytes| bytes.clone())
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

        let mut cache = MockCache::new();
        conf::parse_and_store(cache.borrow_mut(), String::from(payload), 0);

        let api_id = cache.data.get(&String::from("context.0")).unwrap();
        assert_eq!(to_str(api_id).as_str(), "filter2");

        {
            let kind = cache.data.get(&String::from("api_id.filter2")).unwrap();
            assert_eq!(to_str(kind).as_str(), "api_key");
        }
        {
            let in_value = cache.data.get(&String::from("filter2.api_key.in")).unwrap();
            assert_eq!(to_str(in_value).as_str(), "header");
        }
        {
            let name = cache.data.get(&String::from("filter2.api_key.name")).unwrap();
            assert_eq!(to_str(name).as_str(), "x-api-key");
        }

        assert!(conf::is_api_key(&cache, 0).0);
        assert!(!conf::is_basic(&cache, 0).0);
        assert_eq!(conf::is_api_key(&cache, 0).1.unwrap(), String::from("filter2"));

        let spec = get_api_key_spec(&cache, to_str(api_id).as_str());
        assert_eq!(spec.as_ref().unwrap().is_in, ApiKeyLocation::Header);
        assert_eq!(spec.as_ref().unwrap().name, "x-api-key")

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

        let mut cache = MockCache::new();
        conf::parse_and_store(cache.borrow_mut(), String::from(payload), 0);

        {
            let api_id = cache.data.get(&String::from("context.0")).unwrap();
            assert_eq!(to_str(api_id).as_str(), "filter1");
        }

        {
            let kind = cache.data.get(&String::from("api_id.filter1")).unwrap();
            assert_eq!(to_str(kind).as_str(), "basic");
        }

        assert!(conf::is_basic(&cache, 0).0);
        assert!(!conf::is_api_key(&cache, 0).0);
        assert_eq!(conf::is_basic(&cache, 0).1.unwrap(), String::from("filter1"));
    }

    #[test]
    fn service_conf_test() {
        let payload = r#"
{
  "config": "service",
  "service": {
    "host": "localhost",
    "port": 50051
  }
}
"#;

        let json = json::parse(payload);
        println!("{:#?}", json);

        let mut cache = MockCache::new();
        conf::parse_and_store(cache.borrow_mut(), String::from(payload), 0);

        {
            let host = cache.data.get(&String::from(CONF_SERVICE_HOST_KEY)).unwrap();
            assert_eq!(to_str(host).as_str(), "localhost");
        }

        {
            let port = cache.data.get(&String::from(CONF_SERVICE_PORT_KEY)).unwrap();
            assert_eq!(to_str(port).as_str(), "50051");
        }
    }

    fn to_str(b :&Bytes) -> String {
        String::from_utf8(b.clone()).unwrap()
    }

}