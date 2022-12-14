use std::collections::HashMap;
use log;
use crate::cache::AuthError::{Forbidden, Unauthorized};

pub mod hard_coded;

pub struct AuthCache {
    data: HashMap<String, Vec<u8>>,
}

pub enum AuthError {
    Unauthorized=401,
    Forbidden=403
}

impl AuthCache {

    pub fn new() -> AuthCache {
        AuthCache{
            data: HashMap::new()
        }
    }

    pub fn check(&self, client_id: &String, expected: &Vec<u8>) -> Result<(), AuthError> {
        let actual = self.get(client_id);
        if let Some(actual) = actual {
            if actual.eq(expected) {
                Ok(())
            } else {
                Err(Forbidden)
            }
        } else {
            Err(Unauthorized)
        }        
    }

    fn get(&self, client_id: &String) -> Option<&Vec<u8>>{
        self.data.get(client_id)
    }

    pub fn put(&mut self, client_id: String, value: Option<Vec<u8>>) {
        let res = self.data.insert(client_id.clone(), value.unwrap_or(vec![]));
        if let None = res {
            log::info!("Entry add for client_id '{}'", client_id)
        } else {
            log::info!("Entry updated for client_id '{}'", client_id)
        }
    }

    pub fn delete(&mut self, client_id: String) {
        let res = self.data.remove(&client_id[..]);
        if let Some(_) = res {
            log::info!("Entry client_id '{}' removed", client_id)
        } else {
            log::warn!("No entry for client_id '{}'", client_id)
        }
    }
}