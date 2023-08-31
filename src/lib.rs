use std::{collections::HashMap, sync::Mutex};

pub struct AccountInfo {
    public_key: String,
    nonce: String,
}

impl AccountInfo {
    pub fn new(public_key: String) -> AccountInfo {
        AccountInfo {
            public_key,
            nonce: String::from("CHANGE ME"),
        }
    }
}
pub struct InMemDB {
    pub db: Mutex<HashMap<String, AccountInfo>>,
}

impl InMemDB {
    pub fn new() -> InMemDB {
        InMemDB {
            db: Mutex::new(HashMap::<String, AccountInfo>::new()),
        }
    }
}
