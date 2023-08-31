use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct AccountInfo {
    public_key: String,
    nonce: String,
}
fn generate_nonce() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string()
}
impl AccountInfo {
    pub fn new(public_key: String) -> AccountInfo {
        let nonce = generate_nonce();
        AccountInfo { public_key, nonce }
    }

    pub fn public_key(&self) -> &String {
        &self.public_key
    }
    pub fn nonce(&self) -> &String {
        &self.nonce
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

#[cfg(test)]
mod account_info_tests {
    use super::AccountInfo;
    #[test]
    fn constructor() {
        let account_info = AccountInfo::new(String::from("public_key"));
        assert_eq!(account_info.public_key(), "public_key");
    }
}

#[cfg(test)]
mod in_mem_db_tests {}
