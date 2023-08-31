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

#[cfg(test)]
mod account_info_tests {
    use super::AccountInfo;
    #[test]
    fn constructor() {
        let account_info = AccountInfo::new(String::from("public_key"));
        assert_eq!(account_info.public_key, "public_key");
        assert_eq!(account_info.nonce, "CHANGE ME");
    }
}

#[cfg(test)]
mod in_mem_db_tests {}
