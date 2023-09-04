pub mod database {
    use std::{
        collections::HashMap,
        fmt::Debug,
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Debug)]
    pub struct AccountInfo {
        public_key: String,
        nonce: String,
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

    fn generate_nonce() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string()
    }
}
pub mod signature {
    use generic_array::GenericArray;
    use sha2::{digest::generic_array::typenum::U32, Digest, Sha256};
    pub fn hash(message: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        println!("Result: {:x}", &hash);
        hash.into()
    }

    fn decrypt(message: String, public_key: String) {
        unimplemented!()
    }
}
pub mod request {
    use serde::Deserialize;
    use std::fmt::Debug;
    #[derive(Deserialize, Debug)]
    #[serde(crate = "rocket::serde")]
    pub struct Acct<'r> {
        pub account_name: &'r str,
        pub public_key: &'r str,
    }
}
pub mod response {
    use serde::Serialize;
    #[derive(Serialize)]
    pub struct RegResponse {
        pub account_name: String,
        pub nonce: String,
    }
}
#[cfg(test)]
mod signature_tests {
    use super::signature;
    use ed25519_dalek::{VerifyingKey, PUBLIC_KEY_LENGTH};
    use generic_array::{arr, GenericArray};
    use hex;

    const PRIVATE_KEY : &str= "MHQCAQEEIDgqJ4GwH9RpXQgCaPRtC3Cj4ilAlUM18IBVgWct7iLaoAcGBSuBBAAKoUQDQgAEh5Q4EaEIxze8dPbTb11MJ/9apwXaAJSpuwQER1mTn7zDlkIyFRGJt32i8ZFGIWajsykfdLUvVWpF7YMxWf31fg==";
    const PUBLIC_KEY : &str= "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEh5Q4EaEIxze8dPbTb11MJ/9apwXaAJSpuwQER1mTn7zDlkIyFRGJt32i8ZFGIWajsykfdLUvVWpF7YMxWf31fg==";
    const MESSAGE: &str = "The British are coming, the British are coming\n";
    const DIGEST: &str = "a4a13eb5b1297c55e7932bdc46bffba226e55d094406e429ee10661c0cb99b4d";

    #[test]
    fn decrypt_valid_test() {}

    #[test]
    fn hash() {
        let hash_val = signature::hash(&MESSAGE);
        assert_eq!(hex::decode(DIGEST).unwrap(), hash_val.to_vec())
    }
}
#[cfg(test)]
mod account_info_tests {
    use super::database::AccountInfo;
    #[test]
    fn constructor() {
        let account_info = AccountInfo::new(String::from("public_key"));
        assert_eq!(account_info.public_key(), "public_key");
    }
}

#[cfg(test)]
mod in_mem_db_tests {}
