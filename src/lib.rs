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
    use ed25519_dalek::{
        pkcs8::{DecodePrivateKey, DecodePublicKey},
        Signature, Signer, SigningKey, Verifier, VerifyingKey,
    };
    use hex;

    const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPYiycRfCG/4PDFHg+Xkcco0GqH/1AfuaGpwtkZ5EOEq
-----END PRIVATE KEY-----";
    const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4zVrO5Sy/aK27QTnXZzum2QcXKpruZHLM+9MUhC7tbQ=
-----END PUBLIC KEY-----";
    const MESSAGE: &str = "The British are coming, the British are coming\n";
    const DIGEST: &str = "a4a13eb5b1297c55e7932bdc46bffba226e55d094406e429ee10661c0cb99b4d";

    #[test]
    fn decrypt_valid_test() {
        let signing_key: SigningKey =
            SigningKey::from_pkcs8_pem(&PRIVATE_KEY).expect("Invalid Private Key");
        let verifying_key: VerifyingKey =
            VerifyingKey::from_public_key_pem(&PUBLIC_KEY).expect("Invalid Public Key");

        let signature: Signature = signing_key.sign(&MESSAGE.as_bytes());
        println!("Signature: {:?}", signature);
        assert!(verifying_key
            .verify(&MESSAGE.as_bytes(), &signature)
            .is_ok());
    }

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
