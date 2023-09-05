pub mod database {
    use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, Verifier, VerifyingKey};
    use std::{
        collections::HashMap,
        fmt,
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    use base64::{engine::general_purpose, Engine};
    #[derive(Debug)]
    pub struct AccountInfo {
        public_key: String,
        nonce: String,
    }
    pub struct AccountInfoError {
        message: String,
    }

    impl fmt::Display for AccountInfoError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Account Error: {}", self.message)
        }
    }
    impl fmt::Debug for AccountInfoError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "{{ Account Error -- file: {}, line: {} message: {}}}",
                file!(),
                line!(),
                self.message
            )
        }
    }
    impl AccountInfo {
        pub fn new(public_key: String) -> AccountInfo {
            let nonce = generate_nonce();
            AccountInfo { public_key, nonce }
        }

        pub fn public_key(&self) -> &String {
            &self.public_key
        }

        pub fn verify_message(
            &self,
            message: &String,
            signature: &str,
        ) -> Result<(), AccountInfoError> {
            let verifying_key: VerifyingKey =
                match VerifyingKey::from_public_key_pem(&self.public_key) {
                    Ok(key) => key,
                    Err(e) => {
                        return Err(AccountInfoError {
                            message: e.to_string(),
                        });
                    }
                };
            let decoded_signature: [u8; 64] = match general_purpose::STANDARD
                .decode(signature)
                .expect("Signature decode error")
                .try_into()
            {
                Ok(signature) => signature,
                Err(_) => {
                    return Err(AccountInfoError {
                        message: String::from("There was a problem casting from Vec to Array"),
                    });
                }
            };
            let sig: Signature = Signature::from_bytes(&decoded_signature);
            match verifying_key.verify(message.as_bytes(), &sig) {
                Ok(()) => Ok(()),
                Err(e) => Err(AccountInfoError {
                    message: e.to_string(),
                }),
            }
        }

        pub fn nonce(&self) -> &String {
            &self.nonce
        }
        pub fn new_nonce(&mut self) {
            self.nonce = generate_nonce();
        }
        pub fn verify_nonce(&self, input_nonce: &String) -> bool {
            self.nonce.eq(input_nonce)
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
    use super::database::AccountInfo;
    use base64::{engine::general_purpose, Engine};
    use ed25519_dalek::{
        pkcs8::{DecodePrivateKey, DecodePublicKey},
        Signature, Signer, SigningKey, Verifier, VerifyingKey,
    };

    const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPYiycRfCG/4PDFHg+Xkcco0GqH/1AfuaGpwtkZ5EOEq
-----END PRIVATE KEY-----";
    const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4zVrO5Sy/aK27QTnXZzum2QcXKpruZHLM+9MUhC7tbQ=
-----END PUBLIC KEY-----";
    const MESSAGE: &str = "The British are coming, the British are coming\n";
    const OTHER_SIGNATURE: &str =
        "X+d7aJnuKShO3hgjJb/BzrkGUtAb3ts5al79O5bz7rABk/SAiya7HK7XMLt2jA3ZT/tiAMhhWXakH6/IH8gpBQ==";
    const SIGNATURE: [u8; 64] = [
        95, 231, 123, 104, 153, 238, 41, 40, 78, 222, 24, 35, 37, 191, 193, 206, 185, 6, 82, 208,
        27, 222, 219, 57, 106, 94, 253, 59, 150, 243, 238, 176, 1, 147, 244, 128, 139, 38, 187, 28,
        174, 215, 48, 187, 118, 140, 13, 217, 79, 251, 98, 0, 200, 97, 89, 118, 164, 31, 175, 200,
        31, 200, 41, 5,
    ];

    #[test]
    fn decrypt_valid_test() {
        let a = AccountInfo::new(String::from(PUBLIC_KEY));
        let signing_key: SigningKey =
            SigningKey::from_pkcs8_pem(&PRIVATE_KEY).expect("Invalid Private Key");
        let verifying_key: VerifyingKey =
            VerifyingKey::from_public_key_pem(&PUBLIC_KEY).expect("Invalid Public Key");

        let signature: Signature = signing_key.sign(&MESSAGE.as_bytes());
        let b64: String = general_purpose::STANDARD.encode(&signature.to_bytes());
        assert_eq!(OTHER_SIGNATURE, b64);
        assert_eq!(signature.to_bytes(), SIGNATURE);

        assert!(verifying_key
            .verify(&MESSAGE.as_bytes(), &signature)
            .is_ok());
        debug_assert!(a
            .verify_message(&String::from(MESSAGE), &OTHER_SIGNATURE)
            .is_ok());
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
