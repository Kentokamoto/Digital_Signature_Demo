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
        nonce: u128,
    }
    pub struct AccountInfoError {
        pub message: String,
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
        pub fn new(public_key: String) -> Result<AccountInfo, AccountInfoError> {
            let nonce = generate_nonce();
            match VerifyingKey::from_public_key_pem(&public_key.as_str()) {
                Ok(_) => Ok(AccountInfo { public_key, nonce }),
                Err(e) => Err(AccountInfoError {
                    message: e.to_string(),
                }),
            }
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

        pub fn nonce(&self) -> &u128 {
            &self.nonce
        }
        pub fn new_nonce(&mut self) {
            self.nonce = generate_nonce();
        }
        pub fn verify_nonce(&self, input_nonce: &u128) -> bool {
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

    fn generate_nonce() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }
}

pub mod request {
    use serde::Deserialize;
    use std::fmt::Debug;
    #[derive(Deserialize, Debug)]
    #[serde(crate = "rocket::serde")]
    pub struct Acct {
        pub account_name: String,
        pub public_key: String,
    }

    #[derive(Deserialize, Debug)]
    #[serde(crate = "rocket::serde")]
    pub struct SignedMessage {
        pub account_name: String,
        pub nonce: u128,
        pub message: String,
        pub digest: String,
    }
}
pub mod response {
    use serde::Serialize;
    #[derive(Serialize)]
    pub struct RegResponse {
        pub account_name: String,
        pub nonce: u128,
        pub message: String,
    }
    pub struct ResponseErr {
        pub message: String,
    }
}
#[cfg(test)]
mod account_info_tests {
    use super::database::AccountInfo;
    use ed25519_dalek::{
        pkcs8::{DecodePrivateKey, DecodePublicKey},
        Signature, Signer, SigningKey, Verifier, VerifyingKey,
    };

    const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIPYiycRfCG/4PDFHg+Xkcco0GqH/1AfuaGpwtkZ5EOEq\n-----END PRIVATE KEY-----";
    const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA4zVrO5Sy/aK27QTnXZzum2QcXKpruZHLM+9MUhC7tbQ=\n-----END PUBLIC KEY-----";
    const MESSAGE: &str = "I need twenty-five dollar bills\n";
    const SIGNATURE: &str =
        "gBgj3wtNB2GwtpooYi3KIG9wTHYmvu1DIOiNA6Q6wy3EhN20j+tRsbJ4cDcVJZCrQlS0cSB0Y/zEC74AUB3cDQ==";

    #[test]
    fn constructor() {
        let account_info =
            AccountInfo::new(String::from(PUBLIC_KEY).replace("\n", "\r\n")).unwrap();
        assert_eq!(account_info.public_key(), &PUBLIC_KEY.replace("\n", "\r\n"));
    }

    #[test]
    fn message_verify_valid_test() {
        let a = AccountInfo::new(String::from(PUBLIC_KEY).replace("\n", "\r\n")).unwrap();
        let signing_key: SigningKey =
            SigningKey::from_pkcs8_pem(&PRIVATE_KEY.replace("\n", "\r\n"))
                .expect("Invalid Private Key");
        let verifying_key: VerifyingKey =
            VerifyingKey::from_public_key_pem(&PUBLIC_KEY.replace("\n", "\r\n"))
                .expect("Invalid Public Key");

        let signature: Signature = signing_key.sign(&MESSAGE.as_bytes());

        assert!(verifying_key
            .verify(&MESSAGE.as_bytes(), &signature)
            .is_ok());
        assert!(a.verify_message(&String::from(MESSAGE), &SIGNATURE).is_ok());
    }
    #[test]
    fn message_verify_tampered_test() {
        let a = AccountInfo::new(String::from(PUBLIC_KEY).replace("\n", "\r\n")).unwrap();
        let signing_key: SigningKey =
            SigningKey::from_pkcs8_pem(&PRIVATE_KEY.replace("\n", "\r\n"))
                .expect("Invalid Private Key");
        let verifying_key: VerifyingKey =
            VerifyingKey::from_public_key_pem(&PUBLIC_KEY.replace("\n", "\r\n"))
                .expect("Invalid Public Key");

        let signature: Signature = signing_key.sign(&MESSAGE.as_bytes());
        let mut altered_message = String::from(MESSAGE);
        altered_message = altered_message.replace("twenty-five dollar", "twenty five-dollar");
        assert!(verifying_key
            .verify(&altered_message.as_bytes(), &signature)
            .is_err());
        assert!(a.verify_message(&altered_message, &SIGNATURE).is_err());
    }
}
