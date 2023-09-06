# Digital_Signature_Demo

```
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
python3 test.py
```

starts on http://localhost:8000

```
cargo run
```

endpoints:

- /register
  - request:
    - account_name: name of account
    - public_key: ED25519 public key. Since json cannot have values that are multilined, replace each end of line with a `\n` in the string
  - response:
    - account_name: name of account
    - nonce: one time value
    - message: any message that may be sent by server
- /message:
  - request:
    - account_name: name of account
    - nonce: nonce that was given by server
    - message: The message you would like to send to the server
    - digest: message signature
  - response:
    - account_name: name of account
    - nonce: if account is found in database, a new nonce will be generated
    - message: Any messages that may be sent by server
