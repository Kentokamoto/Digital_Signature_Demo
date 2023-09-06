# Digital_Signature_Demo

This is a brief demonstration of how digital signatures work written in Rust. The goal is to show that if a holder were
to share their public key to the backend server (verifier), the holder can sign a message with their private key and
have the server verify that the message and the signature are from said holder without the message getting tampered with
onroute.

## Assumptions:

This only implements the process of sharing a public key and verifying a message with a signature. Everything in between
like the handshake to exchange keys with the server and the client are not a part of this demo so all REST API requests
are sent unencrypted.

We are only implementing the ED25519 cryptography algorithm. The more RSA256 is not used here. If you would like to test
the web server demo with your own public/private key, you will need to generate one with this defined as the algorithm
of choice. A tutorial of how to run this manually can be seen in the [Manually running](#manually-running) section

## Installing

From the root of the project directory:

```
cargo build
```

## Starting the server

```
cargo run
```

This will start the web server on `http://localhost:8000`.

There are 2 endpoints that you will need in order for this demo to work. The payload of each request endpoint is sent in
JSON format.

endpoints:

-   `/register`
    -   request body:
        -   account_name: name of account
        -   public_key: ED25519 public key in [pkcs8](https://en.wikipedia.org/wiki/PKCS_8) syntax. Since JSON cannot
            have values that are multilined, replace each end of line with a `\n` in the string
    -   response body:
        -   account_name: name of account
        -   nonce: one time value used prevent replay attacks
        -   message: any message that may be sent by server
-   `/message`:
    -   request body:
        -   account_name: name of account
        -   nonce: most recent nonce that was returned by server
        -   message: The message you would like to send to the server
        -   digest: message signature
    -   response body:
        -   account_name: name of account
        -   nonce: if an account is found in the database, a new nonce will be generated
        -   message: Any messages that may be sent by server

### Manually running

If you would like to generate your own key and verify the functionality, follow these steps.

**Note** If you are running on macOS, you may need to install a different version of OpenSSL that does not come by
default.

1. Generate the private key

```
$ openssl genpkey -algorithm ed25519 -outform PEM -out private.pem
```

2. Generate the public key

```
$ openssl pkey -in private.pem -pubout -out public.pem
```

3. Create a file that includes a message you would like to send to the server:

```
$ touch msg.txt | echo "Here is the message I would like the server to see" > msg.txt
```

4. Sign the message file using the private key

```
$ openssl pkeyutl -sign -inkey secret.pem -out signature.bin -rawin -in msg.txt
```

5. Register your public key with the server. Note the public key must be on one line. Make note of the nonce value that
   it returns.

```
$ curl --request POST \
  --url http://localhost:8000/register \
  --header 'Content-Type: application/json' \
  --data '{"account_name": "<Your account name here>",
"public_key": "-----BEGIN PUBLIC KEY-----\nYOUR PUBLIC KEY CONTENT GOES HERE\n-----END PUBLIC KEY-----"}'
```

6. Encode your signature to base64 and copy the output

```
$ cat signature.bin | base64
```

7. Send the message you created earlier to the server

```
$ curl --request POST \
  --url http://localhost:8000/message \
  --header 'Content-Type: application/json' \
  --data '{"account_name": "<Your account name here>",
"nonce": <nonce from earlier>,
"message": "<contents of msg.txt>",
"digest": "<base64 encoded signature>"}'
```

If all goes well, you should see an "ACK" in the message section of the response.

---

## Testing

### Unit Testing

```
cargo test
```

There are 2 unit tests written mostly to verify both valid and invalid use cases for the struct being used.

### End-to-End Testing

This test was written in Python under the <root>/test directory. We will run this in a virtual environment. Make sure
you have the web server up and running as well.

```
$ cd test/
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
$ python3 test.py
```
