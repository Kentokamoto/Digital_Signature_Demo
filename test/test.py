import unittest
import base64
from cryptography.hazmat.primitives import serialization
import requests
from datetime import datetime



class Test(unittest.TestCase):
    base_url = "http://localhost:8000/"
    priv = bytes("""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPYiycRfCG/4PDFHg+Xkcco0GqH/1AfuaGpwtkZ5EOEq
-----END PRIVATE KEY-----""", "utf-8")
    message = "The British are coming, the British are coming\n"

    def setUp(self):
        self.private_key = serialization.load_pem_private_key(self.priv, password=None)
        public_key = self.private_key.public_key()
        self.public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    def test_registration(self):
        name = "registration_name" + str(datetime.now())
        register_body = {"account_name": name, 
                         "public_key": self.public_key_pem.decode()}
        response = requests.post(self.base_url+"register", json=register_body)
        self.assertEqual(response.status_code, 201)

    def test_verification_success(self):
        name = "test_verification_success" + str(datetime.now())
        register_body = {"account_name": name, 
                         "public_key": self.public_key_pem.decode()}
        response = requests.post(self.base_url+"register", json=register_body)
        self.assertEqual(response.status_code, 201)
        nonce = response.json()["nonce"]
        # Sign the message with the private key
        signature = base64.b64encode(self.private_key.sign(
            bytes(self.message, "utf-8")))
        message_body = {"account_name": name,
                        "nonce": int(nonce),
                        "message":self.message,
                        "digest": signature.decode()}
        response = requests.post(self.base_url+"message", json=message_body)
        self.assertEqual(response.status_code, 202)


    def test_verification_fail(self):
        name = "test_verification_fail" + str(datetime.now())
        register_body = {"account_name": name, 
                         "public_key": self.public_key_pem.decode()}
        response = requests.post(self.base_url+"register", json=register_body)
        self.assertEqual(response.status_code, 201)
        nonce = response.json()["nonce"]

        # Sign the message with the private key
        signature = base64.b64encode(self.private_key.sign(
            bytes(self.message, "utf-8")))
        # Alter the message 
        message_body = {"account_name": name,
                        "nonce": int(nonce),
                        "message": "Everyone!" + self.message,
                        "digest": signature.decode()}

        response = requests.post(self.base_url+"message", json=message_body)
        self.assertEqual(response.status_code, 406)


if __name__ == '__main__':
    unittest.main()
