import zipfile
import json
import yaml
import os
import time
from datetime import datetime, timedelta
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


class PayloadProcessor:
    def __init__(self, zip_path, config_path):
        self.zip_path = zip_path
        self.config = self.load_config(config_path)
        self.payload_dir = "unzipped_payload"
        self.metadata = {}
        self.encrypted_data = b""
        self.signature = b""

    def load_config(self, path):
        with open(path, 'r') as f:
            return yaml.safe_load(f)

    def unzip_payload(self):
        with zipfile.ZipFile(self.zip_path, 'r') as zip_ref:
            zip_ref.extractall(self.payload_dir)

    def parse_metadata(self):
        with open(os.path.join(self.payload_dir, "metadata.json"), 'r') as f:
            self.metadata = json.load(f)

        sender = self.metadata["sender_unit_id"]
        timestamp = datetime.fromisoformat(self.metadata["timestamp"].replace("Z", "+00:00"))
        purpose = self.metadata["purpose"]

        if sender not in self.config['allowed_units']:
            raise Exception("Sender unit not recognized")

        now = datetime.utcnow()
        if abs(now - timestamp) > timedelta(minutes=self.config['allowed_drift_minutes']):
            raise Exception("Timestamp invalid")

        if purpose not in ["VerifyBiometric", "RegisterNew", "CheckDuplicate"]:
            raise Exception("Purpose not allowed")

    def verify_signature(self):
        with open(os.path.join(self.payload_dir, "encrypted_data.bin"), 'rb') as f:
            self.encrypted_data = f.read()

        with open(os.path.join(self.payload_dir, "signature.sig"), 'rb') as f:
            self.signature = f.read()

        with open(self.config['my_public_key.pem'], 'rb') as f:
            public_key = RSA.import_key(f.read())

        h = SHA256.new(self.encrypted_data)

        try:
            pkcs1_15.new(public_key).verify(h, self.signature)
            print(" Signature verified.")
        except (ValueError, TypeError):
            raise Exception(" Signature verification failed")

    def decrypt_payload(self):
        key = bytes.fromhex(self.config['session_key'])
        iv = bytes.fromhex(self.config['aes_iv'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(self.encrypted_data)

        # Remove PKCS7 padding
        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]

        with open("decrypted_payload.json", "wb") as f:
            f.write(plaintext)
        print("✔ Decrypted and saved to decrypted_payload.json")

    def log_transaction(self):
        print(" Logging transaction:")
        print(json.dumps({
            "transaction_id": self.metadata['transaction_id'],
            "sender_unit_id": self.metadata['sender_unit_id'],
            "timestamp": self.metadata['timestamp'],
            "purpose": self.metadata['purpose'],
            "status": "RECEIVED"
        }, indent=2))

    def prepare_response(self, result_data):
        result_json = json.dumps(result_data).encode('utf-8')
        pad_len = 16 - (len(result_json) % 16)
        result_json += bytes([pad_len]) * pad_len

        key = bytes.fromhex(self.config['session_key'])
        iv = bytes.fromhex(self.config['aes_iv'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_result = cipher.encrypt(result_json)

        result_hash = SHA256.new(encrypted_result)
        with open(self.config['my_private_key.pem'], 'rb') as f:
            private_key = RSA.import_key(f.read())
        signature = pkcs1_15.new(private_key).sign(result_hash)

        os.makedirs("tx_response", exist_ok=True)
        with open("tx_response/encrypted_result.bin", "wb") as f:
            f.write(encrypted_result)
        with open("tx_response/signature.sig", "wb") as f:
            f.write(signature)
        with open("tx_response/result_metadata.json", "w") as f:
            json.dump({
                "transaction_id": self.metadata['transaction_id'],
                "receiver_unit_id": self.metadata['sender_unit_id'],
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "status": result_data['status']
            }, f, indent=2)

        with zipfile.ZipFile("tx_response_payload.zip", "w") as zipf:
            zipf.write("tx_response/encrypted_result.bin", arcname="encrypted_result.bin")
            zipf.write("tx_response/signature.sig", arcname="signature.sig")
            zipf.write("tx_response/result_metadata.json", arcname="result_metadata.json")
        print("✔ Response zipped and ready to send back")

    def run(self):
        self.unzip_payload()
        self.parse_metadata()
        self.verify_signature()
        self.decrypt_payload()
        self.log_transaction()
        self.prepare_response({"status": "MATCH_FOUND"})


if __name__ == "__main__":
    processor = PayloadProcessor(zip_path="payload.zip", config_path="config.yaml")
    processor.run()
