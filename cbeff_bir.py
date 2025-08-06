import json, zipfile, os, hashlib, yaml, io
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256

class CBEFFPayload:
    def __init__(self, yaml_path="bio_data.yaml"):
        self.yaml_path = yaml_path
        self.load_data()
        self.load_keys()
        self.key = self.derive_aes_key_from_ecc()
        self.iv = os.urandom(16)

    def load_data(self):
        if not os.path.exists(self.yaml_path):
            data = {
                "biometric": {
                    "fingerprint": "template123",
                    "roi": "roiScannedData",
                    "face": "faceTemplate"
                },
                "biographic": {
                    "name": "Roilan Belaro",
                    "dob": "2004-10-14",
                    "datatype": "national id",
                    "nationality": "PH"
                }
            }
            with open(self.yaml_path, "w") as f:
                yaml.dump(data, f)
        else:
            with open(self.yaml_path, "r") as f:
                data = yaml.safe_load(f)
        self.biometric = data["biometric"]
        self.biographic = data["biographic"]

    def load_keys(self):
        # Load ECC private key
        self.private_key = ECC.import_key(open("my_private_key.pem").read())

        # Load ECC peer public key
        self.peer_public_key = ECC.import_key(open("my_public_key.pem").read())

    def derive_aes_key_from_ecc(self):
        shared_point = self.private_key.d * self.peer_public_key.pointQ
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        return SHA256.new(shared_secret).digest()

    def encrypt_payload(self):
        data = json.dumps({
            "biometric": self.biometric,
            "biographic": self.biographic
        }).encode()

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zipf:
            # Add JSON data
            zipf.writestr("data.json", data)

            # === INCLUDE FACE IMAGE ===
            face_path = "face.jpg"  # Update this if your image is .jpg
            if os.path.exists(face_path):
                with open(face_path, "rb") as facef:
                    zipf.writestr("face_image.png", facef.read())
            else:
                print(f"⚠️ Face image not found: {face_path}")

            # === INCLUDE FINGERPRINT IMAGE ===
            finger_path = "finger.jpg"
            if os.path.exists(finger_path):
                with open(finger_path, "rb") as fingerf:
                    zipf.writestr("finger_image.jpg", fingerf.read())
            else:
                print(f"⚠️ Fingerprint image not found: {finger_path}")

        # Encrypt the final ZIP
        zip_bytes = zip_buffer.getvalue()
        padded = pad(zip_bytes, AES.block_size)

        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(padded)

    def sha256_digest(self, data):
        return hashlib.sha256(data).digest()

    def create_payload_files(self, sbh, bdb, sb):
        with open("sbh.txt", "w") as f:
            f.write(sbh)
        with open("bdb.enc", "wb") as f:
            f.write(bdb)
        with open("sb.txt", "w") as f:
            f.write(sb)

    def package_zip(self, output_zip="payload_cbeff.zip"):
        with zipfile.ZipFile(output_zip, "w") as zipf:
            zipf.write("sbh.txt")
            zipf.write("bdb.enc")
            zipf.write("sb.txt")
        return output_zip

    def generate(self):
        ciphertext = self.encrypt_payload()
        digest = self.sha256_digest(ciphertext)

        timestamp = datetime.utcnow().isoformat() + "Z"
        sbh = f"""CBEFF_VERSION: ISO-19785-3
OWNER: Roilan Belaro Lab
FORMAT_TYPE: JSON+ZIP
TIMESTAMP: {timestamp}
IV: {self.iv.hex()}"""

        sb = f"""SECURITY_LEVEL: HIGH
PAYLOAD_DIGEST_SHA256: {digest.hex()}"""

        self.create_payload_files(sbh, ciphertext, sb)
        return self.package_zip()

# ==== Usage ====
if __name__ == "__main__":
    generator = CBEFFPayload()
    output = generator.generate()
    print(f"✅ Final CBEFF Payload ZIP created: {output}")
