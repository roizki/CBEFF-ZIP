import json, zipfile, os, hashlib, struct, yaml
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256

class CBEFFPayload:
    def __init__(self, yaml_path="bio_data.yaml"):
        self.yaml_path = yaml_path
        self.load_data()
        self.private_key = ECC.generate(curve='P-256')
        self.peer_public_key = ECC.generate(curve='P-256').public_key()
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

    def derive_aes_key_from_ecc(self):
        shared_point = self.private_key.d * self.peer_public_key.pointQ
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        return SHA256.new(shared_secret).digest()

    def encrypt_payload(self):
        data = json.dumps({"biometric": self.biometric, "biographic": self.biographic}).encode()
        with zipfile.ZipFile("payload.zip", "w") as zipf:
            zipf.writestr("data.json", data)
        with open("payload.zip", "rb") as f:
            raw = f.read()
        padded = pad(raw, AES.block_size)
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
        sbh = "ISOHeader2020"
        sb = "Level:High;" + digest.hex()
        self.create_payload_files(sbh, ciphertext, sb)
        zip_path = self.package_zip()
        return zip_path

# Usage
if __name__ == "__main__":
    generator = CBEFFPayload()
    output = generator.generate()
    print(f"Payload ZIP created: {output}")
 