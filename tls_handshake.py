import yaml
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import os

# 🔧 Configuration block — edit these values as needed
tls_config = {
    "tls_version": "TLS 1.2",
    "cipher_suites": [
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    ],
    "server_cert_path": "server_cert.pem",  # 🔌 Path to your real certificate
    "session_key_length": 64                # 🔑 Total bytes (32 for client, 32 for server)
}

class TLSHandshake:
    def __init__(self, config):
        self.tls_version = config["tls_version"]
        self.cipher_suites = config["cipher_suites"]
        self.selected_cipher = self.cipher_suites[0]
        self.server_cert_path = config["server_cert_path"]
        self.session_key_length = config["session_key_length"]
        self.client_random = get_random_bytes(32)
        self.server_random = get_random_bytes(32)
        self.pre_master_secret = None
        self.master_secret = None
        self.session_keys = None

    def client_hello(self):
        print("📤 Client Hello")
        print(f"TLS Version: {self.tls_version}")
        print(f"Client Random: {self.client_random.hex()}")
        print(f"Supported Cipher Suites: {self.cipher_suites}")

    def server_hello(self):
        print("\n📥 Server Hello")
        print(f"TLS Version: {self.tls_version}")
        print(f"Server Random: {self.server_random.hex()}")
        print(f"Selected Cipher Suite: {self.selected_cipher}")

    def generate_pre_master_secret(self):
        version_bytes = b'\x03\x03'  # TLS 1.2
        random_bytes = get_random_bytes(46)
        self.pre_master_secret = version_bytes + random_bytes
        print("\n🔐 Pre-Master Secret Generated.")

    def load_server_public_key(self):
        if os.path.exists(self.server_cert_path):
            with open(self.server_cert_path, "rb") as cert_file:
                server_pub_pem = cert_file.read()
            print("🔌 Loaded Server Public Key from Certificate.")
        else:
            # Fallback: generate temporary RSA key for demo
            print("⚠️ Certificate not found. Using temporary RSA key.")
            temp_key = RSA.generate(2048)
            server_pub_pem = temp_key.publickey().export_key()
        return server_pub_pem

    def encrypt_pre_master_secret(self, server_public_key_pem):
        server_key = RSA.import_key(server_public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(server_key)
        encrypted = cipher_rsa.encrypt(self.pre_master_secret)
        print("🔐 Pre-Master Secret Encrypted with Server Public Key.")
        return encrypted

    def derive_master_secret(self):
        seed = self.client_random + self.server_random
        self.master_secret = bytes(a ^ b for a, b in zip(self.pre_master_secret[:len(seed)], seed))
        print("🔑 Master Secret Derived.")
        return self.master_secret

    def derive_session_keys(self):
        salt = self.client_random + self.server_random
        key_material = HKDF(master=self.master_secret, key_len=self.session_key_length, salt=salt, hashmod=SHA256)
        client_write_key = key_material[:self.session_key_length // 2]
        server_write_key = key_material[self.session_key_length // 2:]
        self.session_keys = {
            "client_write_key": client_write_key,
            "server_write_key": server_write_key
        }
        print("🔑 Session Keys Derived.")
        return self.session_keys

# 🧪 Run the handshake simulation
if __name__ == "__main__":
    tls = TLSHandshake(tls_config)

    tls.client_hello()
    tls.server_hello()
    tls.generate_pre_master_secret()

    server_pub_pem = tls.load_server_public_key()
    encrypted_pms = tls.encrypt_pre_master_secret(server_pub_pem)

    master_secret = tls.derive_master_secret()
    print(f"\nMaster Secret (hex): {master_secret.hex()}")

    session_keys = tls.derive_session_keys()
    print(f"\nClient Write Key (hex): {session_keys['client_write_key'].hex()}")
    print(f"Server Write Key (hex): {session_keys['server_write_key'].hex()}")
