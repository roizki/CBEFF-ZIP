import os
import zipfile
import json
import io
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

def load_keys():
    # Load ECC private key
    with open("my_private_key.pem", "r") as f:
        private_key = ECC.import_key(f.read())

    # Load ECC peer public key
    with open("my_public_key.pem", "r") as f:
        peer_public_key = ECC.import_key(f.read())

    return private_key, peer_public_key

def derive_aes_key(private_key, peer_public_key):
    shared_point = private_key.d * peer_public_key.pointQ
    shared_secret = int(shared_point.x).to_bytes(32, 'big')
    return SHA256.new(shared_secret).digest()

def extract_iv_from_sbh():
    with open("sbh.txt", "r") as f:
        for line in f:
            if line.startswith("IV:"):
                iv_hex = line.strip().split("IV:")[1].strip()
                return bytes.fromhex(iv_hex)
    raise ValueError("IV not found in sbh.txt")

def decrypt_bdb(enc_file, key, iv):
    with open(enc_file, "rb") as f:
        encrypted_data = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_data)
    decrypted = unpad(decrypted_padded, AES.block_size)
    return decrypted

def extract_zip_content(zip_bytes, output_folder="decrypted_output"):
    os.makedirs(output_folder, exist_ok=True)
    zip_buffer = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(zip_buffer, "r") as zipf:
        zipf.extractall(output_folder)

    print(f" Decrypted contents extracted to: {output_folder}")
    return output_folder

def show_json_data(output_folder):
    json_path = os.path.join(output_folder, "data.json")
    if os.path.exists(json_path):
        with open(json_path, "r") as f:
            data = json.load(f)
            print("Biometric + Biographic Data:")
            print(json.dumps(data, indent=4))
    else:
        print(" data.json not found in decrypted output.")

if __name__ == "__main__":
    print("🔓 Starting decryption process...")

    private_key, peer_public_key = load_keys()
    aes_key = derive_aes_key(private_key, peer_public_key)
    iv = extract_iv_from_sbh()

    zip_bytes = decrypt_bdb("bdb.enc", aes_key, iv)
    folder = extract_zip_content(zip_bytes)
    show_json_data(folder)
