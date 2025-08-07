# CBEFF Payload Generator

This repository contains code for generating CBEFF-compliant biometric payloads. The generator combines biometric and biographic data, encrypts them using AES-256 (key derived from ECC), and packages the result into a ZIP file with CBEFF metadata blocks.

## Getting Started

### Prerequisites

Make sure you have the following installed:
- **Python 3.10+**
- **PyCryptodome** (`pip install pycryptodome`)
- **PyYAML** (`pip install pyyaml`)

### Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/cbeff-payload-generator.git
cd cbeff-payload-generator/CBEFF-ZIP
```

Install dependencies:

```bash
pip install pycryptodome pyyaml
```

### Key Generation

Before running, generate ECC key pairs:

```python
from Crypto.PublicKey import ECC

private_key = ECC.generate(curve='P-256')
with open("my_private_key.pem", "wt") as f:
    f.write(private_key.export_key(format='PEM'))

public_key = private_key.public_key()
with open("my_public_key.pem", "wt") as f:
    f.write(public_key.export_key(format='PEM'))
```

### Usage

Run the payload generator:

```bash
python cbeff_bir.py
```

This will:
- Load biometric and biographic data from `bio_data.yaml` (or create a sample if missing)
- Generate an encrypted ZIP containing the data and images
- Write CBEFF metadata blocks (`sbh.txt`, `sb.txt`)
- Output the final payload as `payload_cbeff.zip`

#### Output Files

- `payload_cbeff.zip`: The final CBEFF-compliant ZIP payload
- `sbh.txt`: Security Block Header (CBEFF metadata)
- `bdb.enc`: Encrypted biometric/biographic ZIP
- `sb.txt`: Security Block (digest and security level)

### Example

Sample `bio_data.yaml`:

```yaml
biographic:
  datatype: national id
  dob: '2004-10-14'
  name: Roilan Belaro
  nationality: PH
biometric:
  face: faceTemplate
  fingerprint: template123
  roi: roiScannedData
```

After running the script, you will see:

```
Final CBEFF Payload ZIP created: payload_cbeff.zip
```

### Encryption

All sensitive data is encrypted using AES-256 in CBC mode. The encryption key is derived from an ECC (Elliptic Curve Cryptography) key exchange and SHA-256 hashing. Each payload uses a random IV (initialization vector).

No Fernet or pre-generated key is used in this implementation.

### Logging

The script prints status messages to the console.

### Cleanup

To remove generated files:

```bash
rm sbh.txt sb.txt bdb.enc payload_cbeff.zip
```

## Configuration

- To use your own biometric/biographic data, edit `bio_data.yaml`.
- Place your biometric images (`face.jpg`, `finger.jpg`) in the same directory.

## Built With

* [Python 3.10](https://www.python.org/)
* [PyCryptodome](https://www.pycryptodome.org/)
* [PyYAML](https://pyyaml.org/)

## Authors

Roilan Belaro - _Initial work_

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Acknowledgements

- Based on the CBEFF ISO-19785
