# CBEFF-ZIP Payload 

This repository contains code for generating CBEFF-compliant biometric payloads. The generator combines biometric and biographic data, encrypts them using ECC-derived AES-256 keys, and packages the result into a ZIP file with CBEFF metadata blocks.

## Getting Started

### Prerequisites

Make sure you have the following installed:
- **Python 3.13.5**
- **PyCryptodome** (`pip install pycryptodome`)
- **PyYAML** (`pip install pyyaml`)

### Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/cbeff-zip-generator.git
cd cbeff-zip-generator
```

Install dependencies:

```bash
pip install pycryptodome pyyaml
```

### Usage

Run the payload generator:

```bash
python CBEFF-ZIP/cbeff_bir.py
```

This will:
- Load biometric and biographic data from `bio_data.yaml` (or create a sample if missing)
- Generate ECC keys and derive an AES-256 key
- Encrypt the data as a ZIP file
- Write CBEFF metadata blocks (`sbh.txt`, `sb.txt`)
- Output the final payload as `payload_cbeff.zip`

#### Output Files

- `payload_cbeff.zip`: The final CBEFF-compliant ZIP payload
- `sbh.txt`: Security Block Header (CBEFF metadata)
- `bdb.enc`: Encrypted biometric/biographic ZIP
- `sb.txt`: Security Block (digest and security level)

### File Structure

| File                | Purpose                                      |
|---------------------|----------------------------------------------|
| `CBEFF-ZIP/cbeff_bir.py` | Main payload generator script           |
| `bio_data.yaml`     | Input YAML with biometric/biographic data    |
| `payload_cbeff.zip` | Output ZIP containing CBEFF blocks           |
| `sbh.txt`           | Security Block Header (CBEFF metadata)       |
| `bdb.enc`           | Encrypted ZIP of biometric/biographic data   |
| `sb.txt`            | Security Block (digest, security level)      |

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

### Configuration

- To use your own biometric/biographic data, edit `bio_data.yaml`.
- The script generates new ECC keys and IV for each run.

### Logging

The script prints status messages to the console.

### Cleanup

To remove generated files:

```bash
rm sbh.txt sb.txt bdb.enc payload_cbeff.zip
```

## Built With

* [Python 3.13.5](https://www.python.org/)
* [PyCryptodome](https://www.pycryptodome.org/)
* [PyYAML](https://pyyaml.org/)

## Authors

Roilan Belaro - _Initial work_  https://github.com/roizki

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Acknowledgements

- Based on the CBEFF ISO-19785-3 standard.
