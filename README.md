# IXORYN — Unified Cybersecurity Framework

Author: Ademoh Mustapha Onimisi

IXORYN is a unified, research-grade cybersecurity framework integrating
cryptography, steganography, password intelligence, and malicious domain analysis
into a single hardened system.

Designed for real-world use, academic research, and controlled enterprise environments.

---

## Features

### 🔐 Cryptography
- Secure file, image, and text encryption
- Argon2 password-based key derivation
- Automatic salt generation
- Fail-closed decryption

### 🕵️ Steganography
- Lossless image (PNG/BMP) and audio (WAV) steganography
- Operational and research modes
- Password-protected payloads
- ML-based steganalysis (probabilistic detection)

### 🔑 Password Auditing
- Entropy estimation
- Crack-time approximation
- Hash type identification
- Integrated into crypto and stego workflows

### 🌐 URL / Domain Analysis
- Phishing detection
- Typosquatting analysis
- Homograph attack detection
- DNS inspection

---

## Installation

```bash
git clone https://github.com/<ademohmustapha>/ixoryn.git
cd ixoryn
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
````

---

## Usage

Run the CLI:

```bash
python ixoryn.py
```

Optional GUI launcher:

```bash
python gui_shell.py
```

---

## Configuration

IXORYN uses a centralized configuration file:

```
ixoryn.yaml
```

This allows administrators to tune:

* File size limits
* Logging levels
* ML detection thresholds
* Output locations

---

## Reports & Logging

* All actions are logged to `/logs`
* JSON forensic reports can be exported for SOC or legal workflows
* Deterministic execution for reproducibility

---

## Limitations

* Steganography does not survive lossy recompression by social media platforms
* ML steganalysis is probabilistic
* Not certified as a legal forensic tool
* Assumes a trusted execution environment

---

## License

MIT License

---

## Disclaimer

IXORYN is a defensive security framework provided for research and educational purposes.
No warranty is provided.

---

© Ademoh Mustapha Onimisi

````

---




