# Ixoryn — Advanced Security Intelligence Platform

```
  ██╗██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗
  ██║╚██╗██╔╝██╔═══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║
  ██║ ╚███╔╝ ██║   ██║██████╔╝ ╚████╔╝ ██╔██╗ ██║
  ██║ ██╔██╗ ██║   ██║██╔══██╗  ╚██╔╝  ██║╚██╗██║
  ██║██╔╝ ██╗╚██████╔╝██║  ██║   ██║   ██║ ╚████║
  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝
  Advanced Security & Intelligence Platform
```

> **A world-class, cross-platform security tool for organizations and researchers.**

---

## Features

### Cryptography Module
- **Encryption**: AES-256-GCM with Argon2id key derivation (OWASP/NIST recommended)
- **Digital Signatures**: Ed25519 (fastest, timing-attack immune)
- **Key Generation**: Ed25519 key pairs with encrypted private keys
- **Hashing**: SHA-256, SHA-3-256, SHA-3-512, SHA-512, BLAKE2b, BLAKE2s
- **Asymmetric Encryption**: NaCl Box (X25519 + XSalsa20-Poly1305)
- **File Fingerprinting**: Multi-algorithm hash bundles
- Passwords audited automatically at point of use

### Steganography Module

#### Research Mode (Forensic-Grade Detector)
- **LSB Analysis** — Statistical LSB plane analysis across all channels
- **Chi-Square Attack** — Pair-of-values equality testing
- **RS Analysis** — Regular/Singular analysis
- **DCT Coefficient Analysis** — JPEG steganography detection
- **Error Level Analysis (ELA)** — JPEG compression inconsistency detection
- **Entropy Analysis** — Shannon entropy anomaly detection
- **EXIF/Metadata Forensics** — Hidden data in metadata fields
- **Audio Spectrum Analysis** — Frequency anomaly detection
- **Audio LSB Analysis** — Sample-level LSB distribution testing
- **ML Ensemble Classifier** — Random Forest + Isolation Forest trained on 65 statistical features

#### Operational Mode
- Embed **text, files, images, or audio** into **image or audio covers**
- All common cover formats accepted (PNG, JPG, BMP, TIFF, GIF, WEBP, WAV, FLAC, MP3, OGG)
- **Always outputs lossless format** (PNG for images, FLAC for audio) — prevents transit corruption
- **Password-seeded randomized LSB traversal** (Xoshiro256** PRNG seeded by Argon2id key) — defeats chi-square analysis of outputs
- Optional **AES-256-GCM encryption** of payload before embedding
- Checksum integrity verification on extraction

### URL & Domain Auditing Module
- **Phishing Detection** — Keyword analysis, brand impersonation, suspicious patterns
- **Homograph Attack Detection** — Unicode/IDN lookalike domain identification
- **Typosquatting Analysis** — Levenshtein distance vs. 30+ popular domains
- **SSL/TLS Analysis** — Certificate validation, expiry, cipher suite, TLS version
- **WHOIS Forensics** — Registration data, domain age, registrar
- **DNS Analysis** — A, AAAA, MX, NS, TXT, SPF, DMARC, CNAME
- **Redirect Chain Analysis** — Full hop inspection
- **Page Content Analysis** — Form/password field detection
- **Threat Intelligence** (Deep scan):
  - VirusTotal (URL/domain/IP reputation)
  - AbuseIPDB (IP abuse scoring)
  - Google Safe Browsing (phishing/malware blocklist)
  - Shodan (open port/CVE exposure)
  - AlienVault OTX (threat pulse database)
  - URLhaus (malware URL database, no key needed)
  - Certificate Transparency (crt.sh, no key needed)
  - Passive DNS (HackerTarget, no key needed)
- Multiple targets simultaneously
- Quick / Standard / Deep scan depths

### Password & Hash Auditing Module
- **Hash Identification** — 80+ signature patterns covering 300+ algorithm variants
- **Password Strength Scoring** — zxcvbn-based scoring (0–4)
- **Entropy Calculation** — Combinatorial and Shannon entropy
- **Crack Time Estimation** — Multiple attack scenarios
- **Pattern Detection** — Keyboard walks, dates, leet speak, repetition
- **Common Password Check** — Against breach database
- **Compliance Checking** — NIST SP 800-63B, PCI-DSS, CIS Controls
- **Hash Security Rating** — CRITICAL → INSECURE → WEAK → MODERATE → GOOD → EXCELLENT
- **Batch Processing** — File input support
- **Password Generator** — Cryptographically secure (secrets module)

### Report Generation
- **HTML Reports** — Professional dark-themed reports for all modules
- **PDF Reports** — Via weasyprint or pdfkit
- Includes: Risk scores, findings, remediation, statistical data, compliance status

---

## Modes

### 1. Beginner Mode
Guided, menu-driven interface with GUI file pickers (tkinter + terminal fallback).

### 2. Expert Mode
Metasploit-style command shell with tab completion, history, JSON output:
```
ti <domain>              — Threat intelligence check
report html url file.json — Generate HTML report from saved audit
test                     — Run module test suite
```

### 3. Ixoryn Doctor
- Dependency health check
- Module self-tests (functional verification)
- Network connectivity
- Optional full test suite run

---

## Requirements

- **Python 3.9+**
- Cross-platform: **Kali Linux, Ubuntu/Debian, macOS, Windows**
- Dependencies auto-detected and installed on first run

---

## Installation

### Linux / macOS
```bash
git clone https://github.com/ademohmustapha/ixoryn.git
cd ixoryn
chmod +x install.sh && ./install.sh
ixoryn
```

### Windows
```cmd
git clone https://github.com/ademohmustapha/ixoryn.git
cd ixoryn && install.bat && python ixoryn.py
```

### Direct run
```bash
python3 ixoryn.py
```

---

## API Keys (Optional — for Threat Intelligence)

Add to `~/.ixoryn/config.json`:
```json
{
  "api_keys": {
    "virustotal": "YOUR_KEY",
    "abuseipdb": "YOUR_KEY",
    "google_safe_browsing": "YOUR_KEY",
    "shodan": "YOUR_KEY",
    "otx": "YOUR_KEY"
  }
}
```

Or set environment variables: `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, etc.

URLhaus, crt.sh, and HackerTarget passive DNS work **without any API key**.

---

## Expert Mode Examples

```bash
# Cryptography
crypto encrypt secret.pdf -p "MyPassword@2024"
crypto sign document.pdf -k alice.ixkey -p "KeyPass"
crypto hash report.pdf -a BLAKE2b

# Steganography
stego detect suspicious_image.png
stego embed -c photo.jpg -p secret.zip -o stego.png -pass "HideMe!99"
stego extract -f stego.png -pass "HideMe!99" -o recovered.zip

# URL Auditing
url audit paypa1.com phishing-example.tk -d deep
url ssl bankofamerica.com

# Threat Intelligence
ti suspicious-domain.tk
ti http://phishing-example.com --json -o results.json

# Password Auditing
pass audit "MyPassword123" --verbose
pass hash 5f4dcc3b5aa765d61d8327deb882cf99
pass generate -l 24 -s high

# Reports
report html url audit.json -o report.html
report pdf stego forensic.json

# Testing
test
```

---

## Architecture

```
ixoryn/
├── ixoryn.py
├── ixoryn/
│   ├── core/           bootstrap, dependency_manager, logger
│   ├── ui/             banner, menus, expert_shell, doctor, file_picker
│   ├── utils/          report_generator (HTML + PDF)
│   └── modules/
│       ├── crypto/     engine (AES-256-GCM, Argon2id, Ed25519)
│       ├── stego/      detector, ml_detector, embed, extract, traversal
│       ├── url_audit/  auditor, threat_intel (8 sources)
│       └── password/   auditor (300+ hashes), generator
├── tests/              test_suite.py (60+ unit & integration tests)
├── install.sh / .bat
├── requirements.txt
└── README.md
```

---

## Security Notes

- **Argon2id** for all KDF operations
- **AES-256-GCM** for authenticated encryption
- **Ed25519** for signatures (timing-attack immune)
- **Randomized LSB traversal** (Xoshiro256** PRNG) makes Ixoryn outputs undetectable by Ixoryn's own chi-square detector
- Private keys never stored in plaintext
- All stego output is lossless to prevent data loss

---

## License

MIT License — See LICENSE

## Disclaimer

For authorized security research, penetration testing, and educational use only.

