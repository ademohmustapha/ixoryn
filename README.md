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

### 🔐 Cryptography Module
- **Encryption**: AES-256-GCM with Argon2id key derivation (OWASP/NIST recommended)
- **Digital Signatures**: Ed25519 (fastest, timing-attack immune)
- **Key Generation**: Ed25519 key pairs with encrypted private keys
- **Hashing**: SHA-256, SHA-3-256, SHA-3-512, SHA-512, BLAKE2b, BLAKE2s
- **Asymmetric Encryption**: NaCl Box (X25519 + XSalsa20-Poly1305)
- **File Fingerprinting**: Multi-algorithm hash bundles
- Passwords audited automatically at point of use

### 🕵️ Steganography Module

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

### 🌐 URL & Domain Auditing Module
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

### 🔑 Password & Hash Auditing Module
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

### 📊 Report Generation
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

### 🔐 Cryptography Module
- **Encryption**: AES-256-GCM with Argon2id key derivation (industry gold standard)
- **Digital Signatures**: Ed25519 (fastest, most secure asymmetric signing)
- **Key Generation**: Ed25519 key pair generation with encrypted private keys
- **Hashing**: SHA-256, SHA-3-256, SHA-3-512, SHA-512, BLAKE2b, BLAKE2s
- **Asymmetric Encryption**: NaCl Box (X25519 + XSalsa20-Poly1305)
- Passwords audited at point of use

### 🕵️ Steganography Module

#### Research Mode (Forensic-Grade Detector)
- **LSB Analysis** — Statistical LSB plane analysis across all channels
- **Chi-Square Attack** — Pair-of-values equality testing
- **RS Analysis** — Regular/Singular analysis for LSB detection
- **DCT Coefficient Analysis** — JPEG steganography detection
- **Error Level Analysis (ELA)** — JPEG compression inconsistency detection
- **Entropy Analysis** — Shannon entropy anomaly detection
- **EXIF/Metadata Forensics** — Hidden data in metadata fields
- **Audio Spectrum Analysis** — Frequency anomaly detection in audio
- **Audio LSB Analysis** — Sample-level LSB distribution testing
- Comprehensive JSON/text forensic reports

#### Operational Mode
- Embed **text, files, images, or audio** into **image or audio covers**
- Accepts all common cover formats (PNG, JPG, BMP, TIFF, GIF, WEBP, WAV, FLAC, MP3, OGG)
- **Always outputs lossless format** (PNG for images, FLAC for audio) — prevents transit corruption
- Optional **AES-256-GCM encryption** of payload before embedding
- Checksum integrity verification on extraction

### 🌐 URL & Domain Auditing Module
- **Phishing Detection** — Keyword analysis, brand impersonation, suspicious patterns
- **Homograph Attack Detection** — Unicode/IDN lookalike domain identification
- **Typosquatting Analysis** — Levenshtein distance comparison against 30+ popular domains
- **Pharming Indicators** — DNS anomaly detection
- **SSL/TLS Analysis** — Certificate validation, expiry, cipher suite, TLS version
- **WHOIS Forensics** — Registration data, domain age, registrar analysis
- **DNS Record Analysis** — A, AAAA, MX, NS, TXT, SPF, DMARC, CNAME
- **Redirect Chain Analysis** — Full redirect following with hop inspection
- **Page Content Analysis** — Form detection, password field scanning, brand mention detection
- **Multiple targets** supported simultaneously
- Quick / Standard / Deep scan depths

### 🔑 Password & Hash Auditing Module
- **Hash Identification** — 80+ hash signature patterns covering 300+ algorithm variants
- **Password Strength Scoring** — zxcvbn-based scoring (0-4)
- **Entropy Calculation** — Combinatorial and Shannon entropy
- **Crack Time Estimation** — Online throttled, online fast, offline GPU scenarios
- **Pattern Detection** — Keyboard walks, dates, leet speak, repetition, sequences
- **Common Password Check** — Against built-in breach database
- **Compliance Checking** — NIST SP 800-63B, PCI-DSS, CIS Controls
- **Hash Security Rating** — CRITICAL → INSECURE → WEAK → MODERATE → GOOD → EXCELLENT
- **Batch Processing** — Multiple passwords/hashes from file
- **Password Generator** — Cryptographically secure password/passphrase generation

---

## Modes

### 1. Beginner Mode
Guided, menu-driven interface. Step-by-step prompts, GUI file pickers, clear explanations at every step.

### 2. Expert Mode
Metasploit-style command shell with:
- Full command-line control over all modules
- Tab completion
- Command history
- JSON output support
- File input/output flags

### 3. Ixoryn Doctor
Comprehensive health check:
- Python version verification
- All dependency status
- Module self-tests (functional verification)
- Network connectivity
- File system health
- Clear issue reporting and fix guidance

---

## Requirements

- **Python 3.9+**
- Cross-platform: **Kali Linux, Ubuntu/Debian, macOS, Windows**
- Dependencies are **automatically detected and installed** on first run

---

## Installation

### Linux / macOS
```bash
git clone https://github.com/ademohmustapha/ixoryn.git
cd ixoryn
chmod +x install.sh
./install.sh
ixoryn
```

### Windows
```cmd
git clone https://github.com/ademohmustapha/ixoryn.git
cd ixoryn
install.bat
python ixoryn.py
```

### Via pip
```bash
pip install ixoryn
ixoryn
```

### Direct run (no install)
```bash
python3 ixoryn.py
```

On first run, Ixoryn will detect missing dependencies and prompt you to install them automatically (Y/n).

---

## Usage

### Beginner Mode
```
ixoryn → 1 (Beginner Mode) → Select module → Follow prompts
```

### Expert Mode Examples
```bash
# Cryptography
crypto encrypt secret.pdf -p "MyPassword@2024"
crypto decrypt secret.pdf.ixenc -p "MyPassword@2024" -o recovered.pdf
crypto keygen -n alice -p "KeyPassword!9"
crypto sign document.pdf -k alice.ixkey -p "KeyPassword!9"
crypto verify document.pdf -s document.ixsig -k alice.ixpub
crypto hash report.pdf -a BLAKE2b

# Steganography
stego detect suspicious_image.png
stego embed -c photo.jpg -p secret.zip -o stego.png -pass "HideMe!99"
stego extract -f stego.png -pass "HideMe!99" -o recovered.zip

# URL Auditing
url audit paypa1.com phishing-example.tk -d deep
url ssl bankofamerica.com
url whois google.com
url homograph xn--pypal-4ve.com

# Password Auditing
pass audit "MyPassword123" --verbose
pass hash 5f4dcc3b5aa765d61d8327deb882cf99
pass batch -f passwords.txt --json -o results.json
pass generate -l 24 -s high
```

---

## Architecture

```
ixoryn/
├── ixoryn.py                    # Entry point
├── ixoryn/
│   ├── core/
│   │   ├── bootstrap.py         # Environment initialization
│   │   ├── dependency_manager.py # Auto-install system
│   │   └── logger.py            # Centralized logging
│   ├── ui/
│   │   ├── banner.py            # Colors, Banner, display utils
│   │   ├── main_menu.py         # Mode selection
│   │   ├── beginner_menu.py     # Full guided interface
│   │   ├── expert_shell.py      # Metasploit-style shell
│   │   ├── doctor.py            # Health check UI
│   │   └── file_picker.py       # Cross-platform file picker
│   └── modules/
│       ├── crypto/
│       │   └── engine.py        # AES-256-GCM + Argon2id + Ed25519
│       ├── stego/
│       │   ├── detector.py      # Forensic stego detector
│       │   ├── embed.py         # LSB embedding engine
│       │   └── extract.py       # Extraction engine
│       ├── url_audit/
│       │   └── auditor.py       # Full URL/domain auditor
│       └── password/
│           ├── auditor.py       # Password & hash analyzer
│           └── generator.py     # Secure password generator
├── install.sh                   # Linux/macOS installer
├── install.bat                  # Windows installer
├── requirements.txt
├── setup.py
└── README.md
```

---

## Security Notes

- **Argon2id** is used for all key derivation (OWASP/NIST recommended over bcrypt, scrypt, PBKDF2)
- **AES-256-GCM** provides authenticated encryption (integrity + confidentiality)
- **Ed25519** signatures are immune to timing attacks and use smaller, faster keys than RSA
- Private keys are never stored in plaintext
- All stego outputs are lossless format to prevent data loss
- Dependency auto-install uses `--break-system-packages` flag where needed to bypass externally-managed environment restrictions

---

## License

MIT License — See LICENSE file

---

## Disclaimer

Ixoryn is developed for legitimate security research, penetration testing with proper authorization, and educational purposes. Users are responsible for ensuring legal compliance in their jurisdiction.
