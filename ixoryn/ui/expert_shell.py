"""
Ixoryn Expert Mode
Metasploit-style command shell with full access to all modules.
"""

import sys
import os
import shlex
from typing import Dict, Callable, List, Optional
from ixoryn.ui.banner import Banner, Colors, cprint


HELP_TEXT = """
{cyan}╔══════════════════════════════════════════════════════════════════════╗
║                      IXORYN EXPERT MODE HELP                        ║
║              Type  help <module>  for deep module help              ║
╚══════════════════════════════════════════════════════════════════════╝{reset}

{bold}GENERAL COMMANDS{reset}
  help                    Show this help menu
  help crypto             Deep help: cryptography
  help stego              Deep help: steganography
  help url                Deep help: URL/domain auditing
  help pass               Deep help: password and hash auditing
  help ti                 Deep help: threat intelligence
  help report             Deep help: report generation
  exit / quit             Exit expert mode
  clear                   Clear the terminal screen
  banner                  Show Ixoryn banner
  doctor                  Run full system health check
  history                 Show command history
  test                    Run the full module test suite

{bold}CRYPTOGRAPHY  (prefix: crypto){reset}
  crypto encrypt <file|text> -p <password>
      Encrypt a file or text using AES-256-GCM + Argon2id.
      Output file: <file>.ixenc  |  Text output: Base64 string

  crypto decrypt <file|base64> -p <password> [-o <output>]
      Decrypt an Ixoryn-encrypted file or Base64 blob.

  crypto hash <file|text> -a <algorithm>
      Hash data. Algorithms: SHA-256, SHA-3-256, SHA-3-512,
                              SHA-512, BLAKE2b, BLAKE2s

  crypto keygen -n <name> -p <password>
      Generate Ed25519 key pair. Saves <name>.ixkey and <name>.ixpub

  crypto sign <file> -k <private.ixkey> -p <password> [-o <sig>]
      Sign data with Ed25519 private key. Saves <file>.ixsig

  crypto verify <file> -s <sig.ixsig> -k <public.ixpub>
      Verify Ed25519 signature. Returns VALID or INVALID.

  crypto algorithms
      List all supported algorithms with descriptions.

{bold}STEGANOGRAPHY  (prefix: stego){reset}
  stego detect <file>
      Forensic analysis: LSB, chi-square, RS analysis, DCT,
      ELA, entropy, EXIF forensics, ML ensemble classifier.
      Output: suspicion score (0-100), findings list, verdict.

  stego embed -c <cover> -p <payload> -o <output> [-pass <password>]
      Hide a file inside a cover image or audio file.
      -c    Cover file (PNG/JPG/BMP/TIFF/WAV/FLAC/MP3/OGG accepted)
      -p    Payload file to hide (any type)
      -o    Output path (auto-converted to PNG or FLAC)
      -pass Password (enables AES-256-GCM + randomized pixel traversal)

  stego extract -f <stego_file> [-pass <password>] -o <output>
      Extract hidden payload from a stego file.
      -f    Stego file (PNG, BMP, WAV, FLAC — lossless only)
      -pass Password (required if used during embed)
      -o    Output path for the recovered payload

  stego info <file>
      Show file metadata: format, dimensions, checksums, timestamps.

{bold}URL & DOMAIN AUDITING  (prefix: url){reset}
  url audit <target1> [<target2> ...] [-d quick|standard|deep]
      Full security audit. Multiple targets supported.
      quick    = phishing/homograph/typosquat checks (fastest)
      standard = + SSL/TLS, DNS, redirect chain analysis
      deep     = + WHOIS, threat intelligence, page content

  url phishing <target>     Phishing indicator analysis
  url homograph <domain>    Homograph/IDN attack detection
  url typosquat <domain>    Typosquatting analysis
  url ssl <domain>          SSL/TLS certificate deep analysis
  url whois <domain>        WHOIS registration forensics
  url dns <domain>          DNS records: A, AAAA, MX, NS, TXT, SPF, DMARC

{bold}THREAT INTELLIGENCE  (prefix: ti  or  intel){reset}
  ti <target>
      Query all available threat intelligence sources.
      Sources: VirusTotal, AbuseIPDB, Google Safe Browsing,
               Shodan, AlienVault OTX, URLhaus (no key needed),
               crt.sh cert transparency (no key needed),
               HackerTarget passive DNS (no key needed)

  ti <target> --json [-o <output.json>]
      JSON output, optionally save to file.

  ti <target> -report html
  ti <target> -report pdf
      Generate formatted HTML or PDF threat intelligence report.

  API keys: add to ~/.ixoryn/config.json under "api_keys"
  or set environment variables: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY,
  GSB_API_KEY, SHODAN_API_KEY, OTX_API_KEY

{bold}PASSWORD & HASH AUDITING  (prefix: pass){reset}
  pass audit <password> [<password2> ...] [--verbose]
      Audit password: entropy, strength score, crack time estimates,
      pattern detection, compliance (NIST SP 800-63B, PCI-DSS, CIS).

  pass hash <hash_value>
      Identify hash algorithm and rate security level.
      Covers MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2,
      NTLM, LM, WPA, scrypt, PBKDF2 and 300+ more variants.

  pass hash -f <file>
      Identify and audit all hashes from file (one per line).

  pass batch -f <file> [--json] [-o <output>]
      Audit all passwords from file. JSON output supported.

  pass generate -l <length> -s <strength>
      Generate a cryptographically secure password.
      -l    Length 8-128 (default: 20)
      -s    medium | high | passphrase (default: high)

{bold}REPORT GENERATION  (prefix: report){reset}
  report html <type> <json_file> [-o <output.html>]
  report pdf  <type> <json_file> [-o <output.pdf>]
      type: url | stego | password | hash | threat_intel
      Generates professional dark-themed HTML or PDF report.

{bold}GLOBAL OUTPUT FLAGS{reset}
  -o <file>      Save output to file
  --json         Output as JSON
  --verbose      More detailed output

{bold}NETWORK & INTELLIGENCE{reset}
  scan <target> [-d quick|standard|deep] [-p ports] [--verbose]
      Port scan + service detection + OS fingerprint + vuln analysis.

  sub <domain> [--bruteforce] [--passive-only]
      Subdomain enumeration: cert transparency + DNS brute-force.

  cve <software> [version]  |  cve <CVE-ID>
      Real-time CVE lookup from NIST NVD database.

  breach password <value>
      Check if password appears in 613M+ breach records (k-Anonymity).

  breach email <address>
      Check email against HaveIBeenPwned breach database.

{bold}UTILITIES{reset}
  encode <method> <data>    Encode: base64, hex, url, binary, rot13, md5
  decode <method> <data>    Decode: base64, hex, url, binary
  version                   Show Ixoryn version and module info

{bold}QUICK EXAMPLES{reset}
  scan example.com -d standard --verbose
  sub example.com --bruteforce -o subdomains.json
  cve apache 2.4.49
  cve CVE-2021-44228
  breach password "Password123"
  encode base64 "Hello World"
  decode hex 48656c6c6f
  crypto encrypt report.pdf -p "Str0ng@Pass#2024"
  crypto keygen -n mykey -p "KeyP@ss!9" && ls *.ixkey *.ixpub
  stego detect suspicious_photo.jpg
  stego embed -c cover.png -p secrets.zip -o hidden.png -pass "HideMe!"
  stego extract -f hidden.png -pass "HideMe!" -o recovered.zip
  url audit paypal-secure-login.tk phishing.xyz -d deep
  url ssl bankofamerica.com
  ti malicious-domain.xyz --json -o intel_results.json
  pass audit "Password123" "MyDog2019!" --verbose
  pass hash 5f4dcc3b5aa765d61d8327deb882cf99
  pass generate -l 32 -s passphrase
  report html url last_audit.json -o audit_report.html

""".format(cyan=Colors.CYAN, reset=Colors.RESET, bold=Colors.BOLD)

MODULE_HELPS = {
    "crypto": """
{cyan}CRYPTOGRAPHY MODULE HELP{reset}

Algorithms available for hashing: SHA-256, SHA-3-256, SHA-3-512, BLAKE2b, BLAKE2s, SHA-512
Encryption: AES-256-GCM with Argon2id key derivation
Signatures: Ed25519

Examples:
  crypto encrypt myfile.pdf -p "StrongPass!2024"
  crypto decrypt myfile.pdf.ixenc -p "StrongPass!2024" -o decrypted.pdf
  crypto hash myfile.pdf -a BLAKE2b
  crypto keygen -n alice -p "KeyPass!2024"
  crypto sign document.pdf -k alice.ixkey -p "KeyPass!2024"
  crypto verify document.pdf -s document.ixsig -k alice.ixpub
""",
    "stego": """
{cyan}STEGANOGRAPHY MODULE HELP{reset}

Research (Forensic) Mode:
  Analyzes files using: Chi-square, RS analysis, DCT coefficient analysis,
  LSB plane visualization, entropy analysis, metadata forensics, ELA,
  JPEG ghost detection, audio spectrum analysis, statistical anomalies.

Operational Mode:
  Supports: Image covers (PNG, JPG, BMP, TIFF, GIF, WEBP)
            Audio covers (WAV, FLAC, MP3, OGG, AIFF)
  Payload: Any file, text, image, or audio
  Output: Always lossless (PNG for images, FLAC for audio)

Examples:
  stego detect suspicious.png
  stego embed -c photo.jpg -p secret.zip -o stego_out.png -pass "HideMe!99"
  stego extract -f stego_out.png -pass "HideMe!99" -o recovered.zip
""",
    "url": """
{cyan}URL & DOMAIN AUDITING MODULE HELP{reset}

Checks performed:
  - Phishing indicators (visual spoofing, suspicious patterns)
  - Pharming detection (DNS poisoning signatures)
  - Homograph attacks (Unicode/IDN lookalike detection)
  - Typosquatting analysis (edit distance, common typos)
  - SSL/TLS certificate validation and analysis
  - WHOIS registration forensics
  - DNS record analysis (A, MX, TXT, SPF, DMARC, NS)
  - Domain age and reputation scoring
  - Redirect chain analysis
  - Blacklist/threat intelligence lookups

Examples:
  url audit suspicious-paypa1.com -d deep
  url homograph раypal.com
  url ssl bankofamerica.com
""",
    "pass": """
{cyan}PASSWORD & HASH MODULE HELP{reset}

Password audit checks:
  - Entropy calculation (bits of randomness)
  - Strength scoring (0-4 scale via zxcvbn)
  - Pattern detection (keyboard walks, dates, common words)
  - Crack time estimation (online/offline scenarios)
  - Dictionary match detection
  - Compliance checking (NIST, common policy requirements)

Hash identification supports 300+ hash types including:
  MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2, NTLM, LM, WPA, etc.

Examples:
  pass audit "MyP@ssw0rd!" --verbose
  pass hash 5f4dcc3b5aa765d61d8327deb882cf99
  pass batch -f wordlist.txt --json -o results.json
  pass generate -l 24 -s high
""",
    "scan": """
{cyan}NETWORK SCANNER MODULE HELP{reset}

Performs TCP/UDP port scanning, service fingerprinting, banner grabbing,
OS fingerprinting via TTL analysis, and automated vulnerability assessment.

Options:
  -d quick|standard|deep   Scan depth (default: standard)
  -p <ports>               Custom ports: 22,80,443 or 1-1000
  --udp                    Also scan UDP ports
  --verbose                Show extra details
  --json                   JSON output
  -o <file>                Save to file

Examples:
  scan 192.168.1.1 -d standard
  scan example.com -p 22,80,443,8080,3306 --verbose
  scan 10.0.0.1 -d deep --json -o results.json
""",
    "sub": """
{cyan}SUBDOMAIN ENUMERATION MODULE HELP{reset}

Discovers subdomains using multiple passive and active methods:
  - Certificate Transparency (crt.sh) — passive, no packets to target
  - HackerTarget passive DNS — passive
  - DNS brute-force (built-in 500-word list) — active

Options:
  --bruteforce             Include DNS brute-force (default: enabled)
  --passive-only           Certificate transparency + passive DNS only
  --json                   JSON output
  -o <file>                Save results to file

Examples:
  sub example.com
  sub example.com --passive-only
  sub example.com --bruteforce -o subs.json
""",
    "cve": """
{cyan}CVE LOOKUP MODULE HELP{reset}

Queries NIST NVD (National Vulnerability Database) in real-time.
No API key required for basic queries (rate-limited).

Usage:
  cve <software> [version]      Search CVEs by software name
  cve <CVE-ID>                  Look up specific CVE

Examples:
  cve apache 2.4.49
  cve openssl 1.0.2
  cve CVE-2021-44228
  cve wordpress
""",
    "breach": """
{cyan}BREACH INTELLIGENCE MODULE HELP{reset}

Checks against known breach databases. Password checking uses
k-Anonymity — the full password is NEVER transmitted.

Subcommands:
  breach password <value>   Check if password appears in breaches
  breach email <address>    Check if email is in breach data (needs HIBP key)
  breach domain <domain>    Find breaches involving a domain

API Key: Add 'hibp' to ~/.ixoryn/config.json for email/domain lookups.
Get free key at: haveibeenpwned.com/API/Key

Examples:
  breach password "MySecretPassword"
  breach email john@example.com
  breach domain example.com
""",
    "encode": """
{cyan}ENCODE/DECODE MODULE HELP{reset}

Quick encoding and decoding utilities.

encode <method> <data>    Encode data
decode <method> <data>    Decode data

Methods: base64, hex, url, binary, rot13, md5, sha1, sha256

Examples:
  encode base64 Hello World
  decode base64 SGVsbG8gV29ybGQ=
  encode hex "secret"
  encode md5 "password"
"""
}


class ExpertShell:
    def __init__(self):
        self.prompt = f"{Colors.CYAN}ixoryn{Colors.RESET}{Colors.DIM}>{Colors.RESET} "
        self.history = []
        self.running = True

    def run(self):
        Banner.section("Expert Mode — Command Shell")
        cprint("  Type 'help' for commands, 'exit' to quit.\n", Colors.DIM)

        try:
            import readline
            readline.set_completer(self._completer)
            readline.parse_and_bind("tab: complete")
        except ImportError:
            pass

        while self.running:
            try:
                raw = input(self.prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                cprint("\n  [*] Exiting Expert Mode.\n", Colors.YELLOW)
                return

            if not raw:
                continue

            self.history.append(raw)
            self._dispatch(raw)

    def _completer(self, text, state):
        commands = [
            "help", "exit", "quit", "clear", "banner", "doctor",
            "crypto encrypt", "crypto decrypt", "crypto hash", "crypto sign",
            "crypto verify", "crypto keygen", "crypto algorithms",
            "stego detect", "stego embed", "stego extract", "stego info",
            "url audit", "url phishing", "url homograph", "url typosquat",
            "url ssl", "url whois", "url dns",
            "pass audit", "pass hash", "pass batch", "pass generate",
        ]
        matches = [c for c in commands if c.startswith(text)]
        return matches[state] if state < len(matches) else None

    def _dispatch(self, raw: str):
        try:
            parts = shlex.split(raw)
        except ValueError as e:
            Banner.error(f"Parse error: {e}")
            return

        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        handlers = {
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "clear": self._cmd_clear,
            "banner": lambda _: Banner.print_banner(),
            "doctor": self._cmd_doctor,
            "crypto": self._cmd_crypto,
            "stego": self._cmd_stego,
            "url": self._cmd_url,
            "pass": self._cmd_pass,
            "history": self._cmd_history,
            "ti": self._cmd_threat_intel,
            "intel": self._cmd_threat_intel,
            "report": self._cmd_report,
            "test": self._cmd_test,
            "scan": self._cmd_scan,
            "net": self._cmd_scan,
            "sub": self._cmd_subdomain,
            "subdomain": self._cmd_subdomain,
            "cve": self._cmd_cve,
            "breach": self._cmd_breach,
            "pwned": self._cmd_breach,
            "encode": self._cmd_encode,
            "decode": self._cmd_decode,
            "version": self._cmd_version,
            "crack": self._cmd_crack,
            "hashcat": self._cmd_crack,
            "wordlist": self._cmd_wordlist,
            "wl": self._cmd_wordlist,
        }

        if cmd in handlers:
            try:
                handlers[cmd](args)
            except KeyboardInterrupt:
                cprint("\n  [*] Command interrupted.", Colors.YELLOW)
            except Exception as e:
                Banner.error(f"Command error: {e}", str(e))
        else:
            Banner.error(f"Unknown command: '{cmd}'. Type 'help' for available commands.")

    # ─── BUILT-IN COMMANDS ───────────────────────────────────────────
    def _cmd_exit(self, args):
        cprint("\n  [*] Exiting Expert Mode.\n", Colors.YELLOW)
        self.running = False

    def _cmd_clear(self, args):
        os.system("cls" if os.name == "nt" else "clear")

    def _cmd_history(self, args):
        Banner.section("Command History")
        for i, cmd in enumerate(self.history, 1):
            print(f"  {Colors.DIM}{i:3}.{Colors.RESET} {cmd}")

    def _cmd_doctor(self, args):
        from ixoryn.ui.doctor import IxorynDoctor
        doctor = IxorynDoctor()
        doctor.run()

    def _cmd_help(self, args):
        if args and args[0] in MODULE_HELPS:
            txt = MODULE_HELPS[args[0]].format(cyan=Colors.CYAN, reset=Colors.RESET)
            print(txt)
        else:
            print(HELP_TEXT)

    # ─── CRYPTO COMMANDS ─────────────────────────────────────────────
    def _cmd_crypto(self, args):
        from ixoryn.modules.crypto.engine import CryptoEngine
        from ixoryn.modules.password.auditor import PasswordAuditor

        if not args:
            print(MODULE_HELPS["crypto"].format(cyan=Colors.CYAN, reset=Colors.RESET))
            return

        sub = args[0].lower()
        rest = args[1:]
        engine = CryptoEngine()
        parsed = self._parse_flags(rest)

        if sub == "encrypt":
            target = parsed.get("_positional", [])
            password = parsed.get("p") or parsed.get("password")
            if not target:
                Banner.error("Usage: crypto encrypt <file_or_text> -p <password>")
                return
            target = " ".join(target)
            if not password:
                import getpass
                password = getpass.getpass("  Password: ")

            # Audit password
            auditor = PasswordAuditor()
            rpt = auditor.audit_password(password)
            self._show_mini_password_audit(rpt)

            if os.path.isfile(target):
                with open(target, "rb") as f:
                    data = f.read()
                fname = os.path.basename(target)
                result = engine.encrypt(data, password, filename=fname)
                out = parsed.get("o") or target + ".ixenc"
                with open(out, "wb") as f:
                    f.write(result)
                Banner.success(f"Encrypted → {out}")
            else:
                result = engine.encrypt(target.encode(), password)
                import base64
                Banner.success("Encrypted:")
                print(f"  {base64.b64encode(result).decode()}")

        elif sub == "decrypt":
            target = " ".join(parsed.get("_positional", []))
            password = parsed.get("p") or parsed.get("password")
            if not target:
                Banner.error("Usage: crypto decrypt <file_or_base64> -p <password>")
                return
            if not password:
                import getpass
                password = getpass.getpass("  Password: ")

            if os.path.isfile(target):
                with open(target, "rb") as f:
                    data = f.read()
                plaintext, fname = engine.decrypt(data, password)
                out = parsed.get("o") or target.replace(".ixenc", ".decrypted")
                if fname:
                    out = parsed.get("o") or fname
                with open(out, "wb") as f:
                    f.write(plaintext)
                Banner.success(f"Decrypted → {out}")
            else:
                import base64
                data = base64.b64decode(target)
                plaintext, _ = engine.decrypt(data, password)
                Banner.success("Decrypted:")
                print(f"  {plaintext.decode('utf-8', errors='replace')}")

        elif sub == "hash":
            target = " ".join(parsed.get("_positional", []))
            alg = parsed.get("a") or parsed.get("algorithm", "SHA-256")
            if not target:
                Banner.error("Usage: crypto hash <file_or_text> -a <algorithm>")
                return
            if os.path.isfile(target):
                with open(target, "rb") as f:
                    data = f.read()
            else:
                data = target.encode()
            result = engine.hash_data(data, alg)
            Banner.success(f"{alg}: {result}")

        elif sub == "keygen":
            name = parsed.get("n") or parsed.get("name", "ixoryn_key")
            password = parsed.get("p") or parsed.get("password")
            if not password:
                import getpass
                password = getpass.getpass("  Key password: ")
            priv, pub = engine.generate_keypair(password)
            priv_path = parsed.get("o") or f"{name}.ixkey"
            pub_path = priv_path.replace(".ixkey", ".ixpub")
            with open(priv_path, "wb") as f:
                f.write(priv)
            with open(pub_path, "wb") as f:
                f.write(pub)
            Banner.success(f"Private key → {priv_path}")
            Banner.success(f"Public key  → {pub_path}")

        elif sub == "sign":
            target = " ".join(parsed.get("_positional", []))
            keyfile = parsed.get("k") or parsed.get("key")
            password = parsed.get("p") or parsed.get("password")
            if not target or not keyfile:
                Banner.error("Usage: crypto sign <file> -k <keyfile> -p <password>")
                return
            if not password:
                import getpass
                password = getpass.getpass("  Key password: ")
            if os.path.isfile(target):
                with open(target, "rb") as f:
                    data = f.read()
            else:
                data = target.encode()
            with open(keyfile, "rb") as f:
                key_data = f.read()
            sig = engine.sign(data, key_data, password)
            import base64
            sig_b64 = base64.b64encode(sig).decode()
            out = parsed.get("o") or target + ".ixsig"
            with open(out, "w") as f:
                f.write(sig_b64)
            Banner.success(f"Signature → {out}")

        elif sub == "verify":
            target = " ".join(parsed.get("_positional", []))
            sig_path = parsed.get("s") or parsed.get("sig")
            pub_path = parsed.get("k") or parsed.get("key")
            if not target or not sig_path or not pub_path:
                Banner.error("Usage: crypto verify <file> -s <sig_file> -k <pubkey>")
                return
            if os.path.isfile(target):
                with open(target, "rb") as f:
                    data = f.read()
            else:
                data = target.encode()
            with open(sig_path, "r") as f:
                import base64
                sig = base64.b64decode(f.read().strip())
            with open(pub_path, "rb") as f:
                pub_key = f.read()
            valid = engine.verify(data, sig, pub_key)
            if valid:
                Banner.success("SIGNATURE VALID — Data is authentic.")
            else:
                Banner.error("SIGNATURE INVALID — Data may be tampered.")

        elif sub == "algorithms":
            Banner.section("Supported Algorithms")
            print(f"  {Colors.CYAN}Hashing:{Colors.RESET} SHA-256, SHA-3-256, SHA-3-512, BLAKE2b, BLAKE2s, SHA-512")
            print(f"  {Colors.CYAN}Encryption:{Colors.RESET} AES-256-GCM (key via Argon2id)")
            print(f"  {Colors.CYAN}Signatures:{Colors.RESET} Ed25519")
            print(f"  {Colors.CYAN}KDF:{Colors.RESET} Argon2id (time=3, mem=64MB, parallel=4)")
        else:
            Banner.error(f"Unknown crypto command: '{sub}'. Type 'help crypto'.")

    # ─── STEGO COMMANDS ───────────────────────────────────────────────
    def _cmd_stego(self, args):
        if not args:
            print(MODULE_HELPS["stego"].format(cyan=Colors.CYAN, reset=Colors.RESET))
            return

        sub = args[0].lower()
        rest = args[1:]
        parsed = self._parse_flags(rest)

        if sub == "detect":
            target = parsed.get("_positional", [])
            if not target:
                target = [parsed.get("f", "")]
            filepath = " ".join(target) if isinstance(target, list) else target
            if not filepath or not os.path.isfile(filepath):
                Banner.error("Usage: stego detect <file>")
                return
            from ixoryn.modules.stego.detector import StegoDetector
            detector = StegoDetector()
            report = detector.analyze(filepath)
            if "--json" in rest:
                import json
                print(json.dumps(report, indent=2, default=str))
            else:
                detector.print_report(report)

        elif sub == "embed":
            cover = parsed.get("c") or parsed.get("cover")
            payload = parsed.get("p") or parsed.get("payload")
            out = parsed.get("o") or parsed.get("out", "stego_output.png")
            password = parsed.get("pass") or parsed.get("password")

            if not cover or not payload:
                Banner.error("Usage: stego embed -c <cover> -p <payload> -o <output> [-pass <password>]")
                return
            if not os.path.isfile(cover):
                Banner.error(f"Cover file not found: {cover}")
                return
            if not os.path.isfile(payload):
                Banner.error(f"Payload file not found: {payload}")
                return

            with open(payload, "rb") as f:
                payload_data = f.read()
            payload_name = os.path.basename(payload)

            from ixoryn.modules.stego.embed import StegoEmbed
            embedder = StegoEmbed()
            result_path = embedder.embed(cover, payload_data, payload_name, out, password=password)
            Banner.success(f"Embedded → {result_path}")

        elif sub == "extract":
            filepath = parsed.get("f") or " ".join(parsed.get("_positional", []))
            out = parsed.get("o") or parsed.get("output", "extracted_payload")
            password = parsed.get("pass") or parsed.get("password")

            if not filepath or not os.path.isfile(filepath):
                Banner.error("Usage: stego extract -f <stego_file> -o <output> [-pass <password>]")
                return

            from ixoryn.modules.stego.extract import StegoExtract
            extractor = StegoExtract()
            payload_data, payload_name = extractor.extract(filepath, password)
            out_path = out if out.endswith(payload_name.split(".")[-1]) else out + "_" + payload_name
            with open(out_path, "wb") as f:
                f.write(payload_data)
            Banner.success(f"Extracted '{payload_name}' → {out_path}")

        elif sub == "info":
            target = " ".join(parsed.get("_positional", []))
            if not target or not os.path.isfile(target):
                Banner.error("Usage: stego info <file>")
                return
            from ixoryn.modules.stego.detector import StegoDetector
            detector = StegoDetector()
            meta = detector.get_metadata(target)
            Banner.section(f"File Info: {target}")
            for k, v in meta.items():
                Banner.result(k, str(v))
        else:
            Banner.error(f"Unknown stego command: '{sub}'. Type 'help stego'.")

    # ─── URL COMMANDS ─────────────────────────────────────────────────
    def _cmd_url(self, args):
        if not args:
            print(MODULE_HELPS["url"].format(cyan=Colors.CYAN, reset=Colors.RESET))
            return

        from ixoryn.modules.url_audit.auditor import URLAuditor
        sub = args[0].lower()
        rest = args[1:]
        parsed = self._parse_flags(rest)
        targets = parsed.get("_positional", [])
        auditor = URLAuditor()

        if sub == "audit":
            if not targets:
                Banner.error("Usage: url audit <target> [<target2>...] [-d quick|standard|deep]")
                return
            depth = parsed.get("d", "standard")
            for t in targets:
                Banner.subsection(f"Auditing: {t}")
                report = auditor.audit(t, depth=depth)
                if "--json" in rest:
                    import json
                    print(json.dumps(report, indent=2, default=str))
                else:
                    auditor.print_report(report)

        elif sub in ("phishing", "homograph", "typosquat"):
            if not targets:
                Banner.error(f"Usage: url {sub} <target>")
                return
            for t in targets:
                report = auditor.audit(t, depth="deep")
                key_map = {
                    "phishing": "phishing_score",
                    "homograph": "homograph",
                    "typosquat": "typosquatting",
                }
                Banner.section(f"{sub.title()} Analysis: {t}")
                relevant = report.get(key_map.get(sub, sub), {})
                if isinstance(relevant, dict):
                    for k, v in relevant.items():
                        Banner.result(k, str(v))
                else:
                    print(f"  {relevant}")

        elif sub == "ssl":
            if not targets:
                Banner.error("Usage: url ssl <domain>")
                return
            for t in targets:
                ssl_info = auditor.analyze_ssl(t)
                Banner.section(f"SSL/TLS Analysis: {t}")
                for k, v in ssl_info.items():
                    Banner.result(k, str(v))

        elif sub == "whois":
            if not targets:
                Banner.error("Usage: url whois <domain>")
                return
            for t in targets:
                whois_info = auditor.whois_lookup(t)
                Banner.section(f"WHOIS: {t}")
                for k, v in whois_info.items():
                    Banner.result(k, str(v))

        elif sub == "dns":
            if not targets:
                Banner.error("Usage: url dns <domain>")
                return
            for t in targets:
                dns_info = auditor.dns_lookup(t)
                Banner.section(f"DNS Records: {t}")
                for k, v in dns_info.items():
                    Banner.result(k, str(v))
        else:
            Banner.error(f"Unknown url command: '{sub}'. Type 'help url'.")

    # ─── PASS COMMANDS ────────────────────────────────────────────────
    def _cmd_pass(self, args):
        if not args:
            print(MODULE_HELPS["pass"].format(cyan=Colors.CYAN, reset=Colors.RESET))
            return

        from ixoryn.modules.password.auditor import PasswordAuditor
        sub = args[0].lower()
        rest = args[1:]
        parsed = self._parse_flags(rest)
        targets = parsed.get("_positional", [])
        auditor = PasswordAuditor()

        if sub == "audit":
            if not targets:
                Banner.error("Usage: pass audit <password> [<password2>...]")
                return
            for pwd in targets:
                report = auditor.audit_password(pwd)
                if "--json" in rest:
                    import json
                    print(json.dumps(report, indent=2, default=str))
                else:
                    auditor.print_password_report(report, verbose="--verbose" in rest)

        elif sub == "hash":
            f = parsed.get("f") or parsed.get("file")
            if f:
                with open(f, "r", errors="replace") as fh:
                    lines = [l.strip() for l in fh if l.strip()]
                for h in lines:
                    report = auditor.audit_hash(h)
                    if "--json" in rest:
                        import json
                        print(json.dumps(report, indent=2, default=str))
                    else:
                        auditor.print_hash_report(report)
            elif targets:
                for h in targets:
                    report = auditor.audit_hash(h)
                    if "--json" in rest:
                        import json
                        print(json.dumps(report, indent=2, default=str))
                    else:
                        auditor.print_hash_report(report)
            else:
                Banner.error("Usage: pass hash <hash> or pass hash -f <file>")

        elif sub == "batch":
            f = parsed.get("f") or parsed.get("file")
            if not f:
                Banner.error("Usage: pass batch -f <file>")
                return
            with open(f, "r", errors="replace") as fh:
                lines = [l.strip() for l in fh if l.strip()]
            Banner.info(f"Auditing {len(lines)} entries...")
            results = []
            for entry in lines:
                report = auditor.audit_auto(entry)
                results.append(report)
                if "--json" not in rest:
                    if report.get("type") == "hash":
                        auditor.print_hash_report(report)
                    else:
                        auditor.print_password_report(report)

            if "--json" in rest:
                import json
                out = parsed.get("o")
                output = json.dumps(results, indent=2, default=str)
                if out:
                    with open(out, "w") as fh:
                        fh.write(output)
                    Banner.success(f"Results saved to: {out}")
                else:
                    print(output)

        elif sub == "generate":
            length = int(parsed.get("l") or parsed.get("length", 20))
            strength = parsed.get("s") or parsed.get("strength", "high")
            from ixoryn.modules.password.generator import PasswordGenerator
            gen = PasswordGenerator()
            pwd = gen.generate(length=length, strength=strength)
            report = auditor.audit_password(pwd)
            Banner.success(f"Generated password: {Colors.YELLOW}{pwd}{Colors.RESET}")
            Banner.result("Strength", report.get("strength", "?"))
            Banner.result("Entropy", f"{report.get('entropy', 0):.1f} bits")
        else:
            Banner.error(f"Unknown pass command: '{sub}'. Type 'help pass'.")

    # ─── HELPERS ──────────────────────────────────────────────────────
    def _parse_flags(self, args: List[str]) -> Dict:
        """Parse -flag value style arguments."""
        result = {"_positional": []}
        i = 0
        while i < len(args):
            a = args[i]
            if a.startswith("--"):
                key = a[2:]
                # Support --key value pairs (e.g. --output file.json)
                if i + 1 < len(args) and not args[i + 1].startswith("-"):
                    result[key] = args[i + 1]
                    i += 1
                else:
                    result[key] = True
            elif a.startswith("-") and len(a) > 1:
                key = a[1:]
                if i + 1 < len(args) and not args[i + 1].startswith("-"):
                    result[key] = args[i + 1]
                    i += 1
                else:
                    result[key] = True
            else:
                result["_positional"].append(a)
            i += 1
        return result

    def _parse_args(self, args: List[str]) -> Dict:
        """
        Extended argument parser used by world-class commands (scan, sub, cve, etc.).
        Handles both -flag and --flag styles, with value capture for both.
        Identical in structure to _parse_flags but explicitly supports --flag value pairs.
        """
        return self._parse_flags(args)

    def _show_mini_password_audit(self, report: dict):
        strength = report.get("strength", "?")
        score = report.get("score", 0)
        color = Colors.GREEN if score >= 3 else Colors.YELLOW if score >= 2 else Colors.RED
        print(f"  {Colors.DIM}[Password Audit] Strength: {color}{strength}{Colors.RESET}"
              f" | Entropy: {report.get('entropy', 0):.1f} bits"
              f" | Crack time: {report.get('crack_time_display', '?')}")

    def _cmd_threat_intel(self, args):
        """ti <target> [--json] [-o <file>]"""
        if not args:
            cprint("  Usage: ti <target_url_or_domain>  [--json] [-o <output_file>]", Colors.YELLOW)
            cprint("  Examples:", Colors.DIM)
            cprint("    ti suspicious-domain.tk", Colors.DIM)
            cprint("    ti http://phishing-example.com --json -o results.json", Colors.DIM)
            return

        parsed = self._parse_flags(args)
        target = " ".join(parsed.get("_positional", []))
        if not target:
            Banner.error("No target provided.")
            return

        from ixoryn.modules.url_audit.threat_intel import ThreatIntelligence
        Banner.info(f"Running threat intelligence on: {target}")
        ti = ThreatIntelligence()
        results = ti.full_check(target)

        if "--json" in args:
            import json
            output = json.dumps(results, indent=2, default=str)
            out_file = parsed.get("o")
            if out_file:
                with open(out_file, "w") as f:
                    f.write(output)
                Banner.success(f"Results saved to: {out_file}")
            else:
                print(output)
        else:
            ti.print_results(results)

        # Offer HTML/PDF report
        report_fmt = parsed.get("report") or parsed.get("r")
        if report_fmt:
            from ixoryn.utils.report_generator import ReportGenerator
            rgen = ReportGenerator()
            if report_fmt == "pdf":
                path = rgen.generate_pdf(results, "threat_intel")
            else:
                path = rgen.generate_html(results, "threat_intel")
            Banner.success(f"Report saved: {path}")

    def _cmd_report(self, args):
        """Generate HTML or PDF report from last audit data."""
        parsed = self._parse_flags(args)
        positional = parsed.get("_positional", [])

        if not positional:
            cprint("  Usage: report <html|pdf> <audit_type> <json_file>", Colors.YELLOW)
            cprint("  Example: report html url /tmp/audit.json", Colors.DIM)
            return

        fmt = positional[0] if positional else "html"
        audit_type = positional[1] if len(positional) > 1 else "url"
        json_file = positional[2] if len(positional) > 2 else parsed.get("f")

        if not json_file:
            Banner.error("Provide a JSON report file: report html url audit.json")
            return

        import json
        with open(json_file) as f:
            data = json.load(f)

        from ixoryn.utils.report_generator import ReportGenerator
        rgen = ReportGenerator()
        out = parsed.get("o")

        if fmt == "pdf":
            path = rgen.generate_pdf(data, audit_type, out)
        else:
            path = rgen.generate_html(data, audit_type, out)

        Banner.success(f"Report saved to: {path}")

    def _cmd_test(self, args):
        """Run Ixoryn test suite."""
        Banner.info("Running Ixoryn test suite...")
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "tests/test_suite.py"],
            capture_output=False,
        )
        if result.returncode == 0:
            Banner.success("All tests passed.")
        else:
            Banner.error("Some tests failed. Check output above.")

    # ─── NEW WORLD-CLASS COMMANDS ─────────────────────────────────────

    def _cmd_scan(self, args):
        """Network port scanner with service detection and vulnerability analysis."""
        if not args:
            cprint("  Usage: scan <target> [-p <ports>] [-d quick|standard|deep] [--udp] [--verbose] [-o <file>]", Colors.DIM)
            cprint("  Example: scan 192.168.1.1 -d standard", Colors.DIM)
            cprint("  Example: scan example.com -p 22,80,443,8080 --verbose", Colors.DIM)
            return

        parsed = self._parse_args(args)
        positional = parsed.get("_positional", [])
        if not positional:
            Banner.error("Provide a target: scan <target>")
            return

        target = positional[0]
        depth = parsed.get("d", "standard")
        ports = parsed.get("p")
        udp = "--udp" in args
        verbose = "--verbose" in args or "-v" in args
        output = parsed.get("o")
        json_out = "--json" in args

        try:
            from ixoryn.modules.network import NetworkScanner
            scanner = NetworkScanner(timeout=2.0)
            Banner.info(f"Scanning {target} [{depth} depth]...")
            if depth == "deep":
                cprint("  [!] Deep scan (all 65535 ports) may take several minutes.", Colors.YELLOW)

            report = scanner.scan(target, ports=ports, depth=depth, udp=udp)

            if json_out:
                import json
                output_str = json.dumps(report, indent=2)
                if output:
                    with open(output, "w") as f:
                        f.write(output_str)
                    Banner.success(f"Results saved to: {output}")
                else:
                    print(output_str)
            else:
                print(scanner.format_report(report, verbose=verbose))
                if output:
                    import json
                    with open(output, "w") as f:
                        json.dump(report, f, indent=2)
                    Banner.success(f"Raw JSON saved to: {output}")

        except Exception as e:
            Banner.error(f"Scan failed: {e}")

    def _cmd_subdomain(self, args):
        """Subdomain enumeration via cert transparency, passive DNS, and brute-force."""
        if not args:
            cprint("  Usage: sub <domain> [--bruteforce] [--passive-only] [-o <file>]", Colors.DIM)
            cprint("  Example: sub example.com", Colors.DIM)
            cprint("  Example: sub example.com --bruteforce -o subs.json", Colors.DIM)
            return

        parsed = self._parse_args(args)
        positional = parsed.get("_positional", [])
        if not positional:
            Banner.error("Provide a domain: sub <domain>")
            return

        domain = positional[0].lower().strip()
        output = parsed.get("o")
        json_out = "--json" in args
        passive_only = "--passive-only" in args
        bruteforce = "--bruteforce" in args or not passive_only

        methods = ["certsh", "hackertarget"]
        if bruteforce:
            methods.append("bruteforce")

        try:
            from ixoryn.modules.network import SubdomainEnumerator
            enumerator = SubdomainEnumerator()
            Banner.info(f"Enumerating subdomains for: {domain}")
            cprint(f"  Methods: {', '.join(methods)}", Colors.DIM)

            result = enumerator.enumerate(domain, methods=methods)

            if json_out or output:
                import json
                data = json.dumps(result, indent=2)
                if output:
                    with open(output, "w") as f:
                        f.write(data)
                    Banner.success(f"Results saved to: {output}")
                if json_out:
                    print(data)
            else:
                print(enumerator.format_results(result))
                if output:
                    import json
                    with open(output, "w") as f:
                        json.dump(result, f, indent=2)
                    Banner.success(f"Results saved to: {output}")

        except Exception as e:
            Banner.error(f"Subdomain enumeration failed: {e}")

    def _cmd_cve(self, args):
        """Query NIST NVD for CVEs related to software or a specific CVE ID."""
        if not args:
            cprint("  Usage: cve <software> [version] [-n <max_results>]", Colors.DIM)
            cprint("         cve CVE-2021-44228", Colors.DIM)
            cprint("  Example: cve apache 2.4.49", Colors.DIM)
            cprint("  Example: cve openssl 1.0.2", Colors.DIM)
            cprint("  Example: cve CVE-2022-0847", Colors.DIM)
            return

        parsed = self._parse_args(args)
        positional = parsed.get("_positional", [])
        if not positional:
            Banner.error("Provide software name or CVE ID")
            return

        query = positional[0]
        version = positional[1] if len(positional) > 1 else None
        max_results = int(parsed.get("n", 5))

        try:
            from ixoryn.modules.network import CVELookup
            lookup = CVELookup()

            # Check if it's a CVE ID lookup
            if query.upper().startswith("CVE-"):
                Banner.info(f"Looking up {query.upper()} on NVD...")
                result = lookup.lookup_cve(query.upper())
                from ixoryn.ui.banner import Colors as C
                if result.get("error"):
                    Banner.error(result["error"])
                else:
                    print(f"\n  {C.BOLD}{result['cve_id']}{C.RESET}")
                    print(f"  CVSS Score: {result.get('cvss_score')} ({result.get('severity')})")
                    print(f"  Published:  {result.get('published')}")
                    print(f"  {result.get('description', '')[:300]}")
                    print(f"\n  {C.CYAN}{result.get('nvd_url')}{C.RESET}")
                    for ref in result.get("references", [])[:3]:
                        print(f"  Reference: {ref}")
            else:
                Banner.info(f"Searching NVD for: {query} {version or ''}")
                result = lookup.lookup_software(query, version, max_results)
                print(lookup.format_results(result))

        except Exception as e:
            Banner.error(f"CVE lookup failed: {e}")

    def _cmd_breach(self, args):
        """Check if a password or email has appeared in known data breaches."""
        if not args:
            cprint("  Usage: breach password <value>    # Check password (k-Anonymity)", Colors.DIM)
            cprint("         breach email <address>     # Check email (requires HIBP key)", Colors.DIM)
            cprint("         breach domain <domain>     # Check domain breaches", Colors.DIM)
            cprint("  Example: breach password MyPassword123", Colors.DIM)
            cprint("  Example: breach email user@example.com", Colors.DIM)
            return

        if len(args) < 2:
            Banner.error("Provide subcommand and value: breach password <value>")
            return

        subcommand = args[0].lower()
        value = args[1]

        try:
            from ixoryn.modules.network import BreachIntelligence
            from ixoryn.core.bootstrap import Bootstrap

            # Load API key
            config = Bootstrap.load_config()
            hibp_key = (config.get("api_keys", {}).get("hibp") or
                       __import__("os").environ.get("HIBP_API_KEY"))

            intel = BreachIntelligence(hibp_api_key=hibp_key)

            if subcommand in ("password", "pass", "pwd"):
                Banner.info(f"Checking password against {'{:,}'.format(613_584_246)} known pwned passwords...")
                cprint("  [*] Using k-Anonymity — password is NEVER transmitted.", Colors.DIM)
                result = intel.check_password_pwned(value)
                print(intel.format_password_check(result))

            elif subcommand in ("email", "e"):
                Banner.info(f"Checking {value} against breach databases...")
                result = intel.check_email_breached(value)
                print(intel.format_email_check(result))

            elif subcommand in ("domain", "d"):
                Banner.info(f"Checking breaches for domain: {value}")
                result = intel.check_domain_breaches(value)
                if result.get("error"):
                    Banner.error(result["error"])
                else:
                    from ixoryn.ui.banner import Colors as C
                    print(f"\n  Domain: {value}")
                    print(f"  Breaches involving this domain: {len(result['breaches'])}")
                    print(f"  Total accounts exposed: {result['total_accounts_exposed']:,}")
                    if result.get("data_types_found"):
                        print(f"  Data types exposed: {', '.join(result['data_types_found'][:8])}")
                    for b in result["breaches"][:5]:
                        print(f"\n  [{b['breach_date']}] {b['name']} — {b['pwn_count']:,} accounts")
            else:
                Banner.error(f"Unknown subcommand: {subcommand}. Use: password, email, domain")

        except Exception as e:
            Banner.error(f"Breach check failed: {e}")

    def _cmd_encode(self, args):
        """Encode/decode data: base64, hex, URL, binary, ROT13, morse."""
        if not args:
            cprint("  Usage: encode <method> <data>", Colors.DIM)
            cprint("  Methods: base64, hex, url, binary, rot13, morse", Colors.DIM)
            cprint("  Example: encode base64 Hello World", Colors.DIM)
            cprint("  Example: encode hex 'secret data'", Colors.DIM)
            return

        method = args[0].lower()
        data = " ".join(args[1:]) if len(args) > 1 else ""

        if not data:
            Banner.error("Provide data to encode")
            return

        try:
            import base64
            import urllib.parse

            result = None
            if method in ("base64", "b64"):
                result = base64.b64encode(data.encode()).decode()
            elif method == "hex":
                result = data.encode().hex()
            elif method in ("url", "urlencode"):
                result = urllib.parse.quote(data)
            elif method == "binary":
                result = " ".join(format(ord(c), "08b") for c in data)
            elif method == "rot13":
                import codecs
                result = codecs.encode(data, "rot_13")
            elif method == "md5":
                import hashlib
                result = hashlib.md5(data.encode()).hexdigest()
            elif method == "sha1":
                import hashlib
                result = hashlib.sha1(data.encode()).hexdigest()
            elif method == "sha256":
                import hashlib
                result = hashlib.sha256(data.encode()).hexdigest()
            else:
                Banner.error(f"Unknown encoding: {method}. Options: base64, hex, url, binary, rot13, md5, sha1, sha256")
                return

            from ixoryn.ui.banner import Colors as C
            print(f"\n  {C.CYAN}Input:{C.RESET}    {data}")
            print(f"  {C.CYAN}Method:{C.RESET}   {method}")
            print(f"  {C.GREEN}Result:{C.RESET}   {result}\n")

        except Exception as e:
            Banner.error(f"Encoding failed: {e}")

    def _cmd_decode(self, args):
        """Decode encoded data: base64, hex, URL."""
        if not args:
            cprint("  Usage: decode <method> <data>", Colors.DIM)
            cprint("  Methods: base64, hex, url, binary", Colors.DIM)
            cprint("  Example: decode base64 SGVsbG8gV29ybGQ=", Colors.DIM)
            return

        method = args[0].lower()
        data = " ".join(args[1:]) if len(args) > 1 else ""

        if not data:
            Banner.error("Provide data to decode")
            return

        try:
            import base64
            import urllib.parse

            result = None
            if method in ("base64", "b64"):
                result = base64.b64decode(data.encode()).decode("utf-8", errors="replace")
            elif method == "hex":
                result = bytes.fromhex(data.replace(" ", "")).decode("utf-8", errors="replace")
            elif method in ("url", "urldecode"):
                result = urllib.parse.unquote(data)
            elif method == "binary":
                binary_str = data.replace(" ", "")
                result = "".join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))
            elif method == "rot13":
                import codecs
                result = codecs.decode(data, "rot_13")
            else:
                Banner.error(f"Unknown decoding method: {method}")
                return

            from ixoryn.ui.banner import Colors as C
            print(f"\n  {C.CYAN}Input:{C.RESET}    {data[:80]}")
            print(f"  {C.CYAN}Method:{C.RESET}   {method}")
            print(f"  {C.GREEN}Result:{C.RESET}   {result}\n")

        except Exception as e:
            Banner.error(f"Decoding failed: {e}")

    def _cmd_version(self, args):
        """Display Ixoryn version information and build details."""
        from ixoryn.ui.banner import Colors as C
        print(f"""
{C.CYAN}  ╔══════════════════════════════════════════════════╗
  ║              IXORYN VERSION INFO                 ║
  ╚══════════════════════════════════════════════════╝{C.RESET}

  {C.WHITE}Version:{C.RESET}     1.0
  {C.WHITE}Author:{C.RESET}      Ademoh Mustapha Onimisi
  {C.WHITE}Build:{C.RESET}       Production · MIT License

  {C.WHITE}Modules:{C.RESET}
    ✓ Cryptography         AES-256-GCM + Argon2id + Ed25519
    ✓ Steganography        LSB + ML Ensemble + Randomized Traversal
    ✓ URL Audit            8-source Threat Intelligence
    ✓ Password/Hash        300+ algorithms + zxcvbn + compliance
    ✓ Network Scanner      Port scan + CVE + OS fingerprint
    ✓ Subdomain Enum       Cert transparency + DNS brute-force
    ✓ CVE Lookup           Real-time NVD/NIST integration
    ✓ Breach Intelligence  HIBP + k-Anonymity password check
    ✓ Hash Cracking        Real Hashcat integration (dict/mask/hybrid/smart)
    ✓ Report Generator     HTML + PDF professional reports
    ✓ Expert Shell         Full command interface
    ✓ Cross-Platform       Windows · macOS · Linux (Kali/Ubuntu/Arch)

  {C.WHITE}License:{C.RESET}     MIT
  {C.WHITE}GitHub:{C.RESET}      github.com/ademohmustapha/ixoryn
        """)

    # ─── HASHCAT CRACKING COMMANDS ────────────────────────────────────

    def _cmd_crack(self, args):
        """Real Hashcat hash cracking with smart auto-attack strategy."""
        if not args:
            cprint("  Usage: crack <hash> [-t <type>] [-w <wordlist>] [-m <mode>] [--dict|--mask|--hybrid|--smart]", Colors.DIM)
            cprint("  Examples:", Colors.DIM)
            cprint("    crack 5f4dcc3b5aa765d61d8327deb882cf99                    # Auto-detect + smart attack", Colors.DIM)
            cprint("    crack 5f4dcc3b5aa765d61d8327deb882cf99 -t MD5 --dict      # Dictionary attack", Colors.DIM)
            cprint("    crack 5f4dcc3b5aa765d61d8327deb882cf99 -t MD5 --mask '?d?d?d?d?d?d'", Colors.DIM)
            cprint("    crack 5f4dcc3b5aa765d61d8327deb882cf99 -w /path/to/list.txt", Colors.DIM)
            cprint("    crack --check                                              # Check hashcat status", Colors.DIM)
            cprint("    crack --wordlists                                          # List available wordlists", Colors.DIM)
            cprint("    crack --benchmark 1000                                     # Benchmark NTLM speed", Colors.DIM)
            return

        from ixoryn.modules.password.hashcat_engine import HashcatEngine
        from ixoryn.modules.password.auditor import PasswordAuditor
        from ixoryn.core.platform_compat import WordlistManager

        engine = HashcatEngine()

        parsed = self._parse_args(args)
        positional = parsed.get("_positional", [])

        # -- Special subcommands
        if positional and positional[0] == "--check" or "--check" in args:
            self._crack_status_check(engine)
            return

        if "--wordlists" in args:
            self._crack_list_wordlists()
            return

        if "--benchmark" in args:
            idx = args.index("--benchmark")
            mode = int(args[idx+1]) if idx+1 < len(args) else 1000
            Banner.info(f"Benchmarking hashcat mode {mode}...")
            result = engine.benchmark(mode)
            if result.get("error"):
                Banner.error(result["error"])
            else:
                Banner.success(f"Speed: {result.get('speed', 'N/A')}")
            return

        if "--sessions" in args:
            sessions = engine.list_sessions()
            if not sessions:
                Banner.info("No saved sessions found.")
            else:
                Banner.section("Saved Hashcat Sessions")
                for s in sessions:
                    print(f"  {Colors.CYAN}{s['name']}{Colors.RESET}  {Colors.DIM}{s['modified']}{Colors.RESET}")
                cprint("  Resume with: crack --resume <session_name>", Colors.DIM)
            return

        if "--resume" in args:
            idx = args.index("--resume")
            if idx+1 < len(args):
                session = args[idx+1]
                Banner.info(f"Resuming session: {session}")
                result = engine.resume_session(session, progress_callback=self._crack_progress)
                self._display_crack_result(result)
            else:
                Banner.error("Provide session name: crack --resume <name>")
            return

        # -- Main crack flow
        if not positional:
            Banner.error("Provide a hash to crack.")
            return

        hash_value = positional[0]
        hash_type  = parsed.get("t")
        wordlist   = parsed.get("w")
        hc_mode    = parsed.get("m")
        mask       = parsed.get("mask") or parsed.get("mask_pattern")

        # Check hashcat available
        if not engine.is_available():
            Banner.warn("Hashcat not found on this system.")
            cprint(f"\n  {engine.get_install_instructions()}\n", Colors.YELLOW)
            cprint("  Note: Ixoryn can still identify and analyze hashes without hashcat.", Colors.DIM)
            cprint("  Run:  pass hash <value>  for analysis without cracking.", Colors.DIM)
            return

        # Auto-identify hash type if not specified
        if not hash_type:
            auditor = PasswordAuditor()
            report = auditor.audit_hash(hash_value)
            matches = report.get("matches", [])
            if matches:
                hash_type = matches[0].get("name", "Unknown")
                Banner.info(f"Auto-detected hash type: {Colors.CYAN}{hash_type}{Colors.RESET}")
                Banner.info(f"Hashcat mode: {engine.get_hashcat_mode(hash_type)}")
            else:
                Banner.warn("Could not identify hash type. Use -t <type> to specify.")
                cprint("  Run: pass hash <value>  to see identification details.", Colors.DIM)
                return

        # Resolve mode number
        if hc_mode:
            mode_num = int(hc_mode)
        else:
            mode_num = engine.get_hashcat_mode(hash_type)
            if mode_num is None:
                Banner.error(f"No hashcat mode found for: {hash_type}")
                return
            if mode_num == -1:
                Banner.warn(f"{hash_type} uses a memory-hard key derivation function.")
                cprint("  This hash type is specifically designed to resist GPU cracking.", Colors.DIM)
                cprint("  It is NOT crackable with hashcat — this is correct security behavior.", Colors.DIM)
                return

        # Resolve wordlist
        if not wordlist:
            wl_manager = WordlistManager()
            wordlist = wl_manager.find_wordlist("rockyou")
            if not wordlist:
                Banner.warn("rockyou.txt not found. Using built-in top-1000 wordlist.")
                wordlist = WordlistManager.get_builtin_wordlist()
            else:
                Banner.info(f"Using wordlist: {wordlist}")

        # Attack type
        if "--mask" in args or mask:
            mask_pattern = mask or "?a?a?a?a?a?a?a?a"
            Banner.info(f"Mask attack: {mask_pattern}  |  Mode: {mode_num} ({hash_type})")
            result = engine.crack_mask(hash_value, mode_num, mask_pattern,
                                       progress_callback=self._crack_progress)

        elif "--hybrid" in args:
            Banner.info(f"Hybrid attack (wordlist + mask)  |  Mode: {mode_num}")
            result = engine.crack_hybrid(hash_value, mode_num, wordlist, "?d?d?d?d",
                                          progress_callback=self._crack_progress)

        elif "--dict" in args:
            rules_arg = parsed.get("r")
            Banner.info(f"Dictionary attack  |  Mode: {mode_num}  |  Wordlist: {wordlist}")
            result = engine.crack_dictionary(hash_value, mode_num, wordlist,
                                              rules=[rules_arg] if rules_arg else None,
                                              progress_callback=self._crack_progress)
        else:
            # Default: smart auto-attack
            Banner.info(f"Smart auto-attack  |  Hash: {hash_type}  |  Mode: {mode_num}")
            cprint("  Trying multiple strategies automatically...", Colors.DIM)
            result = engine.crack_smart(hash_value, hash_type, wordlist,
                                         progress_callback=self._crack_progress)

        self._display_crack_result(result)

    def _crack_status_check(self, engine):
        """Display hashcat availability and system info."""
        from ixoryn.core.platform_compat import ToolFinder, WordlistManager, PlatformInfo
        Banner.section("Hashcat & System Status")
        print(f"  Platform:    {PlatformInfo.describe()}")
        print(f"  Python:      {PlatformInfo.PYTHON_VER}")
        print()

        if engine.is_available():
            ver = engine.get_version()
            Banner.success(f"Hashcat found: {engine.hashcat_bin}")
            Banner.success(f"Version: {ver}")
        else:
            Banner.error("Hashcat NOT found")
            cprint(f"\n{engine.get_install_instructions()}\n", Colors.YELLOW)

        print(f"\n  {Colors.CYAN}── System Tools ──────────────────{Colors.RESET}")
        for tool in ToolFinder.system_tools_report():
            if tool["available"]:
                Banner.success(f"{tool['tool']:<15} {tool['path']}")
            else:
                cprint(f"  {Colors.RED}[✗]{Colors.RESET} {tool['tool']:<15} {Colors.DIM}Install: {tool['install_cmd']}{Colors.RESET}")

        print(f"\n  {Colors.CYAN}── Wordlists ─────────────────────{Colors.RESET}")
        for wl in WordlistManager.list_available():
            status = Colors.GREEN + "[✓]" + Colors.RESET if wl["available"] else Colors.DIM + "[ ]" + Colors.RESET
            print(f"  {status} {wl['name']:<25} {wl['entries']} entries  {Colors.DIM}{wl['path']}{Colors.RESET}")

    def _crack_list_wordlists(self):
        """List all available wordlists."""
        from ixoryn.core.platform_compat import WordlistManager
        Banner.section("Available Wordlists")
        for wl in WordlistManager.list_available():
            status = f"{Colors.GREEN}AVAILABLE{Colors.RESET}" if wl["available"] else f"{Colors.DIM}NOT FOUND{Colors.RESET}"
            print(f"  {wl['name']:<25} {status}  {wl['entries']} entries")
            print(f"  {Colors.DIM}  {wl['path']}{Colors.RESET}")
        cprint("\n  Add custom wordlists: crack -w /path/to/wordlist.txt <hash>", Colors.DIM)

    def _crack_progress(self, stage: str, message: str):
        """Progress callback for crack operations."""
        if stage == "output" and message.strip():
            if any(k in message for k in ["Speed.", "Progress", "Status", "Recovered"]):
                print(f"  {Colors.DIM}{message}{Colors.RESET}")
        elif stage.startswith("strategy"):
            cprint(f"\n  [{stage}] {message}", Colors.CYAN)

    def _display_crack_result(self, result: Dict):
        """Display crack result with clear formatting."""
        print()
        if result.get("error") and "not found" in str(result.get("error", "")):
            Banner.error(f"Error: {result['error']}")
            if result.get("install_instructions"):
                cprint(f"\n{result['install_instructions']}\n", Colors.YELLOW)
            return

        if result.get("note"):
            cprint(f"\n  {Colors.YELLOW}ℹ  {result['note']}{Colors.RESET}\n", Colors.YELLOW)
            return

        if result.get("cracked") and result.get("plaintext"):
            print(f"  {Colors.GREEN}{'═'*50}{Colors.RESET}")
            print(f"  {Colors.GREEN}  ✓  HASH CRACKED!{Colors.RESET}")
            print(f"  {Colors.GREEN}{'═'*50}{Colors.RESET}")
            print(f"\n  {Colors.WHITE}Hash:{Colors.RESET}      {result.get('hash', '')[:60]}")
            print(f"  {Colors.WHITE}Plaintext:{Colors.RESET} {Colors.GREEN}{Colors.BOLD}{result['plaintext']}{Colors.RESET}")
            if result.get("attack_used"):
                print(f"  {Colors.WHITE}Method:{Colors.RESET}    {result['attack_used']}")
            if result.get("time_seconds"):
                print(f"  {Colors.WHITE}Time:{Colors.RESET}      {result['time_seconds']}s")
            print()
        elif result.get("error"):
            Banner.error(f"Crack failed: {result['error']}")
        else:
            print(f"  {Colors.YELLOW}{'─'*50}{Colors.RESET}")
            print(f"  {Colors.YELLOW}  ✗  Hash not cracked with current strategy.{Colors.RESET}")
            print(f"  {Colors.YELLOW}{'─'*50}{Colors.RESET}")
            cprint("  Tips:", Colors.DIM)
            cprint("    • Try a larger wordlist: crack <hash> -w /usr/share/wordlists/rockyou.txt", Colors.DIM)
            cprint("    • Try mask attack:        crack <hash> --mask '?a?a?a?a?a?a?a?a'", Colors.DIM)
            cprint("    • Try hybrid attack:      crack <hash> --hybrid", Colors.DIM)
            if result.get("attempts"):
                cprint(f"    • Strategies tried: {len(result['attempts'])}", Colors.DIM)
            print()

    def _cmd_wordlist(self, args):
        """Wordlist management: find, list, create context-based lists."""
        if not args:
            cprint("  Usage: wordlist list                          # Show available wordlists", Colors.DIM)
            cprint("         wordlist create -n <name> <words...>  # Create custom wordlist", Colors.DIM)
            cprint("         wordlist context                       # Build from personal context", Colors.DIM)
            return

        from ixoryn.core.platform_compat import WordlistManager
        from ixoryn.modules.password.hashcat_engine import HashcatEngine

        sub = args[0].lower()

        if sub == "list":
            self._crack_list_wordlists()

        elif sub == "context":
            Banner.section("Context-Based Wordlist Generator")
            cprint("  Build a targeted wordlist from personal info about the target.", Colors.DIM)
            cprint("  (For authorized penetration testing only)\n", Colors.YELLOW)

            name = Banner.prompt("Target name (or blank):")
            username = Banner.prompt("Username (or blank):")
            company = Banner.prompt("Company name (or blank):")
            birth = Banner.prompt("Birthdate (DDMMYYYY or blank):")
            keywords_raw = Banner.prompt("Other keywords (comma-separated or blank):")

            context = {
                "name": name,
                "username": username,
                "company": company,
                "birthdate": birth,
                "keywords": [k.strip() for k in keywords_raw.split(",") if k.strip()],
            }

            engine = HashcatEngine()
            path = engine.create_wordlist_from_context(context)
            word_count = sum(1 for _ in open(path))
            Banner.success(f"Generated {word_count} targeted words → {path}")
            cprint(f"  Use: crack <hash> -w {path}", Colors.DIM)

        elif sub == "create":
            parsed = self._parse_args(args[1:])
            name = parsed.get("n", "custom")
            words = parsed.get("_positional", [])
            if not words:
                Banner.error("Provide words: wordlist create -n mylist word1 word2 word3")
                return
            import tempfile
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                              prefix=f"ixoryn_{name}_",
                                              delete=False)
            for w in words:
                tmp.write(w + "\n")
            tmp.close()
            Banner.success(f"Created wordlist with {len(words)} words: {tmp.name}")
        else:
            Banner.error(f"Unknown subcommand: {sub}")

