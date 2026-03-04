"""
Ixoryn Beginner Mode
Guided menu-driven interface for all four modules.
"""

from ixoryn.ui.banner import Banner, Colors, cprint
from ixoryn.ui.file_picker import pick_file, pick_save_file


class BeginnerMenu:
    def run(self):
        while True:
            Banner.section("Beginner Mode — Main Menu")
            print(f"  {Colors.BOLD}{Colors.CYAN}1.{Colors.RESET} Cryptography")
            print(f"  {Colors.DIM}     Encrypt, decrypt, sign, and verify data with Argon2id + AES-256-GCM{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.CYAN}2.{Colors.RESET} Steganography")
            print(f"  {Colors.DIM}     Hide/reveal data in images/audio or run forensic detection{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.CYAN}3.{Colors.RESET} URL & Domain Auditing")
            print(f"  {Colors.DIM}     Detect phishing, pharming, homograph, typosquatting attacks{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.CYAN}4.{Colors.RESET} Password & Hash Auditing")
            print(f"  {Colors.DIM}     Identify hash types, audit strength, estimate crack time{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.CYAN}5.{Colors.RESET} Network Scanner")
            print(f"  {Colors.DIM}     Port scan, OS fingerprint, banner grab, vulnerability detection{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.CYAN}6.{Colors.RESET} Subdomain Finder")
            print(f"  {Colors.DIM}     Discover subdomains via cert transparency and DNS brute-force{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.CYAN}7.{Colors.RESET} Breach Intelligence")
            print(f"  {Colors.DIM}     Check if passwords/emails appear in data breach databases{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.CYAN}8.{Colors.RESET} File Forensics")
            print(f"  {Colors.DIM}     Hash fingerprinting, metadata, entropy, hidden data detection{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.CYAN}9.{Colors.RESET} CVE Lookup")
            print(f"  {Colors.DIM}     Search NIST NVD for known vulnerabilities in real-time{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.CYAN}10.{Colors.RESET} Hash Cracker")
            print(f"  {Colors.DIM}     Crack MD5, SHA-1, NTLM, bcrypt and 300+ more with Hashcat{Colors.RESET}\n")
            print(f"  {Colors.BOLD}{Colors.RED}0.{Colors.RESET} Back to Main Menu\n")

            choice = Banner.prompt("Select module [1-10/0]:")

            if choice == "0":
                return
            elif choice == "1":
                self._crypto_menu()
            elif choice == "2":
                self._stego_menu()
            elif choice == "3":
                self._url_menu()
            elif choice == "4":
                self._password_menu()
            elif choice == "5":
                self._network_scan_menu()
            elif choice == "6":
                self._subdomain_menu()
            elif choice == "7":
                self._breach_menu()
            elif choice == "8":
                self._file_forensics_menu()
            elif choice == "9":
                self._cve_menu()
            elif choice == "10":
                self._crack_menu()
            else:
                Banner.error("Invalid selection.")

    # ─── CRYPTOGRAPHY ────────────────────────────────────────────────
    def _crypto_menu(self):
        from ixoryn.modules.crypto.engine import CryptoEngine
        engine = CryptoEngine()

        while True:
            Banner.section("Cryptography Module")
            print(f"  {Colors.CYAN}1.{Colors.RESET} Encrypt a file or text")
            print(f"  {Colors.CYAN}2.{Colors.RESET} Decrypt a file or text")
            print(f"  {Colors.CYAN}3.{Colors.RESET} Sign data (Digital Signature)")
            print(f"  {Colors.CYAN}4.{Colors.RESET} Verify signature")
            print(f"  {Colors.CYAN}5.{Colors.RESET} Generate key pair (Ed25519)")
            print(f"  {Colors.CYAN}6.{Colors.RESET} Hash data (SHA-3, BLAKE2b, SHA-256)")
            print(f"  {Colors.RED}0.{Colors.RESET} Back\n")

            choice = Banner.prompt("Select [1-6/0]:")

            if choice == "0":
                return
            elif choice == "1":
                self._crypto_encrypt(engine)
            elif choice == "2":
                self._crypto_decrypt(engine)
            elif choice == "3":
                self._crypto_sign(engine)
            elif choice == "4":
                self._crypto_verify(engine)
            elif choice == "5":
                self._crypto_keygen(engine)
            elif choice == "6":
                self._crypto_hash(engine)
            else:
                Banner.error("Invalid selection.")

    def _crypto_encrypt(self, engine):
        Banner.section("Encrypt Data")
        print(f"  {Colors.CYAN}1.{Colors.RESET} Encrypt text")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Encrypt a file\n")
        mode = Banner.prompt("Select [1/2]:")

        if mode == "1":
            plaintext = Banner.prompt("Enter text to encrypt:")
            if not plaintext:
                Banner.error("No text provided.")
                return
            data = plaintext.encode()
            is_file = False
            filename = None
        elif mode == "2":
            filepath = pick_file("Select file to encrypt")
            if not filepath:
                Banner.warn("No file selected.")
                return
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
            except Exception as e:
                Banner.error("Could not read file.", str(e))
                return
            is_file = True
            import os
            filename = os.path.basename(filepath)
        else:
            Banner.error("Invalid choice.")
            return

        password = self._get_password_with_audit("encryption")
        if not password:
            return

        Banner.info("Encrypting...")
        try:
            result = engine.encrypt(data, password, filename=filename if is_file else None)
            if is_file:
                out_path = pick_save_file("Save encrypted file", ".ixenc")
                if out_path:
                    with open(out_path, "wb") as f:
                        f.write(result)
                    Banner.success(f"File encrypted and saved to: {out_path}")
                else:
                    Banner.warn("Save cancelled.")
            else:
                import base64
                Banner.success("Encryption successful!")
                print(f"\n  {Colors.YELLOW}Encrypted (Base64):{Colors.RESET}")
                print(f"  {base64.b64encode(result).decode()}\n")
        except Exception as e:
            Banner.error("Encryption failed.", str(e))

    def _crypto_decrypt(self, engine):
        Banner.section("Decrypt Data")
        print(f"  {Colors.CYAN}1.{Colors.RESET} Decrypt text (Base64 input)")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Decrypt a file\n")
        mode = Banner.prompt("Select [1/2]:")

        if mode == "1":
            import base64
            b64 = Banner.prompt("Paste encrypted Base64 text:")
            try:
                data = base64.b64decode(b64)
            except Exception:
                Banner.error("Invalid Base64 input.")
                return
        elif mode == "2":
            filepath = pick_file("Select encrypted file (.ixenc)", [("Ixoryn Encrypted", "*.ixenc"), ("All", "*.*")])
            if not filepath:
                Banner.warn("No file selected.")
                return
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
            except Exception as e:
                Banner.error("Could not read file.", str(e))
                return
        else:
            Banner.error("Invalid choice.")
            return

        password = Banner.prompt("Enter decryption password:")
        if not password:
            Banner.error("No password provided.")
            return

        Banner.info("Decrypting...")
        try:
            plaintext, filename = engine.decrypt(data, password)
            if filename:
                out_path = pick_save_file(f"Save decrypted file '{filename}'", f".{filename.split('.')[-1] if '.' in filename else 'bin'}")
                if out_path:
                    with open(out_path, "wb") as f:
                        f.write(plaintext)
                    Banner.success(f"File decrypted and saved to: {out_path}")
            else:
                Banner.success("Decryption successful!")
                print(f"\n  {Colors.GREEN}Decrypted text:{Colors.RESET}")
                try:
                    print(f"  {plaintext.decode()}\n")
                except Exception:
                    print(f"  [Binary data - {len(plaintext)} bytes]\n")
        except Exception as e:
            Banner.error("Decryption failed. Wrong password or corrupted data.", str(e))

    def _crypto_sign(self, engine):
        Banner.section("Digital Signature — Sign Data")
        key_path = pick_file("Select your private key (.ixkey)", [("Ixoryn Key", "*.ixkey"), ("All", "*.*")])
        if not key_path:
            Banner.warn("No key selected.")
            return

        print(f"\n  {Colors.CYAN}1.{Colors.RESET} Sign text")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Sign a file\n")
        mode = Banner.prompt("Select [1/2]:")

        if mode == "1":
            text = Banner.prompt("Enter text to sign:")
            data = text.encode()
        elif mode == "2":
            fp = pick_file("Select file to sign")
            if not fp:
                return
            with open(fp, "rb") as f:
                data = f.read()
        else:
            return

        password = Banner.prompt("Enter key password (to unlock private key):")
        try:
            with open(key_path, "rb") as f:
                key_data = f.read()
            signature = engine.sign(data, key_data, password)
            import base64
            sig_b64 = base64.b64encode(signature).decode()
            Banner.success("Signature generated!")
            print(f"\n  {Colors.YELLOW}Signature (Base64):{Colors.RESET}")
            print(f"  {sig_b64}\n")

            save = Banner.prompt("Save signature to file? [y/N]:")
            if save.lower() == "y":
                out = pick_save_file("Save signature", ".ixsig")
                if out:
                    with open(out, "w") as f:
                        f.write(sig_b64)
                    Banner.success(f"Signature saved to: {out}")
        except Exception as e:
            Banner.error("Signing failed.", str(e))

    def _crypto_verify(self, engine):
        Banner.section("Digital Signature — Verify")
        pub_path = pick_file("Select public key (.ixpub)", [("Ixoryn Public Key", "*.ixpub"), ("All", "*.*")])
        if not pub_path:
            return

        print(f"\n  {Colors.CYAN}1.{Colors.RESET} Verify text")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Verify a file\n")
        mode = Banner.prompt("Select [1/2]:")

        if mode == "1":
            text = Banner.prompt("Enter original text:")
            data = text.encode()
        elif mode == "2":
            fp = pick_file("Select original file")
            if not fp:
                return
            with open(fp, "rb") as f:
                data = f.read()
        else:
            return

        sig_input = Banner.prompt("Paste the signature (Base64) or press Enter to load from file:")
        if not sig_input:
            sig_file = pick_file("Select signature file (.ixsig)", [("Ixoryn Signature", "*.ixsig"), ("All", "*.*")])
            if not sig_file:
                return
            with open(sig_file, "r") as f:
                sig_input = f.read().strip()

        try:
            import base64
            signature = base64.b64decode(sig_input)
            with open(pub_path, "rb") as f:
                pub_key = f.read()
            valid = engine.verify(data, signature, pub_key)
            if valid:
                Banner.success("SIGNATURE VALID — Data is authentic and unmodified.")
            else:
                Banner.error("SIGNATURE INVALID — Data may have been tampered with.")
        except Exception as e:
            Banner.error("Verification failed.", str(e))

    def _crypto_keygen(self, engine):
        Banner.section("Generate Key Pair (Ed25519)")
        name = Banner.prompt("Enter a name/label for this key pair:")
        password = self._get_password_with_audit("key protection")
        if not password:
            return

        try:
            priv_key, pub_key = engine.generate_keypair(password)
            out_dir = pick_save_file(f"Save private key as '{name}.ixkey'", ".ixkey")
            if out_dir:
                with open(out_dir, "wb") as f:
                    f.write(priv_key)
                pub_path = out_dir.replace(".ixkey", ".ixpub")
                with open(pub_path, "wb") as f:
                    f.write(pub_key)
                Banner.success(f"Private key saved: {out_dir}")
                Banner.success(f"Public key saved:  {pub_path}")
                Banner.warn("KEEP YOUR PRIVATE KEY SAFE. Never share it.")
        except Exception as e:
            Banner.error("Key generation failed.", str(e))

    def _crypto_hash(self, engine):
        Banner.section("Hash Data")
        algs = ["SHA-256", "SHA-3-256", "SHA-3-512", "BLAKE2b", "BLAKE2s", "SHA-512"]
        for i, a in enumerate(algs, 1):
            print(f"  {Colors.CYAN}{i}.{Colors.RESET} {a}")
        print()
        choice = Banner.prompt(f"Select algorithm [1-{len(algs)}]:")
        try:
            alg = algs[int(choice) - 1]
        except (ValueError, IndexError):
            Banner.error("Invalid selection.")
            return

        print(f"\n  {Colors.CYAN}1.{Colors.RESET} Hash text")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Hash a file\n")
        mode = Banner.prompt("Select [1/2]:")

        if mode == "1":
            text = Banner.prompt("Enter text to hash:")
            data = text.encode()
        elif mode == "2":
            fp = pick_file("Select file to hash")
            if not fp:
                return
            with open(fp, "rb") as f:
                data = f.read()
        else:
            return

        try:
            hsh = engine.hash_data(data, alg)
            Banner.success(f"{alg} Hash:")
            print(f"\n  {Colors.YELLOW}{hsh}{Colors.RESET}\n")
        except Exception as e:
            Banner.error("Hashing failed.", str(e))

    # ─── STEGANOGRAPHY ───────────────────────────────────────────────
    def _stego_menu(self):
        while True:
            Banner.section("Steganography Module")
            print(f"  {Colors.CYAN}1.{Colors.RESET} Forensic Research Mode")
            print(f"  {Colors.DIM}     World-class stego detector — analyze images/audio for hidden data{Colors.RESET}\n")
            print(f"  {Colors.CYAN}2.{Colors.RESET} Operational Mode")
            print(f"  {Colors.DIM}     Embed or extract hidden files, text, images, or audio{Colors.RESET}\n")
            print(f"  {Colors.RED}0.{Colors.RESET} Back\n")

            choice = Banner.prompt("Select [1/2/0]:")
            if choice == "0":
                return
            elif choice == "1":
                self._stego_research()
            elif choice == "2":
                self._stego_operational()
            else:
                Banner.error("Invalid selection.")

    def _stego_research(self):
        from ixoryn.modules.stego.detector import StegoDetector
        Banner.section("Forensic Research Mode — Stego Detector")
        Banner.info("Select a file to analyze for hidden steganographic content.")
        filepath = pick_file("Select image or audio file to analyze",
                             [("Images", "*.png *.jpg *.jpeg *.bmp *.tiff *.gif *.webp"),
                              ("Audio", "*.wav *.flac *.mp3 *.ogg *.aiff"),
                              ("All files", "*.*")])
        if not filepath:
            Banner.warn("No file selected.")
            return

        Banner.info(f"Analyzing: {filepath}")
        try:
            detector = StegoDetector()
            report = detector.analyze(filepath)
            detector.print_report(report)

            save = Banner.prompt("Save forensic report? [y/N] (Enter 'html' or 'pdf' for formatted report):")
            if save.lower() in ("y", "yes", "html", "pdf"):
                from ixoryn.utils.report_generator import ReportGenerator
                rgen = ReportGenerator()
                import os
                if save.lower() == "pdf":
                    out_path = rgen.generate_pdf(report, "stego")
                else:
                    out_path = rgen.generate_html(report, "stego")
                Banner.success(f"Report saved to: {out_path}")
            elif save.lower() == "json":
                import json, os
                from pathlib import Path
                out_dir = Path.home() / ".ixoryn" / "output" / "stego"
                out_file = out_dir / f"forensic_{os.path.basename(filepath)}_{detector._timestamp()}.json"
                with open(out_file, "w") as f:
                    json.dump(report, f, indent=2, default=str)
                Banner.success(f"JSON report saved to: {out_file}")
        except Exception as e:
            Banner.error("Analysis failed.", str(e))

    def _stego_operational(self):
        from ixoryn.modules.stego.embed import StegoEmbed
        from ixoryn.modules.stego.extract import StegoExtract

        while True:
            Banner.section("Operational Mode")
            print(f"  {Colors.CYAN}1.{Colors.RESET} Embed (Hide data in a cover file)")
            print(f"  {Colors.CYAN}2.{Colors.RESET} Extract (Reveal hidden data)")
            print(f"  {Colors.RED}0.{Colors.RESET} Back\n")
            choice = Banner.prompt("Select [1/2/0]:")

            if choice == "0":
                return
            elif choice == "1":
                self._stego_embed()
            elif choice == "2":
                self._stego_extract()
            else:
                Banner.error("Invalid selection.")

    def _stego_embed(self):
        from ixoryn.modules.stego.embed import StegoEmbed
        Banner.section("Embed — Hide Data in Cover File")

        # Select cover file
        Banner.info("Step 1: Select cover file (image or audio)")
        cover = pick_file("Select cover image or audio",
                          [("Images", "*.png *.jpg *.jpeg *.bmp *.tiff *.gif *.webp"),
                           ("Audio", "*.wav *.flac *.mp3 *.ogg *.aiff"),
                           ("All files", "*.*")])
        if not cover:
            Banner.warn("No cover file selected.")
            return

        # Select payload type
        Banner.info("Step 2: Select what to hide")
        print(f"  {Colors.CYAN}1.{Colors.RESET} Text message")
        print(f"  {Colors.CYAN}2.{Colors.RESET} File (any type)")
        print(f"  {Colors.CYAN}3.{Colors.RESET} Image")
        print(f"  {Colors.CYAN}4.{Colors.RESET} Audio file\n")
        ptype = Banner.prompt("Select payload type [1-4]:")

        payload_data = None
        payload_name = "payload"

        if ptype == "1":
            text = Banner.prompt("Enter the secret message:")
            if not text:
                Banner.error("Empty message.")
                return
            payload_data = text.encode("utf-8")
            payload_name = "message.txt"
        elif ptype in ("2", "3", "4"):
            labels = {
                "2": ("Select file to hide", [("All files", "*.*")]),
                "3": ("Select image to hide", [("Images", "*.png *.jpg *.jpeg *.bmp"), ("All", "*.*")]),
                "4": ("Select audio to hide", [("Audio", "*.wav *.flac *.mp3 *.ogg"), ("All", "*.*")]),
            }
            label, ftypes = labels[ptype]
            fp = pick_file(label, ftypes)
            if not fp:
                return
            import os
            with open(fp, "rb") as f:
                payload_data = f.read()
            payload_name = os.path.basename(fp)
        else:
            Banner.error("Invalid selection.")
            return

        # Password protection
        password = self._get_password_with_audit("steganographic protection (recommended)")
        if not password:
            confirm = Banner.prompt("Proceed WITHOUT password protection? [y/N]:")
            if confirm.lower() != "y":
                return
            password = None

        # Output path
        Banner.info("Step 3: Select output location")
        out_path = pick_save_file("Save stego output (will be lossless PNG or FLAC)",
                                  ".png",
                                  [("PNG Image", "*.png"), ("FLAC Audio", "*.flac"), ("All", "*.*")])
        if not out_path:
            Banner.warn("Save cancelled.")
            return

        Banner.info("Embedding payload...")
        try:
            embedder = StegoEmbed()
            result_path = embedder.embed(cover, payload_data, payload_name, out_path, password=password)
            Banner.success(f"Data successfully embedded!")
            Banner.success(f"Output saved to: {result_path}")
            Banner.info("Output is in lossless format to prevent data corruption during transit.")
        except Exception as e:
            Banner.error("Embedding failed.", str(e))

    def _stego_extract(self):
        from ixoryn.modules.stego.extract import StegoExtract
        Banner.section("Extract — Reveal Hidden Data")

        stego_file = pick_file("Select stego file to extract from",
                               [("Images", "*.png *.bmp *.tiff"), ("Audio", "*.wav *.flac"), ("All", "*.*")])
        if not stego_file:
            Banner.warn("No file selected.")
            return

        password = Banner.prompt("Enter password (leave blank if no password was used):")

        Banner.info("Extracting hidden data...")
        try:
            extractor = StegoExtract()
            payload_data, payload_name = extractor.extract(stego_file, password if password else None)

            Banner.success(f"Extraction successful! Payload name: {payload_name}")

            if payload_name.endswith(".txt") or payload_name == "message.txt":
                print(f"\n  {Colors.GREEN}Hidden message:{Colors.RESET}")
                print(f"  {payload_data.decode('utf-8', errors='replace')}\n")
            else:
                out_path = pick_save_file(f"Save extracted '{payload_name}'",
                                          f".{payload_name.split('.')[-1]}")
                if out_path:
                    with open(out_path, "wb") as f:
                        f.write(payload_data)
                    Banner.success(f"Extracted payload saved to: {out_path}")
        except Exception as e:
            Banner.error("Extraction failed. Wrong password or no hidden data found.", str(e))

    # ─── URL AUDITING ────────────────────────────────────────────────
    def _url_menu(self):
        from ixoryn.modules.url_audit.auditor import URLAuditor
        Banner.section("URL & Domain Auditing")

        print(f"  {Colors.CYAN}How would you like to provide targets?{Colors.RESET}\n")
        print(f"  {Colors.CYAN}1.{Colors.RESET} Type / paste URLs or domains manually")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Load from a text file  {Colors.DIM}(one URL per line){Colors.RESET}")
        print(f"  {Colors.RED}0.{Colors.RESET} Back\n")
        input_mode = Banner.prompt("Select input method [1/2/0]:")

        if input_mode == "0":
            return

        targets = []

        if input_mode == "1":
            Banner.info("Enter one or more URLs/domains — separate multiple with commas.")
            Banner.info("Examples: google.com,   http://suspicious.tk,   paypa1.com")
            print()
            raw = Banner.prompt("Enter target URL(s) or domain(s):")
            if not raw:
                Banner.error("No targets provided.")
                return
            targets = [t.strip() for t in raw.replace("\n", ",").split(",") if t.strip()]

        elif input_mode == "2":
            fp = pick_file("Select text file containing URLs (one per line)",
                           [("Text files", "*.txt *.csv"), ("All files", "*.*")])
            if not fp:
                Banner.warn("No file selected.")
                return
            try:
                with open(fp, "r", errors="replace") as f:
                    raw_lines = f.readlines()
                targets = [l.strip() for l in raw_lines
                           if l.strip() and not l.strip().startswith("#")]
                if not targets:
                    Banner.error("File is empty or has no valid entries.")
                    return
                Banner.success(f"Loaded {len(targets)} URL(s) from: {fp}")
            except Exception as e:
                Banner.error(f"Could not read file: {e}")
                return
        else:
            Banner.error("Invalid selection.")
            return

        if not targets:
            Banner.error("No valid targets found.")
            return

        # Preview
        print(f"\n  {Colors.CYAN}Targets to audit ({len(targets)}):{Colors.RESET}")
        for i, t in enumerate(targets[:8]):
            print(f"    {Colors.DIM}{i+1}.{Colors.RESET} {t}")
        if len(targets) > 8:
            print(f"    {Colors.DIM}... and {len(targets)-8} more{Colors.RESET}")
        print()

        print(f"  {Colors.CYAN}Select audit depth:{Colors.RESET}")
        print(f"  1. Quick Scan  {Colors.DIM}— Basic phishing/typosquat checks (fast){Colors.RESET}")
        print(f"  2. Standard Scan  {Colors.DIM}— Comprehensive checks including SSL + DNS{Colors.RESET}")
        print(f"  3. Deep Scan  {Colors.DIM}— Full forensic + threat intelligence (slower){Colors.RESET}\n")
        depth_choice = Banner.prompt("Select depth [1/2/3]:")
        depth_map = {"1": "quick", "2": "standard", "3": "deep"}
        depth = depth_map.get(depth_choice, "standard")

        Banner.info(f"Auditing {len(targets)} target(s) at [{depth}] depth...")
        print()

        try:
            auditor = URLAuditor()
            all_reports = {}
            for target in targets:
                Banner.subsection(f"Target: {target}")
                report = auditor.audit(target, depth=depth)
                all_reports[target] = report
                auditor.print_report(report)

            save = Banner.prompt("\nSave report? [N / html / pdf / json]:")
            if save.lower() in ("y", "yes", "html", "pdf", "json"):
                import json
                from pathlib import Path
                from datetime import datetime
                from ixoryn.utils.report_generator import ReportGenerator
                rgen = ReportGenerator()
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                if save.lower() == "html":
                    for t, r in all_reports.items():
                        p = rgen.generate_html(r, "url")
                        Banner.success(f"HTML report: {p}")
                elif save.lower() == "pdf":
                    for t, r in all_reports.items():
                        p = rgen.generate_pdf(r, "url")
                        Banner.success(f"PDF report: {p}")
                else:
                    out = Path.home() / ".ixoryn" / "output" / "url_audit" / f"audit_{ts}.json"
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with open(out, "w") as f:
                        json.dump(all_reports, f, indent=2, default=str)
                    Banner.success(f"JSON saved to: {out}")
        except Exception as e:
            Banner.error("URL audit failed.", str(e))

    # ─── PASSWORD AUDITING ───────────────────────────────────────────
    def _password_menu(self):
        from ixoryn.modules.password.auditor import PasswordAuditor
        Banner.section("Password & Hash Auditing")

        print(f"  {Colors.CYAN}What would you like to audit?{Colors.RESET}\n")
        print(f"  {Colors.CYAN}1.{Colors.RESET} Audit password(s) — strength, entropy, crack time")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Audit hash(es) — identify type, assess security level")
        print(f"  {Colors.CYAN}3.{Colors.RESET} Auto-detect — let Ixoryn decide if it's a password or hash")
        print(f"  {Colors.RED}0.{Colors.RESET} Back\n")
        choice = Banner.prompt("Select [1-3/0]:")

        if choice == "0":
            return
        if choice not in ("1", "2", "3"):
            Banner.error("Invalid selection.")
            return

        auditor = PasswordAuditor()

        # ── Input method selection
        print(f"\n  {Colors.CYAN}How would you like to provide input?{Colors.RESET}\n")
        print(f"  {Colors.CYAN}A.{Colors.RESET} Type / paste manually  {Colors.DIM}(single or comma-separated){Colors.RESET}")
        print(f"  {Colors.CYAN}B.{Colors.RESET} Load from a text file  {Colors.DIM}(one entry per line){Colors.RESET}\n")
        input_mode = Banner.prompt("Select input method [A/B]:").strip().upper()

        entries = []

        if input_mode == "A":
            if choice == "1":
                Banner.info("Tip: separate multiple passwords with commas.")
                raw = Banner.prompt("Enter password(s):")
            elif choice == "2":
                Banner.info("Tip: separate multiple hashes with commas.")
                raw = Banner.prompt("Enter hash(es):")
            else:
                Banner.info("Paste passwords or hashes — Ixoryn will auto-detect each one.")
                raw = Banner.prompt("Enter password(s) or hash(es):")
            if not raw:
                Banner.error("Nothing entered.")
                return
            entries = [t.strip() for t in raw.split(",") if t.strip()]

        elif input_mode == "B":
            label = {
                "1": "Select text file with passwords (one per line)",
                "2": "Select text file with hashes (one per line)",
                "3": "Select text file with passwords/hashes (one per line)",
            }.get(choice, "Select text file")
            fp = pick_file(label, [("Text files", "*.txt *.csv *.lst"), ("All files", "*.*")])
            if not fp:
                Banner.warn("No file selected.")
                return
            try:
                with open(fp, "r", errors="replace") as f:
                    raw_lines = f.readlines()
                entries = [l.strip() for l in raw_lines
                           if l.strip() and not l.strip().startswith("#")]
                if not entries:
                    Banner.error("File is empty or has no valid entries.")
                    return
                Banner.success(f"Loaded {len(entries)} entries from: {fp}")
                # Preview
                print(f"\n  {Colors.CYAN}Preview (first 5):{Colors.RESET}")
                for e in entries[:5]:
                    masked = e[:3] + "***" + e[-3:] if len(e) > 8 else "***"
                    print(f"    {Colors.DIM}{masked}{Colors.RESET}")
                print()
            except Exception as e:
                Banner.error(f"Could not read file: {e}")
                return
        else:
            Banner.error("Invalid input method.")
            return

        if not entries:
            Banner.error("No entries to process.")
            return

        # Confirm if large batch
        if len(entries) > 20:
            confirm = Banner.prompt(f"About to audit {len(entries)} entries. Continue? [y/N]:")
            if confirm.lower() != "y":
                return

        # Save option for large batches
        save_results = False
        out_file = None
        if len(entries) > 5:
            save_q = Banner.prompt("Save results to file? [y/N]:")
            if save_q.lower() == "y":
                save_results = True
                out_file = pick_save_file("Save audit results", ".txt")

        # Run audit
        Banner.info(f"Auditing {len(entries)} entry/entries...")
        results_text = []

        for entry in entries:
            try:
                if choice == "1":
                    report = auditor.audit_password(entry)
                    auditor.print_password_report(report)
                    results_text.append(
                        f"[PASSWORD] {entry[:3]}*** | Strength: {report.get('strength','?')} | "
                        f"Score: {report.get('score','?')}/4 | Entropy: {report.get('entropy',0):.1f}bits"
                    )
                elif choice == "2":
                    report = auditor.audit_hash(entry)
                    auditor.print_hash_report(report)
                    results_text.append(
                        f"[HASH] {entry[:16]}... | Type: {report.get('best_match','?')} | "
                        f"Rating: {report.get('security_rating','?')}"
                    )
                else:
                    report = auditor.audit_auto(entry)
                    if report.get("type") == "hash":
                        auditor.print_hash_report(report)
                        results_text.append(f"[HASH] {entry[:16]}... | Auto-detected as hash")
                    else:
                        auditor.print_password_report(report)
                        results_text.append(f"[PASS] {entry[:3]}*** | Auto-detected as password")
            except Exception as e:
                Banner.warn(f"Error auditing entry: {e}")

        if save_results and out_file and results_text:
            try:
                with open(out_file, "w") as f:
                    f.write("Ixoryn Password/Hash Audit Results\n")
                    f.write("=" * 60 + "\n")
                    for r in results_text:
                        f.write(r + "\n")
                Banner.success(f"Results saved to: {out_file}")
            except Exception as e:
                Banner.warn(f"Could not save results: {e}")

    # ─── SHARED HELPERS ──────────────────────────────────────────────
    def _get_password_with_audit(self, context: str = "this operation") -> str:
        """Get password from user, run audit, and confirm."""
        from ixoryn.modules.password.auditor import PasswordAuditor

        import getpass
        try:
            password = getpass.getpass(f"\n  {Colors.MAGENTA}  [?] Enter password for {context}: {Colors.RESET}")
        except Exception:
            password = Banner.prompt(f"Enter password for {context}:")

        if not password:
            return ""

        # Quick audit
        auditor = PasswordAuditor()
        report = auditor.audit_password(password)
        score = report.get("score", 0)
        strength = report.get("strength", "Unknown")
        crack_time = report.get("crack_time_display", "Unknown")

        print(f"\n  {Colors.YELLOW}  ── Password Audit ──{Colors.RESET}")
        Banner.result("Strength", strength,
                      Colors.GREEN if score >= 3 else Colors.YELLOW if score >= 2 else Colors.RED)
        Banner.result("Entropy", f"{report.get('entropy', 0):.1f} bits")
        Banner.result("Est. Crack Time (offline)", crack_time)

        if report.get("warnings"):
            for w in report["warnings"]:
                Banner.warn(f"  {w}")

        if score < 2:
            confirm = Banner.prompt("  Password is WEAK. Proceed anyway? [y/N]:")
            if confirm.lower() != "y":
                return ""

        try:
            confirm_pwd = getpass.getpass(f"  {Colors.MAGENTA}  [?] Confirm password: {Colors.RESET}")
        except Exception:
            confirm_pwd = Banner.prompt("  Confirm password:")

        if password != confirm_pwd:
            Banner.error("Passwords do not match.")
            return ""

        print()
        return password

    # ─── NETWORK SCANNER ────────────────────────────────────────────
    def _network_scan_menu(self):
        Banner.section("Network Scanner")
        print(f"  Scan a host for open ports, services, and vulnerabilities.")
        print(f"  {Colors.YELLOW}⚠  Only scan hosts you own or have written permission to scan.{Colors.RESET}\n")

        target = Banner.prompt("Enter target IP or hostname (e.g. 192.168.1.1 or example.com):")
        if not target:
            return

        print(f"\n  Scan Depth:")
        print(f"  {Colors.CYAN}1.{Colors.RESET} Quick — common ports only (fastest)")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Standard — top 100 ports (recommended)")
        print(f"  {Colors.CYAN}3.{Colors.RESET} Deep — all 65535 ports (slowest)\n")
        depth_choice = Banner.prompt("Select depth [1/2/3]:")
        depth = {"1": "quick", "2": "standard", "3": "deep"}.get(depth_choice, "standard")

        verbose = Banner.prompt("Show verbose output? [y/N]:").lower() == "y"

        try:
            from ixoryn.modules.network import NetworkScanner
            scanner = NetworkScanner()
            Banner.info(f"Scanning {target} ({depth} mode)...")
            if depth == "deep":
                cprint("  [!] Deep scan may take several minutes.", Colors.YELLOW)

            report = scanner.scan(target, depth=depth)
            print(scanner.format_report(report, verbose=verbose))

            save = Banner.prompt("Save results to file? [y/N]:")
            if save.lower() == "y":
                import json, os
                from pathlib import Path
                out_dir = Path.home() / ".ixoryn" / "output"
                out_dir.mkdir(exist_ok=True)
                fname = out_dir / f"scan_{target.replace('.','_')}_{depth}.json"
                with open(fname, "w") as f:
                    json.dump(report, f, indent=2)
                Banner.success(f"Results saved to: {fname}")

        except Exception as e:
            Banner.error(f"Scan failed: {e}")

    # ─── SUBDOMAIN FINDER ────────────────────────────────────────────
    def _subdomain_menu(self):
        Banner.section("Subdomain Finder")
        print(f"  Discover subdomains using certificate transparency logs and DNS lookup.")
        print(f"  {Colors.GREEN}✓ Passive methods — no packets sent to target.{Colors.RESET}\n")

        domain = Banner.prompt("Enter domain to enumerate (e.g. example.com):")
        if not domain:
            return

        print(f"\n  Method:")
        print(f"  {Colors.CYAN}1.{Colors.RESET} Passive only — cert transparency + HackerTarget (safest)")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Full — passive + DNS brute-force (recommended)\n")
        method_choice = Banner.prompt("Select [1/2]:")

        methods = ["certsh", "hackertarget"]
        if method_choice == "2":
            methods.append("bruteforce")

        try:
            from ixoryn.modules.network import SubdomainEnumerator
            enumerator = SubdomainEnumerator()
            Banner.info(f"Enumerating subdomains for {domain}...")
            result = enumerator.enumerate(domain.strip(), methods=methods)
            print(enumerator.format_results(result))

            save = Banner.prompt("Save results to file? [y/N]:")
            if save.lower() == "y":
                import json
                from pathlib import Path
                out_dir = Path.home() / ".ixoryn" / "output"
                out_dir.mkdir(exist_ok=True)
                fname = out_dir / f"subdomains_{domain.replace('.','_')}.json"
                with open(fname, "w") as f:
                    json.dump(result, f, indent=2)
                Banner.success(f"Saved to: {fname}")

        except Exception as e:
            Banner.error(f"Enumeration failed: {e}")

    # ─── BREACH INTELLIGENCE ─────────────────────────────────────────
    def _breach_menu(self):
        Banner.section("Breach Intelligence")
        print(f"  Check if your password or email has appeared in known data breaches.")
        print(f"  {Colors.GREEN}✓ Password check uses k-Anonymity — your password is NEVER transmitted.{Colors.RESET}\n")

        print(f"  {Colors.CYAN}1.{Colors.RESET} Check a password (safe — k-Anonymity)")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Check an email address (requires free HIBP API key)")
        print(f"  {Colors.RED}0.{Colors.RESET} Back\n")

        choice = Banner.prompt("Select [1/2/0]:")

        try:
            from ixoryn.modules.network import BreachIntelligence
            from ixoryn.core.bootstrap import Bootstrap
            import os

            config = Bootstrap.load_config()
            hibp_key = config.get("api_keys", {}).get("hibp") or os.environ.get("HIBP_API_KEY")
            intel = BreachIntelligence(hibp_api_key=hibp_key)

            if choice == "1":
                import getpass
                try:
                    password = getpass.getpass(f"  {Colors.CYAN}[?] Enter password to check: {Colors.RESET}")
                except Exception:
                    password = Banner.prompt("Enter password:")

                if password:
                    Banner.info("Checking against 613M+ breach records...")
                    result = intel.check_password_pwned(password)
                    print(intel.format_password_check(result))

            elif choice == "2":
                email = Banner.prompt("Enter email address:")
                if email:
                    Banner.info(f"Checking {email} in breach databases...")
                    result = intel.check_email_breached(email)
                    print(intel.format_email_check(result))

        except Exception as e:
            Banner.error(f"Breach check failed: {e}")

    # ─── FILE FORENSICS ──────────────────────────────────────────────
    def _file_forensics_menu(self):
        Banner.section("File Forensics")
        print(f"  Deep analysis of any file: hash fingerprinting, metadata,")
        print(f"  entropy analysis, embedded strings, and sensitive data detection.\n")

        print(f"  {Colors.CYAN}1.{Colors.RESET} Analyze a file")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Compare two files (hash verification)")
        print(f"  {Colors.RED}0.{Colors.RESET} Back\n")

        choice = Banner.prompt("Select [1/2/0]:")

        try:
            from ixoryn.modules.forensics import FileForensics
            forensics = FileForensics()

            if choice == "1":
                filepath = Banner.prompt("Enter file path to analyze:")
                if filepath:
                    filepath = filepath.strip().strip("'\"")
                    verbose = Banner.prompt("Show verbose output (metadata, strings)? [y/N]:").lower() == "y"
                    Banner.info(f"Analyzing: {filepath}")
                    result = forensics.analyze(filepath, deep=True)
                    print(forensics.format_report(result, verbose=verbose))

                    save = Banner.prompt("Save JSON report? [y/N]:")
                    if save.lower() == "y":
                        import json
                        from pathlib import Path
                        out_dir = Path.home() / ".ixoryn" / "output"
                        out_dir.mkdir(exist_ok=True)
                        fname = out_dir / f"forensics_{Path(filepath).name}.json"
                        with open(fname, "w") as f:
                            json.dump(result, f, indent=2, default=str)
                        Banner.success(f"Report saved to: {fname}")

            elif choice == "2":
                file1 = Banner.prompt("Enter path to first file:").strip().strip("'\"")
                file2 = Banner.prompt("Enter path to second file:").strip().strip("'\"")
                if file1 and file2:
                    result = forensics.compare_files(file1, file2)
                    if result.get("error"):
                        Banner.error(result["error"])
                    else:
                        from ixoryn.ui.banner import Colors as C
                        identical = result["identical"]
                        status_color = C.GREEN if identical else C.RED
                        print(f"\n  Files are: {status_color}{'IDENTICAL' if identical else 'DIFFERENT'}{C.RESET}")
                        if not identical:
                            print(f"  Size difference: {result['size_difference']:+,} bytes")
                            for diff in result.get("differences", []):
                                print(f"  → {diff}")
                        print(f"\n  File 1 SHA-256: {result['file1_hashes']['sha256']}")
                        print(f"  File 2 SHA-256: {result['file2_hashes']['sha256']}\n")

        except Exception as e:
            Banner.error(f"File forensics failed: {e}")

    # ─── CVE LOOKUP ──────────────────────────────────────────────────
    def _cve_menu(self):
        Banner.section("CVE Lookup — NIST National Vulnerability Database")
        print(f"  Search for known vulnerabilities in real-time from NIST NVD.")
        print(f"  No API key required.\n")

        print(f"  {Colors.CYAN}1.{Colors.RESET} Search by software name/version")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Look up a specific CVE ID")
        print(f"  {Colors.RED}0.{Colors.RESET} Back\n")

        choice = Banner.prompt("Select [1/2/0]:")

        try:
            from ixoryn.modules.network import CVELookup
            lookup = CVELookup()

            if choice == "1":
                software = Banner.prompt("Enter software name (e.g. apache, openssl, wordpress):")
                version = Banner.prompt("Enter version (optional, press Enter to skip):")
                if software:
                    Banner.info(f"Searching NVD for {software} {version}...")
                    result = lookup.lookup_software(software.strip(), version.strip() or None)
                    print(lookup.format_results(result))

            elif choice == "2":
                cve_id = Banner.prompt("Enter CVE ID (e.g. CVE-2021-44228):")
                if cve_id:
                    Banner.info(f"Looking up {cve_id.upper()}...")
                    result = lookup.lookup_cve(cve_id.strip().upper())
                    from ixoryn.ui.banner import Colors as C
                    if result.get("error"):
                        Banner.error(result["error"])
                    else:
                        sev = result.get("severity", "UNKNOWN")
                        sev_color = C.RED if sev in ("CRITICAL", "HIGH") else C.YELLOW
                        print(f"\n  {C.BOLD}{result['cve_id']}{C.RESET}")
                        print(f"  Severity:    {sev_color}{sev}{C.RESET}")
                        print(f"  CVSS Score:  {result.get('cvss_score', 'N/A')}")
                        print(f"  Published:   {result.get('published', 'N/A')}")
                        print(f"\n  {result.get('description', 'No description')[:300]}")
                        print(f"\n  {C.CYAN}{result.get('nvd_url', '')}{C.RESET}\n")

        except Exception as e:
            Banner.error(f"CVE lookup failed: {e}")

    # ─── HASH CRACKING (HASHCAT) ─────────────────────────────────────
    def _crack_menu(self):
        """Beginner-friendly guided hash cracking with Hashcat."""
        from ixoryn.modules.password.hashcat_engine import HashcatEngine
        from ixoryn.modules.password.auditor import PasswordAuditor
        from ixoryn.core.platform_compat import WordlistManager

        engine = HashcatEngine()
        Banner.section("Hash Cracker — Powered by Hashcat")

        # Check hashcat
        if not engine.is_available():
            Banner.warn("Hashcat is not installed on this system.")
            print(f"\n{Colors.YELLOW}{engine.get_install_instructions()}{Colors.RESET}\n")
            Banner.info("After installing hashcat, come back to this menu.")
            Banner.info("Tip: On Kali Linux, run:  sudo apt install hashcat")
            return

        Banner.success(f"Hashcat found: {engine.hashcat_bin}")
        ver = engine.get_version()
        if ver:
            Banner.info(f"Version: {ver}")
        print()

        # Step 1: Get hash
        Banner.info("Step 1: Enter the hash you want to crack")
        print(f"  {Colors.DIM}Example: 5f4dcc3b5aa765d61d8327deb882cf99{Colors.RESET}\n")
        hash_value = Banner.prompt("Paste the hash:")
        if not hash_value:
            Banner.error("No hash provided.")
            return
        hash_value = hash_value.strip()

        # Step 2: Auto-identify
        Banner.info("Step 2: Identifying hash type...")
        auditor = PasswordAuditor()
        report = auditor.audit_hash(hash_value)
        matches = report.get("matches", [])

        if not matches:
            Banner.warn("Could not identify hash type automatically.")
            hash_name = Banner.prompt("Enter hash type manually (e.g. MD5, SHA-1, NTLM):")
            if not hash_name:
                return
        else:
            print(f"\n  {Colors.CYAN}Identified hash type(s):{Colors.RESET}")
            for i, m in enumerate(matches[:5], 1):
                mode = engine.get_hashcat_mode(m["name"])
                mode_str = f"(hashcat -m {mode})" if mode and mode != -1 else "(not GPU-crackable)" if mode == -1 else "(unknown mode)"
                print(f"  {Colors.CYAN}{i}.{Colors.RESET} {m['name']}  {Colors.DIM}{mode_str}{Colors.RESET}")
            print(f"  {Colors.CYAN}{len(matches[:5])+1}.{Colors.RESET} Enter type manually")
            print()
            choice = Banner.prompt(f"Select hash type [1-{len(matches[:5])+1}]:")
            try:
                idx = int(choice) - 1
                if idx < len(matches[:5]):
                    hash_name = matches[idx]["name"]
                else:
                    hash_name = Banner.prompt("Enter hash type:")
            except (ValueError, IndexError):
                hash_name = matches[0]["name"] if matches else "MD5"

        mode_num = engine.get_hashcat_mode(hash_name)
        if mode_num == -1:
            Banner.warn(f"{hash_name} is memory-hard (Argon2/bcrypt with high cost).")
            Banner.info("These hashes are specifically designed to resist GPU cracking.")
            Banner.info("This means whoever created them used proper security — good news!")
            return
        if mode_num is None:
            Banner.error(f"No hashcat mode found for: {hash_name}")
            return

        Banner.success(f"Hash type: {hash_name}  |  Hashcat mode: {mode_num}")

        # Step 3: Choose attack
        print(f"\n  {Colors.CYAN}Step 3: Choose attack strategy{Colors.RESET}\n")
        print(f"  {Colors.CYAN}1.{Colors.RESET} Smart Auto  {Colors.DIM}— Ixoryn tries multiple strategies automatically (recommended){Colors.RESET}")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Dictionary  {Colors.DIM}— Try every word from a wordlist{Colors.RESET}")
        print(f"  {Colors.CYAN}3.{Colors.RESET} Mask/Brute  {Colors.DIM}— Try all combinations matching a pattern (e.g. 6-digit PIN){Colors.RESET}")
        print(f"  {Colors.CYAN}4.{Colors.RESET} Hybrid      {Colors.DIM}— Dictionary word + number suffix (e.g. 'password123'){Colors.RESET}")
        print(f"  {Colors.RED}0.{Colors.RESET} Back\n")
        attack_choice = Banner.prompt("Select attack [1-4/0]:")

        if attack_choice == "0":
            return

        # Step 4: Wordlist
        wordlist = None
        if attack_choice in ("1", "2", "4"):
            print(f"\n  {Colors.CYAN}Step 4: Select wordlist{Colors.RESET}\n")
            wl_list = WordlistManager.list_available()
            for i, wl in enumerate(wl_list[:6], 1):
                avail_str = f"{Colors.GREEN}AVAILABLE{Colors.RESET}" if wl["available"] else f"{Colors.DIM}NOT FOUND{Colors.RESET}"
                print(f"  {Colors.CYAN}{i}.{Colors.RESET} {wl['name']:<25} {wl['entries']} entries  {avail_str}")
            print(f"  {Colors.CYAN}{len(wl_list[:6])+1}.{Colors.RESET} Browse for a custom wordlist file")
            print()
            wl_choice = Banner.prompt(f"Select wordlist [1-{len(wl_list[:6])+1}]:")
            try:
                wl_idx = int(wl_choice) - 1
                if wl_idx < len(wl_list[:6]):
                    selected = wl_list[wl_idx]
                    if selected.get("builtin"):
                        wordlist = WordlistManager.get_builtin_wordlist()
                        Banner.info("Using built-in top-1000 wordlist.")
                    elif selected.get("available"):
                        wordlist = selected["path"]
                        Banner.info(f"Using: {wordlist}")
                    else:
                        Banner.warn("Wordlist not found. Using built-in top-1000.")
                        wordlist = WordlistManager.get_builtin_wordlist()
                else:
                    from ixoryn.ui.file_picker import pick_file
                    wordlist = pick_file("Select wordlist file",
                                         [("Text files", "*.txt *.lst"), ("All", "*.*")])
                    if not wordlist:
                        Banner.warn("No file selected. Using built-in top-1000.")
                        wordlist = WordlistManager.get_builtin_wordlist()
            except (ValueError, IndexError):
                wordlist = WordlistManager.get_builtin_wordlist()

        # Step 5: Mask (if mask attack)
        mask = None
        if attack_choice == "3":
            print(f"\n  {Colors.CYAN}Common mask patterns:{Colors.RESET}")
            masks = [
                ("?d?d?d?d",             "4-digit PIN (0000-9999)"),
                ("?d?d?d?d?d?d",         "6-digit PIN"),
                ("?d?d?d?d?d?d?d?d",     "8-digit (dates, etc.)"),
                ("?l?l?l?l?l?l",         "6 lowercase letters"),
                ("?u?l?l?l?l?l?d?d",     "8-char (Uppercase + lower + digits)"),
                ("?a?a?a?a?a?a?a?a",     "8-char all types (SLOW)"),
            ]
            for i, (m, desc) in enumerate(masks, 1):
                print(f"  {Colors.CYAN}{i}.{Colors.RESET} {m:<30} {Colors.DIM}{desc}{Colors.RESET}")
            print(f"  {Colors.CYAN}{len(masks)+1}.{Colors.RESET} Enter custom mask")
            print()
            mask_choice = Banner.prompt(f"Select mask [1-{len(masks)+1}]:")
            try:
                m_idx = int(mask_choice) - 1
                if m_idx < len(masks):
                    mask = masks[m_idx][0]
                else:
                    mask = Banner.prompt("Enter mask (e.g. ?u?l?l?l?d?d):")
                    if not mask:
                        mask = "?a?a?a?a?a?a"
            except (ValueError, IndexError):
                mask = "?d?d?d?d?d?d"

        # Run attack
        print()
        Banner.info(f"Starting crack  |  Hash: {hash_name}  |  Mode: {mode_num}")
        Banner.warn("Press Ctrl+C to stop at any time.")
        print()

        def progress(stage, msg):
            if msg and msg.strip() and any(k in msg for k in ["Speed.", "Progress", "Recovered", "strategy"]):
                print(f"  {Colors.DIM}{msg}{Colors.RESET}")

        try:
            if attack_choice == "1":
                result = engine.crack_smart(hash_value, hash_name, wordlist, progress)
            elif attack_choice == "2":
                result = engine.crack_dictionary(hash_value, mode_num, wordlist,
                                                  progress_callback=progress)
            elif attack_choice == "3":
                result = engine.crack_mask(hash_value, mode_num, mask,
                                            progress_callback=progress)
            elif attack_choice == "4":
                result = engine.crack_hybrid(hash_value, mode_num, wordlist, "?d?d?d?d",
                                              progress_callback=progress)
            else:
                return

            # Display result
            print()
            if result.get("cracked") and result.get("plaintext"):
                Banner.success("═" * 50)
                Banner.success(f"  HASH CRACKED!")
                Banner.success("═" * 50)
                print(f"\n  {Colors.WHITE}Hash:{Colors.RESET}       {hash_value[:60]}")
                print(f"  {Colors.WHITE}Password:{Colors.RESET}   {Colors.GREEN}{Colors.BOLD}{result['plaintext']}{Colors.RESET}\n")
                if result.get("attack_used"):
                    Banner.info(f"Method used: {result['attack_used']}")
                save = Banner.prompt("Save result to file? [y/N]:")
                if save.lower() == "y":
                    from ixoryn.ui.file_picker import pick_save_file
                    out = pick_save_file("Save crack result", ".txt")
                    if out:
                        with open(out, "w") as f:
                            f.write(f"Hash:      {hash_value}\n")
                            f.write(f"Type:      {hash_name}\n")
                            f.write(f"Password:  {result['plaintext']}\n")
                        Banner.success(f"Saved to: {out}")
            elif result.get("note"):
                Banner.warn(result["note"])
            else:
                Banner.warn("Hash was not cracked with this strategy.")
                print(f"\n  {Colors.DIM}Tips:{Colors.RESET}")
                print(f"  {Colors.DIM}• Try the Smart Auto attack — it combines multiple methods{Colors.RESET}")
                print(f"  {Colors.DIM}• Make sure rockyou.txt is available (sudo apt install wordlists on Kali){Colors.RESET}")
                print(f"  {Colors.DIM}• Try Expert Mode for advanced hashcat options{Colors.RESET}\n")

        except KeyboardInterrupt:
            Banner.warn("Crack interrupted. Session may be resumable via Expert Mode.")
            Banner.info("In Expert Mode: crack --resume <session_name>")

