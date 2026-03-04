"""
Ixoryn Test Suite
Unit and integration tests for all modules.
Run with: python -m pytest tests/ -v
      or: python tests/test_suite.py
"""

import sys
import os
import json
import tempfile
import hashlib
import struct
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ─────────────────────────────────────────────────────────────────────
# CRYPTOGRAPHY TESTS
# ─────────────────────────────────────────────────────────────────────
class TestCryptoEngine(unittest.TestCase):

    def setUp(self):
        try:
            from ixoryn.modules.crypto.engine import CryptoEngine
            self.engine = CryptoEngine()
        except ImportError as e:
            self.skipTest(f"Crypto dependency missing: {e}")

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt should return original data."""
        data = b"Hello, Ixoryn! This is a test payload."
        password = "TestPassword@2024!"
        encrypted = self.engine.encrypt(data, password)
        decrypted, _ = self.engine.decrypt(encrypted, password)
        self.assertEqual(data, decrypted)

    def test_encrypt_wrong_password_fails(self):
        """Decryption with wrong password should raise ValueError."""
        data = b"Secret data"
        encrypted = self.engine.encrypt(data, "correct_password")
        with self.assertRaises(Exception):
            self.engine.decrypt(encrypted, "wrong_password")

    def test_filename_preserved(self):
        """Filename metadata should survive encrypt/decrypt."""
        data = b"File content"
        encrypted = self.engine.encrypt(data, "pass123", filename="document.pdf")
        _, fname = self.engine.decrypt(encrypted, "pass123")
        self.assertEqual(fname, "document.pdf")

    def test_encrypt_empty_data(self):
        """Empty data should encrypt and decrypt correctly."""
        encrypted = self.engine.encrypt(b"", "password")
        decrypted, _ = self.engine.decrypt(encrypted, "password")
        self.assertEqual(decrypted, b"")

    def test_encrypt_large_data(self):
        """Large data (10MB) should encrypt and decrypt correctly."""
        data = os.urandom(10 * 1024 * 1024)
        encrypted = self.engine.encrypt(data, "large_test_pass")
        decrypted, _ = self.engine.decrypt(encrypted, "large_test_pass")
        self.assertEqual(data, decrypted)

    def test_ciphertext_is_different_each_time(self):
        """Same plaintext encrypted twice should produce different ciphertext (random salt/nonce)."""
        data = b"Same data"
        e1 = self.engine.encrypt(data, "password")
        e2 = self.engine.encrypt(data, "password")
        self.assertNotEqual(e1, e2)

    def test_hash_sha256(self):
        """SHA-256 hash of known input."""
        data = b"abc"
        expected = hashlib.sha256(data).hexdigest()
        result = self.engine.hash_data(data, "SHA-256")
        self.assertEqual(result, expected)

    def test_hash_sha3_256(self):
        """SHA3-256 hash."""
        data = b"test"
        expected = hashlib.sha3_256(data).hexdigest()
        result = self.engine.hash_data(data, "SHA-3-256")
        self.assertEqual(result, expected)

    def test_hash_blake2b(self):
        """BLAKE2b hash."""
        data = b"ixoryn"
        expected = hashlib.blake2b(data).hexdigest()
        result = self.engine.hash_data(data, "BLAKE2b")
        self.assertEqual(result, expected)

    def test_hash_invalid_algorithm(self):
        """Invalid algorithm should raise ValueError."""
        with self.assertRaises(ValueError):
            self.engine.hash_data(b"data", "MD2-BROKEN")

    def test_keypair_generation(self):
        """Key pair generation should produce non-empty keys."""
        priv, pub = self.engine.generate_keypair("keypair_password")
        self.assertGreater(len(priv), 0)
        self.assertGreater(len(pub), 0)
        # Public key should be 32 bytes for Ed25519
        self.assertEqual(len(pub), 32)

    def test_sign_verify_valid(self):
        """Sign data and verify with public key should return True."""
        priv, pub = self.engine.generate_keypair("sign_pass")
        data = b"Data to sign"
        sig = self.engine.sign(data, priv, "sign_pass")
        valid = self.engine.verify(data, sig, pub)
        self.assertTrue(valid)

    def test_verify_tampered_data(self):
        """Verification of tampered data should return False."""
        priv, pub = self.engine.generate_keypair("sign_pass2")
        data = b"Original data"
        sig = self.engine.sign(data, priv, "sign_pass2")
        tampered = b"Tampered data"
        valid = self.engine.verify(tampered, sig, pub)
        self.assertFalse(valid)

    def test_fingerprint_keys_present(self):
        """File fingerprint should include all hash algorithms."""
        data = b"fingerprint test"
        fp = self.engine.get_file_fingerprint(data)
        for key in ("md5", "sha1", "sha256", "sha512", "blake2b"):
            self.assertIn(key, fp)

    def test_magic_bytes_in_output(self):
        """Encrypted output should start with Ixoryn magic bytes."""
        encrypted = self.engine.encrypt(b"test", "pass")
        self.assertTrue(encrypted.startswith(b"IXORYN\x01"))

    def test_unicode_password(self):
        """Unicode passwords should work correctly."""
        data = b"unicode test"
        password = "p@$$w0rd_日本語_🔐"
        encrypted = self.engine.encrypt(data, password)
        decrypted, _ = self.engine.decrypt(encrypted, password)
        self.assertEqual(data, decrypted)


# ─────────────────────────────────────────────────────────────────────
# PASSWORD AUDITOR TESTS
# ─────────────────────────────────────────────────────────────────────
class TestPasswordAuditor(unittest.TestCase):

    def setUp(self):
        from ixoryn.modules.password.auditor import PasswordAuditor
        self.auditor = PasswordAuditor()

    def test_common_password_flagged(self):
        """Common passwords should be flagged."""
        report = self.auditor.audit_password("123456")
        self.assertTrue(report["is_common"])
        self.assertEqual(report["score"], 0)

    def test_strong_password_high_score(self):
        """Very strong passwords should score 3 or 4."""
        report = self.auditor.audit_password("T!m3-C0mpl3x_P@$$w0rd#99XY")
        self.assertGreaterEqual(report["score"], 3)

    def test_short_password_weak(self):
        """Short passwords should score low."""
        report = self.auditor.audit_password("abc")
        self.assertLessEqual(report["score"], 1)

    def test_entropy_positive(self):
        """Entropy should be a positive float."""
        report = self.auditor.audit_password("SomePassword123!")
        self.assertGreater(report["entropy"], 0)

    def test_entropy_increases_with_complexity(self):
        """More complex passwords should have higher entropy."""
        simple = self.auditor.audit_password("password")
        complex_ = self.auditor.audit_password("P@$$w0rd!XyZ_99#AbC")
        self.assertGreater(complex_["entropy"], simple["entropy"])

    def test_charset_detection_lowercase(self):
        """Lowercase-only password should have correct charset."""
        report = self.auditor.audit_password("alllowercase")
        self.assertIn("lowercase", report["charsets_used"])
        self.assertNotIn("uppercase", report["charsets_used"])

    def test_charset_detection_mixed(self):
        """Mixed charset password detected correctly."""
        report = self.auditor.audit_password("Mixed123!@#")
        for cs in ("lowercase", "uppercase", "digits", "special"):
            self.assertIn(cs, report["charsets_used"])

    def test_keyboard_walk_detected(self):
        """Keyboard walks should be detected."""
        report = self.auditor.audit_password("qwerty123")
        pattern_types = [p["type"] for p in report.get("patterns_detected", [])]
        self.assertIn("Keyboard Walk", pattern_types)

    def test_compliance_nist_short_fails(self):
        """Passwords under 8 chars should fail NIST."""
        report = self.auditor.audit_password("short")
        nist = report.get("compliance", {}).get("NIST_SP_800_63B", {})
        self.assertFalse(nist.get("compliant", True))

    def test_compliance_nist_strong_passes(self):
        """Strong password should pass NIST."""
        report = self.auditor.audit_password("LongEnoughAndNotCommon99!")
        nist = report.get("compliance", {}).get("NIST_SP_800_63B", {})
        self.assertTrue(nist.get("compliant", False))

    def test_hash_md5_identified(self):
        """MD5-length hex string should be identified as MD5."""
        md5_hash = hashlib.md5(b"test").hexdigest()
        report = self.auditor.audit_hash(md5_hash)
        algo_names = [m["algorithm"] for m in report.get("likely_types", [])]
        self.assertTrue(any("MD5" in n or "NTLM" in n for n in algo_names))

    def test_hash_sha256_identified(self):
        """SHA-256 hash should be identified."""
        sha256 = hashlib.sha256(b"test").hexdigest()
        report = self.auditor.audit_hash(sha256)
        algo_names = [m["algorithm"] for m in report.get("likely_types", [])]
        self.assertTrue(any("SHA-256" in n or "SHA3-256" in n or "BLAKE2" in n for n in algo_names))

    def test_bcrypt_hash_identified(self):
        """bcrypt hash should be correctly identified."""
        bcrypt_hash = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        report = self.auditor.audit_hash(bcrypt_hash)
        algo_names = [m["algorithm"] for m in report.get("likely_types", [])]
        self.assertTrue(any("bcrypt" in n.lower() for n in algo_names))

    def test_argon2id_hash_identified(self):
        """Argon2id hash should be identified and rated EXCELLENT."""
        argon2_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
        report = self.auditor.audit_hash(argon2_hash)
        algo_names = [m["algorithm"] for m in report.get("likely_types", [])]
        self.assertTrue(any("Argon2id" in n for n in algo_names))

    def test_auto_detects_hash(self):
        """Auto-detect should correctly identify hex as hash."""
        hex_val = "a" * 64  # SHA-256 length
        report = self.auditor.audit_auto(hex_val)
        self.assertEqual(report["type"], "hash")

    def test_auto_detects_password(self):
        """Auto-detect should classify non-hex as password."""
        report = self.auditor.audit_auto("MyNormalPassword")
        self.assertEqual(report["type"], "password")

    def test_report_has_required_fields(self):
        """Password report should have all required fields."""
        report = self.auditor.audit_password("TestPassword123!")
        for field in ("type", "strength", "entropy", "score",
                      "crack_time_display", "compliance", "suggestions"):
            self.assertIn(field, report)


# ─────────────────────────────────────────────────────────────────────
# PASSWORD GENERATOR TESTS
# ─────────────────────────────────────────────────────────────────────
class TestPasswordGenerator(unittest.TestCase):

    def setUp(self):
        from ixoryn.modules.password.generator import PasswordGenerator
        self.gen = PasswordGenerator()

    def test_generate_correct_length(self):
        """Generated password should match requested length."""
        for length in (8, 12, 20, 32, 64):
            pwd = self.gen.generate(length=length)
            self.assertEqual(len(pwd), length)

    def test_generate_high_strength_has_all_charsets(self):
        """High strength passwords should contain all character types."""
        import re
        for _ in range(10):
            pwd = self.gen.generate(length=20, strength="high")
            self.assertTrue(re.search(r"[a-z]", pwd), "Missing lowercase")
            self.assertTrue(re.search(r"[A-Z]", pwd), "Missing uppercase")
            self.assertTrue(re.search(r"\d", pwd), "Missing digit")
            self.assertTrue(re.search(r"[^a-zA-Z0-9]", pwd), "Missing special")

    def test_generate_medium_strength_no_special(self):
        """Medium strength should not require special chars."""
        import re
        pwd = self.gen.generate(length=16, strength="medium")
        # Should have at least upper, lower, digit
        self.assertTrue(re.search(r"[a-z]", pwd))
        self.assertTrue(re.search(r"[A-Z]", pwd))
        self.assertTrue(re.search(r"\d", pwd))

    def test_generate_passphrase(self):
        """Passphrase should contain word separators."""
        pwd = self.gen.generate(length=5, strength="passphrase")
        self.assertGreater(len(pwd), 10)

    def test_passwords_are_unique(self):
        """Two generated passwords should not be identical."""
        passwords = {self.gen.generate(length=20) for _ in range(20)}
        self.assertGreater(len(passwords), 15)

    def test_min_length_enforced(self):
        """Length below 8 should be clamped to 8."""
        pwd = self.gen.generate(length=3)
        self.assertGreaterEqual(len(pwd), 8)


# ─────────────────────────────────────────────────────────────────────
# STEGANOGRAPHY TRAVERSAL TESTS
# ─────────────────────────────────────────────────────────────────────
class TestRandomLSBTraversal(unittest.TestCase):

    def setUp(self):
        from ixoryn.modules.stego.traversal import RandomLSBTraversal
        self.Traversal = RandomLSBTraversal

    def test_sequential_without_password(self):
        """Without password, order should be sequential."""
        t = self.Traversal(None, 100)
        self.assertEqual(t.get_order(), list(range(100)))

    def test_randomized_with_password(self):
        """With password, order should not be sequential."""
        t = self.Traversal("password", 1000)
        order = t.get_order()
        self.assertNotEqual(order, list(range(1000)))

    def test_same_password_same_order(self):
        """Same password and size should produce same order."""
        t1 = self.Traversal("testpass", 500)
        t2 = self.Traversal("testpass", 500)
        self.assertEqual(t1.get_order(), t2.get_order())

    def test_different_password_different_order(self):
        """Different passwords should produce different orders."""
        t1 = self.Traversal("password1", 500)
        t2 = self.Traversal("password2", 500)
        self.assertNotEqual(t1.get_order(), t2.get_order())

    def test_order_is_permutation(self):
        """Order should be a permutation of [0, n)."""
        n = 200
        t = self.Traversal("anypassword", n)
        self.assertEqual(sorted(t.get_order()), list(range(n)))


# ─────────────────────────────────────────────────────────────────────
# STEGANOGRAPHY EMBED/EXTRACT TESTS
# ─────────────────────────────────────────────────────────────────────
class TestStegoEmbedExtract(unittest.TestCase):

    def setUp(self):
        try:
            from PIL import Image
            import numpy as np
            self.pil_available = True
        except ImportError:
            self.pil_available = False

        from ixoryn.modules.stego.embed import StegoEmbed
        from ixoryn.modules.stego.extract import StegoExtract
        self.embed = StegoEmbed()
        self.extract = StegoExtract()
        self.tmpdir = tempfile.mkdtemp()

    def _create_test_image(self, width=200, height=200) -> str:
        """Create a test PNG image."""
        if not self.pil_available:
            self.skipTest("PIL not available")
        from PIL import Image
        import numpy as np
        arr = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
        img = Image.fromarray(arr, "RGB")
        path = os.path.join(self.tmpdir, "cover.png")
        img.save(path, "PNG")
        return path

    def test_text_embed_extract_no_password(self):
        """Embed and extract text without password."""
        cover = self._create_test_image()
        payload = b"Secret message for testing"
        out = os.path.join(self.tmpdir, "stego_text.png")

        result_path = self.embed.embed(cover, payload, "message.txt", out)
        extracted, name = self.extract.extract(result_path, password=None)

        self.assertEqual(extracted, payload)
        self.assertEqual(name, "message.txt")

    def test_file_embed_extract_with_password(self):
        """Embed and extract file with password protection."""
        cover = self._create_test_image(300, 300)
        payload = b"Top secret file content for Ixoryn test"
        out = os.path.join(self.tmpdir, "stego_file.png")
        password = "TestEmbedPass@99"

        result_path = self.embed.embed(cover, payload, "secret.txt", out, password=password)
        extracted, name = self.extract.extract(result_path, password=password)

        self.assertEqual(extracted, payload)

    def test_extract_wrong_password_fails(self):
        """Extracting with wrong password should raise exception."""
        cover = self._create_test_image()
        out = os.path.join(self.tmpdir, "stego_wrong.png")
        self.embed.embed(cover, b"data", "d.txt", out, password="correctpass")

        with self.assertRaises(Exception):
            self.extract.extract(out, password="wrongpass")

    def test_output_is_png(self):
        """Output should always be PNG regardless of input."""
        cover = self._create_test_image()
        out = os.path.join(self.tmpdir, "output.bmp")  # Request BMP

        result = self.embed.embed(cover, b"data", "d.txt", out)
        self.assertTrue(result.endswith(".png"))

    def test_capacity_error_too_large(self):
        """Embedding payload larger than cover capacity should raise ValueError."""
        cover = self._create_test_image(10, 10)  # Very small cover
        huge_payload = os.urandom(10000)  # Way too large

        with self.assertRaises(ValueError):
            self.embed.embed(cover, huge_payload, "huge.bin",
                             os.path.join(self.tmpdir, "fail.png"))

    def test_binary_payload_preserved(self):
        """Binary payloads should be preserved exactly."""
        cover = self._create_test_image(400, 400)
        payload = os.urandom(500)
        out = os.path.join(self.tmpdir, "stego_bin.png")

        result_path = self.embed.embed(cover, payload, "random.bin", out)
        extracted, _ = self.extract.extract(result_path)

        self.assertEqual(extracted, payload)


# ─────────────────────────────────────────────────────────────────────
# URL AUDITOR TESTS
# ─────────────────────────────────────────────────────────────────────
class TestURLAuditor(unittest.TestCase):

    def setUp(self):
        from ixoryn.modules.url_audit.auditor import URLAuditor
        self.auditor = URLAuditor()

    def test_phishing_keywords_detected(self):
        """Phishing keywords in domains should be flagged."""
        report = self.auditor._check_phishing_indicators(
            "http://paypal-secure-login.tk", "paypal-secure-login.tk", "paypal-secure-login"
        )
        self.assertGreater(report["score"], 0)
        self.assertGreater(len(report["indicators"]), 0)

    def test_suspicious_tld_flagged(self):
        """Suspicious TLDs should be detected."""
        report = self.auditor._check_phishing_indicators(
            "http://example.tk", "example.tk", "example.tk"
        )
        self.assertTrue(any(".tk" in ind for ind in report["indicators"]))

    def test_ip_host_flagged(self):
        """IP address as hostname should be flagged."""
        report = self.auditor._check_phishing_indicators(
            "http://192.168.1.1/login", "192.168.1.1", "192.168.1.1"
        )
        self.assertTrue(any("IP" in ind for ind in report["indicators"]))

    def test_homograph_clean_domain(self):
        """ASCII-only domain should not trigger homograph alert."""
        result = self.auditor._check_homograph("google.com")
        self.assertFalse(result.get("is_idn"))
        self.assertEqual(result["risk"], "LOW")

    def test_typosquatting_google(self):
        """'googgle.com' should be flagged as typosquatting google.com."""
        result = self.auditor._check_typosquatting("googgle.com")
        targets = [t["similar_to"] for t in result.get("likely_targets", [])]
        self.assertTrue(any("google" in t for t in targets))

    def test_typosquatting_paypal(self):
        """'paypa1.com' edit distance from paypal should be detected."""
        result = self.auditor._check_typosquatting("paypa1.com")
        targets = result.get("likely_targets", [])
        self.assertGreater(len(targets), 0)

    def test_levenshtein_identical(self):
        """Levenshtein of identical strings is 0."""
        self.assertEqual(self.auditor._levenshtein("google", "google"), 0)

    def test_levenshtein_one_insert(self):
        """Single insertion = distance 1."""
        self.assertEqual(self.auditor._levenshtein("gogle", "google"), 1)

    def test_levenshtein_substitution(self):
        """Single substitution = distance 1."""
        self.assertEqual(self.auditor._levenshtein("geogle", "google"), 1)

    def test_url_structure_analysis(self):
        """URL structure analysis should return correct fields."""
        import urllib.parse
        url = "https://user@example.com:8080/path/to/page?q=1&r=2#frag"
        parsed = urllib.parse.urlparse(url)
        result = self.auditor._analyze_url_structure(url, parsed)
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["query_params"], 2)
        self.assertTrue(result["has_user_info"])
        self.assertEqual(result["port"], 8080)


# ─────────────────────────────────────────────────────────────────────
# REPORT GENERATOR TESTS
# ─────────────────────────────────────────────────────────────────────
class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        from ixoryn.utils.report_generator import ReportGenerator
        self.gen = ReportGenerator()
        self.tmpdir = tempfile.mkdtemp()

    def test_html_url_report_generated(self):
        """HTML URL report should be a valid HTML file."""
        data = {
            "target": "test.example.com",
            "risk_level": "LOW",
            "risk_score": 10,
            "depth": "quick",
            "timestamp": "2024-01-01T00:00:00",
            "findings": [],
            "ssl": {},
            "typosquatting": {},
        }
        out = os.path.join(self.tmpdir, "test_url.html")
        path = self.gen.generate_html(data, "url", out)
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("IXORYN", content)
        self.assertIn("test.example.com", content)

    def test_html_stego_report_generated(self):
        """HTML stego report should contain key fields."""
        data = {
            "file": "/tmp/test.png",
            "filename": "test.png",
            "overall_suspicion": "LOW",
            "suspicion_score": 5.0,
            "verdict": "No stego detected.",
            "findings": [],
            "metadata": {"md5": "abc123", "sha256": "def456", "size_human": "1.0 KB"},
            "analysis": {},
        }
        out = os.path.join(self.tmpdir, "test_stego.html")
        path = self.gen.generate_html(data, "stego", out)
        self.assertTrue(os.path.exists(path))

    def test_html_password_report_generated(self):
        """HTML password report should include strength info."""
        data = {
            "target": "audit",
            "score": 3,
            "strength": "Strong",
            "entropy": 55.2,
            "length": 16,
            "charsets_used": ["lowercase", "uppercase", "digits"],
            "crack_time_display": "Years",
            "is_common": False,
            "warnings": [],
            "suggestions": ["Add special characters"],
            "compliance": {
                "NIST_SP_800_63B": {"compliant": True}
            },
        }
        out = os.path.join(self.tmpdir, "test_pass.html")
        path = self.gen.generate_html(data, "password", out)
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("Strong", content)


# ─────────────────────────────────────────────────────────────────────
# STEGO DETECTOR TESTS
# ─────────────────────────────────────────────────────────────────────
class TestStegoDetector(unittest.TestCase):

    def setUp(self):
        from ixoryn.modules.stego.detector import StegoDetector
        self.detector = StegoDetector()
        self.tmpdir = tempfile.mkdtemp()

    def _create_test_image(self, width=100, height=100) -> str:
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            self.skipTest("PIL not available")
        arr = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
        img = Image.fromarray(arr, "RGB")
        path = os.path.join(self.tmpdir, "test.png")
        img.save(path)
        return path

    def test_report_has_all_fields(self):
        """Forensic report should contain all required top-level fields."""
        path = self._create_test_image()
        report = self.detector.analyze(path)
        for field in ("file", "filename", "file_size", "overall_suspicion",
                      "suspicion_score", "findings", "metadata", "verdict"):
            self.assertIn(field, report)

    def test_clean_image_low_suspicion(self):
        """Clean random image should score low suspicion."""
        path = self._create_test_image()
        report = self.detector.analyze(path)
        self.assertLessEqual(report["suspicion_score"], 60)

    def test_metadata_contains_hashes(self):
        """Metadata should include MD5 and SHA256."""
        path = self._create_test_image()
        meta = self.detector.get_metadata(path)
        self.assertIn("md5", meta)
        self.assertIn("sha256", meta)
        self.assertEqual(len(meta["md5"]), 32)
        self.assertEqual(len(meta["sha256"]), 64)

    def test_entropy_analysis_present(self):
        """Entropy analysis should appear in analysis section."""
        path = self._create_test_image()
        report = self.detector.analyze(path)
        self.assertIn("entropy", report.get("analysis", {}))


# ─────────────────────────────────────────────────────────────────────
# BOOTSTRAP / CORE TESTS
# ─────────────────────────────────────────────────────────────────────
class TestBootstrap(unittest.TestCase):

    def test_bootstrap_creates_dirs(self):
        """Bootstrap should create required directories."""
        from ixoryn.core.bootstrap import Bootstrap
        b = Bootstrap()
        b.initialize()
        self.assertTrue(b.home_dir.exists())
        self.assertTrue(b.logs_dir.exists())
        self.assertTrue(b.output_dir.exists())

    def test_config_created(self):
        """Config file should be created on initialization."""
        from ixoryn.core.bootstrap import Bootstrap
        b = Bootstrap()
        b.initialize()
        self.assertTrue(b.config_file.exists())

    def test_config_valid_json(self):
        """Config file should contain valid JSON."""
        from ixoryn.core.bootstrap import Bootstrap
        b = Bootstrap()
        b.initialize()
        config = b.get_config()
        self.assertIsInstance(config, dict)
        self.assertIn("version", config)


# ─────────────────────────────────────────────────────────────────────
# TEST RUNNER
# ─────────────────────────────────────────────────────────────────────
def run_tests():
    """Run all tests with detailed output."""
    print("\n" + "=" * 70)
    print("  IXORYN TEST SUITE")
    print("=" * 70 + "\n")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestCryptoEngine,
        TestPasswordAuditor,
        TestPasswordGenerator,
        TestRandomLSBTraversal,
        TestStegoEmbedExtract,
        TestURLAuditor,
        TestReportGenerator,
        TestStegoDetector,
        TestBootstrap,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    print(f"  Tests run:    {result.testsRun}")
    print(f"  Failures:     {len(result.failures)}")
    print(f"  Errors:       {len(result.errors)}")
    print(f"  Skipped:      {len(result.skipped)}")
    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"  Passed:       {passed}")
    status = "ALL TESTS PASSED" if result.wasSuccessful() else "SOME TESTS FAILED"
    print(f"\n  Status: {status}")
    print("=" * 70 + "\n")

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())


class TestNetworkScanner(unittest.TestCase):
    """Tests for the new NetworkScanner module."""

    def setUp(self):
        from ixoryn.modules.network.scanner import NetworkScanner
        self.scanner = NetworkScanner(timeout=1.0)

    def test_scanner_instantiation(self):
        """NetworkScanner should instantiate without error."""
        from ixoryn.modules.network.scanner import NetworkScanner
        scanner = NetworkScanner()
        self.assertIsNotNone(scanner)

    def test_parse_ports_quick(self):
        """Quick depth returns common ports list."""
        ports = self.scanner._parse_ports(None, "quick")
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(22, ports)

    def test_parse_ports_custom(self):
        """Custom port string is parsed correctly."""
        ports = self.scanner._parse_ports("22,80,443", "standard")
        self.assertEqual(sorted(ports), [22, 80, 443])

    def test_parse_ports_range(self):
        """Port range string is expanded correctly."""
        ports = self.scanner._parse_ports("80-85", "standard")
        self.assertEqual(ports, [80, 81, 82, 83, 84, 85])

    def test_os_fingerprint_returns_dict(self):
        """OS fingerprinting returns a dict with os key."""
        result = self.scanner._os_fingerprint("127.0.0.1", [])
        self.assertIsInstance(result, dict)
        self.assertIn("os", result)
        self.assertIn("confidence", result)

    def test_vulnerability_analysis_dangerous_ports(self):
        """Dangerous ports should generate vulnerability findings."""
        fake_ports = [
            {"port": 6379, "service": "Redis", "banner": "Redis 3.2.1",
             "version": None, "ssl": False, "vulnerabilities": [],
             "http_analysis": None, "ssl_cert": None}
        ]
        vulns = self.scanner._analyze_vulnerabilities(fake_ports)
        self.assertTrue(any(v["port"] == 6379 for v in vulns))
        # Redis exposed should be CRITICAL
        redis_vulns = [v for v in vulns if v["port"] == 6379]
        self.assertEqual(redis_vulns[0]["severity"], "CRITICAL")

    def test_version_parsing(self):
        """Version strings should be extracted from banners."""
        banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        version = self.scanner._parse_version(banner, 22)
        self.assertIsNotNone(version)
        self.assertIn("OpenSSH", version)

    def test_risk_compute_low(self):
        """No vulnerabilities should yield low risk."""
        report = {"vulnerabilities": [], "open_ports": []}
        self.scanner._compute_risk(report)
        self.assertEqual(report["risk_level"], "LOW")

    def test_risk_compute_critical(self):
        """Critical vulnerabilities should yield critical risk."""
        report = {
            "vulnerabilities": [
                {"severity": "CRITICAL"}, {"severity": "CRITICAL"},
                {"severity": "HIGH"}
            ],
            "open_ports": []
        }
        self.scanner._compute_risk(report)
        self.assertIn(report["risk_level"], ("CRITICAL", "HIGH"))

    def test_scan_localhost(self):
        """Scanning localhost should succeed and return a report dict."""
        result = self.scanner.scan("127.0.0.1", ports="22,80,443", depth="quick")
        self.assertIn("target", result)
        self.assertIn("open_ports", result)
        self.assertIn("risk_level", result)
        self.assertIsInstance(result["open_ports"], list)


class TestSubdomainEnumerator(unittest.TestCase):
    """Tests for the SubdomainEnumerator module."""

    def setUp(self):
        from ixoryn.modules.network.subdomain import SubdomainEnumerator
        self.enumerator = SubdomainEnumerator(timeout=2.0, max_threads=20)

    def test_enumerator_instantiation(self):
        """SubdomainEnumerator instantiates correctly."""
        from ixoryn.modules.network.subdomain import SubdomainEnumerator
        e = SubdomainEnumerator()
        self.assertIsNotNone(e)

    def test_dns_bruteforce_localhost(self):
        """Brute-force against localhost domain should return list."""
        result = self.enumerator._dns_bruteforce("localhost", ["www", "mail", "ftp"])
        self.assertIsInstance(result, list)

    def test_enumerate_returns_dict(self):
        """Enumerate returns properly structured dict."""
        result = self.enumerator.enumerate(
            "example.com",
            methods=["bruteforce"],
            wordlist=["www", "mail"]
        )
        self.assertIn("domain", result)
        self.assertIn("subdomains", result)
        self.assertIn("total_found", result)
        self.assertIn("by_method", result)
        self.assertIsInstance(result["subdomains"], list)

    def test_resolve_all_returns_list(self):
        """_resolve_all returns list of dicts with subdomain and ip."""
        results = self.enumerator._resolve_all(["www.google.com"], "google.com")
        self.assertIsInstance(results, list)
        if results:
            self.assertIn("subdomain", results[0])
            self.assertIn("ip", results[0])


class TestBreachIntelligence(unittest.TestCase):
    """Tests for BreachIntelligence module."""

    def setUp(self):
        from ixoryn.modules.network.breach_intel import BreachIntelligence
        self.intel = BreachIntelligence()

    def test_password_check_common(self):
        """Common password 'password' should be found in breaches."""
        result = self.intel.check_password_pwned("password")
        self.assertIn("pwned", result)
        self.assertIn("pwned_count", result)
        self.assertIn("method", result)
        # 'password' is in every breach database
        if not result.get("error"):
            self.assertTrue(result["pwned"])
            self.assertGreater(result["pwned_count"], 1000)

    def test_password_check_unique(self):
        """Unique random password should not be found in breaches."""
        import uuid
        unique_pass = f"IxorynTest_{uuid.uuid4().hex}_XqZ9!"
        result = self.intel.check_password_pwned(unique_pass)
        self.assertIn("pwned", result)
        if not result.get("error"):
            self.assertFalse(result["pwned"])

    def test_password_check_k_anonymity(self):
        """Only SHA1 prefix should be sent — method confirms k-Anonymity."""
        result = self.intel.check_password_pwned("test")
        self.assertIn("k-Anonymity", result.get("method", ""))

    def test_email_check_no_key(self):
        """Email check without API key should return helpful error."""
        result = self.intel.check_email_breached("test@example.com")
        self.assertIn("error", result)
        self.assertIn("hibp", result["error"].lower())

    def test_format_password_check_pwned(self):
        """Format function produces non-empty string output."""
        fake_result = {
            "pwned": True, "pwned_count": 5000000,
            "severity": "CRITICAL",
            "message": "Change this immediately",
            "method": "k-Anonymity",
            "source": "HIBP"
        }
        output = self.intel.format_password_check(fake_result)
        self.assertIsInstance(output, str)
        self.assertGreater(len(output), 10)


class TestCVELookup(unittest.TestCase):
    """Tests for CVELookup module."""

    def setUp(self):
        from ixoryn.modules.network.cve_lookup import CVELookup
        self.lookup = CVELookup()

    def test_cve_instantiation(self):
        """CVELookup instantiates correctly."""
        from ixoryn.modules.network.cve_lookup import CVELookup
        l = CVELookup()
        self.assertIsNotNone(l)

    def test_score_to_severity(self):
        """CVSS score correctly maps to severity."""
        self.assertEqual(self.lookup._score_to_severity(9.8), "CRITICAL")
        self.assertEqual(self.lookup._score_to_severity(7.5), "HIGH")
        self.assertEqual(self.lookup._score_to_severity(5.0), "MEDIUM")
        self.assertEqual(self.lookup._score_to_severity(2.0), "LOW")
        self.assertEqual(self.lookup._score_to_severity(None), "UNKNOWN")

    def test_lookup_result_structure(self):
        """CVE lookup returns properly structured dict even on network error."""
        # Use cache to avoid actual network call in tests
        result = {
            "software": "test",
            "version": "1.0",
            "cves": [],
            "critical_count": 0,
            "high_count": 0,
            "source": "NVD/NIST",
            "queried_at": "2024-01-01T00:00:00",
            "error": None,
        }
        formatted = self.lookup.format_results(result)
        self.assertIsInstance(formatted, str)

    def test_cve_caching(self):
        """Same query should use cache on second call."""
        cache_key = "test_software:1.0"
        self.lookup.cache[cache_key] = {"software": "test", "cves": [], "critical_count": 0, "high_count": 0}
        result = self.lookup.lookup_software("test_software", "1.0")
        self.assertEqual(result["software"], "test")

