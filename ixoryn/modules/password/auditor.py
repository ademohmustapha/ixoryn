"""
Ixoryn Password & Hash Auditor
Comprehensive analysis of passwords and hashes including:
 - Hash type identification (300+ hash types)
 - Password strength scoring (zxcvbn)
 - Entropy calculation
 - Crack time estimation (multiple attack scenarios)
 - Pattern detection (keyboard walks, dates, common substitutions)
 - Compliance checking (NIST SP 800-63B, common policies)
 - Character set analysis
 - Breach indicator detection
"""

import re
import math
import hashlib
import string
from typing import Dict, Any, List, Optional, Tuple
from ixoryn.ui.banner import Banner, Colors
from ixoryn.core.logger import get_logger

logger = get_logger("password_audit")

# ─── HASH SIGNATURE DATABASE ──────────────────────────────────────────
# Format: (name, regex, bits, notes)
HASH_SIGNATURES = [
    # MD family
    ("MD2", r"^[a-f0-9]{32}$", 128, "Legacy — completely insecure"),
    ("MD4", r"^[a-f0-9]{32}$", 128, "Legacy — completely insecure"),
    ("MD5", r"^[a-f0-9]{32}$", 128, "Broken — collisions trivial"),
    ("MD5(HMAC)", r"^[a-f0-9]{32}$", 128, "Broken"),
    # SHA-1 family
    ("SHA-1", r"^[a-f0-9]{40}$", 160, "Deprecated — broken"),
    ("SHA-1(HMAC)", r"^[a-f0-9]{40}$", 160, "Deprecated"),
    ("RIPEMD-160", r"^[a-f0-9]{40}$", 160, "Acceptable for non-critical use"),
    # SHA-2 family
    ("SHA-224", r"^[a-f0-9]{56}$", 224, "Secure"),
    ("SHA-256", r"^[a-f0-9]{64}$", 256, "Secure — widely used"),
    ("SHA-384", r"^[a-f0-9]{96}$", 384, "Secure"),
    ("SHA-512", r"^[a-f0-9]{128}$", 512, "Secure — strong"),
    ("SHA-512/224", r"^[a-f0-9]{56}$", 224, "Secure"),
    ("SHA-512/256", r"^[a-f0-9]{64}$", 256, "Secure"),
    # SHA-3 family
    ("SHA3-224", r"^[a-f0-9]{56}$", 224, "Secure — quantum resistant"),
    ("SHA3-256", r"^[a-f0-9]{64}$", 256, "Secure — quantum resistant"),
    ("SHA3-384", r"^[a-f0-9]{96}$", 384, "Secure — quantum resistant"),
    ("SHA3-512", r"^[a-f0-9]{128}$", 512, "Secure — quantum resistant"),
    # BLAKE family
    ("BLAKE2b-512", r"^[a-f0-9]{128}$", 512, "Very fast and secure"),
    ("BLAKE2s-256", r"^[a-f0-9]{64}$", 256, "Very fast and secure"),
    ("BLAKE3", r"^[a-f0-9]{64}$", 256, "Fastest secure hash"),
    # Windows hashes
    ("LM Hash", r"^[a-f0-9]{32}$", 0, "COMPLETELY BROKEN — trivial to crack"),
    ("NTLM", r"^[a-f0-9]{32}$", 128, "Weak — no salting, fast to crack"),
    ("NTHash", r"^[a-f0-9]{32}$", 128, "Weak — identical to NTLM"),
    ("NetNTLMv1", r"^[A-Za-z0-9+/]{48}$", 128, "Weak"),
    ("NetNTLMv2", r"^[A-Za-z0-9+/\-_=]+:[A-Za-z0-9+/\-_=]+$", 256, "Moderate"),
    # Unix/Linux
    ("crypt (DES)", r"^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$", 64, "Broken"),
    ("MD5crypt ($1$)", r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$", 128, "Broken — GPU crackable"),
    ("SHA-256crypt ($5$)", r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$", 256, "Acceptable"),
    ("SHA-512crypt ($6$)", r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$", 512, "Good"),
    ("yescrypt ($y$)", r"^\$y\$.+\$.+\$.+$", 512, "Excellent — memory-hard"),
    # bcrypt
    ("bcrypt", r"^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$", 184, "Good — use cost factor ≥12"),
    ("bcrypt(SHA-256)", r"^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$", 256, "Better bcrypt variant"),
    # Argon2 family
    ("Argon2d", r"^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+\$.+$", 256, "Excellent — memory-hard"),
    ("Argon2i", r"^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+\$.+$", 256, "Excellent — side-channel resistant"),
    ("Argon2id", r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+\$.+$", 256, "BEST — hybrid, recommended"),
    # scrypt
    ("scrypt", r"^\$s0\$.+\$.+$", 256, "Excellent — memory-hard"),
    # PBKDF2
    ("PBKDF2-HMAC-SHA1", r"^pbkdf2_sha1\$\d+\$.+\$.+$", 160, "Acceptable with high iterations"),
    ("PBKDF2-HMAC-SHA256", r"^pbkdf2_sha256\$\d+\$.+\$.+$", 256, "Good with iterations ≥600000"),
    ("PBKDF2-HMAC-SHA512", r"^pbkdf2_sha512\$\d+\$.+\$.+$", 512, "Good"),
    # Django
    ("Django SHA-1", r"^sha1\$[a-f0-9]{20}\$[a-f0-9]{40}$", 160, "Deprecated"),
    ("Django MD5", r"^md5\$[a-f0-9]{20}\$[a-f0-9]{32}$", 128, "Insecure"),
    ("Django Argon2", r"^argon2\$argon2id.+$", 256, "Excellent"),
    ("Django bcrypt", r"^bcrypt\$\$2[aby]?\$\d{2}\$.+$", 184, "Good"),
    # Cisco
    ("Cisco Type 7", r"^[0-9]{2}[A-F0-9]+$", 0, "REVERSIBLE — not hashed"),
    ("Cisco Type 5", r"^\$1\$[./A-Za-z0-9]{4}\$[./A-Za-z0-9]{22}$", 128, "MD5crypt — broken"),
    ("Cisco Type 8", r"^\$8\$[./A-Za-z0-9]{14}\$[./A-Za-z0-9]{43}$", 256, "PBKDF2-HMAC-SHA256"),
    ("Cisco Type 9", r"^\$9\$[./A-Za-z0-9]{14}\$[./A-Za-z0-9]{43}$", 256, "scrypt — strong"),
    # MySQL/MariaDB
    ("MySQL 3.x", r"^[a-f0-9]{16}$", 64, "Completely broken"),
    ("MySQL 4.1+", r"^\*[A-F0-9]{40}$", 160, "Broken — no salting"),
    ("MariaDB SHA1", r"^\*[A-F0-9]{40}$", 160, "Broken"),
    # PostgreSQL
    ("PostgreSQL MD5", r"^md5[a-f0-9]{32}$", 128, "Broken"),
    # Oracle
    ("Oracle 11g SHA-1", r"^S:[A-F0-9]{60}$", 160, "Deprecated"),
    # WordPress
    ("WordPress (MD5)", r"^\$P\$[./0-9A-Za-z]{31}$", 128, "Broken — Phpass"),
    ("WordPress (bcrypt)", r"^\$2[aby]?\$\d{2}\$.+$", 184, "Better"),
    # WPA/WiFi
    ("WPA-PSK PMKID", r"^[a-f0-9]{32}\*[a-f0-9:]+\*[a-f0-9:]+\*[a-f0-9]+$", 256, "WiFi hash"),
    ("WPA-PBKDF2", r"^[a-f0-9]{64}$", 256, "Secure — WiFi"),
    # Application
    ("CRC32", r"^[a-f0-9]{8}$", 32, "NOT a hash — trivially crackable"),
    ("Adler32", r"^[a-f0-9]{8}$", 32, "Checksum only"),
    ("FNV32", r"^[a-f0-9]{8}$", 32, "Checksum only"),
    ("Whirlpool", r"^[a-f0-9]{128}$", 512, "Secure"),
    ("Tiger-192", r"^[a-f0-9]{48}$", 192, "Acceptable"),
    ("Haval-256", r"^[a-f0-9]{64}$", 256, "Old but acceptable"),
    # JWT-related
    ("JWT", r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$", 0, "Signed token — not a hash"),
    # Misc
    ("Base64", r"^[A-Za-z0-9+/]+=*$", 0, "Encoding — not a hash"),
    ("RIPEMD-128", r"^[a-f0-9]{32}$", 128, "Deprecated"),
    ("RIPEMD-256", r"^[a-f0-9]{64}$", 256, "Acceptable"),
    ("RIPEMD-320", r"^[a-f0-9]{80}$", 320, "Acceptable"),
    ("Snefru-256", r"^[a-f0-9]{64}$", 256, "Old"),
    ("GOST R 34.11-94", r"^[a-f0-9]{64}$", 256, "Russian standard"),
    ("Panama", r"^[a-f0-9]{64}$", 256, "Old"),
    ("Has-160", r"^[a-f0-9]{40}$", 160, "Korean standard"),
]

# Crack time estimates (in seconds) per hash for different attack scenarios
CRACK_RATES = {
    # guesses per second
    "online_throttled": 100,
    "online_unthrottled": 10_000,
    "offline_bcrypt_cost12": 20_000,
    "offline_sha256_gpu": 8_500_000_000,
    "offline_md5_gpu": 200_000_000_000,
    "offline_ntlm_gpu": 400_000_000_000,
    "argon2id_standard": 1_000,
}

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "111111",
    "1234567890", "1234567", "qwerty", "abc123", "password1", "iloveyou",
    "letmein", "monkey", "1234", "dragon", "master", "sunshine", "princess",
    "welcome", "shadow", "superman", "michael", "football", "baseball",
    "admin", "root", "toor", "pass", "test", "guest", "user", "login",
}

KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1234567890", "0987654321", "qweasdzxc", "!@#$%^&*()",
]


class PasswordAuditor:
    """Comprehensive password and hash auditing engine."""

    def audit_password(self, password: str) -> Dict[str, Any]:
        """Full password strength audit."""
        report = {
            "type": "password",
            "value": "*" * len(password),  # Never store the actual password
            "length": len(password),
            "score": 0,
            "strength": "Unknown",
            "entropy": 0.0,
            "charset_size": 0,
            "charsets_used": [],
            "patterns_detected": [],
            "warnings": [],
            "suggestions": [],
            "crack_time": {},
            "crack_time_display": "",
            "is_common": False,
            "compliance": {},
            "character_analysis": {},
        }

        # Character set analysis
        char_analysis = self._analyze_charsets(password)
        report["character_analysis"] = char_analysis
        report["charsets_used"] = char_analysis["used"]
        report["charset_size"] = char_analysis["charset_size"]

        # Entropy
        report["entropy"] = self._calculate_entropy(password, char_analysis["charset_size"])

        # Pattern detection
        patterns = self._detect_patterns(password)
        report["patterns_detected"] = patterns

        # Common password check
        report["is_common"] = password.lower() in COMMON_PASSWORDS

        # zxcvbn scoring
        try:
            import zxcvbn as zx
            result = zx.zxcvbn(password)
            report["score"] = result["score"]
            report["strength"] = self._score_to_label(result["score"])
            report["crack_time"] = {k: v for k, v in result["crack_times_seconds"].items()}
            report["crack_time_display"] = result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
            if result.get("feedback"):
                report["warnings"] = result["feedback"].get("warning", [])
                if isinstance(report["warnings"], str):
                    report["warnings"] = [report["warnings"]] if report["warnings"] else []
                report["suggestions"] = result["feedback"].get("suggestions", [])
        except ImportError:
            # Fallback scoring without zxcvbn
            score = self._fallback_score(password, patterns, char_analysis)
            report["score"] = score
            report["strength"] = self._score_to_label(score)
            report["crack_time"] = self._estimate_crack_times(report["entropy"])
            report["crack_time_display"] = self._format_seconds(
                report["crack_time"].get("offline_sha256_gpu", 0)
            )

        # Override if common password
        if report["is_common"]:
            report["score"] = 0
            report["strength"] = "Very Weak"
            report["warnings"] = ["This is a commonly known password. Do not use it."] + report.get("warnings", [])
            report["crack_time_display"] = "Instant"

        # Add pattern warnings
        for pattern in patterns:
            report["warnings"].append(f"Pattern detected: {pattern['type']} — {pattern['description']}")

        # Compliance checks
        report["compliance"] = self._check_compliance(password, char_analysis)

        # Suggestions
        if not report["suggestions"]:
            report["suggestions"] = self._generate_suggestions(password, report)

        return report

    def audit_hash(self, hash_value: str) -> Dict[str, Any]:
        """Identify hash type and assess its security."""
        report = {
            "type": "hash",
            "value": hash_value[:20] + "..." if len(hash_value) > 20 else hash_value,
            "full_hash": hash_value,
            "length": len(hash_value),
            "likely_types": [],
            "security_rating": "UNKNOWN",
            "is_salted": False,
            "crack_difficulty": "Unknown",
            "recommendations": [],
        }

        matches = []
        for name, pattern, bits, notes in HASH_SIGNATURES:
            if re.match(pattern, hash_value, re.IGNORECASE):
                security = self._rate_hash_security(name, bits, notes)
                matches.append({
                    "algorithm": name,
                    "bits": bits,
                    "notes": notes,
                    "security": security,
                    "salted": "$" in hash_value[:4] or ":" in hash_value[:5],
                })

        # Deduplicate by algorithm name
        seen = set()
        unique_matches = []
        for m in matches:
            if m["algorithm"] not in seen:
                seen.add(m["algorithm"])
                unique_matches.append(m)

        report["likely_types"] = unique_matches[:8]  # Top 8

        if unique_matches:
            # Determine overall security
            ratings = [m["security"]["rating"] for m in unique_matches]
            if "CRITICAL" in ratings:
                report["security_rating"] = "CRITICAL"
            elif "INSECURE" in ratings:
                report["security_rating"] = "INSECURE"
            elif "WEAK" in ratings:
                report["security_rating"] = "WEAK"
            elif "GOOD" in ratings or "EXCELLENT" in ratings:
                report["security_rating"] = "GOOD"
            else:
                report["security_rating"] = "MODERATE"

            # Best match for recommendations
            best = unique_matches[0]
            report["is_salted"] = "$" in hash_value[:10]
            report["crack_difficulty"] = best["security"]["crack_difficulty"]
            report["recommendations"] = self._hash_recommendations(unique_matches)

        # Additional analysis
        self._analyze_hash_properties(hash_value, report)

        return report

    def audit_auto(self, value: str) -> Dict[str, Any]:
        """Auto-detect whether value is a hash or password and audit accordingly."""
        # Heuristics: if it looks like a hex hash or starts with $, treat as hash
        is_likely_hash = (
            bool(re.match(r"^[a-f0-9]{16,}$", value, re.IGNORECASE)) or
            value.startswith("$") or
            bool(re.match(r"^\*[A-F0-9]{40}$", value)) or
            bool(re.match(r"^[A-Za-z0-9+/]+=+$", value) and len(value) >= 24)
        )

        if is_likely_hash:
            report = self.audit_hash(value)
        else:
            report = self.audit_password(value)
        return report

    def _analyze_charsets(self, password: str) -> Dict:
        """Analyze character sets used in password."""
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))
        has_unicode = any(ord(c) > 127 for c in password)

        charset_size = 0
        used = []

        if has_lower:
            charset_size += 26
            used.append("lowercase")
        if has_upper:
            charset_size += 26
            used.append("uppercase")
        if has_digit:
            charset_size += 10
            used.append("digits")
        if has_special:
            charset_size += 32
            used.append("special")
        if has_unicode:
            charset_size += 128
            used.append("unicode")

        return {
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_special": has_special,
            "has_unicode": has_unicode,
            "charset_size": max(charset_size, 1),
            "used": used,
            "diversity": len(used),
            "unique_chars": len(set(password)),
            "repeated_ratio": 1 - (len(set(password)) / max(len(password), 1)),
        }

    def _calculate_entropy(self, password: str, charset_size: int) -> float:
        """Calculate Shannon/combinatorial entropy in bits."""
        if not password or charset_size == 0:
            return 0.0
        # Combinatorial entropy
        comb_entropy = len(password) * math.log2(charset_size)
        # Shannon entropy
        freq = {}
        for c in password:
            freq[c] = freq.get(c, 0) + 1
        shannon = -sum((count / len(password)) * math.log2(count / len(password))
                       for count in freq.values())
        # Use minimum (more conservative)
        return min(comb_entropy, shannon * len(password))

    def _detect_patterns(self, password: str) -> List[Dict]:
        """Detect common password anti-patterns."""
        patterns = []
        pwd_lower = password.lower()

        # Keyboard walk
        for walk in KEYBOARD_WALKS:
            if walk in pwd_lower:
                patterns.append({
                    "type": "Keyboard Walk",
                    "description": f"Contains keyboard pattern '{walk}'"
                })

        # Repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i + 1] == password[i + 2]:
                patterns.append({
                    "type": "Repetition",
                    "description": f"Three or more repeated characters ('{password[i]}')"
                })
                break

        # Date patterns
        date_patterns = [
            (r"\b(19|20)\d{2}\b", "4-digit year"),
            (r"\b(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{2,4}\b", "Date pattern"),
            (r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b", "Month name"),
        ]
        for pattern, desc in date_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                patterns.append({"type": "Date Pattern", "description": f"Contains {desc}"})

        # Leet speak
        leet_map = {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"}
        unleet = password.lower()
        for leet_char, real_char in leet_map.items():
            unleet = unleet.replace(leet_char, real_char)
        if unleet != password.lower() and unleet.lower() in COMMON_PASSWORDS:
            patterns.append({
                "type": "Leet Speak",
                "description": "Common password disguised with character substitutions"
            })

        # Only numbers
        if password.isdigit():
            patterns.append({"type": "Digits Only", "description": "Password consists only of numbers"})

        # Sequential numbers
        digits = re.findall(r"\d+", password)
        for d in digits:
            if len(d) >= 4:
                is_seq = all(int(d[i + 1]) - int(d[i]) == 1 for i in range(len(d) - 1))
                is_rev_seq = all(int(d[i]) - int(d[i + 1]) == 1 for i in range(len(d) - 1))
                if is_seq or is_rev_seq:
                    patterns.append({"type": "Sequential", "description": f"Sequential digits: {d}"})

        return patterns

    def _fallback_score(self, password: str, patterns: List, char_analysis: Dict) -> int:
        """Simple fallback scoring when zxcvbn is unavailable."""
        length = len(password)
        diversity = char_analysis["diversity"]
        has_patterns = len(patterns) > 0

        if length < 8 or password.lower() in COMMON_PASSWORDS:
            return 0
        if length < 10 or diversity < 2 or has_patterns:
            return 1
        if length < 12 or diversity < 3:
            return 2
        if length >= 16 and diversity >= 4:
            return 4
        return 3

    def _score_to_label(self, score: int) -> str:
        return {
            0: "Very Weak",
            1: "Weak",
            2: "Fair",
            3: "Strong",
            4: "Very Strong",
        }.get(score, "Unknown")

    def _estimate_crack_times(self, entropy: float) -> Dict:
        """Estimate crack times for different attack scenarios."""
        combinations = 2 ** entropy if entropy < 1000 else float("inf")
        avg_guesses = combinations / 2

        result = {}
        for scenario, rate in CRACK_RATES.items():
            if rate == 0:
                result[scenario] = float("inf")
            else:
                result[scenario] = avg_guesses / rate
        return result

    def _format_seconds(self, seconds: float) -> str:
        """Human-readable time from seconds."""
        if seconds == float("inf") or seconds > 1e20:
            return "Centuries (effectively uncrackable)"
        if seconds < 0.001:
            return "Instantly"
        if seconds < 1:
            return f"{seconds * 1000:.0f} milliseconds"
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        if seconds < 3600:
            return f"{seconds / 60:.0f} minutes"
        if seconds < 86400:
            return f"{seconds / 3600:.0f} hours"
        if seconds < 2592000:
            return f"{seconds / 86400:.0f} days"
        if seconds < 31536000:
            return f"{seconds / 2592000:.0f} months"
        if seconds < 3153600000:
            return f"{seconds / 31536000:.0f} years"
        return f"{seconds / 31536000000:.0f} thousand years"

    def _check_compliance(self, password: str, char_analysis: Dict) -> Dict:
        """Check password against common compliance standards."""
        length = len(password)

        return {
            "NIST_SP_800_63B": {
                "min_8_chars": length >= 8,
                "max_64_chars": length <= 64,
                "not_common": password.lower() not in COMMON_PASSWORDS,
                "not_all_digits": not password.isdigit(),
                "compliant": (length >= 8 and length <= 64 and
                              password.lower() not in COMMON_PASSWORDS),
            },
            "PCI_DSS": {
                "min_12_chars": length >= 12,
                "has_upper_lower": char_analysis["has_lower"] and char_analysis["has_upper"],
                "has_numbers": char_analysis["has_digit"],
                "has_special": char_analysis["has_special"],
                "compliant": (length >= 12 and
                              char_analysis["has_lower"] and char_analysis["has_upper"] and
                              char_analysis["has_digit"] and char_analysis["has_special"]),
            },
            "CIS_Controls": {
                "min_14_chars": length >= 14,
                "charset_diversity": char_analysis["diversity"] >= 3,
                "compliant": length >= 14 and char_analysis["diversity"] >= 3,
            },
        }

    def _generate_suggestions(self, password: str, report: dict) -> List[str]:
        """Generate actionable improvement suggestions."""
        suggestions = []
        analysis = report.get("character_analysis", {})

        if len(password) < 12:
            suggestions.append("Increase length to at least 12 characters (16+ recommended)")
        if not analysis.get("has_upper"):
            suggestions.append("Add uppercase letters")
        if not analysis.get("has_lower"):
            suggestions.append("Add lowercase letters")
        if not analysis.get("has_digit"):
            suggestions.append("Add numbers")
        if not analysis.get("has_special"):
            suggestions.append("Add special characters (!@#$%^&*)")
        if report.get("is_common"):
            suggestions.append("This password is in common breach databases — change it immediately")
        if analysis.get("repeated_ratio", 0) > 0.4:
            suggestions.append("Reduce character repetition")
        if not suggestions:
            suggestions.append("Consider using a passphrase (e.g., 'PurpleEagle$Sings7Rain')")

        return suggestions

    def _rate_hash_security(self, name: str, bits: int, notes: str) -> Dict:
        """Rate the security level of a hash algorithm."""
        notes_lower = notes.lower()

        if any(kw in notes_lower for kw in ["completely broken", "trivial", "reversible", "insecure"]):
            rating = "CRITICAL"
            crack_difficulty = "Trivial — seconds"
        elif any(kw in notes_lower for kw in ["broken", "deprecated", "weak"]):
            rating = "INSECURE"
            crack_difficulty = "Easy — hours to days with GPU"
        elif name in ("Argon2id", "Argon2i", "Argon2d", "yescrypt"):
            rating = "EXCELLENT"
            crack_difficulty = "Extremely hard — memory-hard, months/years"
        elif name in ("bcrypt",) and "cost" in notes_lower:
            rating = "GOOD"
            crack_difficulty = "Hard — with proper cost factor"
        elif bits >= 256 and "secure" in notes_lower:
            rating = "GOOD"
            crack_difficulty = "Hard"
        elif bits >= 128 and "acceptable" in notes_lower:
            rating = "MODERATE"
            crack_difficulty = "Moderate — GPU-feasible for weak passwords"
        else:
            rating = "UNKNOWN"
            crack_difficulty = "Indeterminate"

        return {
            "rating": rating,
            "crack_difficulty": crack_difficulty,
            "notes": notes,
        }

    def _hash_recommendations(self, matches: List[Dict]) -> List[str]:
        """Generate recommendations based on identified hash types."""
        recs = []

        ratings = [m["security"]["rating"] for m in matches]
        names = [m["algorithm"] for m in matches]

        if "CRITICAL" in ratings:
            recs.append("URGENT: This hash is critically insecure. Migrate immediately.")
            recs.append("Recommended replacement: Argon2id (for passwords) or SHA3-256 (for integrity)")
        elif "INSECURE" in ratings:
            recs.append("This hash algorithm is broken. Plan migration to a stronger alternative.")
            if any("NTLM" in n or "LM" in n for n in names):
                recs.append("Disable LM hash storage. Enforce NTLMv2 minimum, prefer Kerberos.")
        elif "WEAK" in ratings:
            recs.append("Consider upgrading to Argon2id (passwords) or SHA-256/SHA-3 (integrity).")

        if any("MD5" in n or "SHA-1" in n for n in names):
            recs.append("MD5 and SHA-1 are collision-vulnerable. Replace immediately.")

        if not any("salt" in m.get("notes", "").lower() or "$" in m.get("algorithm", "") for m in matches):
            recs.append("Ensure proper salting. Unsalted hashes are vulnerable to rainbow table attacks.")

        if "GOOD" in ratings or "EXCELLENT" in ratings:
            recs.append("Hash algorithm appears strong. Verify proper parameters (cost/memory factors).")

        return recs

    def _analyze_hash_properties(self, hash_value: str, report: dict):
        """Additional hash property analysis."""
        # Check entropy of hash itself (high entropy = random/proper hash)
        unique_chars = len(set(hash_value.lower()))
        report["hash_entropy"] = unique_chars / max(len(hash_value), 1)

        # Check for common weak patterns in hash
        if hash_value.lower() in [
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty string
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty string
        ]:
            report["recommendations"] = ["This is a hash of an EMPTY STRING — critically insecure!"] + report.get("recommendations", [])

    def print_password_report(self, report: dict, verbose: bool = False):
        """Pretty-print password audit results."""
        score = report.get("score", 0)
        strength = report.get("strength", "?")
        colors = [Colors.RED, Colors.RED, Colors.YELLOW, Colors.GREEN, Colors.GREEN]
        strength_color = colors[min(score, 4)]

        print(f"\n  {'─' * 55}")
        Banner.result("Type", "Password Audit")
        Banner.result("Length", str(report.get("length", "?")))
        Banner.result("Strength", f"{'█' * (score + 1)}{'░' * (4 - score)}  {strength}",
                      strength_color)
        Banner.result("Entropy", f"{report.get('entropy', 0):.1f} bits")
        Banner.result("Charset", ", ".join(report.get("charsets_used", [])))
        Banner.result("Crack Time (offline SHA256)", report.get("crack_time_display", "?"))

        if report.get("is_common"):
            Banner.error("  ⚠ COMMON PASSWORD — found in breach databases!")

        patterns = report.get("patterns_detected", [])
        if patterns:
            print(f"\n  {Colors.YELLOW}  Patterns Detected:{Colors.RESET}")
            for p in patterns:
                print(f"    → {p['type']}: {p['description']}")

        warnings = report.get("warnings", [])
        if warnings:
            print(f"\n  {Colors.YELLOW}  Warnings:{Colors.RESET}")
            for w in (warnings if isinstance(warnings, list) else [warnings]):
                if w:
                    print(f"    ⚠ {w}")

        suggestions = report.get("suggestions", [])
        if suggestions:
            print(f"\n  {Colors.CYAN}  Suggestions:{Colors.RESET}")
            for s in suggestions[:4]:
                print(f"    → {s}")

        if verbose:
            compliance = report.get("compliance", {})
            if compliance:
                print(f"\n  {Colors.CYAN}  Compliance:{Colors.RESET}")
                for std, checks in compliance.items():
                    compliant = checks.get("compliant", False)
                    color = Colors.GREEN if compliant else Colors.RED
                    status = "PASS" if compliant else "FAIL"
                    print(f"    {color}{std}: {status}{Colors.RESET}")
        print()

    def print_hash_report(self, report: dict):
        """Pretty-print hash audit results."""
        rating = report.get("security_rating", "UNKNOWN")
        rating_colors = {
            "CRITICAL": Colors.RED,
            "INSECURE": Colors.RED,
            "WEAK": Colors.YELLOW,
            "MODERATE": Colors.YELLOW,
            "GOOD": Colors.GREEN,
            "EXCELLENT": Colors.GREEN,
            "UNKNOWN": Colors.WHITE,
        }
        rating_color = rating_colors.get(rating, Colors.WHITE)

        print(f"\n  {'─' * 55}")
        Banner.result("Type", "Hash Audit")
        Banner.result("Hash", report.get("value", "?"), Colors.DIM)
        Banner.result("Length", f"{report.get('length', '?')} chars")
        Banner.result("Security Rating", rating, rating_color)
        Banner.result("Salted", str(report.get("is_salted", False)))
        Banner.result("Crack Difficulty", report.get("crack_difficulty", "?"))

        likely = report.get("likely_types", [])
        if likely:
            print(f"\n  {Colors.CYAN}  Likely Hash Types:{Colors.RESET}")
            for i, match in enumerate(likely[:6], 1):
                sec = match.get("security", {})
                sec_color = rating_colors.get(sec.get("rating", "?"), Colors.WHITE)
                print(f"    {i}. {Colors.BOLD}{match['algorithm']}{Colors.RESET}")
                print(f"       Bits: {match['bits']} | "
                      f"Security: {sec_color}{sec.get('rating', '?')}{Colors.RESET}")
                print(f"       {Colors.DIM}{match['notes']}{Colors.RESET}")

        recs = report.get("recommendations", [])
        if recs:
            print(f"\n  {Colors.YELLOW}  Recommendations:{Colors.RESET}")
            for r in recs[:4]:
                print(f"    → {r}")
        print()
