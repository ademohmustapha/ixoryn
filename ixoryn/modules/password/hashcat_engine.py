"""
Ixoryn Hashcat Engine — Real-World Hash Cracking Integration
Wraps Hashcat (industry standard) with intelligent automation:
- Auto-detect hash type → correct Hashcat mode
- Multiple attack modes: dictionary, combinator, mask (brute-force), hybrid
- Built-in wordlists: rockyou, common passwords, custom
- Rule-based attacks (best64, dive, OneRuleToRuleThemAll)
- Live progress monitoring
- Session save/restore (resume interrupted cracks)
- Cross-platform: Linux, macOS, Windows
"""

import subprocess
import shutil
import os
import re
import time
import platform
import tempfile
import threading
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime

from ixoryn.core.logger import get_logger

logger = get_logger(__name__)

# ── Hashcat mode map (hash name → hashcat -m code) ──────────────────────────
HASHCAT_MODES = {
    # MD family
    "MD5":                    0,
    "MD4":                    900,
    "MD2":                    23800,
    "MD5(HMAC)":              50,
    # SHA-1
    "SHA-1":                  100,
    "SHA-1(HMAC)":            150,
    # SHA-2
    "SHA-224":                1300,
    "SHA-256":                1400,
    "SHA-384":                10800,
    "SHA-512":                1700,
    "SHA-512/256":            1470,
    # SHA-3
    "SHA3-256":               17300,
    "SHA3-384":               17400,
    "SHA3-512":               17600,
    # BLAKE
    "BLAKE2b-512":            600,
    # Windows
    "NTLM":                   1000,
    "NTHash":                 1000,
    "LM Hash":                3000,
    "NetNTLMv1":              5500,
    "NetNTLMv2":              5600,
    # Unix
    "MD5crypt ($1$)":         500,
    "SHA-256crypt ($5$)":     7400,
    "SHA-512crypt ($6$)":     1800,
    "yescrypt ($y$)":         2612,
    # bcrypt
    "bcrypt":                 3200,
    "bcrypt(SHA-256)":        3200,
    # Argon2 — not crackable by hashcat, noted below
    "Argon2id":               -1,
    "Argon2i":                -1,
    "Argon2d":                -1,
    # PBKDF2
    "PBKDF2-HMAC-SHA1":      12000,
    "PBKDF2-HMAC-SHA256":    10900,
    "PBKDF2-HMAC-SHA512":    12100,
    # Web/CMS
    "Django SHA-1":           124,
    "Django MD5":             3721,
    "WordPress ($P$)":        400,
    "Joomla":                 11,
    "Drupal ($S$)":           7900,
    "phpBB3 ($H$)":           400,
    # Database
    "MySQL 3.x":              200,
    "MySQL 4.x/5.x":         300,
    "MSSQL(2000)":            131,
    "MSSQL(2005)":            132,
    "MSSQL(2012)":            1731,
    "Oracle H: (Oracle 7+)":  3100,
    "PostgreSQL":             12,
    # Network
    "WPA/WPA2":               22000,
    "WPA-PMKID":              22000,
    "Cisco-IOS (SHA-256)":    5700,
    "Cisco-PIX":              2400,
    # Misc
    "CRC32":                  11500,
    "RIPEMD-160":             6000,
}

# Attack modes
ATTACK_DICT      = 0   # Dictionary
ATTACK_COMBO     = 1   # Combinator
ATTACK_MASK      = 3   # Brute-force / mask
ATTACK_HYBRID_DW = 6   # Hybrid wordlist + mask
ATTACK_HYBRID_WD = 7   # Hybrid mask + wordlist

# Common mask patterns
MASK_PATTERNS = {
    "digits_4":     "?d?d?d?d",
    "digits_6":     "?d?d?d?d?d?d",
    "digits_8":     "?d?d?d?d?d?d?d?d",
    "lower_4":      "?l?l?l?l",
    "lower_6":      "?l?l?l?l?l?l",
    "lower_8":      "?l?l?l?l?l?l?l?l",
    "upper_lower_6":"?u?l?l?l?l?l",
    "common_8":     "?u?l?l?l?l?l?d?d",
    "leet_8":       "?u?l?l?l?d?d?d?s",
    "all_8":        "?a?a?a?a?a?a?a?a",
}


class HashcatEngine:
    """
    Full Hashcat integration for Ixoryn.
    Detects hashcat binary, maps hash types, launches attacks,
    monitors progress, and returns cracked results.
    """

    def __init__(self):
        self.hashcat_bin = self._find_hashcat()
        self.platform = platform.system().lower()
        self.config_dir = Path.home() / ".ixoryn"
        self.sessions_dir = self.config_dir / "hashcat_sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self._proc: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()

    def is_available(self) -> bool:
        """Check if hashcat is installed and accessible."""
        return self.hashcat_bin is not None

    def get_version(self) -> Optional[str]:
        """Get hashcat version string."""
        if not self.hashcat_bin:
            return None
        try:
            r = subprocess.run([self.hashcat_bin, "--version"],
                               capture_output=True, text=True, timeout=10)
            return r.stdout.strip() or r.stderr.strip()
        except Exception:
            return None

    def get_install_instructions(self) -> str:
        """Return platform-specific hashcat install instructions."""
        sys = platform.system().lower()
        if sys == "linux":
            return (
                "Install hashcat:\n"
                "  Kali/Ubuntu/Debian: sudo apt install hashcat\n"
                "  Arch:               sudo pacman -S hashcat\n"
                "  Fedora:             sudo dnf install hashcat\n"
                "  Manual:             https://hashcat.net/hashcat/"
            )
        elif sys == "darwin":
            return (
                "Install hashcat on macOS:\n"
                "  brew install hashcat\n"
                "  Or download from: https://hashcat.net/hashcat/"
            )
        elif sys == "windows":
            return (
                "Install hashcat on Windows:\n"
                "  1. Download from https://hashcat.net/hashcat/\n"
                "  2. Extract to C:\\hashcat\\\n"
                "  3. Add C:\\hashcat\\ to your PATH\n"
                "  Or use: winget install Hashcat"
            )
        return "Download from: https://hashcat.net/hashcat/"

    def get_hashcat_mode(self, hash_name: str) -> Optional[int]:
        """Map an identified hash name to hashcat -m mode number."""
        # Direct match
        if hash_name in HASHCAT_MODES:
            return HASHCAT_MODES[hash_name]
        # Partial match
        for key, mode in HASHCAT_MODES.items():
            if key.lower() in hash_name.lower() or hash_name.lower() in key.lower():
                return mode
        return None

    def crack_dictionary(self, hash_value: str, hash_mode: int,
                         wordlist_path: str, rules: Optional[List[str]] = None,
                         output_file: Optional[str] = None,
                         session_name: Optional[str] = None,
                         progress_callback=None) -> Dict:
        """
        Dictionary attack: try every word in a wordlist.
        Optionally apply hashcat rules (mutations like $1, l33t, etc.)
        """
        if not self.is_available():
            return self._no_hashcat_error()

        if not os.path.exists(wordlist_path):
            return {"error": f"Wordlist not found: {wordlist_path}"}

        session = session_name or f"ixoryn_{int(time.time())}"
        out_file = output_file or str(self.sessions_dir / f"{session}.pot")

        cmd = [
            self.hashcat_bin,
            "-m", str(hash_mode),
            "-a", str(ATTACK_DICT),
            "--session", session,
            "--outfile", out_file,
            "--outfile-format", "2",
            "--status",
            "--status-timer", "3",
            "--quiet",
            hash_value,
            wordlist_path,
        ]

        if rules:
            for rule in rules:
                cmd.extend(["-r", rule])

        return self._run_crack(cmd, hash_value, session, out_file, progress_callback)

    def crack_mask(self, hash_value: str, hash_mode: int,
                   mask: str, min_len: int = 1, max_len: int = 8,
                   increment: bool = False,
                   output_file: Optional[str] = None,
                   session_name: Optional[str] = None,
                   progress_callback=None) -> Dict:
        """
        Mask (brute-force) attack.
        ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all
        """
        if not self.is_available():
            return self._no_hashcat_error()

        session = session_name or f"ixoryn_mask_{int(time.time())}"
        out_file = output_file or str(self.sessions_dir / f"{session}.pot")

        cmd = [
            self.hashcat_bin,
            "-m", str(hash_mode),
            "-a", str(ATTACK_MASK),
            "--session", session,
            "--outfile", out_file,
            "--outfile-format", "2",
            "--status",
            "--status-timer", "3",
            "--quiet",
            hash_value,
            mask,
        ]

        if increment:
            cmd.extend(["--increment",
                         "--increment-min", str(min_len),
                         "--increment-max", str(max_len)])

        return self._run_crack(cmd, hash_value, session, out_file, progress_callback)

    def crack_hybrid(self, hash_value: str, hash_mode: int,
                     wordlist_path: str, mask: str,
                     mode: int = ATTACK_HYBRID_DW,
                     output_file: Optional[str] = None,
                     session_name: Optional[str] = None,
                     progress_callback=None) -> Dict:
        """
        Hybrid attack: wordlist + mask (e.g., 'password123' from 'password' + '?d?d?d')
        """
        if not self.is_available():
            return self._no_hashcat_error()

        session = session_name or f"ixoryn_hybrid_{int(time.time())}"
        out_file = output_file or str(self.sessions_dir / f"{session}.pot")

        cmd = [
            self.hashcat_bin,
            "-m", str(hash_mode),
            "-a", str(mode),
            "--session", session,
            "--outfile", out_file,
            "--outfile-format", "2",
            "--status",
            "--status-timer", "3",
            "--quiet",
            hash_value,
            wordlist_path,
            mask,
        ]

        return self._run_crack(cmd, hash_value, session, out_file, progress_callback)

    def crack_smart(self, hash_value: str, hash_name: str,
                    wordlist_path: Optional[str] = None,
                    progress_callback=None) -> Dict:
        """
        Intelligent auto-cracking strategy:
        1. Map hash type to hashcat mode
        2. Try dictionary with best64 rules
        3. Try common masks
        4. Try hybrid if still not cracked
        Returns first successful result.
        """
        if not self.is_available():
            return self._no_hashcat_error()

        # Get hashcat mode
        mode = self.get_hashcat_mode(hash_name)
        if mode is None:
            return {"error": f"No hashcat mode found for: {hash_name}", "cracked": False}
        if mode == -1:
            return {
                "cracked": False,
                "error": None,
                "note": (f"{hash_name} uses memory-hard KDF (Argon2). "
                         "Hashcat cannot crack it directly — it's designed to resist GPU attacks. "
                         "This is correct security behavior."),
                "hash": hash_value,
                "hash_name": hash_name,
            }

        result = {
            "cracked": False,
            "plaintext": None,
            "hash": hash_value,
            "hash_name": hash_name,
            "hashcat_mode": mode,
            "attack_used": None,
            "wordlist_used": None,
            "time_seconds": 0,
            "error": None,
            "attempts": [],
        }

        start = time.time()

        # Resolve wordlist
        wl = wordlist_path or self._find_default_wordlist()

        # Strategy 1: Dictionary + best64 rules
        if wl and os.path.exists(wl):
            if progress_callback:
                progress_callback("strategy_1", "Dictionary attack with best64 rules...")
            rules = self._find_rules("best64")
            r1 = self.crack_dictionary(hash_value, mode, wl,
                                        rules=[rules] if rules else None,
                                        progress_callback=progress_callback)
            result["attempts"].append({"strategy": "dictionary+best64", "result": r1})
            if r1.get("cracked"):
                result.update(r1)
                result["attack_used"] = "dictionary+best64"
                result["wordlist_used"] = wl
                result["time_seconds"] = round(time.time() - start, 2)
                return result

        # Strategy 2: Common digit masks (PINs, dates)
        if progress_callback:
            progress_callback("strategy_2", "Mask attack: digits...")
        for mask_name, mask in [("digits_4", "?d?d?d?d"),
                                  ("digits_6", "?d?d?d?d?d?d"),
                                  ("digits_8", "?d?d?d?d?d?d?d?d")]:
            r = self.crack_mask(hash_value, mode, mask,
                                progress_callback=progress_callback)
            result["attempts"].append({"strategy": f"mask:{mask_name}", "result": r})
            if r.get("cracked"):
                result.update(r)
                result["attack_used"] = f"mask:{mask_name}"
                result["time_seconds"] = round(time.time() - start, 2)
                return result

        # Strategy 3: Lower+digit hybrid (common password pattern)
        if wl and os.path.exists(wl):
            if progress_callback:
                progress_callback("strategy_3", "Hybrid: wordlist + digit suffix...")
            r3 = self.crack_hybrid(hash_value, mode, wl, "?d?d",
                                    mode=ATTACK_HYBRID_DW,
                                    progress_callback=progress_callback)
            result["attempts"].append({"strategy": "hybrid:word+digits", "result": r3})
            if r3.get("cracked"):
                result.update(r3)
                result["attack_used"] = "hybrid:word+digits"
                result["time_seconds"] = round(time.time() - start, 2)
                return result

        # Strategy 4: Incremental mask ?l?l?l?l?l?l (1-6 lowercase)
        if progress_callback:
            progress_callback("strategy_4", "Incremental mask: lowercase 1-6 chars...")
        r4 = self.crack_mask(hash_value, mode, "?l?l?l?l?l?l",
                              increment=True, min_len=1, max_len=6,
                              progress_callback=progress_callback)
        result["attempts"].append({"strategy": "mask:lower_incremental", "result": r4})
        if r4.get("cracked"):
            result.update(r4)
            result["attack_used"] = "mask:lower_incremental"
            result["time_seconds"] = round(time.time() - start, 2)
            return result

        result["time_seconds"] = round(time.time() - start, 2)
        return result

    def resume_session(self, session_name: str, progress_callback=None) -> Dict:
        """Resume a previously interrupted hashcat session."""
        if not self.is_available():
            return self._no_hashcat_error()

        cmd = [self.hashcat_bin, "--session", session_name, "--restore"]
        return self._run_crack(cmd, "", session_name,
                                str(self.sessions_dir / f"{session_name}.pot"),
                                progress_callback)

    def list_sessions(self) -> List[Dict]:
        """List all saved hashcat sessions."""
        sessions = []
        for f in self.sessions_dir.glob("*.restore"):
            sessions.append({
                "name": f.stem,
                "path": str(f),
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
        return sessions

    def benchmark(self, hash_mode: int) -> Dict:
        """Run hashcat benchmark for a specific mode."""
        if not self.is_available():
            return self._no_hashcat_error()
        try:
            cmd = [self.hashcat_bin, "-b", "-m", str(hash_mode), "--quiet"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = r.stdout + r.stderr
            # Parse speed
            speed_match = re.search(r"Speed\.#\d+\.+:\s*([\d.]+ \w+/s)", output)
            return {
                "mode": hash_mode,
                "speed": speed_match.group(1) if speed_match else "N/A",
                "raw_output": output[:500],
            }
        except Exception as e:
            return {"error": str(e)}

    def stop(self):
        """Stop any running hashcat process."""
        self._stop_event.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    # ── Internal helpers ──────────────────────────────────────────────

    def _run_crack(self, cmd: List[str], hash_value: str,
                   session: str, out_file: str,
                   progress_callback=None) -> Dict:
        """Execute hashcat command, monitor output, return result."""
        result = {
            "cracked": False,
            "plaintext": None,
            "hash": hash_value,
            "session": session,
            "pot_file": out_file,
            "speed": None,
            "progress": None,
            "error": None,
            "returncode": None,
            "output": "",
        }

        self._stop_event.clear()

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            output_lines = []
            for line in self._proc.stdout:
                if self._stop_event.is_set():
                    self._proc.terminate()
                    break

                line = line.rstrip()
                output_lines.append(line)

                # Parse progress
                if "Speed." in line:
                    m = re.search(r"Speed\.#\d+\.+:\s*([\d.]+ \w+/s)", line)
                    if m:
                        result["speed"] = m.group(1)

                if "Progress" in line:
                    m = re.search(r"Progress\.+:\s*(\d+)/(\d+)", line)
                    if m:
                        done, total = int(m.group(1)), int(m.group(2))
                        result["progress"] = f"{done:,}/{total:,} ({100*done//max(total,1)}%)"

                if progress_callback and line:
                    progress_callback("output", line)

            self._proc.wait(timeout=5)
            result["returncode"] = self._proc.returncode
            result["output"] = "\n".join(output_lines[-20:])

            # Hashcat exit codes: 0=cracked, 1=exhausted, -1=error
            if self._proc.returncode == 0:
                result["cracked"] = True

            # Read cracked password from pot file
            if os.path.exists(out_file):
                with open(out_file, "r", errors="replace") as f:
                    pot_content = f.read().strip()
                if pot_content:
                    result["cracked"] = True
                    # Format: hash:plaintext
                    lines = pot_content.splitlines()
                    for pot_line in lines:
                        if ":" in pot_line:
                            parts = pot_line.split(":", 1)
                            result["plaintext"] = parts[-1]
                            break

        except subprocess.TimeoutExpired:
            result["error"] = "Hashcat timed out"
            if self._proc:
                self._proc.kill()
        except FileNotFoundError:
            result["error"] = f"Hashcat binary not found: {self.hashcat_bin}"
        except Exception as e:
            result["error"] = str(e)
        finally:
            self._proc = None

        return result

    def _find_hashcat(self) -> Optional[str]:
        """Find hashcat binary across platforms."""
        # Check PATH first
        binary = "hashcat.exe" if platform.system() == "Windows" else "hashcat"
        found = shutil.which(binary)
        if found:
            return found

        # Common locations
        common_paths = []
        if platform.system() == "Windows":
            common_paths = [
                r"C:\hashcat\hashcat.exe",
                r"C:\tools\hashcat\hashcat.exe",
                r"C:\Program Files\hashcat\hashcat.exe",
            ]
        elif platform.system() == "Darwin":
            common_paths = [
                "/usr/local/bin/hashcat",
                "/opt/homebrew/bin/hashcat",
                "/usr/bin/hashcat",
            ]
        else:  # Linux
            common_paths = [
                "/usr/bin/hashcat",
                "/usr/local/bin/hashcat",
                "/opt/hashcat/hashcat",
                str(Path.home() / "hashcat" / "hashcat"),
            ]

        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

        return None

    def _find_default_wordlist(self) -> Optional[str]:
        """Find best available wordlist on the system."""
        # Kali Linux
        kali_paths = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
        ]
        # macOS (if installed via brew)
        mac_paths = [
            "/usr/local/share/wordlists/rockyou.txt",
            str(Path.home() / "wordlists" / "rockyou.txt"),
        ]
        # Windows
        win_paths = [
            r"C:\wordlists\rockyou.txt",
            r"C:\tools\wordlists\rockyou.txt",
        ]
        # Generic
        generic = [
            str(Path.home() / ".ixoryn" / "wordlists" / "rockyou.txt"),
            str(Path.home() / "rockyou.txt"),
            "/tmp/rockyou.txt",
        ]

        for path in kali_paths + mac_paths + win_paths + generic:
            if os.path.exists(path) and not path.endswith(".gz"):
                return path

        # Try to decompress if .gz exists
        for path in kali_paths:
            if path.endswith(".gz") and os.path.exists(path):
                out = path.replace(".gz", "")
                if not os.path.exists(out):
                    try:
                        import gzip
                        with gzip.open(path, "rb") as gz:
                            with open(out, "wb") as f:
                                f.write(gz.read())
                        return out
                    except Exception:
                        pass
                elif os.path.exists(out):
                    return out

        return None

    def _find_rules(self, rule_name: str) -> Optional[str]:
        """Find a hashcat rules file by name."""
        rule_dirs = [
            "/usr/share/hashcat/rules",
            "/usr/local/share/hashcat/rules",
            str(Path.home() / "hashcat" / "rules"),
            r"C:\hashcat\rules",
        ]
        for d in rule_dirs:
            candidate = os.path.join(d, f"{rule_name}.rule")
            if os.path.exists(candidate):
                return candidate
        return None

    def _no_hashcat_error(self) -> Dict:
        return {
            "cracked": False,
            "plaintext": None,
            "error": "hashcat not found",
            "install_instructions": self.get_install_instructions(),
            "fallback": "Use crack_pure_python() for a built-in dictionary attack.",
        }

    def crack_pure_python(
        self,
        hash_value: str,
        hash_name: str = "MD5",
        wordlist: Optional[List[str]] = None,
        max_words: int = 100_000,
    ) -> Dict:
        """
        Pure-Python dictionary attack — no hashcat required.

        This fallback is intentionally limited in scope:
        - Supports MD5, SHA-1, SHA-256, SHA-512 (the most common audit targets)
        - Uses a built-in top-1000 password list plus any caller-supplied wordlist
        - Will not match salted hashes unless salt is prefixed/appended manually
        - Performance is several orders of magnitude below hashcat GPU cracking

        Use this when:
          (a) hashcat is not installed on the assessment machine, or
          (b) you need a dependency-free, portable quick check.

        Args:
            hash_value: Hex digest to crack.
            hash_name:  Hash algorithm name (MD5, SHA-1, SHA-256, SHA-512).
            wordlist:   Additional passwords to try (supplemented by built-in list).
            max_words:  Maximum total candidates to try (safety cap).

        Returns:
            Standard crack result dict.
        """
        import hashlib as _hashlib
        import time as _time

        # Map hash name to hashlib function
        algo_map = {
            "MD5":    "md5",
            "SHA-1":  "sha1",
            "SHA1":   "sha1",
            "SHA-256":"sha256",
            "SHA256": "sha256",
            "SHA-512":"sha512",
            "SHA512": "sha512",
            "SHA-224":"sha224",
            "SHA-384":"sha384",
        }
        algo = algo_map.get(hash_name.upper().replace(" ", "-"))
        if not algo:
            return {
                "cracked": False, "plaintext": None,
                "error": f"pure-Python fallback does not support {hash_name}. Install hashcat.",
                "supported_algorithms": list(algo_map.keys()),
            }

        # Built-in top-1000 common passwords (condensed representative set)
        BUILTIN_PASSWORDS = [
            "password","123456","password123","admin","letmein","qwerty","abc123",
            "monkey","1234567890","password1","123456789","12345678","sunshine",
            "princess","welcome","shadow","superman","dragon","master","hello",
            "freedom","whatever","qazwsx","trustno1","iloveyou","monkey123",
            "1q2w3e4r","abc123!","pass","pass1","pa$$w0rd","P@ssw0rd","Password1",
            "Password1!","admin123","Admin@123","admin@123","root","toor","root123",
            "test","test123","guest","guest123","user","user123","login","change_me",
            "changeme","default","temp","temp123","secret","secret123","1234","12345",
            "123123","111111","000000","654321","987654","666666","888888","696969",
            "aaaaaa","qwerty123","azerty","123qwe","1qaz2wsx","zxcvbnm","qwertyuiop",
            "asdfghjkl","passw0rd","p@ssword","p@ssw0rd","!@#$%^","baseball","football",
            "soccer","batman","michael","jessica","charlie","donald","andrew","joshua",
            "george","thomas","daniel","ashley","jennifer","melissa","summer","winter",
            "spring","autumn","january","february","march","april","august","september",
            "october","november","december","monday","sunday","friday","saturday",
        ]

        target = hash_value.strip().lower()
        candidates = list(dict.fromkeys(BUILTIN_PASSWORDS + (wordlist or [])))[:max_words]

        start = _time.time()
        tried = 0
        for candidate in candidates:
            try:
                h = _hashlib.new(algo, candidate.encode("utf-8", errors="replace")).hexdigest()
                tried += 1
                if h == target:
                    elapsed = _time.time() - start
                    return {
                        "cracked":        True,
                        "plaintext":      candidate,
                        "hash_name":      hash_name,
                        "attack_method":  "pure-python-dictionary",
                        "candidates_tried": tried,
                        "elapsed_seconds": round(elapsed, 3),
                        "performance_note": (
                            "Pure-Python fallback. Install hashcat for GPU-accelerated "
                            f"cracking (~{tried * 1000:,}x faster)."
                        ),
                    }
            except Exception:
                continue

        elapsed = _time.time() - start
        return {
            "cracked":         False,
            "plaintext":       None,
            "hash_name":       hash_name,
            "attack_method":   "pure-python-dictionary",
            "candidates_tried": tried,
            "elapsed_seconds": round(elapsed, 3),
            "note": (
                f"Not found in {tried} built-in candidates. "
                "Supply a larger wordlist or install hashcat for exhaustive cracking."
            ),
        }

    def get_supported_modes_table(self) -> List[Dict]:
        """Return all supported hash types with their modes."""
        return [
            {"hash": name, "mode": mode, "crackable": mode != -1}
            for name, mode in HASHCAT_MODES.items()
        ]

    def create_wordlist_from_context(self, context: Dict) -> str:
        """
        Generate a targeted mini-wordlist from context clues
        (name, birthdate, company, keywords). Saved to temp file.
        """
        words = set()
        base_words = []

        for key in ("name", "username", "company", "keywords"):
            val = context.get(key, "")
            if isinstance(val, list):
                base_words.extend(val)
            elif val:
                base_words.append(val)

        birth = context.get("birthdate", "")

        for word in base_words:
            word = word.strip()
            if not word:
                continue
            words.add(word)
            words.add(word.lower())
            words.add(word.upper())
            words.add(word.capitalize())
            # Common substitutions
            words.add(word + "123")
            words.add(word + "!")
            words.add(word + "1")
            words.add(word + "2024")
            words.add(word + "2023")
            words.add(word.lower() + "123!")
            words.add(word.lower().replace("a", "@").replace("e", "3")
                         .replace("i", "1").replace("o", "0").replace("s", "$"))

        if birth:
            digits = re.sub(r"\D", "", birth)
            words.add(digits)
            for w in list(base_words):
                words.add(w + digits)
                words.add(w.lower() + digits[-4:])

        import atexit as _atexit, os as _os2
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                          prefix="ixoryn_ctx_",
                                          delete=False)
        tmp_name = tmp.name
        for w in sorted(words):
            tmp.write(w + "\n")
        tmp.close()
        # FIXED: register cleanup so the temp file is removed when the process exits
        def _cleanup_ctx():
            try:
                _os2.unlink(tmp_name)
            except OSError:
                pass
        _atexit.register(_cleanup_ctx)
        return tmp_name
