"""
Ixoryn Breach Intelligence
Checks emails and domains against known breach databases.
Uses Have I Been Pwned (HIBP) API for email/domain breach lookups.
Uses k-Anonymity model — password hashes are NEVER sent in full.
"""

import hashlib
import json
import time
import requests
from typing import Dict, List, Optional
from datetime import datetime

from ixoryn.core.logger import get_logger
from ixoryn.core.rate_limit import get_limiter as _get_limiter

logger = get_logger(__name__)


HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com/range"


class BreachIntelligence:
    """
    Breach database integration with:
    - Email breach check (HIBP API — requires free API key)
    - Domain breach check (find all breached accounts at a domain)
    - Password pwned check (k-Anonymity — only first 5 chars of SHA1 sent)
    - Breach data formatting with severity assessment
    """

    def __init__(self, hibp_api_key: Optional[str] = None):
        import os as _os
        # Prefer env var over constructor argument (avoids hardcoded keys in code)
        self.hibp_key = _os.environ.get("IXORYN_HIBP_KEY", "") or hibp_api_key or ""
        # FIXED: use self.hibp_key (may come from env var) — not hibp_api_key (may be None)
        self._headers = {
            "User-Agent": "IxorynSecurityPlatform/1.1",
            "hibp-api-key": self.hibp_key,
        }

    def check_password_pwned(self, password: str) -> Dict:
        """
        Check if a password appears in known breach datasets.
        Uses k-Anonymity: only the first 5 chars of SHA1 hash are sent.
        The full password is NEVER transmitted.
        """
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        result = {
            "password": "***REDACTED***",
            "sha1_prefix": prefix,
            "pwned": False,
            "pwned_count": 0,
            "severity": "SAFE",
            "message": "",
            "method": "k-Anonymity (password never transmitted)",
            "source": "HaveIBeenPwned Passwords DB",
        }

        try:
            resp = requests.get(f"{PWNED_PASSWORDS_API}/{prefix}",
                                timeout=8,
                                headers={"User-Agent": "IxorynScanner/1.1"})

            if resp.status_code == 200:
                # Search for our suffix in the response
                for line in resp.text.splitlines():
                    parts = line.split(":")
                    if len(parts) == 2 and parts[0].upper() == suffix:
                        count = int(parts[1].strip())
                        result["pwned"] = True
                        result["pwned_count"] = count
                        if count > 1_000_000:
                            result["severity"] = "CRITICAL"
                            result["message"] = (f"This password has appeared {count:,} times "
                                                 f"in breach data. Extremely common — do NOT use.")
                        elif count > 100_000:
                            result["severity"] = "CRITICAL"
                            result["message"] = (f"This password has appeared {count:,} times "
                                                 f"in breach data. Change immediately.")
                        elif count > 10_000:
                            result["severity"] = "HIGH"
                            result["message"] = (f"This password has appeared {count:,} times "
                                                 f"in breach data. Change immediately.")
                        elif count > 1_000:
                            result["severity"] = "HIGH"
                            result["message"] = f"Found {count:,} times in breach data. Change it."
                        else:
                            result["severity"] = "MEDIUM"
                            result["message"] = f"Found {count:,} time(s) in breach data. Change it."
                        break

                if not result["pwned"]:
                    result["message"] = ("Password not found in known breach databases. "
                                         "This does NOT guarantee it's safe — use a strong, unique password.")
            else:
                result["error"] = f"HIBP API returned HTTP {resp.status_code}"

        except requests.exceptions.ConnectionError:
            result["error"] = "Cannot reach HIBP API — check network connectivity"
        except Exception as e:
            result["error"] = str(e)[:100]

        return result

    def check_email_breached(self, email: str) -> Dict:
        """
        Check if an email address appears in known data breaches.
        Requires a free HIBP API key from haveibeenpwned.com/API/Key
        """
        result = {
            "email": email,
            "breached": False,
            "breach_count": 0,
            "breaches": [],
            "pastes": [],
            "risk_level": "CLEAN",
            "source": "HaveIBeenPwned",
            "queried_at": datetime.now().isoformat(),
        }

        if not self.hibp_key:
            result["error"] = (
                "HIBP API key required for email lookups. "
                "Get a free key at haveibeenpwned.com/API/Key "
                "then add it to ~/.ixoryn/config.json under 'hibp'"
            )
            return result

        try:
            _get_limiter().acquire("hibp")  # global rate coordinator
            time.sleep(1.5)  # HIBP rate limit
            resp = requests.get(
                f"{HIBP_API_BASE}/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers=self._headers,
                timeout=10,
            )

            if resp.status_code == 200:
                breaches = resp.json()
                result["breached"] = True
                result["breach_count"] = len(breaches)

                for breach in breaches:
                    data_classes = breach.get("DataClasses", [])
                    result["breaches"].append({
                        "name": breach.get("Name", ""),
                        "domain": breach.get("Domain", ""),
                        "date": breach.get("BreachDate", ""),
                        "pwn_count": breach.get("PwnCount", 0),
                        "data_classes": data_classes,
                        "verified": breach.get("IsVerified", False),
                        "sensitive": breach.get("IsSensitive", False),
                        "has_passwords": "Passwords" in data_classes,
                    })

                # Determine risk
                has_passwords = any(b["has_passwords"] for b in result["breaches"])
                sensitive_count = sum(1 for b in result["breaches"] if b["sensitive"])

                if has_passwords and len(breaches) > 3:
                    result["risk_level"] = "CRITICAL"
                elif has_passwords:
                    result["risk_level"] = "HIGH"
                elif sensitive_count > 0:
                    result["risk_level"] = "MEDIUM"
                else:
                    result["risk_level"] = "LOW"

            elif resp.status_code == 404:
                result["breached"] = False
                result["risk_level"] = "CLEAN"

            elif resp.status_code == 401:
                result["error"] = "HIBP API key invalid or expired"
            elif resp.status_code == 429:
                result["error"] = "HIBP rate limit exceeded — try again in 60 seconds"
            else:
                result["error"] = f"HIBP API returned HTTP {resp.status_code}"

        except Exception as e:
            result["error"] = str(e)[:100]

        return result

    def check_domain_breaches(self, domain: str) -> Dict:
        """
        Find all breaches that include accounts from a specific domain.
        Useful for organizations checking if their domain appears in breaches.
        """
        result = {
            "domain": domain,
            "breaches": [],
            "total_accounts_exposed": 0,
            "oldest_breach": None,
            "newest_breach": None,
            "data_types_found": set(),
            "source": "HaveIBeenPwned",
            "queried_at": datetime.now().isoformat(),
        }

        if not self.hibp_key:
            result["error"] = "HIBP API key required. Get free key at haveibeenpwned.com/API/Key"
            return result

        try:
            _get_limiter().acquire("hibp")  # global rate coordinator (all-breaches endpoint)
            time.sleep(1.5)
            resp = requests.get(
                f"{HIBP_API_BASE}/breaches",
                headers=self._headers,
                timeout=10,
            )

            if resp.status_code == 200:
                all_breaches = resp.json()
                domain_lower = domain.lower()

                for breach in all_breaches:
                    breach_domain = breach.get("Domain", "").lower()
                    if domain_lower in breach_domain or breach_domain.endswith(f".{domain_lower}"):
                        data_classes = breach.get("DataClasses", [])
                        entry = {
                            "name": breach.get("Name", ""),
                            "breach_date": breach.get("BreachDate", ""),
                            "pwn_count": breach.get("PwnCount", 0),
                            "data_classes": data_classes,
                            "description": breach.get("Description", "")[:200],
                        }
                        result["breaches"].append(entry)
                        result["total_accounts_exposed"] += breach.get("PwnCount", 0)
                        for dc in data_classes:
                            result["data_types_found"].add(dc)

                result["data_types_found"] = list(result["data_types_found"])

                if result["breaches"]:
                    dates = [b["breach_date"] for b in result["breaches"] if b["breach_date"]]
                    if dates:
                        result["oldest_breach"] = min(dates)
                        result["newest_breach"] = max(dates)

        except Exception as e:
            result["error"] = str(e)[:100]

        return result

    def format_password_check(self, result: Dict) -> str:
        """Format password breach check for display."""
        try:
            from ixoryn.ui.banner import Colors as C
        except ImportError:
            class C:
                RED = YELLOW = GREEN = CYAN = RESET = BOLD = MUTED = WHITE = ""

        lines = ["\n"]

        if result.get("error"):
            lines.append(f"  [!] Error: {result['error']}")
            return "\n".join(lines)

        if result["pwned"]:
            count = result["pwned_count"]
            sev = result["severity"]
            color = C.RED if sev in ("CRITICAL", "HIGH") else C.YELLOW

            lines.append(f"  {color}⚠  PASSWORD FOUND IN BREACH DATA{C.RESET}")
            lines.append(f"  Times seen: {C.RED}{count:,}{C.RESET}")
            lines.append(f"  Severity:   {color}{sev}{C.RESET}")
            lines.append(f"  Action:     {C.WHITE}{result['message']}{C.RESET}")
        else:
            lines.append(f"  {C.GREEN}✓  Password not found in known breach databases.{C.RESET}")
            lines.append(f"  {C.MUTED}{result['message']}{C.RESET}")

        lines.append(f"\n  {C.MUTED}Method: {result['method']}{C.RESET}")
        lines.append(f"  {C.MUTED}Source: {result['source']}{C.RESET}")

        return "\n".join(lines)

    def format_email_check(self, result: Dict) -> str:
        """Format email breach check for display."""
        try:
            from ixoryn.ui.banner import Colors as C
        except ImportError:
            class C:
                RED = YELLOW = GREEN = CYAN = RESET = BOLD = MUTED = WHITE = ""

        lines = ["\n"]

        if result.get("error"):
            lines.append(f"  [!] {result['error']}")
            return "\n".join(lines)

        email = result["email"]
        if result["breached"]:
            risk = result["risk_level"]
            color = C.RED if risk in ("CRITICAL", "HIGH") else C.YELLOW
            lines.append(f"  {color}⚠  {email} — FOUND IN {result['breach_count']} BREACH(ES){C.RESET}")
            lines.append(f"  Risk Level: {color}{risk}{C.RESET}\n")

            for i, breach in enumerate(result["breaches"][:10]):
                pwd_tag = f" {C.RED}[PASSWORDS INCLUDED]{C.RESET}" if breach["has_passwords"] else ""
                lines.append(f"  [{i+1}] {C.WHITE}{breach['name']}{C.RESET}{pwd_tag}")
                lines.append(f"      Date: {breach['date']}  |  "
                              f"Accounts: {breach['pwn_count']:,}")
                lines.append(f"      Data: {', '.join(breach['data_classes'][:5])}")
                lines.append("")
        else:
            lines.append(f"  {C.GREEN}✓  {email} — not found in known breach databases.{C.RESET}")

        return "\n".join(lines)
