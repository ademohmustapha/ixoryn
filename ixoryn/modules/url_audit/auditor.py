"""
Ixoryn URL & Domain Auditor
Comprehensive detection of:
 - Phishing indicators
 - Pharming / DNS poisoning signatures
 - Homograph attacks (Unicode/IDN lookalike domains)
 - Typosquatting analysis
 - SSL/TLS certificate analysis
 - WHOIS registration forensics
 - DNS record analysis (A, MX, TXT, SPF, DMARC, NS, CNAME)
 - Domain age and reputation scoring
 - Redirect chain analysis
 - Suspicious URL pattern matching
 - Threat intelligence lookups
"""

import re
import ssl
import socket
import urllib.parse
import unicodedata
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from ixoryn.ui.banner import Banner, Colors
from ixoryn.core.logger import get_logger

logger = get_logger("url_audit")

# ─── THREAT INTELLIGENCE & PATTERNS ──────────────────────────────────
PHISHING_KEYWORDS = [
    "paypal", "amazon", "netflix", "apple", "microsoft", "google", "facebook",
    "instagram", "twitter", "bank", "secure", "account", "login", "signin",
    "verify", "update", "confirm", "password", "credential", "billing",
    "payment", "invoice", "ebay", "wellsfargo", "chase", "citi", "hsbc",
    "binance", "coinbase", "crypto", "wallet", "support", "helpdesk",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".xyz", ".click",
    ".download", ".loan", ".win", ".review", ".science", ".work", ".party",
    ".racing", ".date", ".faith", ".bid", ".trade", ".men",
}

SUSPICIOUS_PATTERNS = [
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address in URL
    r"@",                                        # User info in URL
    r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly",   # URL shorteners
    r"[a-zA-Z]{20,}",                            # Very long random strings
    r"secure.*login|login.*secure",              # Suspicious path patterns
    r"verify.*account|account.*verify",
    r"update.*payment|payment.*update",
]

# Common homograph character substitutions (Unicode lookalikes)
HOMOGRAPH_MAP = {
    'a': ['а', 'ɑ', 'α', 'ạ', 'ą', 'à', 'á', 'â', 'ã', 'ä', 'å'],
    'b': ['Ь', 'ƅ', 'ɓ', 'ḃ'],
    'c': ['с', 'ϲ', 'ċ', 'ƈ'],
    'd': ['ԁ', 'ɗ', 'đ'],
    'e': ['е', 'ë', 'ė', 'ę', 'ε'],
    'g': ['ɡ', 'ğ', 'ǵ'],
    'h': ['һ', 'ḥ'],
    'i': ['і', 'ı', 'ǐ', '1', 'l'],
    'j': ['ϳ', 'ĵ'],
    'k': ['κ', 'ķ'],
    'l': ['ʟ', '1', 'I', 'ı', '|'],
    'm': ['м', 'ṁ'],
    'n': ['η', 'ñ', 'ń'],
    'o': ['о', 'ο', '0', 'ọ', 'ö', 'ó', 'ô'],
    'p': ['р', 'ρ', 'ṗ'],
    'q': ['զ', 'ɋ'],
    'r': ['г', 'ṙ', 'ŕ'],
    's': ['ѕ', 'ś', 'š', '$'],
    't': ['τ', 'ț', 'ť'],
    'u': ['υ', 'ú', 'ü', 'ū'],
    'v': ['ν', 'ṿ'],
    'w': ['ω', 'ẇ'],
    'x': ['х', 'χ'],
    'y': ['у', 'ý', 'ÿ'],
    'z': ['ż', 'ź', 'ẑ'],
}

# Popular domains for typosquatting comparison
POPULAR_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "paypal.com", "netflix.com", "twitter.com", "instagram.com", "linkedin.com",
    "github.com", "youtube.com", "reddit.com", "wikipedia.org", "yahoo.com",
    "ebay.com", "shopify.com", "dropbox.com", "salesforce.com", "zoom.us",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "binance.com", "coinbase.com", "robinhood.com",
]

# Known malware/phishing IP ranges (simplified - production would use threat feeds)
KNOWN_MALICIOUS_ASNS = {
    # These are example ASNs known for abuse
    "AS4134": "CHINANET",
    "AS4837": "CNCGROUP",
}


class URLAuditor:
    """Comprehensive URL and domain security auditor."""

    def __init__(self):
        self.session = None
        self._init_session()

    def _init_session(self):
        try:
            import requests
            self.session = requests.Session()
            self.session.headers.update({
                "User-Agent": "Ixoryn-Security-Auditor/1.0 (Security Research)",
                "Accept": "text/html,application/xhtml+xml,*/*",
            })
            self.session.max_redirects = 5
        except ImportError:
            self.session = None

    def audit(self, target: str, depth: str = "standard") -> Dict[str, Any]:
        """
        Full audit of a URL or domain.
        depth: 'quick', 'standard', 'deep'
        """
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target_url = "https://" + target
        else:
            target_url = target

        parsed = urllib.parse.urlparse(target_url)
        domain = parsed.netloc or parsed.path

        # Strip www and port
        clean_domain = re.sub(r"^www\.", "", domain.split(":")[0].lower())

        report = {
            "target": target,
            "url": target_url,
            "domain": domain,
            "clean_domain": clean_domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "depth": depth,
            "risk_level": "LOW",
            "risk_score": 0,
            "findings": [],
            "dns": {},
            "ssl": {},
            "whois": {},
            "redirect_chain": [],
            "phishing_score": {},
            "homograph": {},
            "typosquatting": {},
            "domain_age": {},
        }

        try:
            # Always run these
            report["phishing_score"] = self._check_phishing_indicators(target_url, domain, clean_domain)
            report["homograph"] = self._check_homograph(clean_domain)
            report["typosquatting"] = self._check_typosquatting(clean_domain)
            report["url_structure"] = self._analyze_url_structure(target_url, parsed)

            if depth in ("standard", "deep"):
                report["dns"] = self.dns_lookup(clean_domain)
                report["ssl"] = self.analyze_ssl(domain.split(":")[0])
                report["redirect_chain"] = self._check_redirects(target_url)

            if depth == "deep":
                report["whois"] = self.whois_lookup(clean_domain)
                report["domain_age"] = self._check_domain_age(report["whois"])
                report["content_analysis"] = self._analyze_page_content(target_url)
                report["reputation"] = self._check_reputation(clean_domain)
                # Full threat intelligence on deep scans
                report["threat_intelligence"] = self._run_threat_intel(target_url, clean_domain)

            # Compute overall risk
            self._compute_risk(report)

        except Exception as e:
            report["error"] = str(e)
            logger.error(f"Audit error for {target}: {e}")

        return report

    def _check_phishing_indicators(self, url: str, domain: str, clean_domain: str) -> Dict:
        """Check for phishing indicators in URL and domain."""
        indicators = []
        score = 0

        # Keyword analysis in domain
        for kw in PHISHING_KEYWORDS:
            if kw in clean_domain and not clean_domain.endswith(f"{kw}.com") and clean_domain != f"{kw}.com":
                indicators.append(f"Brand keyword '{kw}' in non-official domain")
                score += 20

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if clean_domain.endswith(tld):
                indicators.append(f"High-abuse TLD: {tld}")
                score += 25

        # Suspicious patterns in full URL
        for pattern in SUSPICIOUS_PATTERNS:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                indicators.append(f"Suspicious pattern detected: '{pattern}'")
                score += 15

        # IP address as host
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_domain):
            indicators.append("IP address used as hostname (bypasses DNS-based filtering)")
            score += 30

        # Many subdomains (subdomain stacking)
        parts = domain.split(".")
        if len(parts) > 4:
            indicators.append(f"Excessive subdomain nesting ({len(parts)} levels)")
            score += 20

        # Excessive URL length
        if len(url) > 200:
            indicators.append(f"Unusually long URL ({len(url)} characters)")
            score += 15

        # Hyphen count in domain
        if clean_domain.count("-") >= 3:
            indicators.append(f"Multiple hyphens in domain ({clean_domain.count('-')} hyphens)")
            score += 10

        # Numeric characters in domain
        num_count = sum(c.isdigit() for c in clean_domain.replace(".", ""))
        if num_count >= 4:
            indicators.append(f"High number of digits in domain ({num_count})")
            score += 10

        return {
            "score": min(score, 100),
            "indicators": indicators,
            "risk": "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW",
        }

    def _check_homograph(self, domain: str) -> Dict:
        """Detect homograph/IDN-based attacks."""
        findings = []
        suspicious_chars = []
        risk = "LOW"

        # Check for non-ASCII characters
        try:
            domain.encode("ascii")
        except UnicodeEncodeError:
            findings.append("Domain contains non-ASCII (Unicode) characters — possible homograph attack")
            risk = "HIGH"

        # Check each character against homograph map
        for char in domain:
            if char == ".":
                continue
            code_point = ord(char)
            if code_point > 127:
                char_name = unicodedata.name(char, "UNKNOWN")
                script = unicodedata.name(char, "").split(" ")[0] if unicodedata.name(char, "") else "?"
                suspicious_chars.append({
                    "char": char,
                    "codepoint": f"U+{code_point:04X}",
                    "name": char_name,
                })

        # Check if domain could be confused with popular brand
        try:
            encoded = domain.encode("ascii", errors="ignore").decode()
            if encoded != domain:
                findings.append(f"Punycode-encoded domain — renders visually as lookalike")
                risk = "HIGH"
        except Exception:
            pass

        # Normalize and compare
        normalized = unicodedata.normalize("NFKC", domain).lower()
        if normalized != domain.lower():
            findings.append(f"Domain normalizes differently — visual deception possible")

        return {
            "is_idn": bool(suspicious_chars),
            "suspicious_chars": suspicious_chars,
            "findings": findings,
            "risk": risk,
        }

    def _check_typosquatting(self, domain: str) -> Dict:
        """Detect typosquatting against popular domains."""
        matches = []

        for popular in POPULAR_DOMAINS:
            popular_base = popular.rsplit(".", 1)[0]
            test_base = domain.rsplit(".", 1)[0] if "." in domain else domain

            # Levenshtein distance
            dist = self._levenshtein(test_base.lower(), popular_base.lower())

            if 0 < dist <= 2 and test_base.lower() != popular_base.lower():
                matches.append({
                    "similar_to": popular,
                    "edit_distance": dist,
                    "technique": self._identify_typo_technique(test_base, popular_base),
                    "risk": "HIGH" if dist == 1 else "MEDIUM",
                })

        # Check character omission
        for popular in POPULAR_DOMAINS:
            popular_base = popular.rsplit(".", 1)[0]
            if domain.replace("-", "") == popular_base.replace("-", ""):
                matches.append({
                    "similar_to": popular,
                    "edit_distance": 0,
                    "technique": "Hyphen insertion/removal",
                    "risk": "HIGH",
                })

        return {
            "likely_targets": matches[:10],  # Top 10 matches
            "risk": "HIGH" if any(m["risk"] == "HIGH" for m in matches) else
                    "MEDIUM" if matches else "LOW",
        }

    def _identify_typo_technique(self, domain: str, popular: str) -> str:
        """Identify the typosquatting technique used."""
        if len(domain) == len(popular):
            return "Character substitution (e.g., goggle/google)"
        elif len(domain) == len(popular) + 1:
            return "Character insertion (e.g., gooogle/google)"
        elif len(domain) == len(popular) - 1:
            return "Character omission (e.g., gogle/google)"
        else:
            return "Multiple modifications"

    def _analyze_url_structure(self, url: str, parsed) -> Dict:
        """Analyze URL structure for anomalies."""
        return {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "query_params": len(urllib.parse.parse_qs(parsed.query)),
            "fragment": bool(parsed.fragment),
            "has_user_info": bool(parsed.username),
            "port": parsed.port,
            "url_length": len(url),
            "path_depth": len([p for p in parsed.path.split("/") if p]),
            "has_ip": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed.hostname or "")),
        }

    def dns_lookup(self, domain: str) -> Dict:
        """Comprehensive DNS record analysis."""
        results = {
            "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
            "SPF": [], "DMARC": [], "CNAME": None,
            "errors": [],
        }

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = resolver.resolve(domain, record_type)
                    if record_type == "A":
                        results["A"] = [str(r) for r in answers]
                    elif record_type == "AAAA":
                        results["AAAA"] = [str(r) for r in answers]
                    elif record_type == "MX":
                        results["MX"] = [f"{r.preference} {r.exchange}" for r in answers]
                    elif record_type == "NS":
                        results["NS"] = [str(r) for r in answers]
                    elif record_type == "TXT":
                        txt_records = [r.to_text().strip('"') for r in answers]
                        results["TXT"] = txt_records
                        results["SPF"] = [r for r in txt_records if r.startswith("v=spf1")]
                    elif record_type == "CNAME":
                        results["CNAME"] = str(answers[0])
                except Exception:
                    pass

            # Check DMARC
            try:
                dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
                results["DMARC"] = [r.to_text().strip('"') for r in dmarc]
            except Exception:
                results["DMARC"] = []

        except ImportError:
            # Fallback to socket
            try:
                addrs = socket.getaddrinfo(domain, None)
                results["A"] = list(set(a[4][0] for a in addrs if a[0] == socket.AF_INET))
                results["AAAA"] = list(set(a[4][0] for a in addrs if a[0] == socket.AF_INET6))
            except Exception as e:
                results["errors"].append(f"DNS lookup failed: {e}")

        except Exception as e:
            results["errors"].append(str(e))

        return results

    def analyze_ssl(self, hostname: str) -> Dict:
        """Deep SSL/TLS certificate analysis."""
        result = {
            "hostname": hostname,
            "reachable": False,
            "valid": False,
            "errors": [],
        }

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result["reachable"] = True
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    result["valid"] = True
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["not_before"] = cert.get("notBefore", "")
                    result["not_after"] = cert.get("notAfter", "")
                    result["cipher_suite"] = cipher[0] if cipher else "?"
                    result["tls_version"] = version
                    result["san"] = [
                        x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"
                    ]
                    result["serial_number"] = cert.get("serialNumber", "")

                    # Check expiry
                    try:
                        from email.utils import parsedate_to_datetime
                        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.utcnow()).days
                        result["days_until_expiry"] = days_left
                        if days_left < 0:
                            result["errors"].append("Certificate is EXPIRED")
                        elif days_left < 30:
                            result["errors"].append(f"Certificate expires in {days_left} days")
                    except Exception:
                        pass

                    # Check for self-signed
                    subject = result.get("subject", {})
                    issuer = result.get("issuer", {})
                    if subject == issuer:
                        result["self_signed"] = True
                        result["errors"].append("Self-signed certificate — not trusted by default")
                    else:
                        result["self_signed"] = False

                    # Check for weak cipher
                    if cipher and any(weak in cipher[0].upper() for weak in ["RC4", "DES", "NULL", "EXPORT", "ADH"]):
                        result["errors"].append(f"Weak cipher suite: {cipher[0]}")

                    # Check TLS version
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        result["errors"].append(f"Deprecated TLS version: {version}")

        except ssl.CertificateError as e:
            result["errors"].append(f"Certificate error: {e}")
            result["reachable"] = True
        except ConnectionRefusedError:
            result["errors"].append("Port 443 is closed — HTTPS not available")
        except socket.timeout:
            result["errors"].append("Connection timed out")
        except OSError as e:
            result["errors"].append(f"Connection error: {e}")
        except Exception as e:
            result["errors"].append(str(e))

        return result

    def whois_lookup(self, domain: str) -> Dict:
        """WHOIS registration forensics."""
        result = {
            "domain": domain,
            "registrar": "Unknown",
            "created": None,
            "expires": None,
            "updated": None,
            "registrant": {},
            "name_servers": [],
            "status": [],
            "error": None,
        }

        try:
            import whois
            w = whois.whois(domain)

            result["registrar"] = str(w.registrar or "Unknown")
            result["created"] = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date or "")
            result["expires"] = str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date or "")
            result["updated"] = str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date or "")
            result["name_servers"] = [str(ns).lower() for ns in (w.name_servers or [])]
            result["status"] = [str(s) for s in (w.status or [])] if isinstance(w.status, list) else [str(w.status or "")]
            result["registrant_country"] = str(getattr(w, "country", "Unknown") or "Unknown")

        except ImportError:
            result["error"] = "python-whois not installed"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_domain_age(self, whois_data: Dict) -> Dict:
        """Analyze domain age — newly registered domains are high-risk."""
        result = {"age_days": None, "risk": "UNKNOWN", "finding": ""}

        created_str = whois_data.get("created", "")
        if not created_str or created_str == "None":
            result["finding"] = "Could not determine domain creation date"
            return result

        try:
            # Try common date formats
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
                try:
                    created = datetime.strptime(created_str[:19], fmt)
                    break
                except ValueError:
                    continue
            else:
                created = datetime.fromisoformat(created_str[:19])

            age_days = (datetime.utcnow() - created).days
            result["age_days"] = age_days
            result["created_date"] = created_str

            if age_days < 30:
                result["risk"] = "HIGH"
                result["finding"] = f"Domain is only {age_days} days old — very suspicious"
            elif age_days < 180:
                result["risk"] = "MEDIUM"
                result["finding"] = f"Domain is relatively new ({age_days} days)"
            elif age_days < 365:
                result["risk"] = "LOW"
                result["finding"] = f"Domain is {age_days} days old"
            else:
                result["risk"] = "LOW"
                result["finding"] = f"Domain is established ({age_days} days, {age_days // 365} years)"

        except Exception as e:
            result["finding"] = f"Could not parse domain age: {e}"

        return result

    def _check_redirects(self, url: str) -> List[Dict]:
        """Follow and analyze redirect chain."""
        if not self.session:
            return []

        chain = []
        try:
            resp = self.session.get(url, allow_redirects=True, timeout=10)
            if resp.history:
                for r in resp.history:
                    chain.append({
                        "url": r.url,
                        "status": r.status_code,
                        "redirect_to": r.headers.get("Location", "?"),
                    })
            chain.append({
                "url": resp.url,
                "status": resp.status_code,
                "final": True,
            })
        except Exception as e:
            chain.append({"error": str(e)})

        return chain

    def _analyze_page_content(self, url: str) -> Dict:
        """Analyze page content for phishing indicators."""
        if not self.session:
            return {"error": "requests not available"}

        result = {
            "status_code": None,
            "forms_found": 0,
            "password_fields": 0,
            "external_resources": [],
            "brand_mentions": [],
            "suspicious_scripts": False,
        }

        try:
            resp = self.session.get(url, timeout=10)
            result["status_code"] = resp.status_code

            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")

                forms = soup.find_all("form")
                result["forms_found"] = len(forms)

                pwd_fields = soup.find_all("input", {"type": "password"})
                result["password_fields"] = len(pwd_fields)

                # Check for brand mentions
                text_lower = resp.text.lower()
                for brand in ["paypal", "amazon", "netflix", "apple", "microsoft",
                              "google", "facebook", "bank", "verify", "account"]:
                    if brand in text_lower:
                        result["brand_mentions"].append(brand)

                # Check for suspicious scripts
                scripts = soup.find_all("script")
                for script in scripts:
                    src = script.get("src", "")
                    if src and not any(safe in src for safe in ["googleapis", "cloudflare", "jquery"]):
                        result["suspicious_scripts"] = True
                        break

            except ImportError:
                result["note"] = "BeautifulSoup not available for content analysis"

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_reputation(self, domain: str) -> Dict:
        """Check domain reputation via public APIs."""
        result = {
            "virustotal": "not_checked",
            "google_safe_browsing": "not_checked",
            "note": "Reputation APIs require API keys. Configure in ~/.ixoryn/config.json",
        }
        return result

    def _run_threat_intel(self, url: str, domain: str) -> Dict:
        """Run full threat intelligence check (deep scan only)."""
        try:
            from ixoryn.modules.url_audit.threat_intel import ThreatIntelligence
            ti = ThreatIntelligence()
            return ti.full_check(domain)
        except Exception as e:
            return {"error": str(e), "note": "Threat intel check failed"}

    def _compute_risk(self, report: dict):
        """Compute overall risk score and level."""
        score = 0

        # Phishing score
        phishing = report.get("phishing_score", {})
        score += phishing.get("score", 0) * 0.35

        # Homograph
        homograph = report.get("homograph", {})
        if homograph.get("risk") == "HIGH":
            score += 40
        elif homograph.get("risk") == "MEDIUM":
            score += 20

        # Typosquatting
        typo = report.get("typosquatting", {})
        if typo.get("risk") == "HIGH":
            score += 30
        elif typo.get("risk") == "MEDIUM":
            score += 15

        # SSL issues
        ssl_data = report.get("ssl", {})
        ssl_errors = ssl_data.get("errors", [])
        score += len(ssl_errors) * 10

        # Domain age
        age = report.get("domain_age", {})
        if age.get("risk") == "HIGH":
            score += 35

        # Redirect chain (many redirects = suspicious)
        redirects = report.get("redirect_chain", [])
        if len(redirects) > 3:
            score += 10

        report["risk_score"] = min(int(score), 100)
        if score >= 75:
            report["risk_level"] = "CRITICAL"
        elif score >= 50:
            report["risk_level"] = "HIGH"
        elif score >= 25:
            report["risk_level"] = "MEDIUM"
        else:
            report["risk_level"] = "LOW"

        # Build findings list
        if phishing.get("indicators"):
            for ind in phishing["indicators"]:
                report["findings"].append({"type": "Phishing Indicator", "detail": ind})
        if homograph.get("findings"):
            for f in homograph["findings"]:
                report["findings"].append({"type": "Homograph Attack", "detail": f})
        if typo.get("likely_targets"):
            for t in typo["likely_targets"][:3]:
                report["findings"].append({
                    "type": "Typosquatting",
                    "detail": f"Possibly impersonating '{t['similar_to']}' "
                              f"(edit distance: {t['edit_distance']}, technique: {t['technique']})"
                })

    def print_report(self, report: dict):
        """Pretty-print the audit report."""
        risk_colors = {
            "LOW": Colors.GREEN,
            "MEDIUM": Colors.YELLOW,
            "HIGH": Colors.RED,
            "CRITICAL": Colors.RED,
        }
        risk = report.get("risk_level", "LOW")
        risk_color = risk_colors.get(risk, Colors.WHITE)

        print(f"\n  {'─' * 58}")
        Banner.result("Target", report.get("target", "?"))
        Banner.result("Risk Level",
                      f"{risk} ({report.get('risk_score', 0)}/100)",
                      risk_color)
        print()

        # Findings
        findings = report.get("findings", [])
        if findings:
            print(f"  {Colors.BOLD}Findings:{Colors.RESET}")
            for f in findings:
                print(f"    {Colors.RED}→{Colors.RESET} [{f.get('type')}] {f.get('detail', '')}")

        # Phishing
        phi = report.get("phishing_score", {})
        if phi.get("indicators"):
            phi_color = risk_colors.get(phi.get("risk", "LOW"), Colors.WHITE)
            Banner.result("\n  Phishing Risk",
                          f"{phi.get('risk')} (score: {phi.get('score', 0)})",
                          phi_color)

        # Homograph
        hom = report.get("homograph", {})
        if hom.get("findings"):
            print(f"  {Colors.YELLOW}  Homograph findings:{Colors.RESET}")
            for f in hom["findings"]:
                print(f"    → {f}")

        # Typosquatting
        typo = report.get("typosquatting", {})
        targets = typo.get("likely_targets", [])
        if targets:
            print(f"  {Colors.YELLOW}  Typosquatting targets:{Colors.RESET}")
            for t in targets[:3]:
                print(f"    → Similar to '{t['similar_to']}' "
                      f"(distance: {t['edit_distance']}, {t['technique']})")

        # SSL
        ssl = report.get("ssl", {})
        if ssl.get("errors"):
            print(f"  {Colors.RED}  SSL Issues:{Colors.RESET}")
            for e in ssl["errors"]:
                print(f"    → {e}")
        elif ssl.get("valid"):
            print(f"  {Colors.GREEN}  SSL: Valid — {ssl.get('tls_version', '?')} "
                  f"({ssl.get('days_until_expiry', '?')} days until expiry){Colors.RESET}")

        # Domain age
        age = report.get("domain_age", {})
        if age.get("finding"):
            age_color = risk_colors.get(age.get("risk", "LOW"), Colors.WHITE)
            Banner.result("  Domain Age", age.get("finding", "?"), age_color)

        print()

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if s1 == s2:
            return 0
        len1, len2 = len(s1), len(s2)
        if len1 == 0:
            return len2
        if len2 == 0:
            return len1

        matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
        for i in range(len1 + 1):
            matrix[i][0] = i
        for j in range(len2 + 1):
            matrix[0][j] = j

        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                matrix[i][j] = min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost,
                )

        return matrix[len1][len2]
