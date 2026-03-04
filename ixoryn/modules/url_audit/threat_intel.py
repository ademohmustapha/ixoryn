"""
Ixoryn Threat Intelligence Module
Integrates with public threat feeds and APIs:
  - VirusTotal (URL/domain/IP reputation)
  - AbuseIPDB (IP abuse scoring)
  - Google Safe Browsing (phishing/malware lists)
  - Shodan (port/service exposure)
  - URLhaus (malware URL database)
  - AlienVault OTX (open threat exchange)
  - Certificate Transparency logs
  - Passive DNS (via SecurityTrails-compatible structure)

API keys are read from ~/.ixoryn/config.json or environment variables.
All lookups degrade gracefully when keys are absent.
"""

import os
import json
import time
import socket
import hashlib
import urllib.parse
from typing import Dict, Any, Optional, List
from pathlib import Path
from ixoryn.core.logger import get_logger

logger = get_logger("threat_intel")


class ThreatIntelligence:
    """
    Multi-source threat intelligence aggregator.
    Queries available APIs and combines results into a unified risk verdict.
    """

    def __init__(self):
        self.config = self._load_config()
        self.session = self._init_session()
        self.cache = {}  # Simple in-memory cache per run
        self.cache_ttl = 300  # 5 minutes

    def _load_config(self) -> Dict:
        config_path = Path.home() / ".ixoryn" / "config.json"
        try:
            with open(config_path) as f:
                return json.load(f)
        except Exception:
            return {}

    def _init_session(self):
        try:
            import requests
            s = requests.Session()
            s.headers.update({
                "User-Agent": "Ixoryn-Security-Platform/1.0 (Security Research)",
                "Accept": "application/json",
            })
            s.timeout = 10
            return s
        except ImportError:
            return None

    def _get_key(self, service: str) -> Optional[str]:
        """Get API key from config or environment variable."""
        env_map = {
            "virustotal": "VIRUSTOTAL_API_KEY",
            "abuseipdb": "ABUSEIPDB_API_KEY",
            "google_safe_browsing": "GSB_API_KEY",
            "shodan": "SHODAN_API_KEY",
            "otx": "OTX_API_KEY",
            "securitytrails": "SECURITYTRAILS_API_KEY",
        }
        # Check environment first
        env_key = env_map.get(service)
        if env_key and os.environ.get(env_key):
            return os.environ[env_key]
        # Then config file
        return self.config.get("api_keys", {}).get(service)

    def _cached_get(self, url: str, headers: Dict = None, params: Dict = None) -> Optional[Dict]:
        """HTTP GET with simple caching."""
        if not self.session:
            return None
        cache_key = hashlib.sha256(f"{url}{params}".encode()).hexdigest()
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            if time.time() - entry["ts"] < self.cache_ttl:
                return entry["data"]
        try:
            resp = self.session.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                self.cache[cache_key] = {"ts": time.time(), "data": data}
                return data
            logger.debug(f"HTTP {resp.status_code} from {url}")
        except Exception as e:
            logger.debug(f"Request failed {url}: {e}")
        return None

    # ─── VIRUSTOTAL ───────────────────────────────────────────────────
    def check_virustotal(self, target: str) -> Dict:
        """Query VirusTotal for URL/domain/IP reputation."""
        result = {
            "source": "VirusTotal",
            "available": False,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "engines_total": 0,
            "verdict": "unknown",
            "permalink": None,
            "error": None,
        }

        key = self._get_key("virustotal")
        if not key:
            result["error"] = "No API key. Set VIRUSTOTAL_API_KEY or add to ~/.ixoryn/config.json"
            return result

        # Determine if URL, IP, or domain
        headers = {"x-apikey": key}
        try:
            # Encode target for VT API v3
            import base64
            if target.startswith("http"):
                encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
            elif self._is_ip(target):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            else:
                url = f"https://www.virustotal.com/api/v3/domains/{target}"

            data = self._cached_get(url, headers=headers)
            if data and "data" in data:
                attrs = data["data"].get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["available"] = True
                result["malicious"] = stats.get("malicious", 0)
                result["suspicious"] = stats.get("suspicious", 0)
                result["harmless"] = stats.get("harmless", 0)
                result["undetected"] = stats.get("undetected", 0)
                result["engines_total"] = sum(stats.values())
                result["permalink"] = f"https://www.virustotal.com/gui/domain/{target}"

                if result["malicious"] >= 3:
                    result["verdict"] = "MALICIOUS"
                elif result["malicious"] >= 1 or result["suspicious"] >= 3:
                    result["verdict"] = "SUSPICIOUS"
                else:
                    result["verdict"] = "CLEAN"

                logger.info(f"VT check {target}: {result['verdict']} "
                            f"({result['malicious']} malicious engines)")
        except Exception as e:
            result["error"] = str(e)

        return result

    # ─── ABUSEIPDB ────────────────────────────────────────────────────
    def check_abuseipdb(self, ip_or_domain: str) -> Dict:
        """Check IP reputation via AbuseIPDB."""
        result = {
            "source": "AbuseIPDB",
            "available": False,
            "abuse_confidence": 0,
            "total_reports": 0,
            "country": None,
            "isp": None,
            "is_tor": False,
            "verdict": "unknown",
            "error": None,
        }

        key = self._get_key("abuseipdb")
        if not key:
            result["error"] = "No API key. Set ABUSEIPDB_API_KEY"
            return result

        # Resolve domain to IP if needed
        ip = ip_or_domain
        if not self._is_ip(ip_or_domain):
            try:
                ip = socket.gethostbyname(ip_or_domain)
            except Exception:
                result["error"] = f"Could not resolve {ip_or_domain}"
                return result

        try:
            data = self._cached_get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            )
            if data and "data" in data:
                d = data["data"]
                result["available"] = True
                result["abuse_confidence"] = d.get("abuseConfidenceScore", 0)
                result["total_reports"] = d.get("totalReports", 0)
                result["country"] = d.get("countryCode")
                result["isp"] = d.get("isp")
                result["is_tor"] = d.get("isTor", False)

                score = result["abuse_confidence"]
                if score >= 80:
                    result["verdict"] = "MALICIOUS"
                elif score >= 25:
                    result["verdict"] = "SUSPICIOUS"
                else:
                    result["verdict"] = "CLEAN"
        except Exception as e:
            result["error"] = str(e)

        return result

    # ─── GOOGLE SAFE BROWSING ─────────────────────────────────────────
    def check_google_safe_browsing(self, url: str) -> Dict:
        """Check URL against Google Safe Browsing API v4."""
        result = {
            "source": "Google Safe Browsing",
            "available": False,
            "is_phishing": False,
            "is_malware": False,
            "is_unwanted": False,
            "threat_types": [],
            "verdict": "unknown",
            "error": None,
        }

        key = self._get_key("google_safe_browsing")
        if not key:
            result["error"] = "No API key. Set GSB_API_KEY"
            return result

        if not self.session:
            result["error"] = "requests not available"
            return result

        try:
            payload = {
                "client": {"clientId": "ixoryn", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            resp = self.session.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                json=payload, timeout=10,
            )
            if resp.status_code == 200:
                result["available"] = True
                data = resp.json()
                matches = data.get("matches", [])
                for match in matches:
                    tt = match.get("threatType", "")
                    result["threat_types"].append(tt)
                    if tt == "SOCIAL_ENGINEERING":
                        result["is_phishing"] = True
                    elif tt == "MALWARE":
                        result["is_malware"] = True
                    elif tt == "UNWANTED_SOFTWARE":
                        result["is_unwanted"] = True

                if result["is_phishing"] or result["is_malware"]:
                    result["verdict"] = "MALICIOUS"
                elif result["is_unwanted"] or result["threat_types"]:
                    result["verdict"] = "SUSPICIOUS"
                else:
                    result["verdict"] = "CLEAN"
        except Exception as e:
            result["error"] = str(e)

        return result

    # ─── SHODAN ───────────────────────────────────────────────────────
    def check_shodan(self, ip_or_domain: str) -> Dict:
        """Query Shodan for open ports and service exposure."""
        result = {
            "source": "Shodan",
            "available": False,
            "ip": None,
            "ports": [],
            "hostnames": [],
            "country": None,
            "org": None,
            "os": None,
            "vulns": [],
            "risk_ports": [],
            "verdict": "unknown",
            "error": None,
        }

        key = self._get_key("shodan")
        if not key:
            result["error"] = "No API key. Set SHODAN_API_KEY"
            return result

        ip = ip_or_domain
        if not self._is_ip(ip_or_domain):
            try:
                ip = socket.gethostbyname(ip_or_domain)
            except Exception:
                result["error"] = f"Could not resolve {ip_or_domain}"
                return result

        result["ip"] = ip

        RISKY_PORTS = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
            27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
            8080: "HTTP Proxy", 8443: "HTTPS Alt", 445: "SMB",
            135: "RPC", 139: "NetBIOS",
        }

        try:
            data = self._cached_get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": key},
            )
            if data:
                result["available"] = True
                result["ports"] = data.get("ports", [])
                result["hostnames"] = data.get("hostnames", [])
                result["country"] = data.get("country_name")
                result["org"] = data.get("org")
                result["os"] = data.get("os")
                result["vulns"] = list(data.get("vulns", {}).keys())

                for port in result["ports"]:
                    if port in RISKY_PORTS:
                        result["risk_ports"].append(f"{port}/{RISKY_PORTS[port]}")

                if result["vulns"]:
                    result["verdict"] = "HIGH_RISK"
                elif result["risk_ports"]:
                    result["verdict"] = "SUSPICIOUS"
                else:
                    result["verdict"] = "CLEAN"
        except Exception as e:
            result["error"] = str(e)

        return result

    # ─── URLHAUS ──────────────────────────────────────────────────────
    def check_urlhaus(self, url: str) -> Dict:
        """Check URL against URLhaus malware database (no API key needed)."""
        result = {
            "source": "URLhaus",
            "available": False,
            "in_database": False,
            "threat": None,
            "tags": [],
            "date_added": None,
            "verdict": "unknown",
            "error": None,
        }

        if not self.session:
            result["error"] = "requests not available"
            return result

        try:
            resp = self.session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=10,
            )
            if resp.status_code == 200:
                result["available"] = True
                data = resp.json()
                query_status = data.get("query_status", "")

                if query_status == "is_phishing" or query_status == "is_malware":
                    result["in_database"] = True
                    result["threat"] = data.get("threat")
                    result["tags"] = data.get("tags") or []
                    result["date_added"] = data.get("date_added")
                    result["verdict"] = "MALICIOUS"
                elif query_status == "no_results":
                    result["verdict"] = "CLEAN"
                else:
                    result["verdict"] = "unknown"
        except Exception as e:
            result["error"] = str(e)

        return result

    # ─── ALIENVAULT OTX ───────────────────────────────────────────────
    def check_otx(self, target: str) -> Dict:
        """Check AlienVault OTX threat intelligence (free API)."""
        result = {
            "source": "AlienVault OTX",
            "available": False,
            "pulse_count": 0,
            "threat_score": 0,
            "malware_families": [],
            "verdict": "unknown",
            "error": None,
        }

        key = self._get_key("otx")
        if not key:
            result["error"] = "No API key. Set OTX_API_KEY (free at otx.alienvault.com)"
            return result

        headers = {"X-OTX-API-KEY": key}
        try:
            if self._is_ip(target):
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general"
            elif target.startswith("http"):
                encoded = urllib.parse.quote(target, safe="")
                url = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded}/general"
            else:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"

            data = self._cached_get(url, headers=headers)
            if data:
                result["available"] = True
                result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
                result["threat_score"] = data.get("reputation", 0)

                pulses = data.get("pulse_info", {}).get("pulses", [])
                families = set()
                for pulse in pulses[:10]:
                    for mf in pulse.get("malware_families", []):
                        families.add(mf.get("display_name", ""))
                result["malware_families"] = list(families)

                if result["pulse_count"] >= 5:
                    result["verdict"] = "MALICIOUS"
                elif result["pulse_count"] >= 1:
                    result["verdict"] = "SUSPICIOUS"
                else:
                    result["verdict"] = "CLEAN"
        except Exception as e:
            result["error"] = str(e)

        return result

    # ─── CERTIFICATE TRANSPARENCY ─────────────────────────────────────
    def check_cert_transparency(self, domain: str) -> Dict:
        """Query crt.sh for certificate transparency logs."""
        result = {
            "source": "Certificate Transparency (crt.sh)",
            "available": False,
            "certificates": [],
            "subdomains_discovered": [],
            "wildcard_certs": False,
            "suspicious_certs": [],
            "error": None,
        }

        if not self.session:
            result["error"] = "requests not available"
            return result

        try:
            data = self._cached_get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
            )
            if data and isinstance(data, list):
                result["available"] = True
                seen_names = set()

                for cert in data[:100]:
                    name_value = cert.get("name_value", "")
                    issuer = cert.get("issuer_name", "")
                    not_before = cert.get("not_before", "")

                    for name in name_value.split("\n"):
                        name = name.strip()
                        if name and name not in seen_names:
                            seen_names.add(name)
                            if name.startswith("*"):
                                result["wildcard_certs"] = True
                            # Flag very new certs from obscure issuers as suspicious
                            if not_before and not_before > "2024-01-01":
                                if "Let's Encrypt" not in issuer and "DigiCert" not in issuer:
                                    result["suspicious_certs"].append({
                                        "name": name,
                                        "issuer": issuer,
                                        "issued": not_before,
                                    })

                result["subdomains_discovered"] = sorted(list(seen_names))[:50]
                result["certificates"] = data[:10]  # First 10 full cert records
        except Exception as e:
            result["error"] = str(e)

        return result

    # ─── PASSIVE DNS ──────────────────────────────────────────────────
    def check_passive_dns(self, domain: str) -> Dict:
        """Query passive DNS via HackerTarget (no key) for historical resolutions."""
        result = {
            "source": "Passive DNS (HackerTarget)",
            "available": False,
            "historical_ips": [],
            "current_ips": [],
            "ip_count": 0,
            "error": None,
        }

        if not self.session:
            result["error"] = "requests not available"
            return result

        try:
            resp = self.session.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
                timeout=10,
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                result["available"] = True
                lines = resp.text.strip().split("\n")
                ips = []
                for line in lines:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        ips.append({"hostname": parts[0], "ip": parts[1]})
                result["historical_ips"] = ips
                result["ip_count"] = len(ips)
        except Exception as e:
            result["error"] = str(e)

        return result

    # ─── AGGREGATE ────────────────────────────────────────────────────
    def full_check(self, target: str) -> Dict:
        """
        Run all available threat intelligence checks against a target.
        Returns aggregated results with overall verdict.
        """
        results = {
            "target": target,
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            "checks": {},
            "overall_verdict": "CLEAN",
            "overall_risk_score": 0,
            "sources_queried": 0,
            "sources_available": 0,
            "api_key_status": self._get_api_key_status(),
        }

        url = target if target.startswith("http") else f"https://{target}"
        domain = urllib.parse.urlparse(url).netloc or target
        clean_domain = domain.split(":")[0].lstrip("www.")

        # Always run these (no key needed)
        results["checks"]["urlhaus"] = self.check_urlhaus(url)
        results["checks"]["cert_transparency"] = self.check_cert_transparency(clean_domain)
        results["checks"]["passive_dns"] = self.check_passive_dns(clean_domain)

        # Run key-dependent checks
        results["checks"]["virustotal"] = self.check_virustotal(clean_domain)
        results["checks"]["abuseipdb"] = self.check_abuseipdb(clean_domain)
        results["checks"]["google_safe_browsing"] = self.check_google_safe_browsing(url)
        results["checks"]["shodan"] = self.check_shodan(clean_domain)
        results["checks"]["otx"] = self.check_otx(clean_domain)

        # Aggregate
        verdicts = []
        for name, check in results["checks"].items():
            results["sources_queried"] += 1
            if check.get("available"):
                results["sources_available"] += 1
            v = check.get("verdict", "unknown")
            if v not in ("unknown", "CLEAN"):
                verdicts.append(v)

        malicious_count = sum(1 for v in verdicts if v == "MALICIOUS")
        suspicious_count = sum(1 for v in verdicts if v == "SUSPICIOUS")

        score = (malicious_count * 35) + (suspicious_count * 15)
        results["overall_risk_score"] = min(score, 100)

        if malicious_count >= 2:
            results["overall_verdict"] = "MALICIOUS"
        elif malicious_count >= 1 or suspicious_count >= 3:
            results["overall_verdict"] = "SUSPICIOUS"
        elif suspicious_count >= 1:
            results["overall_verdict"] = "LOW_RISK"
        else:
            results["overall_verdict"] = "CLEAN"

        return results

    def _get_api_key_status(self) -> Dict:
        """Show which API keys are configured."""
        services = ["virustotal", "abuseipdb", "google_safe_browsing",
                    "shodan", "otx", "securitytrails"]
        return {
            svc: "configured" if self._get_key(svc) else "missing"
            for svc in services
        }

    def _is_ip(self, value: str) -> bool:
        import re
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))

    def print_results(self, results: Dict):
        """Pretty-print threat intelligence results."""
        from ixoryn.ui.banner import Banner, Colors

        verdict = results.get("overall_verdict", "CLEAN")
        verdict_colors = {
            "MALICIOUS": Colors.RED,
            "SUSPICIOUS": Colors.YELLOW,
            "LOW_RISK": Colors.YELLOW,
            "CLEAN": Colors.GREEN,
        }
        vc = verdict_colors.get(verdict, Colors.WHITE)

        Banner.section("Threat Intelligence Report")
        Banner.result("Target", results.get("target", "?"))
        Banner.result("Overall Verdict", verdict, vc)
        Banner.result("Risk Score", f"{results.get('overall_risk_score', 0)}/100")
        Banner.result("Sources Queried",
                      f"{results.get('sources_available', 0)}/{results.get('sources_queried', 0)} available")

        print(f"\n  {Colors.CYAN}── Per-Source Results ──────────────────────────{Colors.RESET}")
        for name, check in results.get("checks", {}).items():
            v = check.get("verdict", "unknown")
            vc2 = verdict_colors.get(v, Colors.DIM)
            avail = "✓" if check.get("available") else "✗"
            err = f"  {Colors.DIM}({check.get('error', '')}){Colors.RESET}" if check.get("error") else ""
            print(f"  {avail} {check.get('source', name):<35} {vc2}{v}{Colors.RESET}{err}")

        # API key status
        key_status = results.get("api_key_status", {})
        missing = [k for k, v in key_status.items() if v == "missing"]
        if missing:
            print(f"\n  {Colors.YELLOW}── Missing API Keys (add to ~/.ixoryn/config.json) ──{Colors.RESET}")
            key_docs = {
                "virustotal": "https://www.virustotal.com/gui/my-apikey (free)",
                "abuseipdb": "https://www.abuseipdb.com/register (free)",
                "google_safe_browsing": "https://developers.google.com/safe-browsing (free)",
                "shodan": "https://account.shodan.io (free tier)",
                "otx": "https://otx.alienvault.com (free)",
                "securitytrails": "https://securitytrails.com (free tier)",
            }
            for svc in missing:
                print(f"    {Colors.DIM}{svc}: {key_docs.get(svc, 'See docs')}{Colors.RESET}")

        print()
