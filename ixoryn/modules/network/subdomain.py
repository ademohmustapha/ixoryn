"""
Ixoryn Subdomain Enumerator
Discovers subdomains via:
1. Certificate Transparency logs (crt.sh) — passive, no packets to target
2. DNS brute-force with a built-in wordlist
3. Passive DNS via HackerTarget API
4. Common subdomain patterns
"""

import socket
import threading
import time
import requests
import json
from typing import Dict, List, Set, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from ixoryn.core.logger import get_logger

logger = get_logger(__name__)


# Comprehensive subdomain wordlist (top 500 most common)
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email",
    "remote", "blog", "server", "ns1", "ns2", "ns3", "ns4",
    "dev", "staging", "test", "demo", "beta", "alpha", "sandbox",
    "api", "api2", "api-v2", "rest", "graphql", "webhook",
    "admin", "administrator", "panel", "dashboard", "control",
    "cpanel", "whm", "plesk", "webadmin", "manage", "management",
    "vpn", "ssl", "secure", "auth", "login", "sso", "oauth",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "download", "downloads", "upload", "uploads",
    "shop", "store", "cart", "payment", "checkout", "billing",
    "portal", "app", "apps", "mobile", "m", "wap",
    "git", "gitlab", "github", "svn", "repo", "code", "ci", "jenkins",
    "jira", "confluence", "wiki", "docs", "documentation", "help",
    "support", "ticket", "helpdesk", "status", "monitor", "grafana",
    "db", "database", "mysql", "postgres", "oracle", "mongo", "redis",
    "elastic", "kibana", "solr", "ldap", "ldaps",
    "exchange", "autodiscover", "owa", "lync", "skype",
    "backup", "bak", "old", "legacy", "archive",
    "internal", "intranet", "private", "corp", "office",
    "proxy", "gateway", "firewall", "router", "switch",
    "chat", "slack", "teams", "video", "meet", "zoom",
    "crm", "erp", "hr", "finance", "accounting",
    "analytics", "tracking", "metrics", "stats",
    "news", "press", "media", "marketing", "ads",
    "cloud", "aws", "azure", "gcp", "k8s", "docker",
    "registry", "harbor", "nexus", "artifactory",
    "kafka", "rabbitmq", "celery", "worker",
    "health", "healthcheck", "ping",
    "v1", "v2", "v3", "v4",
    "prod", "production", "live", "staging2",
    "uat", "qa", "preprod", "pre-prod",
    "mx", "mx1", "mx2", "relay", "bounce",
    "web", "web1", "web2", "web3", "app1", "app2",
    "node1", "node2", "server1", "server2",
    "us", "eu", "uk", "asia", "au", "ca",
]


class SubdomainEnumerator:
    """
    Fast multi-threaded subdomain enumeration combining multiple techniques.
    """

    def __init__(self, timeout: float = 3.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads

    def enumerate(self, domain: str, wordlist: Optional[List[str]] = None,
                  methods: Optional[List[str]] = None) -> Dict:
        """
        Full subdomain enumeration.
        methods: list of ['certsh', 'bruteforce', 'hackertarget', 'dnsdumpster']
        Default: all passive methods + brute-force
        """
        if methods is None:
            methods = ["certsh", "bruteforce", "hackertarget"]

        start_time = time.time()
        discovered: Set[str] = set()
        results_by_method: Dict[str, List] = {}

        # Method 1: Certificate Transparency (crt.sh)
        if "certsh" in methods:
            certs = self._certsh_lookup(domain)
            results_by_method["cert_transparency"] = certs
            discovered.update(certs)

        # Method 2: HackerTarget Passive DNS
        if "hackertarget" in methods:
            ht = self._hackertarget_lookup(domain)
            results_by_method["hackertarget_dns"] = ht
            discovered.update(ht)

        # Method 3: DNS Brute-force
        if "bruteforce" in methods:
            wordlist_to_use = wordlist or COMMON_SUBDOMAINS
            bruteforced = self._dns_bruteforce(domain, wordlist_to_use)
            results_by_method["dns_bruteforce"] = bruteforced
            discovered.update(bruteforced)

        # Resolve all discovered subdomains
        resolved = self._resolve_all(list(discovered), domain)

        duration = round(time.time() - start_time, 2)

        return {
            "domain": domain,
            "total_found": len(resolved),
            "subdomains": resolved,
            "by_method": {k: len(v) for k, v in results_by_method.items()},
            "raw_by_method": results_by_method,
            "enumerated_at": datetime.now().isoformat(),
            "duration_seconds": duration,
        }

    def _certsh_lookup(self, domain: str) -> List[str]:
        """Query crt.sh certificate transparency logs."""
        found = set()
        try:
            resp = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=15,
                headers={"User-Agent": "IxorynScanner/1.1"}
            )
            if resp.status_code == 200:
                certs = resp.json()
                for cert in certs:
                    name_value = cert.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            found.add(name)
        except Exception as e:
            logger.debug(f"crt.sh lookup failed: {e}")

        return sorted(list(found))

    def _hackertarget_lookup(self, domain: str) -> List[str]:
        """Query HackerTarget passive DNS API (free, no key)."""
        found = set()
        try:
            resp = requests.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
                timeout=10,
                headers={"User-Agent": "IxorynScanner/1.1"}
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().splitlines():
                    parts = line.split(",")
                    if parts:
                        hostname = parts[0].strip().lower()
                        if hostname.endswith(f".{domain}") or hostname == domain:
                            found.add(hostname)
        except Exception as e:
            logger.debug(f"HackerTarget lookup failed: {e}")

        return sorted(list(found))

    def _dns_bruteforce(self, domain: str, wordlist: List[str]) -> List[str]:
        """
        Multi-threaded DNS resolution brute-force.
        Tests each word as a subdomain prefix.
        """
        found = []
        lock = threading.Lock()

        def try_subdomain(word: str):
            fqdn = f"{word}.{domain}"
            try:
                socket.setdefaulttimeout(self.timeout)
                ip = socket.gethostbyname(fqdn)
                with lock:
                    found.append(fqdn)
            except (socket.gaierror, socket.timeout):
                pass

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(try_subdomain, wordlist)

        return sorted(found)

    def _resolve_all(self, subdomains: List[str], base_domain: str) -> List[Dict]:
        """Resolve all discovered subdomains to get IPs and additional info."""
        resolved = []
        lock = threading.Lock()

        def resolve_one(subdomain: str):
            try:
                ip = socket.gethostbyname(subdomain)
                entry = {
                    "subdomain": subdomain,
                    "ip": ip,
                    "is_wildcard": False,
                }
                with lock:
                    resolved.append(entry)
            except Exception:
                # Include even unresolvable ones from cert transparency
                with lock:
                    resolved.append({
                        "subdomain": subdomain,
                        "ip": None,
                        "is_wildcard": False,
                    })

        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(resolve_one, subdomains)

        # Sort: resolved first, then by subdomain name
        resolved.sort(key=lambda x: (x["ip"] is None, x["subdomain"]))
        return resolved

    def format_results(self, result: Dict) -> str:
        """Format subdomain enumeration results for display."""
        try:
            from ixoryn.ui.banner import Colors as C
        except ImportError:
            class C:
                RED = YELLOW = GREEN = CYAN = RESET = BOLD = MUTED = WHITE = ""

        lines = []
        lines.append(f"\n{C.CYAN}{'═'*62}{C.RESET}")
        lines.append(f"{C.BOLD}  SUBDOMAIN ENUMERATION — {result['domain']}{C.RESET}")
        lines.append(f"{C.CYAN}{'═'*62}{C.RESET}")
        lines.append(f"  Total Discovered: {C.WHITE}{result['total_found']}{C.RESET}")
        lines.append(f"  Duration: {result['duration_seconds']}s\n")

        # By method
        lines.append(f"  Sources:")
        for method, count in result["by_method"].items():
            lines.append(f"    {method:<25} {count} subdomains")

        lines.append(f"\n  {'SUBDOMAIN':<45} {'IP ADDRESS'}")
        lines.append(f"  {'─'*45} {'─'*16}")

        for sub in result["subdomains"][:100]:  # Show first 100
            ip_str = sub.get("ip") or C.MUTED + "unresolved" + C.RESET
            sub_str = sub["subdomain"][:43]
            lines.append(f"  {C.GREEN}{sub_str:<45}{C.RESET} {ip_str}")

        if result["total_found"] > 100:
            lines.append(f"\n  ... and {result['total_found'] - 100} more.")

        lines.append(f"\n{C.CYAN}{'═'*62}{C.RESET}\n")
        return "\n".join(lines)
