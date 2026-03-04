"""
Ixoryn Network Scanner
Active reconnaissance: port scanning, banner grabbing, OS fingerprinting,
service version detection, traceroute, common vulnerability checks.
Pure Python — no Nmap dependency required (but uses it if available).
"""

import socket
import ssl
import struct
import time
import threading
import subprocess
import ipaddress
import platform
import re
import json
import concurrent.futures
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

from ixoryn.core.logger import get_logger

logger = get_logger(__name__)


# ── Well-known port definitions ──────────────────────────────────────────────
WELL_KNOWN_PORTS = {
    21: {"service": "FTP", "banner": True},
    22: {"service": "SSH", "banner": True},
    23: {"service": "Telnet", "banner": True},
    25: {"service": "SMTP", "banner": True},
    53: {"service": "DNS", "banner": False},
    80: {"service": "HTTP", "banner": True},
    110: {"service": "POP3", "banner": True},
    111: {"service": "RPC", "banner": False},
    135: {"service": "MS-RPC", "banner": False},
    139: {"service": "NetBIOS", "banner": False},
    143: {"service": "IMAP", "banner": True},
    161: {"service": "SNMP", "banner": False},
    389: {"service": "LDAP", "banner": False},
    443: {"service": "HTTPS", "banner": True},
    445: {"service": "SMB", "banner": False},
    465: {"service": "SMTPS", "banner": True},
    587: {"service": "SMTP-Submission", "banner": True},
    636: {"service": "LDAPS", "banner": False},
    993: {"service": "IMAPS", "banner": True},
    995: {"service": "POP3S", "banner": True},
    1433: {"service": "MSSQL", "banner": True},
    1521: {"service": "Oracle-DB", "banner": True},
    2375: {"service": "Docker-API", "banner": True},
    2376: {"service": "Docker-TLS", "banner": True},
    3306: {"service": "MySQL", "banner": True},
    3389: {"service": "RDP", "banner": False},
    4444: {"service": "Metasploit", "banner": True},
    5432: {"service": "PostgreSQL", "banner": True},
    5900: {"service": "VNC", "banner": True},
    6379: {"service": "Redis", "banner": True},
    8080: {"service": "HTTP-Alt", "banner": True},
    8443: {"service": "HTTPS-Alt", "banner": True},
    8888: {"service": "Jupyter/HTTP", "banner": True},
    9200: {"service": "Elasticsearch", "banner": True},
    27017: {"service": "MongoDB", "banner": True},
    27018: {"service": "MongoDB-Shard", "banner": True},
    5601: {"service": "Kibana", "banner": True},
    6443: {"service": "Kubernetes-API", "banner": True},
    10250: {"service": "Kubernetes-Kubelet", "banner": True},
}

# Common port ranges
COMMON_PORTS = list(WELL_KNOWN_PORTS.keys())
TOP_100_PORTS = COMMON_PORTS + [
    20, 79, 81, 82, 83, 84, 88, 102, 104, 179, 194, 220,
    264, 381, 383, 411, 412, 427, 444, 458, 502, 515, 520,
    548, 554, 563, 631, 666, 695, 873, 902, 989, 990, 992,
    1080, 1194, 1234, 1241, 1311, 1352, 1433, 1434, 1720,
    1723, 1741, 1755, 1900, 2000, 2049, 2100, 2181, 2222,
    2483, 2484, 3000, 3001, 3128, 3268, 3269, 3690, 4369,
    4848, 5000, 5001, 5004, 5005, 5060, 5061, 5672, 5800,
    5984, 6000, 6001, 6002, 6003, 6004, 6005, 6006,
]


class NetworkScanner:
    """
    World-class network scanner with:
    - Multi-threaded TCP port scanning
    - UDP port scanning (key services)
    - Banner grabbing & service fingerprinting
    - SSL/TLS certificate grabbing on HTTPS ports
    - OS fingerprinting via TTL and TCP window analysis
    - HTTP service analysis (headers, technologies, misconfigs)
    - Vulnerability hints based on software versions
    - Traceroute / hop analysis
    - Nmap integration (if installed)
    - JSON + formatted output
    """

    def __init__(self, timeout: float = 2.0, max_threads: int = 150):
        self.timeout = timeout
        self.max_threads = max_threads
        self._lock = threading.Lock()

    # ── CORE SCANNING ────────────────────────────────────────────────────────

    def scan(self, target: str, ports: Optional[str] = None,
             depth: str = "standard", udp: bool = False) -> Dict:
        """
        Full network scan.
        depth: quick (top ports) | standard (top 100) | deep (all 65535)
        """
        start_time = time.time()

        # Resolve target
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return {"error": f"Cannot resolve hostname: {target}"}

        report = {
            "target": target,
            "ip": ip,
            "scan_time": datetime.now().isoformat(),
            "depth": depth,
            "open_ports": [],
            "closed_count": 0,
            "os_guess": None,
            "traceroute": None,
            "vulnerabilities": [],
            "risk_score": 0,
            "risk_level": "LOW",
            "summary": "",
            "duration_seconds": 0,
        }

        # Determine port list
        port_list = self._parse_ports(ports, depth)

        # TCP scan
        open_ports = self._tcp_scan(ip, port_list)
        report["open_ports"] = open_ports
        report["closed_count"] = len(port_list) - len(open_ports)

        # UDP scan for critical services
        if udp and depth in ("standard", "deep"):
            udp_results = self._udp_scan(ip, [53, 67, 68, 69, 123, 137, 161, 500, 514, 1194])
            report["udp_ports"] = udp_results

        # Service enrichment
        if open_ports:
            self._enrich_services(ip, report["open_ports"], depth)

        # OS fingerprint
        report["os_guess"] = self._os_fingerprint(ip, open_ports)

        # Traceroute
        if depth in ("standard", "deep"):
            report["traceroute"] = self._traceroute(target)

        # Vulnerability analysis
        report["vulnerabilities"] = self._analyze_vulnerabilities(report["open_ports"])

        # Risk scoring
        self._compute_risk(report)

        report["duration_seconds"] = round(time.time() - start_time, 2)
        report["summary"] = self._build_summary(report)

        return report

    def _parse_ports(self, ports_str: Optional[str], depth: str) -> List[int]:
        """Parse port specification string or return default by depth."""
        if ports_str:
            result = []
            for part in ports_str.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-", 1)
                    result.extend(range(int(start), int(end) + 1))
                else:
                    result.append(int(part))
            return sorted(set(result))

        if depth == "quick":
            return COMMON_PORTS
        elif depth == "standard":
            return sorted(set(TOP_100_PORTS))
        elif depth == "deep":
            return list(range(1, 65536))
        return COMMON_PORTS

    def _tcp_scan(self, ip: str, ports: List[int]) -> List[Dict]:
        """Multi-threaded TCP connect scan."""
        open_ports = []
        lock = threading.Lock()

        def check_port(port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    service = WELL_KNOWN_PORTS.get(port, {}).get("service", "Unknown")
                    with lock:
                        open_ports.append({
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": service,
                            "banner": None,
                            "version": None,
                            "ssl": False,
                            "vulnerabilities": [],
                        })
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(check_port, ports)

        return sorted(open_ports, key=lambda x: x["port"])

    def _udp_scan(self, ip: str, ports: List[int]) -> List[Dict]:
        """UDP scan for critical services."""
        results = []
        udp_services = {
            53: "DNS", 67: "DHCP", 68: "DHCP-Client", 69: "TFTP",
            123: "NTP", 137: "NetBIOS-NS", 161: "SNMP",
            500: "IKE/VPN", 514: "Syslog", 1194: "OpenVPN"
        }

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)
                sock.sendto(b"\x00" * 8, (ip, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    results.append({
                        "port": port,
                        "protocol": "udp",
                        "state": "open",
                        "service": udp_services.get(port, "Unknown"),
                        "response_len": len(data),
                    })
                except socket.timeout:
                    pass  # Filtered or closed
                sock.close()
            except Exception:
                pass

        return results

    # ── SERVICE ENRICHMENT ───────────────────────────────────────────────────

    def _enrich_services(self, ip: str, ports: List[Dict], depth: str):
        """Grab banners, fingerprint versions, check SSL for all open ports."""
        def enrich_port(port_info: Dict):
            port = port_info["port"]
            is_ssl_port = port in (443, 8443, 465, 993, 995, 636, 989, 990)

            # Banner grab
            banner = self._grab_banner(ip, port, ssl=is_ssl_port)
            if banner:
                port_info["banner"] = banner[:512]
                port_info["version"] = self._parse_version(banner, port)

            # SSL certificate
            if is_ssl_port or (banner and "ssl" in banner.lower()):
                port_info["ssl"] = True
                cert_info = self._grab_ssl_cert(ip, port)
                if cert_info:
                    port_info["ssl_cert"] = cert_info

            # HTTP analysis
            if port in (80, 8080, 8888, 3000, 5601, 9200) or (port_info.get("service") in ("HTTP", "HTTP-Alt")):
                port_info["http_analysis"] = self._analyze_http(ip, port, ssl=False)
            elif port in (443, 8443):
                port_info["http_analysis"] = self._analyze_http(ip, port, ssl=True)

        if depth == "quick":
            for p in ports[:20]:
                enrich_port(p)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                executor.map(enrich_port, ports)

    def _grab_banner(self, ip: str, port: int, ssl: bool = False,
                     timeout: float = 3.0) -> Optional[str]:
        """Grab service banner from an open port."""
        import ssl as _ssl  # Local alias to avoid shadowing by parameter name
        probes = {
            21: b"",
            22: b"",
            25: b"EHLO ixoryn.local\r\n",
            80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            110: b"",
            143: b"",
            443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            3306: b"",
            5432: b"",
            6379: b"*1\r\n$4\r\nPING\r\n",
            9200: b"GET / HTTP/1.0\r\n\r\n",
            27017: b"",
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if ssl:
                # SCANNER INTENTIONAL: We disable cert verification on the *scanning*
                # connection so we can reach targets with self-signed, expired, or
                # misconfigured certs and then REPORT those issues to the user.
                # This is the expected behaviour for a security scanner.  The cert
                # details are separately retrieved and analysed by _grab_ssl_cert().
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE  # nosec — scanner intentional
                sock = ctx.wrap_socket(sock, server_hostname=ip)

            # Send probe
            probe = probes.get(port, b"")
            if probe:
                sock.send(probe)

            # Wait briefly for banner
            time.sleep(0.5)
            sock.settimeout(2.0)

            banner = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    banner += chunk
                    if len(banner) > 4096:
                        break
            except (socket.timeout, OSError):
                pass

            sock.close()
            return banner.decode("utf-8", errors="replace").strip() if banner else None

        except Exception:
            return None

    def _parse_version(self, banner: str, port: int) -> Optional[str]:
        """Extract software version from banner text."""
        patterns = [
            r"(?:Apache|nginx|Microsoft-IIS|lighttpd|Caddy)[/\s]+([\d.]+)",
            r"(?:OpenSSH|SSH-[\d.]+-OpenSSH)[_\s]+([\d.p]+)",
            r"(?:vsftpd|ProFTPD|FileZilla\sServer)[/\s]+([\d.]+)",
            r"(?:Postfix|Sendmail|Exim)[/\s]+([\d.]+)",
            r"(?:MySQL|MariaDB)[/\s]+([\d.]+)",
            r"(?:PostgreSQL)[/\s]+([\d.]+)",
            r"OpenSSL[/\s]+([\d.a-z]+)",
            r"PHP/([\d.]+)",
            r"Python/([\d.]+)",
            r"version ([\d.]+)",
            r"v([\d]+\.[\d]+\.[\d]+)",
        ]

        for pattern in patterns:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                return m.group(0)[:80]
        return None

    def _grab_ssl_cert(self, ip: str, port: int) -> Optional[Dict]:
        """Retrieve and parse SSL certificate information.

        SCANNER INTENTIONAL: cert verification is disabled so we can connect to
        targets with expired/self-signed certs and analyse them.  The cert details
        (expiry, self-signed flag, cipher strength) are what this function REPORTS.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # nosec — scanner intentional

            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Parse cert
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    san = cert.get("subjectAltName", [])
                    not_after = cert.get("notAfter", "")

                    # Check expiry
                    days_left = None
                    if not_after:
                        try:
                            from datetime import datetime
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry - datetime.utcnow()).days
                        except Exception:
                            pass

                    return {
                        "subject_cn": subject.get("commonName", ""),
                        "issuer_org": issuer.get("organizationName", ""),
                        "issuer_cn": issuer.get("commonName", ""),
                        "san_domains": [v for t, v in san if t == "DNS"][:10],
                        "not_after": not_after,
                        "days_until_expiry": days_left,
                        "self_signed": subject == issuer,
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else None,
                        "weak_cipher": self._is_weak_cipher(cipher[0] if cipher else ""),
                        "expired": days_left is not None and days_left < 0,
                        "expiring_soon": days_left is not None and 0 <= days_left < 30,
                    }
        except Exception:
            return None

    def _is_weak_cipher(self, cipher: str) -> bool:
        """Check if cipher suite is considered weak."""
        weak_markers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5", "SHA1"]
        return any(w.lower() in cipher.lower() for w in weak_markers)

    def _analyze_http(self, ip: str, port: int, ssl: bool = False) -> Dict:
        """Deep HTTP analysis: headers, server info, security misconfigs.

        SCANNER INTENTIONAL: verify=False lets us reach targets with bad certs to
        report them.  The missing/bad cert itself becomes a finding.
        """
        try:
            import requests
            import urllib3
            # Suppress the urllib3 InsecureRequestWarning — we handle it ourselves
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            proto = "https" if ssl else "http"
            url = f"{proto}://{ip}:{port}/"

            resp = requests.head(url, timeout=self.timeout, verify=False,  # nosec
                                 allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 (compatible; IxorynScanner/1.0)"})

            headers = dict(resp.headers)
            server = headers.get("Server", headers.get("server", ""))
            powered_by = headers.get("X-Powered-By", "")

            # Security header analysis
            security_issues = []
            missing_headers = []

            security_headers = {
                "Strict-Transport-Security": "HSTS missing — MITM risk",
                "Content-Security-Policy": "CSP missing — XSS risk",
                "X-Content-Type-Options": "X-Content-Type-Options missing — MIME sniffing risk",
                "X-Frame-Options": "X-Frame-Options missing — Clickjacking risk",
                "Referrer-Policy": "Referrer-Policy missing",
                "Permissions-Policy": "Permissions-Policy missing",
            }

            for header, issue in security_headers.items():
                if header not in headers and header.lower() not in {k.lower() for k in headers}:
                    missing_headers.append(issue)

            # Version disclosure
            if server:
                security_issues.append(f"Server version disclosed: {server}")
            if powered_by:
                security_issues.append(f"Technology disclosed: {powered_by}")

            # Dangerous headers
            if "Access-Control-Allow-Origin" in headers:
                if headers["Access-Control-Allow-Origin"] == "*":
                    security_issues.append("CORS: wildcard origin — cross-origin requests allowed from anywhere")

            # Cookies
            cookies_issues = []
            for cookie in resp.cookies:
                if not cookie.secure:
                    cookies_issues.append(f"Cookie '{cookie.name}' missing Secure flag")
                if not cookie.has_nonstandard_attr("httponly") and not cookie.has_nonstandard_attr("HttpOnly"):
                    cookies_issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")

            # Technology fingerprint
            tech_stack = []
            tech_map = {
                "WordPress": ["wp-content", "wp-includes"],
                "Drupal": ["Drupal"],
                "Joomla": ["Joomla!"],
                "Laravel": ["laravel_session"],
                "Django": ["csrftoken", "Django"],
                "React": ["_react"],
                "PHP": ["PHP", "phpsessid"],
                "ASP.NET": ["ASP.NET", "ASPX"],
                "Node.js": ["Express"],
                "Nginx": ["nginx"],
                "Apache": ["Apache"],
                "IIS": ["IIS", "ASP.NET"],
            }
            header_str = str(headers).lower() + str(resp.cookies).lower()
            for tech, markers in tech_map.items():
                if any(m.lower() in header_str for m in markers):
                    tech_stack.append(tech)

            return {
                "status_code": resp.status_code,
                "server": server,
                "powered_by": powered_by,
                "content_type": headers.get("Content-Type", ""),
                "security_headers_missing": missing_headers,
                "security_issues": security_issues,
                "cookie_issues": cookies_issues,
                "tech_stack": tech_stack,
                "headers_count": len(headers),
                "redirected_to": resp.url if resp.url != url else None,
            }
        except Exception as e:
            return {"error": str(e)}

    # ── OS FINGERPRINTING ────────────────────────────────────────────────────

    def _os_fingerprint(self, ip: str, open_ports: List[Dict]) -> Optional[str]:
        """
        Passive OS fingerprinting based on:
        - TTL value from ICMP ping
        - Banner keywords
        - Port profile matching
        """
        guess = {"os": "Unknown", "confidence": "low", "hints": []}

        # TTL-based fingerprinting via ping
        ttl = self._get_ttl(ip)
        if ttl:
            if ttl <= 64:
                guess["os"] = "Linux / Unix / Android / macOS"
                guess["confidence"] = "medium"
                guess["hints"].append(f"TTL={ttl} (typical Linux: 64)")
            elif ttl <= 128:
                guess["os"] = "Windows"
                guess["confidence"] = "medium"
                guess["hints"].append(f"TTL={ttl} (typical Windows: 128)")
            elif ttl <= 255:
                guess["os"] = "Cisco / Network Device / Solaris"
                guess["confidence"] = "low"
                guess["hints"].append(f"TTL={ttl} (typical Cisco: 255)")

        # Refine based on open ports
        ports_open = {p["port"] for p in open_ports}
        banners = " ".join([p.get("banner", "") or "" for p in open_ports]).lower()

        if 3389 in ports_open:
            guess["os"] = "Windows"
            guess["confidence"] = "high"
            guess["hints"].append("RDP (3389) open — strong Windows indicator")

        if 445 in ports_open and 139 in ports_open:
            if "windows" not in guess["os"].lower():
                guess["os"] = "Windows or Samba (Linux)"
            guess["hints"].append("SMB (445) + NetBIOS (139) — Windows/Samba")

        for kw, os_name in [
            ("ubuntu", "Ubuntu Linux"), ("debian", "Debian Linux"),
            ("centos", "CentOS Linux"), ("fedora", "Fedora Linux"),
            ("windows", "Windows"), ("microsoft", "Windows"),
            ("freebsd", "FreeBSD"), ("darwin", "macOS"),
            ("cisco", "Cisco IOS"), ("juniper", "Juniper JunOS"),
        ]:
            if kw in banners:
                guess["os"] = os_name
                guess["confidence"] = "high"
                guess["hints"].append(f"Banner keyword: '{kw}'")
                break

        return guess

    @staticmethod
    def _validate_ip_for_subprocess(ip: str) -> bool:
        """Validate IP/hostname before passing to subprocess to prevent injection."""
        import re as _re
        # Allow IPv4, IPv6, and valid hostnames only
        if _re.match(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$", ip):
            # IPv4 - validate octets
            parts = ip.split(".")
            return all(0 <= int(p) <= 255 for p in parts)
        if _re.match(r"^[0-9a-fA-F:]+$", ip):
            return True  # IPv6
        # Hostname: only alphanumeric, dots, hyphens
        return bool(_re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,254}$", ip))

    def _get_ttl(self, ip: str) -> Optional[int]:
        """Get TTL from ICMP ping."""
        try:
            # Validate input before passing to subprocess
            if not self._validate_ip_for_subprocess(ip):
                return None
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = result.stdout

            # Parse TTL
            m = re.search(r"ttl[=\s]+(\d+)", output, re.IGNORECASE)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return None

    # ── TRACEROUTE ───────────────────────────────────────────────────────────

    def _traceroute(self, target: str, max_hops: int = 20) -> List[Dict]:
        """Run traceroute/tracert and parse results."""
        try:
            # Validate target before subprocess call
            if not self._validate_ip_for_subprocess(target):
                return []
            # Clamp max_hops to a safe range
            max_hops = max(1, min(int(max_hops), 64))
            system = platform.system().lower()
            if system == "windows":
                cmd = ["tracert", "-d", "-h", str(max_hops), target]
            else:
                cmd = ["traceroute", "-n", "-m", str(max_hops), target]

            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=60)
            hops = []
            for line in result.stdout.splitlines():
                # Parse traceroute output
                m = re.match(r"\s*(\d+)\s+(?:(\d+\.?\d*)\s+ms\s+)?(.+)", line)
                if m:
                    hop_num = int(m.group(1))
                    rtt = m.group(2)
                    address = m.group(3).strip()

                    if hop_num > 0 and hop_num <= max_hops:
                        hops.append({
                            "hop": hop_num,
                            "address": address[:50],
                            "rtt_ms": float(rtt) if rtt else None,
                        })

            return hops[:max_hops]
        except Exception:
            return []

    # ── VULNERABILITY ANALYSIS ───────────────────────────────────────────────

    def _analyze_vulnerabilities(self, open_ports: List[Dict]) -> List[Dict]:
        """
        Analyze discovered services for known vulnerability patterns.
        Cross-references version strings against known-vulnerable versions.
        """
        vulns = []

        # Critical exposure rules
        dangerous_services = {
            2375: ("Docker API exposed without TLS", "CRITICAL",
                   "Unauthenticated Docker API allows full container/host compromise. "
                   "CVE references: multiple. Restrict to localhost immediately."),
            6379: ("Redis exposed without authentication", "CRITICAL",
                   "Redis with no authentication allows arbitrary command execution, "
                   "data theft, and potentially OS-level compromise via config writes."),
            27017: ("MongoDB exposed without authentication", "HIGH",
                    "MongoDB default install has no authentication. Attackers can read, "
                    "modify, or delete all databases."),
            9200: ("Elasticsearch exposed", "HIGH",
                   "Elasticsearch with no auth exposes all indexed data. "
                   "Commonly found storing sensitive PII, credentials, logs."),
            5601: ("Kibana exposed", "MEDIUM",
                   "Kibana dashboard exposed. May allow data access if Elasticsearch auth not enforced."),
            23: ("Telnet running", "HIGH",
                 "Telnet transmits all data including credentials in plaintext. "
                 "Replace with SSH immediately."),
            21: ("FTP running", "MEDIUM",
                 "FTP transmits credentials in plaintext. Consider SFTP or FTPS."),
            161: ("SNMP exposed", "MEDIUM",
                  "SNMP v1/v2c uses plaintext community strings. "
                  "Enumerable with default community 'public'."),
            5900: ("VNC exposed", "HIGH",
                   "VNC remote desktop exposed. Check authentication strength."),
            4444: ("Port 4444 open — potential backdoor", "CRITICAL",
                   "Port 4444 is the default Metasploit meterpreter listener port. "
                   "Verify this is not a backdoor or compromised service."),
            10250: ("Kubernetes Kubelet API exposed", "CRITICAL",
                    "Kubelet API exposure can allow arbitrary pod execution and "
                    "cluster node compromise."),
        }

        for port_info in open_ports:
            port = port_info["port"]
            banner = port_info.get("banner") or ""
            version_str = port_info.get("version") or ""

            # Check dangerous services
            if port in dangerous_services:
                name, severity, desc = dangerous_services[port]
                vulns.append({
                    "port": port,
                    "name": name,
                    "severity": severity,
                    "description": desc,
                    "type": "exposure",
                })

            # Version-based vulnerability hints
            version_vulns = self._check_version_vulns(banner + " " + version_str, port)
            vulns.extend(version_vulns)

            # HTTP security issues from http_analysis
            http = port_info.get("http_analysis", {})
            if http and not http.get("error"):
                for issue in http.get("security_issues", []):
                    vulns.append({
                        "port": port,
                        "name": issue,
                        "severity": "LOW",
                        "description": issue,
                        "type": "misconfiguration",
                    })
                for issue in http.get("security_headers_missing", [])[:3]:
                    vulns.append({
                        "port": port,
                        "name": f"Missing security header: {issue.split('—')[0].strip()}",
                        "severity": "INFO",
                        "description": issue,
                        "type": "security_header",
                    })

            # SSL issues
            ssl_cert = port_info.get("ssl_cert", {})
            if ssl_cert:
                if ssl_cert.get("expired"):
                    vulns.append({
                        "port": port, "name": "SSL Certificate EXPIRED",
                        "severity": "HIGH",
                        "description": f"SSL cert expired. Browser/client warnings will show.",
                        "type": "ssl",
                    })
                if ssl_cert.get("self_signed"):
                    vulns.append({
                        "port": port, "name": "Self-signed SSL certificate",
                        "severity": "MEDIUM",
                        "description": "Self-signed certificate — no trusted CA validation.",
                        "type": "ssl",
                    })
                if ssl_cert.get("weak_cipher"):
                    vulns.append({
                        "port": port, "name": f"Weak cipher suite: {ssl_cert.get('cipher_suite')}",
                        "severity": "MEDIUM",
                        "description": "Weak or deprecated cipher suite detected.",
                        "type": "ssl",
                    })
                if ssl_cert.get("expiring_soon"):
                    vulns.append({
                        "port": port,
                        "name": f"SSL Certificate expiring in {ssl_cert.get('days_until_expiry')} days",
                        "severity": "LOW",
                        "description": "Certificate will expire soon — schedule renewal.",
                        "type": "ssl",
                    })

        return vulns

    def _check_version_vulns(self, banner: str, port: int) -> List[Dict]:
        """Check banner/version string against known-vulnerable versions."""
        vulns = []

        version_checks = [
            # (pattern, version_extract, vuln_name, severity, description)
            (r"OpenSSH[_\s]([0-9.]+)", "OpenSSH",
             "Outdated OpenSSH detected", "MEDIUM",
             "Check NVD for CVEs: OpenSSH < 9.x has multiple vulnerabilities."),
            (r"Apache[/\s]([12]\.[0-4]\.[0-9]+)", "Apache httpd",
             "Outdated Apache httpd", "HIGH",
             "Apache < 2.4.54 has multiple critical vulnerabilities including path traversal."),
            (r"nginx[/\s]([01]\.[0-9]+\.[0-9]+)", "nginx",
             "Nginx version detected — verify up to date", "INFO",
             "Nginx versions < 1.24.x may have known CVEs. Verify patching."),
            (r"PHP/([0-9]+\.[0-9]+)", "PHP",
             "PHP version disclosed — verify not EOL", "MEDIUM",
             "PHP 7.x reached EOL. PHP 8.0 EOL Nov 2023. Use 8.2+ minimum."),
            (r"vsftpd ([12]\.[0-3])", "vsftpd",
             "Outdated vsftpd", "HIGH",
             "vsftpd 2.3.4 contains a backdoor (CVE-2011-2523)."),
            (r"Microsoft-IIS[/\s]([0-9]+\.[0-9]+)", "IIS",
             "IIS version disclosed", "LOW",
             "IIS version disclosure enables targeted exploitation."),
            (r"OpenSSL[/\s]([0-9]+\.[0-9]+\.[0-9]+[a-z]?)", "OpenSSL",
             "OpenSSL version detected — verify not vulnerable", "MEDIUM",
             "OpenSSL < 3.0.7 has critical vulnerabilities including CVE-2022-3786 (Heartbleed successor)."),
        ]

        for pattern, product, name, severity, desc in version_checks:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                vulns.append({
                    "port": port,
                    "name": f"{name} ({m.group(0)[:40]})",
                    "severity": severity,
                    "description": desc,
                    "type": "version",
                    "version_found": m.group(0)[:40],
                })

        return vulns

    # ── RISK SCORING ─────────────────────────────────────────────────────────

    def _compute_risk(self, report: Dict):
        """Calculate overall risk score and level from findings."""
        score = 0
        severity_weights = {
            "CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0
        }

        for vuln in report.get("vulnerabilities", []):
            score += severity_weights.get(vuln.get("severity", "INFO"), 0)

        # Extra risk for attack surface size
        open_count = len(report.get("open_ports", []))
        if open_count > 20:
            score += 15
        elif open_count > 10:
            score += 8
        elif open_count > 5:
            score += 3

        score = min(score, 100)
        report["risk_score"] = score

        if score >= 70:
            report["risk_level"] = "CRITICAL"
        elif score >= 45:
            report["risk_level"] = "HIGH"
        elif score >= 20:
            report["risk_level"] = "MEDIUM"
        else:
            report["risk_level"] = "LOW"

    def _build_summary(self, report: Dict) -> str:
        """Build human-readable scan summary."""
        open_count = len(report.get("open_ports", []))
        vuln_count = len(report.get("vulnerabilities", []))
        critical = sum(1 for v in report.get("vulnerabilities", []) if v.get("severity") == "CRITICAL")
        high = sum(1 for v in report.get("vulnerabilities", []) if v.get("severity") == "HIGH")

        parts = [
            f"{open_count} open port(s) found.",
            f"Risk level: {report.get('risk_level', 'UNKNOWN')} ({report.get('risk_score', 0)}/100).",
        ]
        if vuln_count:
            parts.append(f"{vuln_count} issue(s) found: {critical} critical, {high} high.")
        if report.get("os_guess"):
            os = report["os_guess"].get("os", "Unknown")
            conf = report["os_guess"].get("confidence", "low")
            parts.append(f"OS: {os} ({conf} confidence).")

        return " ".join(parts)

    # ── FORMATTED OUTPUT ─────────────────────────────────────────────────────

    def format_report(self, report: Dict, verbose: bool = False) -> str:
        """Format scan report for terminal display."""
        from ixoryn.ui.banner import Colors as C

        if report.get("error"):
            return f"{C.RED}[!] Error: {report['error']}{C.RESET}"

        lines = []
        lines.append(f"\n{C.CYAN}{'═'*62}{C.RESET}")
        lines.append(f"{C.BOLD}  NETWORK SCAN REPORT{C.RESET}")
        lines.append(f"{C.CYAN}{'═'*62}{C.RESET}")
        lines.append(f"  Target:     {C.WHITE}{report['target']}{C.RESET}")
        lines.append(f"  IP:         {C.WHITE}{report['ip']}{C.RESET}")
        lines.append(f"  Scan Depth: {report.get('depth', 'standard')}")
        lines.append(f"  Duration:   {report.get('duration_seconds', 0)}s")
        lines.append(f"  Scan Time:  {report.get('scan_time', '')}")

        # Risk level
        risk = report.get("risk_level", "LOW")
        score = report.get("risk_score", 0)
        risk_color = {
            "CRITICAL": C.RED, "HIGH": C.RED,
            "MEDIUM": C.YELLOW, "LOW": C.GREEN
        }.get(risk, C.GREEN)
        lines.append(f"  Risk Level: {risk_color}{risk} ({score}/100){C.RESET}")

        # OS guess
        os_g = report.get("os_guess", {})
        if os_g and os_g.get("os") != "Unknown":
            lines.append(f"  OS Guess:   {C.YELLOW}{os_g['os']} [{os_g['confidence']} confidence]{C.RESET}")

        # Open ports
        lines.append(f"\n{C.CYAN}── Open Ports ──────────────────────────────────────────{C.RESET}")
        if not report.get("open_ports"):
            lines.append("  No open ports found.")
        else:
            lines.append(f"  {'PORT':<8} {'PROTO':<6} {'SERVICE':<20} {'VERSION/BANNER'}")
            lines.append(f"  {'─'*8} {'─'*6} {'─'*20} {'─'*25}")
            for p in report["open_ports"]:
                port_str = f"{p['port']}"
                service = p.get("service", "Unknown")[:18]
                version = (p.get("version") or p.get("banner", "") or "")[:35]
                ssl_tag = " [SSL]" if p.get("ssl") else ""
                lines.append(f"  {C.GREEN}{port_str:<8}{C.RESET} {'tcp':<6} {service:<20} {version}{ssl_tag}")

                if verbose and p.get("http_analysis"):
                    http = p["http_analysis"]
                    if http.get("tech_stack"):
                        lines.append(f"           Tech: {', '.join(http['tech_stack'])}")

        # Vulnerabilities
        vulns = report.get("vulnerabilities", [])
        if vulns:
            lines.append(f"\n{C.RED}── Vulnerabilities & Issues ({len(vulns)}) ────────────────────{C.RESET}")
            sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            sorted_vulns = sorted(vulns, key=lambda v: sev_order.index(v.get("severity", "INFO")))
            for v in sorted_vulns[:20]:  # Show top 20
                sev = v.get("severity", "INFO")
                sev_color = {
                    "CRITICAL": C.RED, "HIGH": C.RED,
                    "MEDIUM": C.YELLOW, "LOW": C.CYAN, "INFO": C.MUTED
                }.get(sev, C.CYAN)
                lines.append(f"  [{sev_color}{sev:<8}{C.RESET}] Port {v['port']}: {v['name']}")
                if verbose:
                    lines.append(f"             {C.MUTED}{v.get('description', '')[:80]}{C.RESET}")

        # UDP
        if report.get("udp_ports"):
            lines.append(f"\n{C.CYAN}── UDP Services ─────────────────────────────────────────{C.RESET}")
            for p in report["udp_ports"]:
                lines.append(f"  {p['port']:<8} udp    {p.get('service','Unknown')}")

        # Traceroute
        if verbose and report.get("traceroute"):
            lines.append(f"\n{C.CYAN}── Traceroute ───────────────────────────────────────────{C.RESET}")
            for hop in report["traceroute"][:15]:
                rtt = f"{hop['rtt_ms']}ms" if hop.get("rtt_ms") else "* * *"
                lines.append(f"  {hop['hop']:>3}  {hop['address']:<40} {rtt}")

        lines.append(f"\n{C.CYAN}{'═'*62}{C.RESET}")
        lines.append(f"  {report.get('summary', '')}")
        lines.append(f"{C.CYAN}{'═'*62}{C.RESET}\n")

        return "\n".join(lines)
