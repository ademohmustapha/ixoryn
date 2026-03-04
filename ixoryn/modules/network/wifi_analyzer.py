"""
Ixoryn WiFi Security Analyzer
Analyzes wireless network security configurations without active attacks.
Detects weak protocols, default credentials indicators, and security misconfigurations.
Pure Python — uses system tools where available.
"""

import subprocess
import platform
import re
import socket
import json
from typing import Dict, List, Optional
from datetime import datetime

from ixoryn.core.logger import get_logger

logger = get_logger(__name__)


# Known default router credential patterns
KNOWN_DEFAULT_SSIDS = [
    "NETGEAR", "linksys", "dlink", "D-Link", "TP-LINK", "TPLINK",
    "Belkin", "ASUS", "xfinitywifi", "ATT", "Verizon", "Spectrum",
    "HUAWEI", "ZTE", "Zyxel", "default", "HOME", "ROUTER",
    "WiFi", "Wireless", "Network",
]

WEAK_SECURITY_INDICATORS = {
    "WEP": {"severity": "CRITICAL", "description": "WEP is completely broken — cracked in minutes"},
    "OPEN": {"severity": "CRITICAL", "description": "Open network — no encryption, all traffic visible"},
    "None": {"severity": "CRITICAL", "description": "No security — all traffic is unencrypted"},
    "WPA ": {"severity": "HIGH", "description": "WPA (TKIP) has known vulnerabilities — upgrade to WPA3"},
    "WPS": {"severity": "HIGH", "description": "WPS enabled — vulnerable to Pixie Dust and brute-force attacks"},
}

STRONG_INDICATORS = ["WPA2", "WPA3", "SAE", "CCMP", "AES"]


class WiFiAnalyzer:
    """
    WiFi Security Analysis — passive reconnaissance only.
    Analyzes visible networks for security protocol weaknesses.
    """

    def __init__(self):
        self.system = platform.system().lower()
        self._preflight_status = self._check_preflight()

    def _check_preflight(self) -> dict:
        """
        Run pre-flight checks before any scan attempt.
        Returns a dict with privilege status, tool availability, and clear guidance.
        Call get_preflight_status() to expose this to the user before scanning.
        """
        import shutil
        status = {
            "os": self.system,
            "has_root": False,
            "has_wifi_tools": False,
            "available_tools": [],
            "missing_tools": [],
            "warnings": [],
            "ready": False,
        }

        # ── Privilege check ────────────────────────────────────────────────
        if self.system in ("linux", "darwin"):
            import os
            status["has_root"] = (os.geteuid() == 0)
            if not status["has_root"]:
                status["warnings"].append(
                    "Not running as root. Some WiFi scan methods require elevated privileges. "
                    "Re-run with: sudo ixoryn  (or: sudo python -m ixoryn)"
                )
        elif self.system == "windows":
            try:
                import ctypes
                status["has_root"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                status["has_root"] = False
            if not status["has_root"]:
                status["warnings"].append(
                    "Not running as Administrator. WiFi scanning on Windows requires elevation. "
                    "Right-click Ixoryn and choose 'Run as Administrator'."
                )

        # ── Tool availability ──────────────────────────────────────────────
        if self.system == "linux":
            for tool in ["nmcli", "iwlist", "iwconfig"]:
                if shutil.which(tool):
                    status["available_tools"].append(tool)
                else:
                    status["missing_tools"].append(tool)
            if not status["available_tools"]:
                status["warnings"].append(
                    "No WiFi scanning tools found. Install: sudo apt install network-manager iw wireless-tools"
                )
            else:
                status["has_wifi_tools"] = True
        elif self.system == "darwin":
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if shutil.which("airport") or __import__("os").path.exists(airport):
                status["available_tools"].append("airport")
                status["has_wifi_tools"] = True
            else:
                status["warnings"].append(
                    "airport utility not found. WiFi scanning on macOS requires it. "
                    "It is bundled with macOS — check /System/Library/PrivateFrameworks/"
                )
        elif self.system == "windows":
            if shutil.which("netsh"):
                status["available_tools"].append("netsh")
                status["has_wifi_tools"] = True
            else:
                status["warnings"].append("netsh not found — this is unexpected on Windows.")

        # ── Hardware check (Linux only) ────────────────────────────────────
        if self.system == "linux":
            import subprocess
            try:
                r = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
                if "no wireless extensions" in r.stderr.lower() and "ESSID" not in r.stdout:
                    status["warnings"].append(
                        "No wireless interface detected by iwconfig. "
                        "This machine may have no WiFi adapter, or the adapter driver is not loaded. "
                        "Check: lspci | grep -i wireless  and  lsmod | grep 80211"
                    )
            except Exception:
                pass

        status["ready"] = status["has_wifi_tools"] and (
            status["has_root"] or self.system == "linux" and "nmcli" in status["available_tools"]
        )
        return status

    def get_preflight_status(self) -> dict:
        """Return pre-flight status for display before attempting a scan."""
        return self._preflight_status

    def scan_networks(self) -> Dict:
        """Scan for visible WiFi networks and analyze their security."""
        result = {
            "networks": [],
            "total_found": 0,
            "critical_count": 0,
            "high_count": 0,
            "safe_count": 0,
            "scanned_at": datetime.now().isoformat(),
            "scan_method": None,
            "error": None,
            "preflight": self._preflight_status,
            "warnings": list(self._preflight_status.get("warnings", [])),
        }

        # Fail fast with full actionable guidance when tools are missing
        if not self._preflight_status.get("has_wifi_tools") and self.system in ("linux", "darwin", "windows"):
            result["error"] = (
                "WiFi scan pre-flight failed — no scanning tools available. "
                + " | ".join(self._preflight_status.get("warnings", []))
            )
            return result

        if self.system == "linux":
            networks = self._scan_linux()
        elif self.system == "darwin":
            networks = self._scan_macos()
        elif self.system == "windows":
            networks = self._scan_windows()
        else:
            result["error"] = f"Unsupported OS: {self.system}"
            return result

        if isinstance(networks, str):
            result["error"] = networks
            return result

        for net in networks:
            analysis = self._analyze_network(net)
            net.update(analysis)
            result["networks"].append(net)
            sev = analysis.get("severity", "SAFE")
            if sev == "CRITICAL":
                result["critical_count"] += 1
            elif sev == "HIGH":
                result["high_count"] += 1
            else:
                result["safe_count"] += 1

        result["total_found"] = len(result["networks"])
        result["networks"].sort(key=lambda x: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"].index(x.get("severity", "SAFE")),
            -x.get("signal_strength", 0)
        ))

        return result

    def _scan_linux(self) -> List[Dict]:
        """Scan using nmcli or iwlist on Linux."""
        # Try nmcli first (most reliable)
        if subprocess.run(["which", "nmcli"], capture_output=True).returncode == 0:
            try:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY",
                     "device", "wifi", "list"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    return self._parse_nmcli(result.stdout)
            except Exception as e:
                logger.debug(f"nmcli failed: {e}")

        # Fallback: iwlist
        try:
            # Find wireless interface
            iface_result = subprocess.run(
                ["iwconfig"], capture_output=True, text=True, timeout=5
            )
            ifaces = re.findall(r"^(\w+)\s+IEEE", iface_result.stdout, re.MULTILINE)
            if not ifaces:
                return "No wireless interfaces found. Ensure WiFi is enabled."

            iface = ifaces[0]
            result = subprocess.run(
                ["sudo", "iwlist", iface, "scan"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return self._parse_iwlist(result.stdout)
        except Exception as e:
            return f"WiFi scan failed: {e}. Try running as root."

        return "Could not scan WiFi. Install nmcli: sudo apt install network-manager"

    def _scan_macos(self) -> List[Dict]:
        """Scan using airport on macOS."""
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        try:
            result = subprocess.run(
                [airport, "-s"], capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return self._parse_airport(result.stdout)
        except Exception as e:
            return f"Airport scan failed: {e}"
        return "macOS WiFi scan requires airport utility"

    def _scan_windows(self) -> List[Dict]:
        """Scan using netsh on Windows."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace"
            )
            if result.returncode == 0:
                return self._parse_netsh(result.stdout)
        except Exception as e:
            return f"netsh scan failed: {e}"
        return []

    def _parse_nmcli(self, output: str) -> List[Dict]:
        """Parse nmcli -t output."""
        networks = []
        for line in output.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 8:
                ssid = parts[0].replace("\\:", ":") if parts[0] else "<Hidden>"
                security = parts[7].strip() if len(parts) > 7 else "Unknown"
                try:
                    signal = int(parts[6]) if parts[6] else 0
                except ValueError:
                    signal = 0

                networks.append({
                    "ssid": ssid,
                    "bssid": parts[1] if len(parts) > 1 else "Unknown",
                    "channel": parts[3] if len(parts) > 3 else "?",
                    "signal_strength": signal,
                    "security": security,
                    "frequency": parts[4] if len(parts) > 4 else "",
                })
        return networks

    def _parse_iwlist(self, output: str) -> List[Dict]:
        """Parse iwlist scan output."""
        networks = []
        cells = re.split(r"Cell \d+ -", output)[1:]

        for cell in cells:
            ssid_m = re.search(r'ESSID:"([^"]*)"', cell)
            bssid_m = re.search(r"Address: ([0-9A-Fa-f:]+)", cell)
            signal_m = re.search(r"Signal level[=:](-?\d+)", cell)
            chan_m = re.search(r"Channel[:\s]+(\d+)", cell)
            enc_m = re.search(r"Encryption key:(on|off)", cell)
            ie_m = re.findall(r"IE: ([^\n]+)", cell)

            security = "OPEN"
            if enc_m and enc_m.group(1) == "on":
                if any("WPA2" in ie for ie in ie_m):
                    security = "WPA2"
                elif any("WPA" in ie for ie in ie_m):
                    security = "WPA"
                else:
                    security = "WEP"

            networks.append({
                "ssid": ssid_m.group(1) if ssid_m else "<Hidden>",
                "bssid": bssid_m.group(1) if bssid_m else "Unknown",
                "channel": chan_m.group(1) if chan_m else "?",
                "signal_strength": int(signal_m.group(1)) if signal_m else 0,
                "security": security,
                "extra_info": " | ".join(ie_m[:3]),
            })
        return networks

    def _parse_airport(self, output: str) -> List[Dict]:
        """Parse macOS airport -s output."""
        networks = []
        lines = output.strip().splitlines()
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 7:
                networks.append({
                    "ssid": parts[0],
                    "bssid": parts[1],
                    "signal_strength": int(parts[2]) if parts[2].lstrip("-").isdigit() else 0,
                    "channel": parts[3],
                    "security": parts[6] if len(parts) > 6 else "Unknown",
                })
        return networks

    def _parse_netsh(self, output: str) -> List[Dict]:
        """Parse Windows netsh output."""
        networks = []
        blocks = re.split(r"\n\n", output)
        for block in blocks:
            ssid_m = re.search(r"SSID\s+:\s+(.+)", block)
            auth_m = re.search(r"Authentication\s+:\s+(.+)", block)
            enc_m = re.search(r"Encryption\s+:\s+(.+)", block)
            sig_m = re.search(r"Signal\s+:\s+(\d+)%", block)

            if ssid_m:
                networks.append({
                    "ssid": ssid_m.group(1).strip(),
                    "bssid": "N/A",
                    "channel": "?",
                    "signal_strength": int(sig_m.group(1)) if sig_m else 0,
                    "security": f"{auth_m.group(1).strip()} / {enc_m.group(1).strip()}" if auth_m and enc_m else "Unknown",
                })
        return networks

    def _analyze_network(self, network: Dict) -> Dict:
        """Analyze a network's security configuration."""
        ssid = network.get("ssid", "")
        security = network.get("security", "")
        issues = []
        severity = "SAFE"

        # Security protocol check
        if not security or security in ("--", "None", "OPEN", ""):
            issues.append("CRITICAL: Open network — no encryption")
            severity = "CRITICAL"
        elif "WEP" in security:
            issues.append("CRITICAL: WEP encryption — completely broken, crackable in minutes")
            severity = "CRITICAL"
        elif "WPA " in security and "WPA2" not in security and "WPA3" not in security:
            issues.append("HIGH: WPA (TKIP only) — vulnerable to dictionary and KRACK attacks")
            severity = "HIGH" if severity != "CRITICAL" else severity
        elif "WPS" in security:
            issues.append("HIGH: WPS enabled — vulnerable to Pixie Dust attack (CVE-2011-5053)")
            severity = "HIGH" if severity != "CRITICAL" else severity

        # WPA2/WPA3 is generally safe
        if "WPA2" in security or "WPA3" in security or "SAE" in security:
            if severity == "SAFE":
                severity = "SAFE"

        # Default SSID check
        if any(ssid.upper().startswith(d.upper()) for d in KNOWN_DEFAULT_SSIDS):
            issues.append("MEDIUM: Default/generic SSID suggests possible default credentials")
            if severity == "SAFE":
                severity = "MEDIUM"

        # Hidden SSID
        if ssid in ("", "<Hidden>", "<hidden>"):
            issues.append("INFO: Hidden SSID — provides false sense of security (SSID still discoverable)")

        # Signal strength insight
        signal = network.get("signal_strength", 0)
        if signal > 70 or signal > -50:
            issues.append("INFO: Very strong signal — likely a nearby access point")

        return {
            "severity": severity,
            "issues": issues,
            "recommendation": self._get_recommendation(severity, security),
        }

    def _get_recommendation(self, severity: str, security: str) -> str:
        recs = {
            "CRITICAL": "Immediately disconnect and do not use. All traffic is visible to attackers.",
            "HIGH": "Upgrade router firmware and switch to WPA2-AES or WPA3. Disable WPS.",
            "MEDIUM": "Change default SSID and password. Enable WPA2 or WPA3.",
            "LOW": "Consider upgrading to WPA3 for future-proof security.",
            "SAFE": "Security configuration looks adequate. Keep firmware updated.",
        }
        return recs.get(severity, "Review security settings.")

    def analyze_ssid(self, ssid: str, security: str = None) -> Dict:
        """Analyze a specific SSID and security configuration (no scan needed)."""
        network = {
            "ssid": ssid,
            "bssid": "User-provided",
            "channel": "?",
            "signal_strength": 0,
            "security": security or "Unknown",
        }
        analysis = self._analyze_network(network)
        network.update(analysis)
        return network

    def format_results(self, result: Dict) -> str:
        """Format WiFi scan results for display."""
        try:
            from ixoryn.ui.banner import Colors as C
        except ImportError:
            class C:
                RED = YELLOW = GREEN = CYAN = RESET = BOLD = MUTED = WHITE = ""

        if result.get("error"):
            return f"\n  [!] {result['error']}\n"

        lines = [f"\n{C.CYAN}{'═'*62}{C.RESET}"]
        lines.append(f"{C.BOLD}  WiFi SECURITY SCAN RESULTS{C.RESET}")
        lines.append(f"{C.CYAN}{'═'*62}{C.RESET}")
        lines.append(f"  Networks Found: {C.WHITE}{result['total_found']}{C.RESET}")
        lines.append(f"  Critical Risk:  {C.RED}{result['critical_count']}{C.RESET}")
        lines.append(f"  High Risk:      {C.YELLOW}{result['high_count']}{C.RESET}")
        lines.append(f"  Safe:           {C.GREEN}{result['safe_count']}{C.RESET}\n")

        sev_colors = {
            "CRITICAL": C.RED, "HIGH": C.RED,
            "MEDIUM": C.YELLOW, "LOW": C.CYAN, "SAFE": C.GREEN
        }

        for net in result["networks"][:30]:
            sev = net.get("severity", "SAFE")
            color = sev_colors.get(sev, C.CYAN)
            ssid = net.get("ssid", "?")[:30]
            sec = net.get("security", "?")[:20]
            sig = net.get("signal_strength", 0)

            lines.append(f"  [{color}{sev:<8}{C.RESET}] {C.WHITE}{ssid:<32}{C.RESET} {sec:<20} sig:{sig}")
            for issue in net.get("issues", [])[:2]:
                lines.append(f"             {C.MUTED}→ {issue}{C.RESET}")

        lines.append(f"\n{C.CYAN}{'═'*62}{C.RESET}")
        lines.append(f"  Scanned at: {result['scanned_at']}\n")
        return "\n".join(lines)
