"""
Ixoryn CVE & Exploit Intelligence
Queries NVD (NIST) and ExploitDB for known vulnerabilities
associated with discovered software versions.
"""

import re
import json
import time
import requests
from typing import Dict, List, Optional
from datetime import datetime

from ixoryn.core.logger import get_logger
from ixoryn.core.rate_limit import get_limiter as _get_limiter

logger = get_logger(__name__)


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_URL = "https://www.exploit-db.com/search"


class CVELookup:
    """
    Real-time CVE lookup against NIST NVD.
    No API key required for basic queries (rate-limited to 5 req/30s).
    """

    def __init__(self):
        self.cache: Dict = {}
        self._last_request = 0
        self._min_interval = 6.5  # NVD rate limit: 5 requests/30s without key

    def _rate_limit(self):
        """Respect NVD rate limits. Blocks until a global API slot is available."""
        _get_limiter().acquire("nvd")  # global rate coordinator
        elapsed = time.time() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.time()

    def lookup_software(self, software: str, version: str = None,
                        max_results: int = 5) -> Dict:
        """
        Look up CVEs for a software product + optional version.
        Returns list of CVEs with CVSS scores, descriptions, published dates.
        """
        cache_key = f"{software}:{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        result = {
            "software": software,
            "version": version,
            "cves": [],
            "critical_count": 0,
            "high_count": 0,
            "source": "NVD/NIST",
            "queried_at": datetime.now().isoformat(),
            "error": None,
        }

        try:
            self._rate_limit()
            params = {
                "keywordSearch": f"{software} {version}" if version else software,
                "resultsPerPage": min(max_results, 20),
                "startIndex": 0,
            }

            resp = requests.get(NVD_API_URL, params=params,
                                timeout=10,
                                headers={"User-Agent": "IxorynScanner/1.1 (security research)"})

            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])

                for item in vulnerabilities[:max_results]:
                    cve_item = item.get("cve", {})
                    cve_id = cve_item.get("id", "")

                    # Description
                    descs = cve_item.get("descriptions", [])
                    description = next(
                        (d["value"] for d in descs if d.get("lang") == "en"),
                        "No description available"
                    )[:300]

                    # CVSS Score
                    metrics = cve_item.get("metrics", {})
                    cvss_score = None
                    severity = "UNKNOWN"

                    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        metric_list = metrics.get(metric_key, [])
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity",
                                       self._score_to_severity(cvss_score))
                            break

                    published = cve_item.get("published", "")[:10]

                    cve_entry = {
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "published": published,
                        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                    result["cves"].append(cve_entry)

                    if severity in ("CRITICAL",):
                        result["critical_count"] += 1
                    elif severity in ("HIGH",):
                        result["high_count"] += 1

                result["total_found"] = data.get("totalResults", len(result["cves"]))

            elif resp.status_code == 403:
                result["error"] = "NVD rate limit exceeded — wait 30 seconds"
            elif resp.status_code == 503:
                result["error"] = "NVD API temporarily unavailable"
            else:
                result["error"] = f"NVD API returned HTTP {resp.status_code}"

        except requests.exceptions.Timeout:
            result["error"] = "NVD API timeout — no network or API slow"
        except requests.exceptions.ConnectionError:
            result["error"] = "Cannot reach NVD API — check network connectivity"
        except Exception as e:
            result["error"] = f"Lookup error: {str(e)[:100]}"

        self.cache[cache_key] = result
        return result

    def lookup_cve(self, cve_id: str) -> Dict:
        """Look up a specific CVE ID directly."""
        if cve_id in self.cache:
            return self.cache[cve_id]

        try:
            self._rate_limit()
            resp = requests.get(NVD_API_URL,
                                params={"cveId": cve_id},
                                timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_data = vulns[0].get("cve", {})
                    descs = cve_data.get("descriptions", [])
                    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

                    metrics = cve_data.get("metrics", {})
                    score = None
                    severity = "UNKNOWN"
                    for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        ml = metrics.get(mk, [])
                        if ml:
                            cd = ml[0].get("cvssData", {})
                            score = cd.get("baseScore")
                            severity = cd.get("baseSeverity", "")
                            break

                    result = {
                        "cve_id": cve_id,
                        "description": desc[:500],
                        "cvss_score": score,
                        "severity": severity,
                        "published": cve_data.get("published", "")[:10],
                        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "references": [
                            r.get("url", "")
                            for r in cve_data.get("references", [])[:5]
                        ],
                    }
                    self.cache[cve_id] = result
                    return result
        except Exception as e:
            return {"cve_id": cve_id, "error": str(e)[:100]}

        return {"cve_id": cve_id, "error": "Not found"}

    def _score_to_severity(self, score: Optional[float]) -> str:
        """Convert CVSS numeric score to severity label."""
        if score is None:
            return "UNKNOWN"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    def format_results(self, result: Dict) -> str:
        """Format CVE results for terminal display."""
        try:
            from ixoryn.ui.banner import Colors as C
        except ImportError:
            class C:
                RED = YELLOW = GREEN = CYAN = WHITE = BOLD = RESET = MUTED = ""

        lines = []
        if result.get("error"):
            lines.append(f"  [!] {result['error']}")
            return "\n".join(lines)

        cves = result.get("cves", [])
        total = result.get("total_found", len(cves))

        lines.append(f"\n  Software: {C.WHITE}{result['software']}{C.RESET}"
                     + (f" v{result['version']}" if result.get('version') else ""))
        lines.append(f"  CVEs found: {total} total (showing {len(cves)})")
        lines.append(f"  Critical: {result['critical_count']} | High: {result['high_count']}")
        lines.append("")

        sev_colors = {
            "CRITICAL": C.RED, "HIGH": C.RED,
            "MEDIUM": C.YELLOW, "LOW": C.CYAN, "UNKNOWN": C.MUTED
        }

        for cve in cves:
            sev = cve.get("severity", "UNKNOWN")
            score = cve.get("cvss_score")
            score_str = f"CVSS: {score}" if score else "CVSS: N/A"
            color = sev_colors.get(sev, C.MUTED)

            lines.append(f"  {C.BOLD}{cve['cve_id']}{C.RESET}  "
                         f"[{color}{sev}{C.RESET}]  {score_str}  "
                         f"({cve.get('published', '')})")
            lines.append(f"    {cve['description'][:120]}...")
            lines.append(f"    {C.CYAN}{cve['nvd_url']}{C.RESET}")
            lines.append("")

        return "\n".join(lines)
