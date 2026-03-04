"""
Ixoryn Report Generator
Produces professional PDF and HTML reports from audit results.
Supports: URL audit, stego forensic, password audit, threat intelligence reports.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from ixoryn.core.logger import get_logger

logger = get_logger("report_generator")

REPORT_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
       background: #0d1117; color: #c9d1d9; line-height: 1.6; }
.container { max-width: 960px; margin: 0 auto; padding: 32px 24px; }
.header { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
          border: 1px solid #30363d; border-radius: 12px;
          padding: 32px; margin-bottom: 28px; position: relative; }
.header::before { content: ''; position: absolute; top: 0; left: 0; right: 0;
                   height: 3px; background: linear-gradient(90deg, #58a6ff, #3fb950, #f78166);
                   border-radius: 12px 12px 0 0; }
.logo { font-size: 28px; font-weight: 800; letter-spacing: 6px;
        background: linear-gradient(90deg, #58a6ff, #3fb950); -webkit-background-clip: text;
        -webkit-text-fill-color: transparent; background-clip: text; }
.subtitle { color: #8b949e; font-size: 13px; margin-top: 6px; letter-spacing: 1px; }
.meta { display: flex; gap: 24px; margin-top: 20px; flex-wrap: wrap; }
.meta-item { background: #21262d; border-radius: 8px; padding: 10px 16px;
             border: 1px solid #30363d; font-size: 13px; }
.meta-item .label { color: #8b949e; font-size: 11px; text-transform: uppercase;
                    letter-spacing: 1px; margin-bottom: 3px; }
.meta-item .value { color: #e6edf3; font-weight: 600; }
.section { background: #161b22; border: 1px solid #30363d; border-radius: 10px;
           padding: 24px; margin-bottom: 20px; }
.section-title { font-size: 15px; font-weight: 700; color: #58a6ff;
                 margin-bottom: 18px; padding-bottom: 10px;
                 border-bottom: 1px solid #21262d; letter-spacing: 0.5px; }
.verdict-badge { display: inline-flex; align-items: center; gap: 8px;
                 padding: 10px 20px; border-radius: 8px; font-weight: 700;
                 font-size: 16px; letter-spacing: 0.5px; }
.verdict-CRITICAL, .verdict-MALICIOUS { background: rgba(248,81,73,.15);
    color: #f85149; border: 1px solid rgba(248,81,73,.3); }
.verdict-HIGH, .verdict-SUSPICIOUS { background: rgba(210,153,34,.15);
    color: #d2a520; border: 1px solid rgba(210,153,34,.3); }
.verdict-MEDIUM, .verdict-LOW_RISK { background: rgba(210,153,34,.1);
    color: #e3b341; border: 1px solid rgba(210,153,34,.2); }
.verdict-LOW, .verdict-CLEAN { background: rgba(63,185,80,.15);
    color: #3fb950; border: 1px solid rgba(63,185,80,.3); }
.score-bar-wrap { background: #21262d; border-radius: 6px; height: 10px;
                  margin-top: 8px; overflow: hidden; }
.score-bar { height: 100%; border-radius: 6px; transition: width 0.3s ease; }
.score-high { background: linear-gradient(90deg, #f85149, #da3633); }
.score-med  { background: linear-gradient(90deg, #d2a520, #e3b341); }
.score-low  { background: linear-gradient(90deg, #3fb950, #2ea043); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #21262d; color: #8b949e; text-transform: uppercase;
     font-size: 11px; letter-spacing: 1px; padding: 10px 14px; text-align: left; }
td { padding: 10px 14px; border-bottom: 1px solid #21262d; color: #c9d1d9; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(88,166,255,.05); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
         font-size: 11px; font-weight: 600; }
.badge-red { background: rgba(248,81,73,.2); color: #f85149; }
.badge-yellow { background: rgba(210,153,34,.2); color: #d2a520; }
.badge-green { background: rgba(63,185,80,.2); color: #3fb950; }
.badge-blue { background: rgba(88,166,255,.2); color: #58a6ff; }
.badge-gray { background: rgba(139,148,158,.2); color: #8b949e; }
.finding-item { padding: 12px 16px; background: #0d1117; border-radius: 8px;
                border-left: 3px solid #30363d; margin-bottom: 10px; }
.finding-item.HIGH, .finding-item.CRITICAL { border-color: #f85149; }
.finding-item.MEDIUM { border-color: #d2a520; }
.finding-item.LOW { border-color: #3fb950; }
.finding-type { font-weight: 700; font-size: 13px; margin-bottom: 4px; }
.finding-msg { color: #8b949e; font-size: 12px; }
.footer { text-align: center; color: #30363d; font-size: 12px; margin-top: 40px;
          padding-top: 20px; border-top: 1px solid #21262d; }
.key-value { display: flex; justify-content: space-between; padding: 8px 0;
             border-bottom: 1px solid #21262d; font-size: 13px; }
.key-value:last-child { border-bottom: none; }
.kv-key { color: #8b949e; }
.kv-val { color: #e6edf3; font-weight: 500; text-align: right; }
.password-strength { display: flex; align-items: center; gap: 12px; margin: 12px 0; }
.strength-blocks { display: flex; gap: 4px; }
.strength-block { width: 28px; height: 8px; border-radius: 2px;
                  background: #21262d; }
.strength-block.filled-0 { background: #f85149; }
.strength-block.filled-1 { background: #f85149; }
.strength-block.filled-2 { background: #d2a520; }
.strength-block.filled-3 { background: #3fb950; }
.strength-block.filled-4 { background: #3fb950; }
pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
      padding: 12px 16px; font-size: 12px; overflow-x: auto; color: #79c0ff; }
"""


class ReportGenerator:
    """Generates HTML and PDF reports from Ixoryn audit results."""

    def __init__(self):
        self.output_dir = Path.home() / ".ixoryn" / "output"

    def generate_html(self, report_data: Dict, report_type: str,
                      output_path: Optional[str] = None) -> str:
        """Generate an HTML report. Returns the output file path."""
        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(self.output_dir / f"ixoryn_{report_type}_{ts}.html")

        html = self._build_html(report_data, report_type)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML report saved: {output_path}")
        return output_path

    def generate_pdf(self, report_data: Dict, report_type: str,
                     output_path: Optional[str] = None) -> str:
        """Generate a PDF report using weasyprint or pdfkit fallback."""
        html_path = self.generate_html(report_data, report_type,
                                       output_path.replace(".pdf", ".html") if output_path else None)

        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(self.output_dir / f"ixoryn_{report_type}_{ts}.pdf")

        # Try weasyprint first
        try:
            from weasyprint import HTML as WP_HTML
            WP_HTML(filename=html_path).write_pdf(output_path)
            logger.info(f"PDF report saved: {output_path}")
            return output_path
        except ImportError:
            pass

        # Try pdfkit (wkhtmltopdf)
        try:
            import pdfkit
            pdfkit.from_file(html_path, output_path)
            logger.info(f"PDF report saved: {output_path}")
            return output_path
        except ImportError:
            pass

        logger.warning("PDF export requires 'weasyprint' or 'pdfkit'. Saved HTML instead.")
        return html_path

    def _build_html(self, data: Dict, report_type: str) -> str:
        """Build complete HTML report based on report type."""
        builders = {
            "url": self._build_url_report,
            "stego": self._build_stego_report,
            "password": self._build_password_report,
            "hash": self._build_hash_report,
            "threat_intel": self._build_threat_intel_report,
        }
        builder = builders.get(report_type, self._build_generic_report)
        body_content = builder(data)

        timestamp = datetime.now().strftime("%B %d, %Y at %H:%M:%S UTC")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ixoryn Security Report — {report_type.upper()}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">IXORYN</div>
    <div class="subtitle">ADVANCED SECURITY INTELLIGENCE PLATFORM · REPORT</div>
    <div class="meta">
      <div class="meta-item">
        <div class="label">Report Type</div>
        <div class="value">{report_type.replace('_', ' ').upper()}</div>
      </div>
      <div class="meta-item">
        <div class="label">Generated</div>
        <div class="value">{timestamp}</div>
      </div>
      <div class="meta-item">
        <div class="label">Target</div>
        <div class="value">{data.get('target', data.get('file', data.get('domain', 'N/A')))}</div>
      </div>
    </div>
  </div>
  {body_content}
  <div class="footer">
    Generated by Ixoryn Security Platform &bull; For authorized use only &bull;
    <a href="https://github.com/ademohmustapha/ixoryn" style="color:#58a6ff;">github.com/ademohmustapha/ixoryn</a>
  </div>
</div>
</body>
</html>"""

    def _build_url_report(self, data: Dict) -> str:
        risk = data.get("risk_level", "LOW")
        score = data.get("risk_score", 0)
        bar_class = "score-high" if score >= 60 else "score-med" if score >= 30 else "score-low"

        findings_html = ""
        for f in data.get("findings", []):
            sev = f.get("severity", "LOW")
            findings_html += f"""
            <div class="finding-item {sev}">
              <div class="finding-type">[{f.get('type', '?')}]</div>
              <div class="finding-msg">{f.get('detail', f.get('message', ''))}</div>
            </div>"""

        # SSL section
        ssl = data.get("ssl", {})
        ssl_html = ""
        if ssl:
            ssl_valid = ssl.get("valid", False)
            ssl_status = "Valid" if ssl_valid else "Invalid"
            ssl_badge = "badge-green" if ssl_valid else "badge-red"
            ssl_html = f"""
        <div class="section">
          <div class="section-title">🔒 SSL/TLS Analysis</div>
          <div class="key-value">
            <span class="kv-key">Status</span>
            <span class="kv-val"><span class="badge {ssl_badge}">{ssl_status}</span></span>
          </div>
          <div class="key-value">
            <span class="kv-key">TLS Version</span>
            <span class="kv-val">{ssl.get('tls_version', 'N/A')}</span>
          </div>
          <div class="key-value">
            <span class="kv-key">Cipher Suite</span>
            <span class="kv-val">{ssl.get('cipher_suite', 'N/A')}</span>
          </div>
          <div class="key-value">
            <span class="kv-key">Days Until Expiry</span>
            <span class="kv-val">{ssl.get('days_until_expiry', 'N/A')}</span>
          </div>
          {''.join(f"<div class='key-value'><span class='kv-key'>Issue</span><span class='kv-val' style='color:#f85149'>{e}</span></div>" for e in ssl.get('errors', []))}
        </div>"""

        # Typosquatting
        typo = data.get("typosquatting", {})
        typo_html = ""
        if typo.get("likely_targets"):
            rows = ""
            for t in typo["likely_targets"][:10]:
                rows += f"""<tr>
                  <td>{t['similar_to']}</td>
                  <td>{t['edit_distance']}</td>
                  <td>{t['technique']}</td>
                  <td><span class="badge {'badge-red' if t['risk']=='HIGH' else 'badge-yellow'}">{t['risk']}</span></td>
                </tr>"""
            typo_html = f"""
        <div class="section">
          <div class="section-title">🎭 Typosquatting Analysis</div>
          <table>
            <tr><th>Target Domain</th><th>Edit Distance</th><th>Technique</th><th>Risk</th></tr>
            {rows}
          </table>
        </div>"""

        # DNS
        dns = data.get("dns", {})
        dns_html = ""
        if dns:
            dns_items = ""
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SPF", "DMARC"):
                vals = dns.get(rtype, [])
                if vals:
                    dns_items += f"""<div class="key-value">
                      <span class="kv-key">{rtype}</span>
                      <span class="kv-val">{', '.join(str(v) for v in vals[:3])}</span>
                    </div>"""
            if dns_items:
                dns_html = f"""
        <div class="section">
          <div class="section-title">🌐 DNS Records</div>
          {dns_items}
        </div>"""

        return f"""
    <div class="section">
      <div class="section-title">🎯 Audit Summary</div>
      <div class="key-value">
        <span class="kv-key">Target</span>
        <span class="kv-val">{data.get('target', 'N/A')}</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Risk Level</span>
        <span class="kv-val">
          <span class="verdict-badge verdict-{risk}">{risk}</span>
        </span>
      </div>
      <div class="key-value">
        <span class="kv-key">Risk Score</span>
        <span class="kv-val">{score}/100</span>
      </div>
      <div class="score-bar-wrap">
        <div class="score-bar {bar_class}" style="width:{score}%"></div>
      </div>
      <div class="key-value" style="margin-top:16px">
        <span class="kv-key">Scan Depth</span>
        <span class="kv-val">{data.get('depth', 'standard').upper()}</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Timestamp</span>
        <span class="kv-val">{data.get('timestamp', '')}</span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">⚠️ Findings ({len(data.get('findings', []))})</div>
      {findings_html if findings_html else '<p style="color:#8b949e">No significant findings detected.</p>'}
    </div>

    {ssl_html}
    {typo_html}
    {dns_html}
"""

    def _build_stego_report(self, data: Dict) -> str:
        suspicion = data.get("overall_suspicion", "LOW")
        score = data.get("suspicion_score", 0)
        bar_class = "score-high" if score >= 60 else "score-med" if score >= 30 else "score-low"

        findings_html = ""
        for f in data.get("findings", []):
            sev = f.get("severity", "LOW")
            findings_html += f"""
            <div class="finding-item {sev}">
              <div class="finding-type">[{f.get('type', 'Finding')}] <span class="badge {'badge-red' if sev in ('HIGH','CRITICAL') else 'badge-yellow' if sev=='MEDIUM' else 'badge-green'}">{sev}</span></div>
              <div class="finding-msg">{f.get('message', '')}</div>
            </div>"""

        meta = data.get("metadata", {})
        meta_html = "".join(
            f'<div class="key-value"><span class="kv-key">{k}</span><span class="kv-val">{v}</span></div>'
            for k, v in meta.items() if k not in ("md5", "sha256")
        )

        analysis = data.get("analysis", {})
        analysis_rows = ""
        for section, values in analysis.items():
            if isinstance(values, dict):
                for k, v in values.items():
                    analysis_rows += f'<tr><td>{section}</td><td>{k}</td><td>{v}</td></tr>'

        return f"""
    <div class="section">
      <div class="section-title">🔬 Forensic Analysis Summary</div>
      <div class="key-value">
        <span class="kv-key">File</span><span class="kv-val">{data.get('filename','N/A')}</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Suspicion Level</span>
        <span class="kv-val"><span class="verdict-badge verdict-{suspicion}">{suspicion}</span></span>
      </div>
      <div class="key-value">
        <span class="kv-key">Score</span><span class="kv-val">{score:.1f}/100</span>
      </div>
      <div class="score-bar-wrap">
        <div class="score-bar {bar_class}" style="width:{score}%"></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">📋 Verdict</div>
      <p style="color:#c9d1d9;line-height:1.8">{data.get('verdict','')}</p>
    </div>

    <div class="section">
      <div class="section-title">⚠️ Findings ({len(data.get('findings', []))})</div>
      {findings_html if findings_html else '<p style="color:#8b949e">No steganographic indicators detected.</p>'}
    </div>

    <div class="section">
      <div class="section-title">📁 File Metadata</div>
      {meta_html}
      <div class="key-value">
        <span class="kv-key">MD5</span>
        <span class="kv-val" style="font-family:monospace;font-size:12px">{meta.get('md5','N/A')}</span>
      </div>
      <div class="key-value">
        <span class="kv-key">SHA-256</span>
        <span class="kv-val" style="font-family:monospace;font-size:12px">{meta.get('sha256','N/A')}</span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">📊 Statistical Analysis Data</div>
      <table>
        <tr><th>Module</th><th>Metric</th><th>Value</th></tr>
        {analysis_rows}
      </table>
    </div>
"""

    def _build_password_report(self, data: Dict) -> str:
        score = data.get("score", 0)
        strength = data.get("strength", "Unknown")
        entropy = data.get("entropy", 0)
        bar_class = "score-low" if score >= 3 else "score-med" if score >= 2 else "score-high"
        bar_pct = (score / 4) * 100

        blocks = "".join(
            f'<div class="strength-block {"filled-" + str(score) if i <= score else ""}"></div>'
            for i in range(5)
        )

        warnings_html = "".join(
            f'<div class="finding-item HIGH"><div class="finding-msg">⚠ {w}</div></div>'
            for w in data.get("warnings", []) if w
        )
        suggestions_html = "".join(
            f'<div class="finding-item LOW"><div class="finding-msg">→ {s}</div></div>'
            for s in data.get("suggestions", [])
        )

        compliance = data.get("compliance", {})
        comp_rows = ""
        for std, checks in compliance.items():
            c = checks.get("compliant", False)
            comp_rows += f"""<tr>
              <td>{std}</td>
              <td><span class="badge {'badge-green' if c else 'badge-red'}">{'PASS' if c else 'FAIL'}</span></td>
            </tr>"""

        return f"""
    <div class="section">
      <div class="section-title">🔑 Password Audit Summary</div>
      <div class="key-value">
        <span class="kv-key">Strength</span>
        <span class="kv-val">
          <div class="password-strength">
            <div class="strength-blocks">{blocks}</div>
            <span>{strength}</span>
          </div>
        </span>
      </div>
      <div class="score-bar-wrap">
        <div class="score-bar {bar_class}" style="width:{bar_pct}%"></div>
      </div>
      <div class="key-value" style="margin-top:16px">
        <span class="kv-key">Entropy</span>
        <span class="kv-val">{entropy:.1f} bits</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Length</span>
        <span class="kv-val">{data.get('length', 0)} characters</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Character Sets</span>
        <span class="kv-val">{', '.join(data.get('charsets_used', []))}</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Est. Crack Time</span>
        <span class="kv-val">{data.get('crack_time_display', 'N/A')}</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Common Password</span>
        <span class="kv-val">
          <span class="badge {'badge-red' if data.get('is_common') else 'badge-green'}">
            {'YES — INSECURE' if data.get('is_common') else 'No'}
          </span>
        </span>
      </div>
    </div>

    {f'<div class="section"><div class="section-title">⚠️ Warnings</div>{warnings_html}</div>' if warnings_html else ''}
    {f'<div class="section"><div class="section-title">💡 Suggestions</div>{suggestions_html}</div>' if suggestions_html else ''}

    <div class="section">
      <div class="section-title">✅ Compliance Check</div>
      <table>
        <tr><th>Standard</th><th>Status</th></tr>
        {comp_rows}
      </table>
    </div>
"""

    def _build_hash_report(self, data: Dict) -> str:
        rating = data.get("security_rating", "UNKNOWN")
        badge_class = {
            "CRITICAL": "badge-red", "INSECURE": "badge-red",
            "WEAK": "badge-yellow", "MODERATE": "badge-yellow",
            "GOOD": "badge-green", "EXCELLENT": "badge-green",
        }.get(rating, "badge-gray")

        types_html = ""
        for match in data.get("likely_types", []):
            sec = match.get("security", {})
            sec_badge = {
                "CRITICAL": "badge-red", "INSECURE": "badge-red",
                "WEAK": "badge-yellow", "MODERATE": "badge-yellow",
                "GOOD": "badge-green", "EXCELLENT": "badge-green",
            }.get(sec.get("rating", "?"), "badge-gray")
            types_html += f"""<tr>
              <td style="font-family:monospace">{match['algorithm']}</td>
              <td>{match.get('bits', '?')}</td>
              <td><span class="badge {sec_badge}">{sec.get('rating', '?')}</span></td>
              <td style="color:#8b949e;font-size:12px">{match.get('notes', '')}</td>
            </tr>"""

        recs_html = "".join(
            f'<div class="finding-item MEDIUM"><div class="finding-msg">→ {r}</div></div>'
            for r in data.get("recommendations", [])
        )

        return f"""
    <div class="section">
      <div class="section-title">🔒 Hash Audit Summary</div>
      <div class="key-value">
        <span class="kv-key">Hash Value</span>
        <span class="kv-val" style="font-family:monospace;font-size:12px">{data.get('full_hash','N/A')}</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Length</span>
        <span class="kv-val">{data.get('length', '?')} chars</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Security Rating</span>
        <span class="kv-val"><span class="badge {badge_class}">{rating}</span></span>
      </div>
      <div class="key-value">
        <span class="kv-key">Salted</span>
        <span class="kv-val">{'Yes' if data.get('is_salted') else 'No'}</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Crack Difficulty</span>
        <span class="kv-val">{data.get('crack_difficulty', 'Unknown')}</span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">🔍 Likely Algorithm Matches</div>
      <table>
        <tr><th>Algorithm</th><th>Bits</th><th>Security</th><th>Notes</th></tr>
        {types_html}
      </table>
    </div>

    {f'<div class="section"><div class="section-title">💡 Recommendations</div>{recs_html}</div>' if recs_html else ''}
"""

    def _build_threat_intel_report(self, data: Dict) -> str:
        verdict = data.get("overall_verdict", "CLEAN")
        score = data.get("overall_risk_score", 0)
        bar_class = "score-high" if score >= 60 else "score-med" if score >= 30 else "score-low"

        checks_html = ""
        verdict_colors = {
            "MALICIOUS": "badge-red", "SUSPICIOUS": "badge-yellow",
            "HIGH_RISK": "badge-red", "LOW_RISK": "badge-yellow",
            "CLEAN": "badge-green", "unknown": "badge-gray",
        }
        for name, check in data.get("checks", {}).items():
            v = check.get("verdict", "unknown")
            bc = verdict_colors.get(v, "badge-gray")
            avail = "✓" if check.get("available") else "✗"
            err = f"<br><small style='color:#8b949e'>{check.get('error','')}</small>" if check.get("error") else ""
            checks_html += f"""<tr>
              <td>{avail} {check.get('source', name)}</td>
              <td><span class="badge {bc}">{v.upper()}</span></td>
              <td>{err}</td>
            </tr>"""

        return f"""
    <div class="section">
      <div class="section-title">🌐 Threat Intelligence Summary</div>
      <div class="key-value">
        <span class="kv-key">Target</span>
        <span class="kv-val">{data.get('target', 'N/A')}</span>
      </div>
      <div class="key-value">
        <span class="kv-key">Overall Verdict</span>
        <span class="kv-val">
          <span class="verdict-badge verdict-{verdict}">{verdict}</span>
        </span>
      </div>
      <div class="key-value">
        <span class="kv-key">Risk Score</span>
        <span class="kv-val">{score}/100</span>
      </div>
      <div class="score-bar-wrap">
        <div class="score-bar {bar_class}" style="width:{score}%"></div>
      </div>
      <div class="key-value" style="margin-top:16px">
        <span class="kv-key">Sources Available</span>
        <span class="kv-val">{data.get('sources_available',0)}/{data.get('sources_queried',0)}</span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">🔎 Per-Source Results</div>
      <table>
        <tr><th>Source</th><th>Verdict</th><th>Notes</th></tr>
        {checks_html}
      </table>
    </div>
"""

    def _build_generic_report(self, data: Dict) -> str:
        rows = ""
        for k, v in data.items():
            if isinstance(v, (str, int, float, bool)):
                rows += f'<div class="key-value"><span class="kv-key">{k}</span><span class="kv-val">{v}</span></div>'
        return f"""
    <div class="section">
      <div class="section-title">📋 Report Data</div>
      {rows}
      <pre>{json.dumps(data, indent=2, default=str)[:4000]}</pre>
    </div>"""
