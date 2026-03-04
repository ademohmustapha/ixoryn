"""
Ixoryn File Forensics
Deep file analysis: metadata extraction, hash fingerprinting,
hidden data detection, file type verification, entropy analysis,
EXIF data, embedded URLs, and document metadata.
"""

import os
import hashlib
import math
import struct
import json
import re
import zipfile
import tarfile
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from ixoryn.core.logger import get_logger

logger = get_logger(__name__)


# Magic bytes for file type identification
MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"GIF87a": "GIF Image (87a)",
    b"GIF89a": "GIF Image (89a)",
    b"%PDF": "PDF Document",
    b"PK\x03\x04": "ZIP Archive / Office Document",
    b"\x1f\x8b": "GZIP Archive",
    b"BZh": "BZIP2 Archive",
    b"\xfd7zXZ": "XZ Archive",
    b"Rar!": "RAR Archive",
    b"\x7fELF": "ELF Executable (Linux)",
    b"MZ": "PE Executable (Windows)",
    b"\xca\xfe\xba\xbe": "Mach-O Binary (macOS)",
    b"FLAC": "FLAC Audio",
    b"fLaC": "FLAC Audio",
    b"ID3": "MP3 Audio",
    b"RIFF": "WAV/AVI Media",
    b"OggS": "OGG Audio",
    b"\x00\x00\x00 ftyp": "MP4 Video",
    b"\x1aE\xdf\xa3": "MKV/WebM Video",
    b"<!DOCTYPE html": "HTML Document",
    b"<html": "HTML Document",
    b"<?xml": "XML Document",
    b"#!/": "Script (Shebang)",
    b"-----BEGIN": "PEM Certificate/Key",
    b"IXORYN_ENCRYPTED": "Ixoryn Encrypted File",
    b"SQLite format 3": "SQLite Database",
    b"\x1f\x8b\x08": "GZIP Archive",
}

# Strings that indicate potentially sensitive embedded content
SENSITIVE_PATTERNS = [
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+", "Embedded password reference"),
    (r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*\S+", "Embedded API key"),
    (r"(?i)(secret[_-]?key|secret)\s*[=:]\s*\S+", "Embedded secret key"),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email address"),
    (r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b", "IP address"),
    (r"https?://[^\s<>\"']{10,}", "URL"),
    (r"(?i)(BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY)", "Private key material"),
    (r"(?i)aws[_-]?(?:access[_-]?key|secret)[_-]?id\s*[=:]\s*\S+", "AWS credential"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
]


class FileForensics:
    """
    Comprehensive file forensics and analysis.
    """

    @staticmethod
    def _validate_filepath(filepath: str) -> str:
        """Resolve and validate filepath to prevent path traversal attacks."""
        from pathlib import Path as _Path
        p = _Path(filepath).resolve()
        # Ensure the resolved path exists and is a regular file (not a symlink to /etc/passwd etc.)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        if not p.is_file():
            raise ValueError(f"Not a regular file: {filepath}")
        return str(p)

    def analyze(self, filepath: str, deep: bool = True) -> Dict:
        """
        Full forensic analysis of a file.
        Returns hashes, file type verification, metadata, entropy,
        embedded strings, and suspicious content indicators.
        """
        try:
            filepath = self._validate_filepath(filepath)
        except (FileNotFoundError, ValueError) as e:
            return {"error": str(e)}
        path = Path(filepath)

        if not path.exists():
            return {"error": f"File not found: {filepath}"}
        if not path.is_file():
            return {"error": f"Not a file: {filepath}"}

        result = {
            "filepath": str(path.absolute()),
            "filename": path.name,
            "extension": path.suffix.lower(),
            "size_bytes": path.stat().st_size,
            "size_human": self._human_size(path.stat().st_size),
            "created": datetime.fromtimestamp(path.stat().st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
            "permissions": oct(path.stat().st_mode)[-4:],
            "hashes": {},
            "file_type_detected": None,
            "file_type_matches_extension": None,
            "entropy": None,
            "entropy_verdict": None,
            "is_compressed": False,
            "is_encrypted": False,
            "embedded_strings": [],
            "sensitive_findings": [],
            "metadata": {},
            "analyzed_at": datetime.now().isoformat(),
            "risk_indicators": [],
            "risk_level": "LOW",
        }

        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except PermissionError:
            result["error"] = "Permission denied reading file"
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

        # 1. Hash fingerprinting
        result["hashes"] = self._compute_hashes(data)

        # 2. File type identification
        result["file_type_detected"] = self._identify_file_type(data)
        result["file_type_matches_extension"] = self._check_extension_match(
            path.suffix.lower(), result["file_type_detected"]
        )

        # 3. Entropy analysis
        entropy, verdict = self._analyze_entropy(data)
        result["entropy"] = round(entropy, 4)
        result["entropy_verdict"] = verdict
        result["is_encrypted"] = entropy > 7.8
        result["is_compressed"] = 6.5 < entropy <= 7.8

        # 4. Embedded strings and sensitive data
        if deep:
            strings = self._extract_strings(data)
            result["embedded_strings"] = strings[:50]
            result["sensitive_findings"] = self._find_sensitive(data.decode("utf-8", errors="replace"))

        # 5. Type-specific metadata
        if result["file_type_detected"]:
            result["metadata"] = self._extract_metadata(filepath, data, result["file_type_detected"])

        # 6. Risk assessment
        self._assess_risk(result)

        return result

    def _compute_hashes(self, data: bytes) -> Dict:
        """Compute multiple hash digests."""
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "blake2b": hashlib.blake2b(data).hexdigest(),
        }

    def _identify_file_type(self, data: bytes) -> Optional[str]:
        """Identify file type from magic bytes."""
        for magic, name in MAGIC_SIGNATURES.items():
            if data[:len(magic)] == magic or data[:len(magic)].lower() == magic.lower():
                # Special: ZIP might be docx/xlsx/etc
                if magic == b"PK\x03\x04":
                    return self._identify_zip_contents(data) or "ZIP Archive"
                return name
        return "Unknown/Binary"

    def _identify_zip_contents(self, data: bytes) -> Optional[str]:
        """Identify Office documents (which are ZIP files)."""
        import io
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                if "word/document.xml" in names:
                    return "Microsoft Word Document (DOCX)"
                if "xl/workbook.xml" in names:
                    return "Microsoft Excel Workbook (XLSX)"
                if "ppt/presentation.xml" in names:
                    return "Microsoft PowerPoint (PPTX)"
                if any(n.endswith(".py") for n in names):
                    return "Python Package (ZIP)"
                if "AndroidManifest.xml" in names:
                    return "Android APK"
        except Exception:
            pass
        return None

    def _check_extension_match(self, extension: str, detected_type: Optional[str]) -> Optional[bool]:
        """Verify extension matches detected file type."""
        if not detected_type or detected_type == "Unknown/Binary":
            return None

        extension_map = {
            ".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG",
            ".gif": "GIF", ".pdf": "PDF", ".zip": "ZIP",
            ".gz": "GZIP", ".tar": "tar", ".bz2": "BZIP2",
            ".flac": "FLAC", ".mp3": "MP3", ".wav": "WAV",
            ".mp4": "MP4", ".mkv": "MKV", ".html": "HTML",
            ".xml": "XML", ".docx": "Word", ".xlsx": "Excel",
            ".pptx": "PowerPoint", ".apk": "APK", ".exe": "PE",
            ".elf": "ELF", ".sqlite": "SQLite", ".db": "SQLite",
        }

        expected = extension_map.get(extension, "").lower()
        if not expected:
            return None
        return expected.lower() in detected_type.lower()

    def _analyze_entropy(self, data: bytes) -> tuple:
        """
        Calculate Shannon entropy of file data.
        High entropy (>7.5) suggests encryption or compression.
        """
        if not data:
            return 0.0, "Empty file"

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        entropy = 0.0
        total = len(data)
        for count in freq:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        if entropy > 7.8:
            verdict = "Very High — likely encrypted or compressed"
        elif entropy > 6.5:
            verdict = "High — compressed data or binary"
        elif entropy > 5.0:
            verdict = "Medium — mixed text/binary content"
        elif entropy > 3.0:
            verdict = "Low-Medium — text or structured data"
        else:
            verdict = "Low — highly repetitive or sparse data"

        return entropy, verdict

    def _extract_strings(self, data: bytes, min_length: int = 6) -> List[str]:
        """Extract printable strings from binary data."""
        strings = []
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    s = "".join(current).strip()
                    if s and s not in strings:
                        strings.append(s)
                current = []
        return strings[:200]

    def _find_sensitive(self, text: str) -> List[Dict]:
        """Search for sensitive data patterns in file content."""
        findings = []
        for pattern, label in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                # Redact most of the value for safety
                sample = str(matches[0])[:60] + "..." if len(str(matches[0])) > 60 else str(matches[0])
                findings.append({
                    "type": label,
                    "count": len(matches),
                    "sample": sample,
                })
        return findings

    def _extract_metadata(self, filepath: str, data: bytes, file_type: str) -> Dict:
        """Extract type-specific metadata."""
        metadata = {}

        if "JPEG" in file_type or "PNG" in file_type:
            metadata.update(self._extract_image_metadata(filepath))

        if "PDF" in file_type:
            metadata.update(self._extract_pdf_metadata(data))

        if "ZIP" in file_type or any(t in file_type for t in ["Word", "Excel", "PowerPoint"]):
            metadata.update(self._extract_zip_metadata(data))

        if "GZIP" in file_type:
            metadata["compressed_format"] = "gzip"

        return metadata

    def _extract_image_metadata(self, filepath: str) -> Dict:
        """Extract EXIF and image metadata."""
        meta = {}
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            with Image.open(filepath) as img:
                meta["format"] = img.format
                meta["mode"] = img.mode
                meta["dimensions"] = f"{img.width}x{img.height}"
                meta["size_pixels"] = img.width * img.height

                # EXIF data
                exif_data = {}
                if hasattr(img, "_getexif") and img._getexif():
                    for tag_id, value in img._getexif().items():
                        tag = TAGS.get(tag_id, tag_id)
                        if isinstance(value, bytes):
                            value = value.decode("utf-8", errors="replace")[:100]
                        if isinstance(value, (str, int, float)):
                            exif_data[str(tag)] = str(value)[:100]

                if exif_data:
                    meta["exif"] = exif_data
                    # Flag GPS data as privacy risk
                    if "GPSInfo" in exif_data or any("GPS" in k for k in exif_data):
                        meta["gps_data_present"] = True
                        meta["privacy_warning"] = "GPS coordinates embedded in image metadata"
        except Exception as e:
            meta["exif_error"] = str(e)[:50]
        return meta

    def _extract_pdf_metadata(self, data: bytes) -> Dict:
        """Extract PDF metadata."""
        meta = {}
        try:
            # Simple regex-based PDF metadata extraction
            text = data[:10000].decode("utf-8", errors="replace")
            for field in ["Title", "Author", "Subject", "Creator", "Producer", "CreationDate"]:
                m = re.search("/" + field + r"[\s]*[(]([^)]+)[)]", text)
                if m:
                    meta[field.lower()] = m.group(1)[:100]

            # Count pages
            page_count = len(re.findall(rb"/Type\s*/Page\b", data))
            if page_count:
                meta["page_count"] = page_count

            # JavaScript detection
            if b"/JavaScript" in data or b"/JS" in data:
                meta["contains_javascript"] = True
                meta["security_warning"] = "PDF contains JavaScript — potential malware vector"

            # Embedded files
            if b"/EmbeddedFile" in data:
                meta["has_embedded_files"] = True
        except Exception:
            pass
        return meta

    def _extract_zip_metadata(self, data: bytes) -> Dict:
        """Extract ZIP/Office document metadata."""
        meta = {}
        import io
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                meta["contained_files"] = len(zf.namelist())
                meta["file_list_sample"] = zf.namelist()[:10]

                # Try to read Office core properties
                if "docProps/core.xml" in zf.namelist():
                    core_xml = zf.read("docProps/core.xml").decode("utf-8", errors="replace")
                    for tag in ["dc:creator", "cp:lastModifiedBy", "dc:title",
                                "dc:subject", "cp:revision"]:
                    
                        m = re.search(f"<{tag}>([^<]+)</{tag}>", core_xml)
                        if m:
                            meta[tag.split(":")[-1]] = m.group(1)[:100]
        except Exception:
            pass
        return meta

    def _assess_risk(self, result: Dict):
        """Assign risk level based on findings."""
        indicators = []

        # Extension mismatch is a red flag
        if result.get("file_type_matches_extension") is False:
            indicators.append("CRITICAL: File extension does not match actual file type (possible masquerading)")
            result["risk_level"] = "CRITICAL"

        # Encrypted/hidden content
        if result.get("is_encrypted") and result.get("extension") not in (".ixenc", ".gpg", ".enc", ".zip", ".gz"):
            indicators.append("HIGH: File has very high entropy — may be encrypted or contain hidden data")
            if result["risk_level"] == "LOW":
                result["risk_level"] = "HIGH"

        # Sensitive data embedded
        for finding in result.get("sensitive_findings", []):
            if finding["type"] in ("Embedded API key", "Embedded password reference",
                                   "Private key material", "AWS credential",
                                   "GitHub Personal Access Token"):
                indicators.append(f"HIGH: {finding['type']} found embedded in file")
                if result["risk_level"] in ("LOW", "MEDIUM"):
                    result["risk_level"] = "HIGH"

        # JavaScript in PDF
        metadata = result.get("metadata", {})
        if metadata.get("contains_javascript"):
            indicators.append("HIGH: PDF contains JavaScript — scan for malware")
            if result["risk_level"] in ("LOW",):
                result["risk_level"] = "HIGH"

        # GPS data in images (privacy)
        if metadata.get("gps_data_present"):
            indicators.append("MEDIUM: GPS location data embedded in image EXIF")
            if result["risk_level"] == "LOW":
                result["risk_level"] = "MEDIUM"

        result["risk_indicators"] = indicators

    def _human_size(self, size_bytes: int) -> str:
        """Convert bytes to human-readable size."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

    def compare_files(self, file1: str, file2: str) -> Dict:
        """Compare two files by hash to detect modifications."""
        result = {"file1": file1, "file2": file2, "identical": False,
                  "differences": []}

        try:
            with open(file1, "rb") as f:
                data1 = f.read()
            with open(file2, "rb") as f:
                data2 = f.read()
        except Exception as e:
            return {"error": str(e)}

        h1 = self._compute_hashes(data1)
        h2 = self._compute_hashes(data2)

        result["identical"] = h1["sha256"] == h2["sha256"]
        result["file1_hashes"] = h1
        result["file2_hashes"] = h2
        result["size_difference"] = len(data2) - len(data1)

        if not result["identical"]:
            result["differences"].append(f"SHA-256 mismatch — files are different")
            if len(data1) != len(data2):
                result["differences"].append(
                    f"Size difference: {abs(result['size_difference'])} bytes"
                )

        return result


    # ── EXIF stripping ────────────────────────────────────────────────────────

    def strip_exif(self, filepath: str, output_path: str = None,
                   dry_run: bool = False) -> dict:
        """
        Remove all EXIF metadata from an image file (JPEG or PNG).

        Args:
            filepath:    Source image file.
            output_path: Where to write the stripped image.
                         Defaults to '<filename>_stripped.<ext>'.
            dry_run:     If True, report what would be removed without writing.

        Returns:
            dict with: stripped (bool), output_path (str), bytes_removed (int),
            tags_removed (list), error (str|None).
        """
        from pathlib import Path as _Path

        src = _Path(filepath)
        if not src.exists():
            return {"stripped": False, "error": f"File not found: {filepath}"}

        data = src.read_bytes()
        result = {"stripped": False, "output_path": None, "bytes_removed": 0,
                  "tags_removed": [], "error": None}

        if data[:3] == b"\xff\xd8\xff":
            stripped, tags = self._strip_exif_jpeg(data)
        elif data[:8] == b"\x89PNG\r\n\x1a\n":
            stripped, tags = self._strip_exif_png(data)
        else:
            result["error"] = "Unsupported format. Supported: JPEG, PNG."
            return result

        result["bytes_removed"] = len(data) - len(stripped)
        result["tags_removed"]  = tags

        if dry_run:
            result["stripped"] = True
            result["dry_run"] = True
            result["note"] = f"Would remove {result['bytes_removed']} bytes, {len(tags)} tag(s)"
            return result

        out = _Path(output_path) if output_path else src.with_name(src.stem + "_stripped" + src.suffix)
        out.write_bytes(stripped)
        result["stripped"] = True
        result["output_path"] = str(out)
        return result

    def _strip_exif_jpeg(self, data: bytes) -> tuple:
        """Strip EXIF from JPEG by removing APP1/APPn markers."""
        out = bytearray(b"\xff\xd8")
        pos = 2
        tags_removed = []
        while pos < len(data) - 1:
            if data[pos] != 0xFF:
                out.extend(data[pos:])
                break
            marker = data[pos + 1]
            pos += 2
            if marker == 0xD9:
                out.extend(b"\xff\xd9"); break
            if marker in (0xD8, 0x00):
                continue
            if marker == 0xDA:
                out.extend(b"\xff\xda"); out.extend(data[pos:]); break
            if pos + 2 > len(data):
                break
            seg_len = (data[pos] << 8) | data[pos + 1]
            payload = data[pos: pos + seg_len]
            pos += seg_len
            if marker == 0xE1 and payload[2:6] == b"Exif":
                tags_removed.append("EXIF-APP1"); continue
            if marker == 0xE1 and payload[2:12] == b"http://ns.a":
                tags_removed.append("XMP-APP1"); continue
            if marker in range(0xE2, 0xF0):
                tags_removed.append(f"APP{marker - 0xE0}"); continue
            if marker == 0xFE:
                tags_removed.append("JPEG-COMMENT"); continue
            out.extend(b"\xff" + bytes([marker]))
            out.extend(payload)
        return bytes(out), tags_removed

    def _strip_exif_png(self, data: bytes) -> tuple:
        """Strip EXIF from PNG by removing ancillary metadata chunks."""
        import struct as _struct
        REMOVE = {b"tEXt", b"iTXt", b"zTXt", b"eXIf", b"iCCP", b"pCAL", b"sCAL"}
        out = bytearray(data[:8])
        tags_removed = []
        pos = 8
        while pos < len(data):
            if pos + 8 > len(data):
                break
            length = _struct.unpack_from(">I", data, pos)[0]
            chunk_type = data[pos + 4: pos + 8]
            chunk_end = pos + 12 + length
            if chunk_type in REMOVE:
                tags_removed.append(f"PNG-{chunk_type.decode('ascii', errors='replace')}")
            else:
                out.extend(data[pos: chunk_end])
            pos = chunk_end
        return bytes(out), tags_removed

    def analyse_encrypted_file(self, filepath: str) -> dict:
        """
        Detect encrypted/password-protected documents and return a structured
        finding rather than raising an unhandled exception.

        Supports: PDF, Office CFBF (legacy encryption), ZIP/OOXML.
        """
        from pathlib import Path as _Path
        p = _Path(filepath)
        if not p.exists():
            return {"is_encrypted": False, "error": "File not found"}
        data = p.read_bytes()
        result = {"is_encrypted": False, "format": "unknown",
                  "evidence": None, "recommendation": None}

        if data[:4] == b"%PDF":
            result["format"] = "PDF"
            if b"/Encrypt" in data[:4096]:
                result.update(is_encrypted=True,
                    evidence="/Encrypt dictionary in PDF header",
                    recommendation="Use pdfcrack or obtain password for authorised analysis.")

        elif data[:4] == b"\xd0\xcf\x11\xe0":
            result.update(format="Office-CFBF", is_encrypted=True,
                evidence="Compound File Binary Format (CFBF) encryption container",
                recommendation="Use office2john + hashcat for authorised password recovery.")

        elif data[:2] == b"PK":
            result["format"] = "ZIP/OOXML"
            if len(data) > 10 and data[6] & 0x01:
                result.update(is_encrypted=True,
                    evidence="ZIP general purpose bit 0 (encryption flag) set",
                    recommendation="Use zip2john + hashcat for authorised password recovery.")
            elif b"EncryptionInfo" in data:
                result.update(is_encrypted=True,
                    evidence="EncryptionInfo stream found in OOXML container",
                    recommendation="Decrypt with correct password before analysis.")

        if not result["is_encrypted"]:
            result["recommendation"] = "File does not appear to be encrypted."
        return result

    def format_report(self, result: Dict, verbose: bool = False) -> str:
        """Format forensic report for terminal display."""
        try:
            from ixoryn.ui.banner import Colors as C
        except ImportError:
            class C:
                RED = YELLOW = GREEN = CYAN = RESET = BOLD = MUTED = WHITE = ""

        if result.get("error"):
            return f"\n  [!] {result['error']}\n"

        lines = [f"\n{C.CYAN}{'═'*62}{C.RESET}"]
        lines.append(f"{C.BOLD}  FILE FORENSICS REPORT{C.RESET}")
        lines.append(f"{C.CYAN}{'═'*62}{C.RESET}")

        risk = result.get("risk_level", "LOW")
        risk_color = {
            "CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW,
            "LOW": C.GREEN
        }.get(risk, C.GREEN)

        lines.append(f"  File:       {C.WHITE}{result['filename']}{C.RESET}")
        lines.append(f"  Size:       {result['size_human']} ({result['size_bytes']:,} bytes)")
        lines.append(f"  Type:       {result.get('file_type_detected', 'Unknown')}")
        lines.append(f"  Extension:  {result.get('extension', 'none')}")

        # Extension match
        ext_match = result.get("file_type_matches_extension")
        if ext_match is False:
            lines.append(f"  Ext Match:  {C.RED}NO — MISMATCH! File type doesn't match extension{C.RESET}")
        elif ext_match:
            lines.append(f"  Ext Match:  {C.GREEN}Yes{C.RESET}")

        lines.append(f"  Risk Level: {risk_color}{risk}{C.RESET}")
        lines.append(f"  Modified:   {result.get('modified', 'Unknown')}")
        lines.append("")

        # Hashes
        lines.append(f"{C.CYAN}── Hashes ───────────────────────────────────────────────{C.RESET}")
        for algo, value in result.get("hashes", {}).items():
            lines.append(f"  {algo.upper():<10} {value}")

        # Entropy
        lines.append(f"\n{C.CYAN}── Entropy Analysis ─────────────────────────────────────{C.RESET}")
        entropy = result.get("entropy", 0)
        entropy_color = C.RED if entropy > 7.5 else C.YELLOW if entropy > 6.0 else C.GREEN
        lines.append(f"  Entropy:   {entropy_color}{entropy:.4f} / 8.0{C.RESET}")
        lines.append(f"  Verdict:   {result.get('entropy_verdict', 'N/A')}")
        if result.get("is_encrypted"):
            lines.append(f"  {C.YELLOW}⚠  Very high entropy — likely encrypted or packed{C.RESET}")

        # Risk indicators
        if result.get("risk_indicators"):
            lines.append(f"\n{C.RED}── Risk Indicators ──────────────────────────────────────{C.RESET}")
            for ind in result["risk_indicators"]:
                lines.append(f"  ⚠  {ind}")

        # Sensitive findings
        if result.get("sensitive_findings"):
            lines.append(f"\n{C.YELLOW}── Sensitive Data Found ─────────────────────────────────{C.RESET}")
            for finding in result["sensitive_findings"]:
                lines.append(f"  [{finding['count']}x] {finding['type']}")
                if verbose:
                    lines.append(f"        {C.MUTED}Sample: {finding['sample']}{C.RESET}")

        # Metadata
        metadata = result.get("metadata", {})
        if metadata and verbose:
            lines.append(f"\n{C.CYAN}── Metadata ─────────────────────────────────────────────{C.RESET}")
            for key, val in list(metadata.items())[:15]:
                if isinstance(val, (str, int, float)):
                    lines.append(f"  {key:<25} {str(val)[:50]}")

        lines.append(f"\n{C.CYAN}{'═'*62}{C.RESET}\n")
        return "\n".join(lines)
