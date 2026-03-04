"""
Ixoryn Cross-Platform Compatibility Layer
Ensures Ixoryn works on: Kali Linux, Ubuntu, Debian, Fedora, Arch, macOS, Windows 10/11
"""

import os
import sys
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


def _is_kali() -> bool:
    try:
        with open("/etc/os-release") as f:
            return "kali" in f.read().lower()
    except Exception:
        return False


def _detect_system():
    return platform.system()


def _supports_color() -> bool:
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return os.environ.get("TERM_PROGRAM") == "vscode"
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class PlatformInfo:
    """Detect and describe the current platform."""
    SYSTEM  = platform.system()
    MACHINE = platform.machine()
    VERSION = platform.version()
    RELEASE = platform.release()
    IS_WINDOWS = SYSTEM == "Windows"
    IS_MACOS   = SYSTEM == "Darwin"
    IS_LINUX   = SYSTEM == "Linux"
    IS_WSL     = IS_LINUX and "microsoft" in platform.version().lower()
    IS_KALI    = IS_LINUX and _is_kali()
    IS_ARM     = "arm" in platform.machine().lower() or "aarch" in platform.machine().lower()
    IS_64BIT   = sys.maxsize > 2**32
    PYTHON_VER = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    @staticmethod
    def describe() -> str:
        p = PlatformInfo
        parts = [p.SYSTEM, p.RELEASE, p.MACHINE]
        if p.IS_WSL:    parts.append("(WSL)")
        if p.IS_KALI:   parts.append("(Kali Linux)")
        return " ".join(parts)

    @staticmethod
    def get_config_dir() -> Path:
        if PlatformInfo.IS_WINDOWS:
            base = os.environ.get("APPDATA", str(Path.home()))
            return Path(base) / "Ixoryn"
        elif PlatformInfo.IS_MACOS:
            return Path.home() / "Library" / "Application Support" / "Ixoryn"
        return Path.home() / ".ixoryn"

    @staticmethod
    def get_wordlists_dir() -> Path:
        if PlatformInfo.IS_WINDOWS:  return Path("C:/wordlists")
        if PlatformInfo.IS_KALI:     return Path("/usr/share/wordlists")
        if PlatformInfo.IS_MACOS:    return Path.home() / "wordlists"
        return Path("/usr/share/wordlists")

    @staticmethod
    def get_temp_dir() -> Path:
        import tempfile
        return Path(tempfile.gettempdir()) / "ixoryn"

    @staticmethod
    def supports_color() -> bool:
        return _supports_color()


TOOL_LOCATIONS = {
    "hashcat": {
        "linux":   ["/usr/bin/hashcat", "/usr/local/bin/hashcat",
                    str(Path.home() / "hashcat" / "hashcat")],
        "darwin":  ["/usr/local/bin/hashcat", "/opt/homebrew/bin/hashcat"],
        "windows": [r"C:\hashcat\hashcat.exe", r"C:\tools\hashcat\hashcat.exe"],
    },
    "john": {
        "linux":   ["/usr/bin/john", "/usr/local/bin/john", "/usr/sbin/john"],
        "darwin":  ["/usr/local/bin/john", "/opt/homebrew/bin/john"],
        "windows": [r"C:\john\john.exe", r"C:\tools\john\john.exe"],
    },
    "nmap": {
        "linux":   ["/usr/bin/nmap", "/usr/local/bin/nmap"],
        "darwin":  ["/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"],
        "windows": [r"C:\Program Files (x86)\Nmap\nmap.exe"],
    },
    "ffmpeg": {
        "linux":   ["/usr/bin/ffmpeg", "/usr/local/bin/ffmpeg"],
        "darwin":  ["/usr/local/bin/ffmpeg", "/opt/homebrew/bin/ffmpeg"],
        "windows": [r"C:\ffmpeg\bin\ffmpeg.exe"],
    },
    "wkhtmltopdf": {
        "linux":   ["/usr/bin/wkhtmltopdf", "/usr/local/bin/wkhtmltopdf"],
        "darwin":  ["/usr/local/bin/wkhtmltopdf"],
        "windows": [r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"],
    },
}

INSTALL_CMDS = {
    "hashcat": {
        "linux_debian": "sudo apt install hashcat",
        "linux_arch":   "sudo pacman -S hashcat",
        "linux_fedora": "sudo dnf install hashcat",
        "darwin":       "brew install hashcat",
        "windows":      "https://hashcat.net/hashcat/",
    },
    "john": {
        "linux_debian": "sudo apt install john",
        "darwin":       "brew install john",
        "windows":      "https://www.openwall.com/john/",
    },
    "nmap": {
        "linux_debian": "sudo apt install nmap",
        "darwin":       "brew install nmap",
        "windows":      "https://nmap.org/download.html",
    },
    "ffmpeg": {
        "linux_debian": "sudo apt install ffmpeg",
        "darwin":       "brew install ffmpeg",
        "windows":      "https://ffmpeg.org/download.html",
    },
    "wkhtmltopdf": {
        "linux_debian": "sudo apt install wkhtmltopdf",
        "darwin":       "brew install wkhtmltopdf",
        "windows":      "https://wkhtmltopdf.org/downloads.html",
    },
}


class ToolFinder:
    """Find security tools across all platforms."""

    @classmethod
    def find(cls, tool: str) -> Optional[str]:
        found = shutil.which(tool)
        if found:
            return found
        if PlatformInfo.IS_WINDOWS:
            found = shutil.which(tool + ".exe")
            if found:
                return found
        sys_key = platform.system().lower()
        for path in TOOL_LOCATIONS.get(tool, {}).get(sys_key, []):
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    @classmethod
    def get_install_cmd(cls, tool: str) -> str:
        cmds = INSTALL_CMDS.get(tool, {})
        if not cmds:
            return f"Install {tool} manually"
        sys = platform.system().lower()
        if sys == "darwin":
            return cmds.get("darwin", "")
        elif sys == "windows":
            return cmds.get("windows", "")
        try:
            with open("/etc/os-release") as f:
                txt = f.read().lower()
            if any(d in txt for d in ("ubuntu", "debian", "kali")):
                return cmds.get("linux_debian", "")
            if "arch" in txt or "manjaro" in txt:
                return cmds.get("linux_arch", "")
            if any(d in txt for d in ("fedora", "rhel", "centos")):
                return cmds.get("linux_fedora", "")
        except Exception:
            pass
        return cmds.get("linux_debian", "")

    @classmethod
    def system_tools_report(cls) -> List[Dict]:
        tools = ["hashcat", "john", "nmap", "ffmpeg", "wkhtmltopdf"]
        return [
            {
                "tool": t,
                "available": cls.find(t) is not None,
                "path": cls.find(t),
                "install_cmd": cls.get_install_cmd(t) if not cls.find(t) else None,
            }
            for t in tools
        ]


class WordlistManager:
    """Manage wordlists across platforms."""

    BUILTIN_TOP1000 = [
        "password", "123456", "password123", "admin", "letmein", "welcome",
        "monkey", "dragon", "master", "sunshine", "princess", "iloveyou",
        "superman", "batman", "shadow", "hello", "abc123", "qwerty",
        "111111", "12345678", "1q2w3e4r", "123456789", "qwerty123",
        "passw0rd", "Password1", "Password123", "P@ssw0rd", "Admin123",
        "admin123", "root", "toor", "test", "guest", "default", "login",
        "changeme", "secret", "pa$$word", "hunter2", "trustno1",
        "baseball", "football", "soccer", "hockey", "basketball",
        "summer", "winter", "spring", "january", "february", "march",
        "google", "facebook", "twitter", "instagram", "linkedin",
        "apple", "microsoft", "amazon", "netflix", "spotify",
        "computer", "internet", "network", "security", "hacker",
        "access", "system", "server", "database", "administrator",
        "666666", "121212", "123123", "987654321", "pass", "pass123",
        "ninja", "pirate", "ranger", "hunter", "warrior", "love",
        "angel", "purple", "orange", "yellow", "green", "blue",
        "black", "white", "silver", "golden", "crystal",
        "1234", "12345", "0000", "1111", "2222", "3333", "4444",
        "5555", "6666", "7777", "8888", "9999", "0987", "1357",
    ] + [str(i) for i in range(1990, 2025)] + [str(i) for i in range(1000, 1100)]

    @classmethod
    def find_wordlist(cls, name: str = "rockyou") -> Optional[str]:
        sys_key = platform.system().lower()
        candidates = []
        if sys_key == "linux":
            candidates = [
                "/usr/share/wordlists/rockyou.txt",
                str(Path.home() / "wordlists" / "rockyou.txt"),
                "/tmp/rockyou.txt",
            ]
        elif sys_key == "darwin":
            candidates = [
                str(Path.home() / "wordlists" / "rockyou.txt"),
                "/usr/local/share/wordlists/rockyou.txt",
            ]
        else:
            candidates = [
                r"C:\wordlists\rockyou.txt",
                r"C:\tools\wordlists\rockyou.txt",
            ]
        for path in candidates:
            if os.path.exists(path):
                return path
        # Try gz
        gz = "/usr/share/wordlists/rockyou.txt.gz"
        if os.path.exists(gz):
            out = gz.replace(".gz", "")
            try:
                import gzip
                with gzip.open(gz, "rb") as g, open(out, "wb") as f:
                    f.write(g.read())
                return out
            except Exception:
                pass
        return None

    @classmethod
    def get_builtin_wordlist(cls) -> str:
        import tempfile, atexit, os as _os
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                          prefix="ixoryn_builtin_", delete=False)
        tmp_name = tmp.name
        for w in cls.BUILTIN_TOP1000:
            tmp.write(w + "\n")
        tmp.close()
        # FIXED: register cleanup so the temp file is removed when the process exits
        def _cleanup_tmp():
            try:
                _os.unlink(tmp_name)
            except OSError:
                pass
        atexit.register(_cleanup_tmp)
        return tmp_name

    @classmethod
    def list_available(cls) -> List[Dict]:
        rockyou = cls.find_wordlist("rockyou")
        return [
            {
                "name": "builtin_top1000",
                "path": "built-in (no file needed)",
                "available": True,
                "size": "~8KB",
                "entries": "1,000+",
                "builtin": True,
            },
            {
                "name": "rockyou",
                "path": rockyou or "not found",
                "available": rockyou is not None,
                "size": "133MB",
                "entries": "14,000,000",
                "builtin": False,
            },
        ]
