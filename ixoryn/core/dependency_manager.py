"""
Ixoryn Dependency Manager
Handles automatic detection, download, and installation of all required dependencies.
Supports Kali Linux, Ubuntu/Debian, macOS, and Windows.
"""

import sys
import os
import subprocess
import importlib
import platform
import shutil
from typing import Dict, List, Tuple, Optional


REQUIRED_PACKAGES = {
    # Core cryptography
    "cryptography": {"pip": "cryptography", "import": "cryptography"},
    "argon2-cffi": {"pip": "argon2-cffi", "import": "argon2"},
    "pynacl": {"pip": "PyNaCl", "import": "nacl"},
    "bcrypt": {"pip": "bcrypt", "import": "bcrypt"},

    # Steganography
    "Pillow": {"pip": "Pillow", "import": "PIL"},
    "pydub": {"pip": "pydub", "import": "pydub", "optional": True},  # Audio stego (MP3/OGG)
    "numpy": {"pip": "numpy", "import": "numpy"},
    "scipy": {"pip": "scipy", "import": "scipy"},
    "opencv-python": {"pip": "opencv-python", "import": "cv2"},
    "stegano": {"pip": "stegano", "import": "stegano"},
    "wave": {"pip": None, "import": "wave"},  # stdlib

    # URL / Domain Auditing
    "requests": {"pip": "requests", "import": "requests"},
    "dnspython": {"pip": "dnspython", "import": "dns"},
    "whois": {"pip": "python-whois", "import": "whois"},
    "tld": {"pip": "tld", "import": "tld"},
    "urllib3": {"pip": "urllib3", "import": "urllib3"},
    "certifi": {"pip": "certifi", "import": "certifi"},
    "idna": {"pip": "idna", "import": "idna"},
    "beautifulsoup4": {"pip": "beautifulsoup4", "import": "bs4"},
    "sslyze": {"pip": "sslyze", "import": "sslyze"},

    # Password & Hash Auditing
    "hashid": {"pip": "hashid", "import": "hashid"},
    "passlib": {"pip": "passlib", "import": "passlib"},
    "zxcvbn": {"pip": "zxcvbn", "import": "zxcvbn"},

    # UI & Utilities
    "colorama": {"pip": "colorama", "import": "colorama"},
    "rich": {"pip": "rich", "import": "rich"},
    "prompt_toolkit": {"pip": "prompt_toolkit", "import": "prompt_toolkit"},
    "tabulate": {"pip": "tabulate", "import": "tabulate"},
    "tqdm": {"pip": "tqdm", "import": "tqdm"},
    "pyfiglet": {"pip": "pyfiglet", "import": "pyfiglet"},

    # File handling
    "chardet": {"pip": "chardet", "import": "chardet"},
    "python-magic": {"pip": "python-magic", "import": "magic"},
    "filelock": {"pip": "filelock", "import": "filelock"},

    # ML / stego
    "scikit-learn": {"pip": "scikit-learn", "import": "sklearn"},

    # Report generation
    "weasyprint": {"pip": "weasyprint", "import": "weasyprint"},
    "pdfkit": {"pip": "pdfkit", "import": "pdfkit"},

    # Testing
    "pytest": {"pip": "pytest", "import": "pytest"},
}

SYSTEM_DEPS = {
    "linux": {
        "ffmpeg": "ffmpeg",
        "libmagic": "libmagic1",
        "libmagic-dev": "libmagic-dev",
    },
    "darwin": {
        "ffmpeg": "ffmpeg",
        "libmagic": "libmagic",
    },
    "windows": {}
}


class DependencyManager:
    def __init__(self):
        self.system = platform.system().lower()
        self.missing_pip = []
        self.missing_system = []
        self.python_exe = sys.executable

    def _color(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m"

    def info(self, msg): print(self._color(f"  [*] {msg}", "94"))
    def success(self, msg): print(self._color(f"  [+] {msg}", "92"))
    def warn(self, msg): print(self._color(f"  [!] {msg}", "93"))
    def error(self, msg): print(self._color(f"  [-] {msg}", "91"))

    def _can_import(self, module_name: str) -> bool:
        try:
            importlib.import_module(module_name)
            return True
        except ImportError:
            return False

    def _check_system_command(self, cmd: str) -> bool:
        return shutil.which(cmd) is not None

    def scan_missing(self):
        """Scan for all missing dependencies."""
        print(self._color("\n[~] Scanning for required dependencies...\n", "96"))

        for pkg_name, info in REQUIRED_PACKAGES.items():
            if info["pip"] is None:
                continue  # stdlib
            if not self._can_import(info["import"]):
                self.missing_pip.append(info["pip"])

        # Check system deps
        if self.system in ("linux", "darwin"):
            sys_deps = SYSTEM_DEPS.get(self.system, {})
            for cmd, pkg in sys_deps.items():
                if not self._check_system_command(cmd) and cmd not in ("libmagic", "libmagic-dev"):
                    self.missing_system.append((cmd, pkg))

        return self.missing_pip, self.missing_system

    def prompt_install(self) -> bool:
        """Prompt user whether to install missing deps."""
        pip_count = len(self.missing_pip)
        sys_count = len(self.missing_system)

        if pip_count == 0 and sys_count == 0:
            self.success("All dependencies are satisfied!")
            return True

        print(self._color(f"\n  [!] Found {pip_count} missing Python package(s) and {sys_count} missing system package(s).", "93"))

        if self.missing_pip:
            print(self._color("\n  Python packages to install:", "97"))
            for pkg in self.missing_pip:
                print(f"      - {pkg}")

        if self.missing_system:
            print(self._color("\n  System packages to install:", "97"))
            for cmd, pkg in self.missing_system:
                print(f"      - {pkg} (for '{cmd}')")

        print()
        try:
            choice = input(self._color("  [?] Install missing dependencies now? [Y/n]: ", "96")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False

        return choice in ("y", "yes", "")

    def _get_pip_install_cmd(self) -> List[str]:
        """Get the correct pip install command, bypassing venv/externally-managed errors."""
        base = [self.python_exe, "-m", "pip", "install"]

        # Detect if we're in an externally managed environment (PEP 668)
        try:
            result = subprocess.run(
                [self.python_exe, "-m", "pip", "install", "--dry-run", "pip"],
                capture_output=True, text=True
            )
            if "externally-managed-environment" in result.stderr:
                base.append("--break-system-packages")
        except Exception:
            pass

        base += ["--quiet", "--upgrade"]
        return base

    def install_pip_packages(self) -> bool:
        """Install all missing pip packages."""
        if not self.missing_pip:
            return True

        cmd = self._get_pip_install_cmd() + self.missing_pip
        self.info(f"Installing {len(self.missing_pip)} Python package(s)...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.success("Python packages installed successfully.")
                return True
            else:
                # Try one by one
                self.warn("Batch install failed, trying individual installs...")
                failed = []
                base = self._get_pip_install_cmd()
                for pkg in self.missing_pip:
                    r = subprocess.run(base + [pkg], capture_output=True, text=True)
                    if r.returncode != 0:
                        failed.append(pkg)
                        self.error(f"Failed to install: {pkg}")
                    else:
                        self.success(f"Installed: {pkg}")
                return len(failed) == 0
        except Exception as e:
            self.error(f"Installation error: {e}")
            return False

    def install_system_packages(self) -> bool:
        """Install system-level packages."""
        if not self.missing_system:
            return True

        if self.system == "linux":
            # Check for apt
            if shutil.which("apt-get"):
                pkgs = [pkg for _, pkg in self.missing_system]
                self.info(f"Installing system packages via apt-get: {', '.join(pkgs)}")
                try:
                    subprocess.run(["sudo", "apt-get", "install", "-y"] + pkgs,
                                   capture_output=True)
                    return True
                except Exception as e:
                    self.warn(f"Could not auto-install system packages: {e}")
                    return False
            elif shutil.which("pacman"):
                pkgs = [pkg for _, pkg in self.missing_system]
                self.info(f"Installing system packages via pacman...")
                try:
                    subprocess.run(["sudo", "pacman", "-S", "--noconfirm"] + pkgs,
                                   capture_output=True)
                    return True
                except Exception as e:
                    self.warn(f"Could not auto-install system packages: {e}")
                    return False

        elif self.system == "darwin":
            if shutil.which("brew"):
                pkgs = [pkg for _, pkg in self.missing_system]
                self.info(f"Installing system packages via Homebrew...")
                try:
                    subprocess.run(["brew", "install"] + pkgs, capture_output=True)
                    return True
                except Exception as e:
                    self.warn(f"Could not auto-install system packages: {e}")
                    return False
            else:
                self.warn("Homebrew not found. Please install it from https://brew.sh")

        return True

    def check_and_install(self) -> bool:
        """Main method: scan, prompt, and install."""
        pip_missing, sys_missing = self.scan_missing()

        if not pip_missing and not sys_missing:
            return True

        if self.prompt_install():
            ok1 = self.install_system_packages()
            ok2 = self.install_pip_packages()
            # Reload importlib after install
            importlib.invalidate_caches()
            return ok1 and ok2
        return False

    def full_health_check(self) -> Dict:
        """Comprehensive health check for Ixoryn Doctor."""
        results = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "packages": {},
            "system_tools": {},
            "overall_status": "healthy"
        }

        issues = []

        for pkg_name, info in REQUIRED_PACKAGES.items():
            if info["pip"] is None:
                status = "stdlib"
            elif self._can_import(info["import"]):
                try:
                    mod = importlib.import_module(info["import"])
                    ver = getattr(mod, "__version__", "unknown")
                except Exception:
                    ver = "unknown"
                status = f"OK (v{ver})"
            else:
                status = "MISSING"
                issues.append(f"Python package '{info['pip']}' is not installed")
                results["overall_status"] = "degraded"
            results["packages"][pkg_name] = status

        if self.system in ("linux", "darwin"):
            for cmd, pkg in SYSTEM_DEPS.get(self.system, {}).items():
                if cmd in ("libmagic", "libmagic-dev"):
                    continue
                if self._check_system_command(cmd):
                    results["system_tools"][cmd] = "OK"
                else:
                    results["system_tools"][cmd] = "MISSING"
                    issues.append(f"System tool '{cmd}' not found")
                    results["overall_status"] = "degraded"

        results["issues"] = issues
        return results
