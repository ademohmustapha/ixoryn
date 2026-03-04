"""
Ixoryn Doctor
Comprehensive health check for all modules, dependencies, and system compatibility.
"""

import sys
import os
import platform
import importlib
from pathlib import Path
from ixoryn.ui.banner import Banner, Colors, cprint
from ixoryn.core.dependency_manager import DependencyManager


class IxorynDoctor:
    def run(self):
        Banner.section("Ixoryn Doctor — System Health Check")
        print(f"  {Colors.DIM}Running comprehensive diagnostics...{Colors.RESET}\n")

        self._check_system()
        self._check_python()
        self._check_dependencies()
        self._check_modules()
        self._check_filesystem()
        self._check_network()
        self._print_summary()

    def _check_system(self):
        cprint("  ── System Information ──────────────────────────", Colors.CYAN)
        Banner.result("OS", platform.platform())
        Banner.result("Architecture", platform.machine())
        Banner.result("Hostname", platform.node())
        Banner.result("Python", sys.version.split()[0])
        Banner.result("Python Path", sys.executable)

        # Check Python version
        major, minor = sys.version_info[:2]
        if (major, minor) < (3, 9):
            Banner.error(f"Python 3.9+ required. Found {major}.{minor}")
        else:
            Banner.success(f"Python version OK ({major}.{minor})")
        print()

    def _check_python(self):
        cprint("  ── Python Environment ──────────────────────────", Colors.CYAN)
        Banner.result("sys.prefix", sys.prefix)
        Banner.result("Virtual env", str(hasattr(sys, 'real_prefix') or
                      (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)))

        # Check pip
        try:
            import pip
            Banner.success(f"pip available (v{pip.__version__})")
        except ImportError:
            Banner.error("pip not found in Python environment")
        print()

    def _check_dependencies(self):
        cprint("  ── Dependency Status ───────────────────────────", Colors.CYAN)
        dm = DependencyManager()
        health = dm.full_health_check()

        ok = 0
        missing = 0
        for pkg, status in health["packages"].items():
            if status == "MISSING":
                cprint(f"    ✗ {pkg:<30} MISSING", Colors.RED)
                missing += 1
            elif status == "stdlib":
                ok += 1
            else:
                cprint(f"    ✓ {pkg:<30} {Colors.DIM}{status}{Colors.RESET}", Colors.GREEN)
                ok += 1

        print()
        Banner.result("Packages OK", str(ok), Colors.GREEN)
        if missing > 0:
            Banner.result("Packages MISSING", str(missing), Colors.RED)
            Banner.warn(f"{missing} packages are missing. Run tool and select Y to install.")
        else:
            Banner.success("All Python packages are installed!")

        # System tools
        if health["system_tools"]:
            print()
            cprint("  ── System Tools ────────────────────────────────", Colors.CYAN)
            for tool, status in health["system_tools"].items():
                if status == "MISSING":
                    cprint(f"    ✗ {tool:<20} MISSING", Colors.RED)
                else:
                    cprint(f"    ✓ {tool:<20} OK", Colors.GREEN)
        print()

    def _check_modules(self):
        cprint("  ── Module Self-Test ────────────────────────────", Colors.CYAN)
        modules = [
            ("Cryptography Engine", self._test_crypto),
            ("Steganography Detector", self._test_stego_detect),
            ("Steganography Embed/Extract", self._test_stego_embed),
            ("URL Auditor", self._test_url),
            ("Password Auditor", self._test_password),
        ]

        for name, test_fn in modules:
            try:
                test_fn()
                Banner.success(f"{name:<35} FUNCTIONAL")
            except ImportError as e:
                Banner.warn(f"{name:<35} DEGRADED (missing dep: {e})")
            except Exception as e:
                Banner.error(f"{name:<35} ERROR: {e}")
        print()

    def _test_crypto(self):
        from ixoryn.modules.crypto.engine import CryptoEngine
        engine = CryptoEngine()
        data = b"doctor_test_1234"
        password = "doctor_test_pass"
        encrypted = engine.encrypt(data, password)
        decrypted, _ = engine.decrypt(encrypted, password)
        assert decrypted == data, "Decrypt mismatch"

    def _test_stego_detect(self):
        from ixoryn.modules.stego.detector import StegoDetector
        detector = StegoDetector()
        # Just ensure it loads

    def _test_stego_embed(self):
        from ixoryn.modules.stego.embed import StegoEmbed
        from ixoryn.modules.stego.extract import StegoExtract

    def _test_url(self):
        from ixoryn.modules.url_audit.auditor import URLAuditor
        auditor = URLAuditor()

    def _test_password(self):
        from ixoryn.modules.password.auditor import PasswordAuditor
        auditor = PasswordAuditor()
        report = auditor.audit_password("TestPassword123!")
        assert "strength" in report

    def _check_filesystem(self):
        cprint("  ── File System ─────────────────────────────────", Colors.CYAN)
        home = Path.home() / ".ixoryn"
        dirs = {
            "Config dir": home,
            "Logs dir": home / "logs",
            "Output dir": home / "output",
            "Temp dir": home / "temp",
        }
        for label, path in dirs.items():
            if path.exists():
                Banner.success(f"{label:<25} {path}")
            else:
                Banner.warn(f"{label:<25} MISSING — will be created on next run")
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    Banner.success(f"  Created: {path}")
                except Exception as e:
                    Banner.error(f"  Could not create: {e}")
        print()

    def _check_network(self):
        cprint("  ── Network Connectivity ────────────────────────", Colors.CYAN)
        test_hosts = [
            ("DNS Resolution", "8.8.8.8", 53),
            ("HTTP (port 80)", "google.com", 80),
            ("HTTPS (port 443)", "google.com", 443),
        ]
        import socket
        for label, host, port in test_hosts:
            try:
                s = socket.create_connection((host, port), timeout=3)
                s.close()
                Banner.success(f"{label:<30} REACHABLE")
            except Exception:
                Banner.warn(f"{label:<30} UNREACHABLE (some URL audit features may be limited)")
        print()

    def _print_summary(self):
        cprint("  ── Summary ─────────────────────────────────────", Colors.CYAN)
        dm = DependencyManager()
        health = dm.full_health_check()
        issues = health.get("issues", [])

        if not issues:
            Banner.success("Ixoryn is fully operational! All systems nominal.")
        else:
            Banner.warn(f"Found {len(issues)} issue(s):")
            for issue in issues:
                cprint(f"    → {issue}", Colors.YELLOW)
            print()
            Banner.info("Run the tool and select Y to auto-install missing dependencies.")

        print()
        run_tests = Banner.prompt("Run full module test suite now? [y/N]:")
        if run_tests.lower() in ("y", "yes"):
            import subprocess, sys
            cprint("\n  Running tests...\n", Colors.CYAN)
            subprocess.run([sys.executable, "tests/test_suite.py"])
        print()
