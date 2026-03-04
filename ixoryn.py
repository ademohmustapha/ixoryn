#!/usr/bin/env python3
"""
  ██╗██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗
  ██║╚██╗██╔╝██╔═══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║
  ██║ ╚███╔╝ ██║   ██║██████╔╝ ╚████╔╝ ██╔██╗ ██║
  ██║ ██╔██╗ ██║   ██║██╔══██╗  ╚██╔╝  ██║╚██╗██║
  ██║██╔╝ ██╗╚██████╔╝██║  ██║   ██║   ██║ ╚████║
  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝

  Advanced Security & Intelligence Platform
  Cryptography · Steganography · Network Recon · Hash Cracking
  URL Audit · Breach Intel · CVE Lookup · File Forensics

  Author    : Ademoh Mustapha Onimisi
  GitHub    : github.com/ademohmustapha/ixoryn
  License   : MIT
  Copyright : © 2026 Ademoh Mustapha Onimisi. All rights reserved.
"""

import sys
import os

# Ensure the package directory is in the import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ixoryn.core.bootstrap import Bootstrap
from ixoryn.core.dependency_manager import DependencyManager
from ixoryn.ui.banner import Banner
from ixoryn.ui.main_menu import MainMenu


def main():
    """Main entry point for Ixoryn."""
    Banner.print_banner()

    dep_manager = DependencyManager()
    if not dep_manager.check_and_install():
        print("\n[!] Dependency installation was skipped or failed.")
        print("[!] Some features may not work. Run 'doctor' to diagnose.\n")

    bootstrap = Bootstrap()
    bootstrap.initialize()

    menu = MainMenu()
    menu.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Ixoryn terminated by user. Goodbye.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n[FATAL ERROR] {e}")
        print("[*] Run 'Ixoryn Doctor' to diagnose issues.\n")
        sys.exit(1)
