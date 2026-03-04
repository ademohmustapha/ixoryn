"""
Ixoryn — Advanced Security & Intelligence Platform
Author   : Ademoh Mustapha Onimisi
Copyright: © 2026 Ademoh Mustapha Onimisi. All rights reserved.
License  : MIT
GitHub   : https://github.com/ademohmustapha/ixoryn
"""

__version__   = "1.0.0"
__author__    = "Ademoh Mustapha Onimisi"
__copyright__ = "Copyright © 2026 Ademoh Mustapha Onimisi"
__license__   = "MIT"
__url__       = "https://github.com/ademohmustapha/ixoryn"


def main():
    """
    Package entry point for the installed 'ixoryn' console script.
    Called by pip-installed entry point defined in setup.py / pyproject.toml.
    Delegates to the same startup sequence as python ixoryn.py.
    """
    from ixoryn.ui.banner import Banner
    from ixoryn.core.dependency_manager import DependencyManager
    from ixoryn.core.bootstrap import Bootstrap
    from ixoryn.ui.main_menu import MainMenu

    Banner.print_banner()

    dep_manager = DependencyManager()
    if not dep_manager.check_and_install():
        print("\n[!] Dependency installation was skipped or failed.")
        print("[!] Some features may not work. Run 'doctor' to diagnose.\n")

    bootstrap = Bootstrap()
    bootstrap.initialize()

    menu = MainMenu()
    menu.run()
