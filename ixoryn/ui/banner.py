"""
Ixoryn — Banner, Colors, and UI utilities.
Author   : Ademoh Mustapha Onimisi
Copyright: © 2026 Ademoh Mustapha Onimisi. All rights reserved.
License  : MIT
"""

import sys
import platform


class Colors:
    """ANSI color codes used throughout the Ixoryn UI."""
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    MUTED   = "\033[2m"   # alias for DIM — used across modules for subdued output
    RESET   = "\033[0m"
    ORANGE  = "\033[38;5;208m"
    PURPLE  = "\033[38;5;135m"
    TEAL    = "\033[38;5;51m"

    @classmethod
    def disable(cls):
        """Disable all ANSI codes for terminals that don't support them."""
        for attr in dir(cls):
            if not attr.startswith("_") and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, "")


# Enable ANSI on Windows via colorama if available
if platform.system() == "Windows":
    try:
        import colorama
        colorama.init(autoreset=True)
    except ImportError:
        Colors.disable()


def cprint(text: str, color: str = Colors.WHITE, end: str = "\n") -> None:
    print(f"{color}{text}{Colors.RESET}", end=end)


class Banner:
    """All UI print helpers centralised here."""

    # ── Banner box geometry ────────────────────────────────────────────────────
    # Top/bottom borders are 66 chars wide (including the 2-space left indent):
    #   "  ╔" + "═"×62 + "╗"  = 2 + 1 + 62 + 1 = 66
    # Every interior line must therefore be:
    #   "  ║" + <content padded to 62 chars> + "║" = 66
    # ──────────────────────────────────────────────────────────────────────────

    BANNER = (
        f"\n{Colors.CYAN}{Colors.BOLD}"
        "  ██╗██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗\n"
        "  ██║╚██╗██╔╝██╔═══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║\n"
        "  ██║ ╚███╔╝ ██║   ██║██████╔╝ ╚████╔╝ ██╔██╗ ██║\n"
        "  ██║ ██╔██╗ ██║   ██║██╔══██╗  ╚██╔╝  ██║╚██╗██║\n"
        "  ██║██╔╝ ██╗╚██████╔╝██║  ██║   ██║   ██║ ╚████║\n"
        "  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝\n"
        f"{Colors.RESET}{Colors.TEAL}\n"
        # Box: '  ╔' + '═'×62 + '╗'  = 66 chars
        # Each row: '  ║' + <62-char content> + '║' = 66 chars
        "  ╔══════════════════════════════════════════════════════════════╗\n"
        "  ║          Advanced Security & Intelligence Platform           ║\n"
        "  ║ Encrypt · Stego · NetRecon · HashCrack · Breach · Forensics  ║\n"
        "  ║     URL Audit · CVE Lookup · Subdomain Enum · WiFi Scan      ║\n"
        "  ║        © 2026 Ademoh Mustapha Onimisi  ·  MIT License        ║\n"
        "  ║               github.com/ademohmustapha/ixoryn               ║\n"
        "  ╚══════════════════════════════════════════════════════════════╝\n"
        f"{Colors.RESET}"
    )

    @staticmethod
    def print_banner() -> None:
        print(Banner.BANNER)

    @staticmethod
    def section(title: str) -> None:
        width = 62
        print(f"\n{Colors.CYAN}{'═' * width}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}  {title}{Colors.RESET}")
        print(f"{Colors.CYAN}{'═' * width}{Colors.RESET}\n")

    @staticmethod
    def subsection(title: str) -> None:
        pad = max(0, 50 - len(title))
        print(f"\n{Colors.TEAL}  ┌─ {title} {'─' * pad}┐{Colors.RESET}")

    @staticmethod
    def success(msg: str) -> None:
        print(f"{Colors.GREEN}  [✓] {msg}{Colors.RESET}")

    @staticmethod
    def error(msg: str, detail: str = "") -> None:
        print(f"{Colors.RED}  [✗] {msg}{Colors.RESET}")
        if detail:
            print(f"{Colors.DIM}      Reason: {detail}{Colors.RESET}")

    @staticmethod
    def warn(msg: str) -> None:
        print(f"{Colors.YELLOW}  [!] {msg}{Colors.RESET}")

    @staticmethod
    def info(msg: str) -> None:
        print(f"{Colors.BLUE}  [*] {msg}{Colors.RESET}")

    @staticmethod
    def prompt(msg: str) -> str:
        return input(f"{Colors.MAGENTA}  [?] {msg}{Colors.RESET} ").strip()

    @staticmethod
    def result(label: str, value: str, color: str = Colors.WHITE) -> None:
        print(f"  {Colors.DIM}{label}:{Colors.RESET} {color}{value}{Colors.RESET}")
