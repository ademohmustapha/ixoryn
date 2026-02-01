from rich.console import Console
from rich.prompt import Prompt
from core.runner import run_safely
from core.logger import logger

console = Console()


def main_menu():
    while True:
        console.print("\n[bold cyan]IXORYN Unified Cybersecurity Framework[/bold cyan]")
        console.print("1. Cryptography")
        console.print("2. Steganography")
        console.print("3. Password Auditing")
        console.print("4. URL / Domain Analysis")
        console.print("5. Exit")

        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5"])

        if choice == "5":
            logger.info("IXORYN exited normally.")
            console.print("Goodbye.")
            break

        elif choice == "1":
            from modules.crypto.crypto import crypto_menu
            run_safely(crypto_menu)

        elif choice == "2":
            from modules.steganography.stego import stego_menu
            run_safely(stego_menu)

        elif choice == "3":
            from modules.password.audit import password_menu
            run_safely(password_menu)

        elif choice == "4":
            from modules.url_analysis.analyzer import url_menu
            run_safely(url_menu)

