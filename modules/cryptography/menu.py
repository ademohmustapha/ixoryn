from rich.console import Console
from rich.prompt import Prompt
from modules.cryptography.encrypt import encrypt_file
from modules.cryptography.decrypt import decrypt_file

console = Console()

def crypto_menu():
    while True:
        console.print("\n[bold cyan]Cryptography Module[/bold cyan]")
        console.print("1. Encrypt File")
        console.print("2. Decrypt File")
        console.print("0. Back")

        choice = Prompt.ask("Select option", choices=["1", "2", "0"])

        if choice == "1":
            encrypt_file()
        elif choice == "2":
            decrypt_file()
        elif choice == "0":
            break

