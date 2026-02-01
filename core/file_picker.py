from rich.console import Console
from rich.prompt import Prompt

console = Console()

def main_menu():
    while True:
        console.print("\n[bold cyan]IXORYN Unified Cybersecurity Framework[/bold cyan]")
        console.print("1. Cryptography")
        console.print("2. Steganography")
        console.print("3. Password Auditing")
        console.print("4. URL / Domain Analysis")
        console.print("0. Exit")

        choice = Prompt.ask("Select an option", choices=["1","2","3","4","0"])

        if choice == "1":
            console.print("[yellow]Cryptography module coming next[/yellow]")
        elif choice == "2":
            from modules.steganography.menu import stego_menu
            stego_menu()
        elif choice == "3":
            console.print("[yellow]Password auditing coming next[/yellow]")
        elif choice == "4":
            console.print("[yellow]URL analysis coming next[/yellow]")
        elif choice == "0":
            console.print("[green]Goodbye.[/green]")
            break

