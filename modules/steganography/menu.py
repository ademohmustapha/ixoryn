from rich.console import Console
from rich.prompt import Prompt

console = Console()

def stego_menu():
    while True:
        console.print("\n[bold magenta]Steganography Module[/bold magenta]")
        console.print("1. Operational Mode")
        console.print("2. Research Mode")
        console.print("0. Back")

        choice = Prompt.ask("Select mode", choices=["1", "2", "0"])

        if choice == "1":
            from modules.steganography.operational import operational_mode
            operational_mode()

        elif choice == "2":
            from modules.steganography.research import research_mode
            research_mode()

        elif choice == "0":
            break

