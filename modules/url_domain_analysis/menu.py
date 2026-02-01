from rich.console import Console
from rich.prompt import Prompt
from modules.url_domain_analysis.analyzer import analyze_domain

console = Console()

def url_menu():
    while True:
        console.print("\n[bold blue]URL / Domain Analysis[/bold blue]")
        console.print("1. Analyze URL / Domain")
        console.print("0. Back")

        choice = Prompt.ask("Select option", choices=["1", "0"])

        if choice == "1":
            target = Prompt.ask("Enter URL or domain")
            result = analyze_domain(target)
            console.print("\n[bold green]Analysis Result[/bold green]")
            for k, v in result.items():
                console.print(f"{k}: {v}")

        elif choice == "0":
            break

