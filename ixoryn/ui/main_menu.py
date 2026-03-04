"""
Ixoryn Main Menu
Entry point for Beginner Mode, Expert Mode, and Ixoryn Doctor.
"""

import sys
from ixoryn.ui.banner import Banner, Colors, cprint
from ixoryn.ui.beginner_menu import BeginnerMenu
from ixoryn.ui.expert_shell import ExpertShell
from ixoryn.ui.doctor import IxorynDoctor


class MainMenu:
    def __init__(self):
        self.choices = {
            "1": ("Beginner Mode", self._launch_beginner),
            "2": ("Expert Mode", self._launch_expert),
            "3": ("Ixoryn Doctor", self._launch_doctor),
        }

    def _print_menu(self):
        Banner.section("Welcome to Ixoryn — Select Your Mode")
        print(f"  {Colors.BOLD}{Colors.GREEN}1.{Colors.RESET} {Colors.WHITE}Beginner Mode{Colors.RESET}")
        print(f"  {Colors.DIM}     Guided, menu-driven interface — perfect for all skill levels{Colors.RESET}\n")
        print(f"  {Colors.BOLD}{Colors.YELLOW}2.{Colors.RESET} {Colors.WHITE}Expert Mode{Colors.RESET}")
        print(f"  {Colors.DIM}     Command-line shell interface — full control, like Metasploit{Colors.RESET}\n")
        print(f"  {Colors.BOLD}{Colors.CYAN}3.{Colors.RESET} {Colors.WHITE}Ixoryn Doctor{Colors.RESET}")
        print(f"  {Colors.DIM}     Health check — verify all modules, dependencies, and compatibility{Colors.RESET}\n")
        print(f"  {Colors.BOLD}{Colors.RED}0.{Colors.RESET} {Colors.WHITE}Exit{Colors.RESET}\n")

    def run(self):
        while True:
            self._print_menu()
            choice = Banner.prompt("Select mode [1/2/3/0]:")

            if choice == "0" or choice.lower() in ("exit", "quit", "q"):
                cprint("\n  [*] Thank you for using Ixoryn. Stay secure.\n", Colors.CYAN)
                sys.exit(0)

            if choice in self.choices:
                label, func = self.choices[choice]
                cprint(f"\n  [*] Launching {label}...", Colors.CYAN)
                try:
                    func()
                except KeyboardInterrupt:
                    cprint("\n\n  [*] Returning to main menu...", Colors.YELLOW)
            else:
                Banner.error("Invalid selection. Please choose 1, 2, 3, or 0.")

    def _launch_beginner(self):
        menu = BeginnerMenu()
        menu.run()

    def _launch_expert(self):
        shell = ExpertShell()
        shell.run()

    def _launch_doctor(self):
        doctor = IxorynDoctor()
        doctor.run()
