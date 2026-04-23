import sys
import os

sys.path.append(
    "/data/data/com.termux/files/home/projects/credx/modules"
)

RESET   = "\033[0m"
GREEN   = "\033[32m"
CYAN    = "\033[36m"
RED     = "\033[31m"
YELLOW  = "\033[33m"
MAGENTA = "\033[35m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

def banner():
    print(f"""
{BOLD}{CYAN}
  ██████╗██████╗ ███████╗██████╗ ██╗  ██╗
 ██╔════╝██╔══██╗██╔════╝██╔══██╗╚██╗██╔╝
 ██║     ██████╔╝█████╗  ██║  ██║ ╚███╔╝
 ██║     ██╔══██╗██╔══╝  ██║  ██║ ██╔██╗
 ╚██████╗██║  ██║███████╗██████╔╝██╔╝ ██╗
  ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝
{RESET}
  {DIM}Credential Intelligence Toolkit{RESET}
  {DIM}github.com/Mrbead93/credx{RESET}
""")

def menu():
    print(f"{BOLD}{'='*45}{RESET}")
    print(f"  {CYAN}[1]{RESET}  Breach Checker")
    print(f"  {CYAN}[2]{RESET}  Default Credential Tester")
    print(f"  {CYAN}[3]{RESET}  Password Policy Analyser")
    print(f"  {CYAN}[4]{RESET}  Credential Exposure Scanner")
    print(f"  {CYAN}[5]{RESET}  Full Credential Report")
    print(f"  {CYAN}[0]{RESET}  Exit")
    print(f"{'='*45}{RESET}\n")

def main():
    banner()
    while True:
        menu()
        choice = input("  Select option: ").strip()

        if choice == "0":
            print(f"\n  {CYAN}Goodbye.{RESET}\n")
            break

        elif choice == "1":
            try:
                from breach_checker import run_breach_checker
                email = input("\n  Email to check: ").strip()
                run_breach_checker(email)
            except ImportError:
                print(f"\n  {RED}Module not built yet{RESET}\n")

        elif choice == "2":
            try:
                from default_creds import run_default_creds
                target = input("\n  Target IP or hostname: ").strip()
                run_default_creds(target)
            except ImportError:
                print(f"\n  {RED}Module not built yet{RESET}\n")

        elif choice == "3":
            try:
                from policy_analyser import run_policy_analyser
                target = input("\n  Target login URL: ").strip()
                run_policy_analyser(target)
            except ImportError:
                print(f"\n  {RED}Module not built yet{RESET}\n")

        elif choice == "4":
            try:
                from exposure_scanner import run_exposure_scanner
                domain = input("\n  Target domain: ").strip()
                run_exposure_scanner(domain)
            except ImportError:
                print(f"\n  {RED}Module not built yet{RESET}\n")

        elif choice == "5":
            try:
                from breach_checker import run_breach_checker
                from exposure_scanner import run_exposure_scanner
                print(f"\n  {BOLD}Full Credential Report{RESET}")
                target = input("\n  Target domain: ").strip()
                email  = input("  Primary email to check: ").strip()
                print(f"\n{YELLOW}[*] Running breach check...{RESET}")
                run_breach_checker(email)
                print(f"\n{YELLOW}[*] Running exposure scan...{RESET}")
                run_exposure_scanner(target)
            except ImportError:
                print(f"\n  {RED}Module not built yet{RESET}\n")

        else:
            print(f"\n  {RED}Invalid option{RESET}\n")

        input(f"\n  {DIM}Press Enter to return to menu...{RESET}")

if __name__ == "__main__":
    main()
