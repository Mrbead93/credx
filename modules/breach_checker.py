import requests
import hashlib
from datetime import datetime

RESET   = "\033[0m"
GREEN   = "\033[32m"
CYAN    = "\033[36m"
RED     = "\033[31m"
YELLOW  = "\033[33m"
MAGENTA = "\033[35m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

HEADERS = {
    "User-Agent": "CredX-PenTest-Tool"
}

def check_password_pwned(password):
    sha1   = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return int(count)
        return 0
    except:
        return -1

def check_email_breaches(email):
    results = []

    print(f"  {YELLOW}[*] Checking breachdirectory.org...{RESET}")
    try:
        r = requests.get(
            f"https://breachdirectory.org/api?func=auto&term={email}",
            headers=HEADERS,
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("success") and data.get("result"):
                for entry in data["result"][:10]:
                    results.append({
                        "Name"       : entry.get("sources", "Unknown"),
                        "BreachDate" : entry.get("last_breach", "Unknown"),
                        "PwnCount"   : 0,
                        "DataClasses": ["Email addresses", "Passwords"],
                        "IsVerified" : True
                    })
    except:
        pass

    print(f"  {YELLOW}[*] Checking leakcheck.io...{RESET}")
    try:
        r = requests.get(
            f"https://leakcheck.io/api/public?check={email}",
            headers=HEADERS,
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("success") and data.get("sources"):
                for source in data["sources"]:
                    results.append({
                        "Name"       : source.get("name", "Unknown"),
                        "BreachDate" : source.get("date", "Unknown"),
                        "PwnCount"   : source.get("entries", 0),
                        "DataClasses": source.get("data", ["Email addresses"]),
                        "IsVerified" : True
                    })
    except:
        pass

    return results

def check_email_pastes(email):
    try:
        r = requests.get(
            f"https://leakcheck.io/api/public?check={email}&type=paste",
            headers=HEADERS,
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("success") and data.get("sources"):
                return data["sources"]
        return []
    except:
        return []

def print_breach_report(email, breaches, pastes):
    print(f"\n{BOLD}{'='*50}{RESET}")
    print(f"  Breach Report — {CYAN}{email}{RESET}")
    print(f"  Checked : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}{RESET}\n")

    if not breaches:
        print(f"  {GREEN}[CLEAN]{RESET} No breaches found for {email}\n")
    else:
        print(
            f"  {RED}[!] Found in {len(breaches)} breach"
            f"{'es' if len(breaches) > 1 else ''}{RESET}\n"
        )
        for breach in sorted(
            breaches,
            key=lambda x: x.get("BreachDate", ""),
            reverse=True
        ):
            name     = breach.get("Name", "Unknown")
            date     = breach.get("BreachDate", "Unknown")
            count    = breach.get("PwnCount", 0)
            classes  = breach.get("DataClasses", [])
            verified = breach.get("IsVerified", False)

            severity_color = (
                RED    if "Passwords" in classes else
                YELLOW if "Email addresses" in classes else
                CYAN
            )

            print(f"  {severity_color}[BREACH]{RESET} {BOLD}{name}{RESET}")
            print(f"  Date     : {date}")
            if count:
                print(f"  Accounts : {count:,}")
            print(f"  Exposed  : {MAGENTA}{', '.join(classes[:5])}{RESET}")
            print(f"  Verified : {'Yes' if verified else 'Unverified'}")
            if "Passwords" in classes:
                print(
                    f"  {RED}[!] Password exposed"
                    f" — change immediately{RESET}"
                )
            print()

    if pastes:
        print(f"  {BOLD}[ Paste Exposure — {len(pastes)} found ]{RESET}\n")
        for paste in pastes[:5]:
            source = paste.get("name", "Unknown")
            date   = paste.get("date", "Unknown")
            print(f"  {YELLOW}[PASTE]{RESET} {source} — {date}")
        print()
    else:
        print(f"  {BOLD}[ Paste Exposure ]{RESET} {GREEN}None found{RESET}\n")

def save_report(email, breaches, pastes):
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_email = email.replace("@", "_").replace(".", "_")
    filepath   = (
        f"/data/data/com.termux/files/home/projects/"
        f"credx/reports/breach_{safe_email}_{timestamp}.txt"
    )
    with open(filepath, "w") as f:
        f.write(f"Breach Check Report\n")
        f.write(f"{'='*50}\n")
        f.write(f"Email  : {email}\n")
        f.write(
            f"Date   : "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        f.write(f"{'='*50}\n\n")
        f.write(f"Breaches Found: {len(breaches)}\n\n")
        for b in breaches:
            f.write(f"[ {b.get('Name')} ]\n")
            f.write(f"  Date    : {b.get('BreachDate')}\n")
            f.write(
                f"  Accounts: {b.get('PwnCount', 0):,}\n"
            )
            f.write(
                f"  Exposed : "
                f"{', '.join(b.get('DataClasses', []))}\n\n"
            )
        f.write(f"Pastes Found: {len(pastes) if pastes else 0}\n")
    print(
        f"  {GREEN}[SAVED]{RESET}"
        f" breach_{safe_email}_{timestamp}.txt\n"
    )

def run_breach_checker(email=None):
    print(f"\n{BOLD}=== Breach Checker ==={RESET}\n")

    if not email:
        email = input("  Email address to check: ").strip()

    print(f"\n{YELLOW}[*] Checking breaches for {email}...{RESET}\n")
    breaches = check_email_breaches(email)

    print(f"\n{YELLOW}[*] Checking paste exposure...{RESET}")
    pastes = check_email_pastes(email)

    print_breach_report(email, breaches, pastes)

    print(f"{BOLD}=== Password Checker ==={RESET}")
    print(f"{DIM}Uses k-anonymity — your password never leaves your phone.")
    print(f"Only the first 5 chars of the SHA1 hash are sent.{RESET}\n")

    check_pass = input("  Check a password? (y/n): ").strip().lower()

    if check_pass == "y":
        password = input("  Enter password: ").strip()
        print(f"\n{YELLOW}[*] Checking...{RESET}\n")
        count = check_password_pwned(password)

        if count == -1:
            print(f"  {RED}[ERROR]{RESET} Could not reach password API")
        elif count == 0:
            print(f"  {GREEN}[SAFE]{RESET} Not found in any known breaches")
        else:
            print(
                f"  {RED}[PWNED]{RESET}"
                f" Found {count:,} times in breach databases"
            )
            print(f"  {RED}[!]{RESET} Do not use this password anywhere")

    if breaches:
        save = input("\n  Save report? (y/n): ").strip().lower()
        if save == "y":
            save_report(email, breaches, pastes)

if __name__ == "__main__":
    run_breach_checker()
