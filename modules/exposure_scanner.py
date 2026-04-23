import requests
import re
import threading
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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

findings = []
find_lock = threading.Lock()

def search_github(domain):
    print(f"  {YELLOW}[*] Searching GitHub...{RESET}")
    results = []
    queries = [
        f"{domain} password",
        f"{domain} secret",
        f"{domain} api_key",
        f"{domain} credentials",
        f"{domain} smtp password",
        f"{domain} db_password",
    ]

    for query in queries:
        try:
            r = requests.get(
                f"https://api.github.com/search/code"
                f"?q={requests.utils.quote(query)}&per_page=5",
                headers={
                    **HEADERS,
                    "Accept": "application/vnd.github.v3+json"
                },
                timeout=8
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items:
                    result = {
                        "source" : "GitHub",
                        "query"  : query,
                        "file"   : item.get("name", ""),
                        "url"    : item.get("html_url", ""),
                        "repo"   : item.get(
                            "repository", {}
                        ).get("full_name", ""),
                        "severity": "HIGH"
                    }
                    results.append(result)
                    with find_lock:
                        findings.append(result)
                    print(
                        f"  {RED}[EXPOSED]{RESET}"
                        f" {item.get('name','')} in"
                        f" {item.get('repository',{}).get('full_name','')}"
                    )
                    print(
                        f"  {DIM}{item.get('html_url','')}{RESET}"
                    )
            elif r.status_code == 403:
                print(
                    f"  {DIM}GitHub rate limit hit"
                    f" — some results skipped{RESET}"
                )
                break
        except:
            pass

    if not results:
        print(
            f"  {GREEN}[CLEAN]{RESET}"
            f" No exposed credentials found on GitHub"
        )
    return results

def search_pastebin(domain):
    print(f"\n  {YELLOW}[*] Searching Pastebin...{RESET}")
    results = []

    try:
        r = requests.get(
            f"https://psbdmp.ws/api/search/{domain}",
            headers=HEADERS,
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            pastes = data.get("data", [])
            for paste in pastes[:5]:
                result = {
                    "source"  : "Pastebin",
                    "id"      : paste.get("id", ""),
                    "url"     : f"https://pastebin.com/{paste.get('id','')}",
                    "severity": "HIGH"
                }
                results.append(result)
                with find_lock:
                    findings.append(result)
                print(
                    f"  {RED}[PASTE]{RESET}"
                    f" https://pastebin.com/{paste.get('id','')}"
                )
        else:
            print(
                f"  {GREEN}[CLEAN]{RESET}"
                f" No pastes found for {domain}"
            )
    except:
        print(
            f"  {DIM}Could not reach Pastebin API{RESET}"
        )

    return results

def search_cert_emails(domain):
    print(f"\n  {YELLOW}[*] Harvesting emails via crt.sh...{RESET}")
    emails = set()

    try:
        r = requests.get(
            f"https://crt.sh/?q={domain}&output=json",
            headers=HEADERS,
            timeout=10
        )
        if r.status_code == 200:
            certs = r.json()
            email_pattern = re.compile(
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            )
            for cert in certs[:50]:
                name = cert.get("name_value", "")
                found = email_pattern.findall(name)
                for email in found:
                    if domain in email:
                        emails.add(email)

            if emails:
                print(
                    f"  {RED}[FOUND]{RESET}"
                    f" {len(emails)} emails in cert logs:"
                )
                for email in emails:
                    print(f"  {CYAN}  {email}{RESET}")
            else:
                print(
                    f"  {GREEN}[CLEAN]{RESET}"
                    f" No emails in certificate logs"
                )
    except:
        pass

    return list(emails)

def search_google_dorks(domain):
    print(f"\n  {YELLOW}[*] Generating Google dorks...{RESET}")
    dorks = [
        f'site:{domain} filetype:env',
        f'site:{domain} filetype:sql',
        f'site:{domain} filetype:log password',
        f'site:{domain} inurl:config',
        f'site:{domain} inurl:backup',
        f'"@{domain}" password',
        f'site:{domain} "api_key"',
        f'site:{domain} "secret_key"',
    ]

    print(
        f"\n  {BOLD}[ Manual Google Dorks for {domain} ]{RESET}"
    )
    print(
        f"  {DIM}Copy these into Google to find"
        f" exposed credentials:{RESET}\n"
    )
    for dork in dorks:
        print(f"  {CYAN}{dork}{RESET}")

    return dorks

def check_exposed_files(domain):
    print(f"\n  {YELLOW}[*] Checking for exposed files...{RESET}\n")
    sensitive_paths = [
        ".env",
        ".git/config",
        "config.php",
        "wp-config.php",
        "config.yml",
        "config.yaml",
        "database.yml",
        "settings.py",
        "web.config",
        "credentials.xml",
        "id_rsa",
        ".htpasswd",
        "backup.sql",
        "dump.sql",
        "passwords.txt",
        "users.csv"
    ]

    exposed = []
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        for path in sensitive_paths:
            try:
                r = requests.get(
                    f"{url}/{path}",
                    headers=HEADERS,
                    timeout=3,
                    verify=False
                )
                if r.status_code == 200 and len(r.content) > 0:
                    result = {
                        "source"  : "Direct",
                        "url"     : f"{url}/{path}",
                        "size"    : len(r.content),
                        "severity": "CRITICAL"
                    }
                    exposed.append(result)
                    with find_lock:
                        findings.append(result)
                    print(
                        f"  {RED}[CRITICAL]{RESET}"
                        f" Exposed: {url}/{path}"
                        f" ({len(r.content)}b)"
                    )
            except:
                pass

    if not exposed:
        print(
            f"  {GREEN}[CLEAN]{RESET}"
            f" No sensitive files exposed"
        )
    return exposed

def run_exposure_scanner(domain=None):
    print(f"\n{BOLD}=== Credential Exposure Scanner ==={RESET}\n")

    if not domain:
        domain = input("  Target domain: ").strip()
        domain = domain.replace(
            "http://", ""
        ).replace("https://", "").rstrip("/")

    print(
        f"\n{YELLOW}[*] Scanning for credential"
        f" exposure — {domain}...{RESET}\n"
    )

    github_results  = search_github(domain)
    paste_results   = search_pastebin(domain)
    emails          = search_cert_emails(domain)
    dorks           = search_google_dorks(domain)
    exposed_files   = check_exposed_files(domain)

    print(f"\n{BOLD}{'='*50}{RESET}")
    print(f"  Exposure Summary — {CYAN}{domain}{RESET}\n")

    critical = [
        f for f in findings
        if f.get("severity") == "CRITICAL"
    ]
    high = [
        f for f in findings
        if f.get("severity") == "HIGH"
    ]

    print(
        f"  GitHub findings  : "
        f"{RED if github_results else GREEN}"
        f"{len(github_results)}{RESET}"
    )
    print(
        f"  Pastebin hits    : "
        f"{RED if paste_results else GREEN}"
        f"{len(paste_results)}{RESET}"
    )
    print(
        f"  Emails harvested : "
        f"{YELLOW if emails else GREEN}"
        f"{len(emails)}{RESET}"
    )
    print(
        f"  Exposed files    : "
        f"{RED if exposed_files else GREEN}"
        f"{len(exposed_files)}{RESET}"
    )
    print(
        f"  Critical findings: "
        f"{RED if critical else GREEN}"
        f"{len(critical)}{RESET}"
    )
    print(f"\n{'='*50}\n")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_")
    filepath  = (
        f"/data/data/com.termux/files/home/projects/"
        f"credx/reports/exposure_{safe_domain}_{timestamp}.txt"
    )

    with open(filepath, "w") as f:
        f.write(f"Credential Exposure Report\n")
        f.write(f"{'='*50}\n")
        f.write(f"Domain  : {domain}\n")
        f.write(
            f"Date    : "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        f.write(f"{'='*50}\n\n")

        f.write(f"[ GitHub Results — {len(github_results)} ]\n")
        for r in github_results:
            f.write(f"  {r['file']} in {r['repo']}\n")
            f.write(f"  {r['url']}\n\n")

        f.write(f"\n[ Pastebin Results — {len(paste_results)} ]\n")
        for r in paste_results:
            f.write(f"  {r['url']}\n")

        f.write(f"\n[ Emails Found — {len(emails)} ]\n")
        for email in emails:
            f.write(f"  {email}\n")

        f.write(f"\n[ Exposed Files — {len(exposed_files)} ]\n")
        for r in exposed_files:
            f.write(f"  {r['url']} ({r['size']}b)\n")

        f.write(f"\n[ Google Dorks ]\n")
        for dork in dorks:
            f.write(f"  {dork}\n")

    print(
        f"  {GREEN}[SAVED]{RESET}"
        f" exposure_{safe_domain}_{timestamp}.txt\n"
    )

    return findings

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    run_exposure_scanner()
