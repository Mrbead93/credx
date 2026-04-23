import requests
import socket
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
    "User-Agent"  : "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}

found_creds = []
cred_lock   = threading.Lock()
sem         = threading.Semaphore(5)

def load_wordlist(path):
    try:
        with open(path, "r") as f:
            creds = []
            for line in f:
                line = line.strip()
                if ":" in line:
                    user, password = line.split(":", 1)
                    creds.append((user, password))
            return creds
    except:
        return [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "1234"),
            ("root",  "root"),
            ("guest", "guest")
        ]

def detect_login_form(url):
    try:
        r = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=5,
            verify=False
        )
        html  = r.text.lower()
        forms = []

        if "type=\"password\"" in html or "type='password'" in html:
            import re
            action_match = re.search(
                r'<form[^>]*action=["\']([^"\']*)["\']',
                html
            )
            user_match = re.search(
                r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']text["\']|'
                r'<input[^>]*type=["\']text["\'][^>]*name=["\']([^"\']*)["\']',
                html
            )
            pass_match = re.search(
                r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']password["\']|'
                r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']*)["\']',
                html
            )

            action   = action_match.group(1) if action_match else ""
            user_field = "username"
            pass_field = "password"

            if user_match:
                user_field = next(
                    g for g in user_match.groups() if g
                )
            if pass_match:
                pass_field = next(
                    g for g in pass_match.groups() if g
                )

            forms.append({
                "action"    : action,
                "user_field": user_field,
                "pass_field": pass_field
            })

        return forms, r.status_code

    except Exception as e:
        return [], None

def try_http_login(base_url, form, username, password):
    with sem:
        try:
            action = form["action"]
            if action.startswith("http"):
                url = action
            elif action.startswith("/"):
                from urllib.parse import urlparse
                parsed = urlparse(base_url)
                url = f"{parsed.scheme}://{parsed.netloc}{action}"
            else:
                url = f"{base_url}/{action}" if action else base_url

            data = {
                form["user_field"]: username,
                form["pass_field"]: password
            }

            r = requests.post(
                url,
                data=data,
                headers=HEADERS,
                timeout=5,
                allow_redirects=True,
                verify=False
            )

            failed_indicators = [
                "invalid", "incorrect", "wrong", "failed",
                "error", "denied", "unauthorized", "bad credentials",
                "login failed", "authentication failed"
            ]
            success_indicators = [
                "dashboard", "welcome", "logout", "sign out",
                "profile", "account", "admin panel", "logged in"
            ]

            body_lower = r.text.lower()

            has_failure = any(
                i in body_lower for i in failed_indicators
            )
            has_success = any(
                i in body_lower for i in success_indicators
            )

            if has_success and not has_failure:
                with cred_lock:
                    found_creds.append({
                        "url"     : url,
                        "username": username,
                        "password": password,
                        "status"  : r.status_code
                    })
                    print(
                        f"  {GREEN}[SUCCESS]{RESET}"
                        f" {BOLD}{username}:{password}{RESET}"
                        f" — {url}"
                    )
                return True

            elif r.status_code in [301, 302] and not has_failure:
                location = r.headers.get("Location", "")
                if any(
                    s in location.lower()
                    for s in ["dashboard", "admin", "home", "welcome"]
                ):
                    with cred_lock:
                        found_creds.append({
                            "url"     : url,
                            "username": username,
                            "password": password,
                            "status"  : r.status_code
                        })
                        print(
                            f"  {GREEN}[REDIRECT SUCCESS]{RESET}"
                            f" {BOLD}{username}:{password}{RESET}"
                        )
                    return True

        except:
            pass
        return False

def try_ssh_login(ip, port, username, password):
    with sem:
        try:
            import subprocess
            result = subprocess.run(
                [
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=3",
                    "-o", "BatchMode=yes",
                    f"{username}@{ip}", "-p", str(port),
                    "echo credx_test"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            if b"credx_test" in result.stdout:
                with cred_lock:
                    found_creds.append({
                        "service" : "SSH",
                        "ip"      : ip,
                        "port"    : port,
                        "username": username,
                        "password": password
                    })
                    print(
                        f"  {GREEN}[SSH SUCCESS]{RESET}"
                        f" {BOLD}{username}:{password}{RESET}"
                        f" on {ip}:{port}"
                    )
                return True
        except:
            pass
        return False

def try_ftp_login(ip, port, username, password):
    with sem:
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=3)
            ftp.login(username, password)
            ftp.quit()
            with cred_lock:
                found_creds.append({
                    "service" : "FTP",
                    "ip"      : ip,
                    "port"    : port,
                    "username": username,
                    "password": password
                })
                print(
                    f"  {GREEN}[FTP SUCCESS]{RESET}"
                    f" {BOLD}{username}:{password}{RESET}"
                    f" on {ip}:{port}"
                )
            return True
        except:
            pass
        return False

def check_open_services(target):
    services = []
    check_ports = {
        21  : "FTP",
        22  : "SSH",
        23  : "Telnet",
        80  : "HTTP",
        443 : "HTTPS",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }
    for port, name in check_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            if s.connect_ex((target, port)) == 0:
                services.append((port, name))
                print(f"  {GREEN}[OPEN]{RESET} {port} — {name}")
            s.close()
        except:
            pass
    return services

def run_default_creds(target=None):
    print(f"\n{BOLD}=== Default Credential Tester ==={RESET}\n")
    print(
        f"  {YELLOW}[!] Only use against systems you own"
        f" or have permission to test{RESET}\n"
    )

    if not target:
        target = input("  Target IP or hostname: ").strip()

    wordlist_path = (
        "/data/data/com.termux/files/home/projects/"
        "credx/wordlists/default_creds.txt"
    )
    creds = load_wordlist(wordlist_path)

    print(f"\n{YELLOW}[*] Checking open services on {target}...{RESET}\n")
    services = check_open_services(target)

    if not services:
        print(f"  {RED}[!] No common services found on {target}{RESET}\n")
        return

    print(
        f"\n  Found {GREEN}{len(services)}{RESET} services"
        f" — testing {len(creds)} credential pairs\n"
    )

    for port, service_name in services:
        print(
            f"\n{BOLD}[ Testing {service_name}"
            f" on port {port} ]{RESET}\n"
        )

        if service_name == "FTP":
            threads = []
            for user, password in creds[:20]:
                t = threading.Thread(
                    target=try_ftp_login,
                    args=(target, port, user, password)
                )
                threads.append(t)
                t.start()
            for t in threads:
                t.join()

        elif service_name == "SSH":
            print(
                f"  {DIM}Testing top 10 pairs"
                f" (SSH is slow by design){RESET}"
            )
            for user, password in creds[:10]:
                print(
                    f"  {DIM}Trying {user}:{password}...{RESET}",
                    end="\r"
                )
                if try_ssh_login(target, port, user, password):
                    break

        elif service_name in ["HTTP", "HTTPS", "HTTP-Alt", "HTTPS-Alt"]:
            scheme = "https" if "HTTPS" in service_name else "http"
            url    = f"{scheme}://{target}:{port}"

            print(f"  {YELLOW}[*] Detecting login form at {url}...{RESET}")
            forms, status = detect_login_form(url)

            if forms:
                print(
                    f"  {GREEN}[FOUND]{RESET}"
                    f" Login form detected"
                )
                print(
                    f"  Fields: user={forms[0]['user_field']}"
                    f" pass={forms[0]['pass_field']}\n"
                )
                threads = []
                for user, password in creds:
                    t = threading.Thread(
                        target=try_http_login,
                        args=(url, forms[0], user, password)
                    )
                    threads.append(t)
                    t.start()
                for t in threads:
                    t.join()
            else:
                print(
                    f"  {DIM}No login form detected"
                    f" on {url}{RESET}"
                )

    print(f"\n{BOLD}{'='*50}{RESET}")
    if found_creds:
        print(
            f"  {RED}[!] {len(found_creds)} credential"
            f"{'s' if len(found_creds) > 1 else ''} found{RESET}\n"
        )
        for c in found_creds:
            print(
                f"  {GREEN}[VALID]{RESET}"
                f" {c['username']}:{c['password']}"
                f" — {c.get('url', c.get('ip', 'unknown'))}"
            )
    else:
        print(
            f"  {GREEN}[SECURE]{RESET}"
            f" No default credentials found"
        )
    print(f"{'='*50}\n")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath  = (
        f"/data/data/com.termux/files/home/projects/"
        f"credx/reports/default_creds_"
        f"{target.replace('.','_')}_{timestamp}.txt"
    )
    with open(filepath, "w") as f:
        f.write(f"Default Credential Test Report\n")
        f.write(f"{'='*50}\n")
        f.write(f"Target  : {target}\n")
        f.write(
            f"Date    : "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        f.write(f"{'='*50}\n\n")
        f.write(f"Services Found:\n")
        for port, name in services:
            f.write(f"  {port} — {name}\n")
        f.write(f"\nCredentials Found: {len(found_creds)}\n")
        for c in found_creds:
            f.write(
                f"  {c['username']}:{c['password']}"
                f" — {c.get('url', c.get('ip'))}\n"
            )

    print(
        f"  {GREEN}[SAVED]{RESET}"
        f" default_creds_{target.replace('.','_')}"
        f"_{timestamp}.txt\n"
    )

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    run_default_creds()
