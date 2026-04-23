import requests
import time
import re
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

def detect_login_url(base_url):
    common_paths = [
        "", "login", "signin", "admin", "wp-login.php",
        "user/login", "account/login", "auth/login",
        "administrator", "panel", "dashboard"
    ]
    for path in common_paths:
        url = f"{base_url}/{path}" if path else base_url
        try:
            r = requests.get(
                url,
                headers=HEADERS,
                timeout=5,
                verify=False
            )
            if "password" in r.text.lower():
                return url, r
        except:
            pass
    return base_url, None

def extract_form_details(html, base_url):
    details = {
        "user_field": "username",
        "pass_field": "password",
        "action"    : base_url,
        "method"    : "POST"
    }

    action = re.search(
        r'<form[^>]*action=["\']([^"\']*)["\']',
        html, re.IGNORECASE
    )
    method = re.search(
        r'<form[^>]*method=["\']([^"\']*)["\']',
        html, re.IGNORECASE
    )
    user = re.search(
        r'<input[^>]*(?:name=["\']([^"\']*)["\'][^>]*type=["\']text["\']|'
        r'type=["\']text["\'][^>]*name=["\']([^"\']*)["\'])',
        html, re.IGNORECASE
    )
    passwd = re.search(
        r'<input[^>]*(?:name=["\']([^"\']*)["\'][^>]*type=["\']password["\']|'
        r'type=["\']password["\'][^>]*name=["\']([^"\']*)["\'])',
        html, re.IGNORECASE
    )

    if action:
        details["action"] = action.group(1)
    if method:
        details["method"] = method.group(1).upper()
    if user:
        details["user_field"] = next(
            g for g in user.groups() if g
        )
    if passwd:
        details["pass_field"] = next(
            g for g in passwd.groups() if g
        )

    return details

def test_lockout_policy(login_url, form, attempts=6):
    print(f"\n  {BOLD}[ Account Lockout Test ]{RESET}\n")
    print(
        f"  {YELLOW}[*] Sending {attempts} failed"
        f" login attempts...{RESET}\n"
    )

    responses   = []
    locked_out  = False
    lockout_at  = None

    for i in range(1, attempts + 1):
        try:
            data = {
                form["user_field"]: "admin",
                form["pass_field"]: f"wrongpassword{i}"
            }

            action = form["action"]
            if not action.startswith("http"):
                from urllib.parse import urlparse
                parsed = urlparse(login_url)
                action = (
                    f"{parsed.scheme}://{parsed.netloc}"
                    f"{action}"
                    if action.startswith("/")
                    else login_url
                )

            r = requests.post(
                action,
                data=data,
                headers=HEADERS,
                timeout=5,
                allow_redirects=True,
                verify=False
            )

            body_lower = r.text.lower()
            locked = any(w in body_lower for w in [
                "locked", "too many", "blocked",
                "temporarily", "suspended", "captcha",
                "verify", "unusual activity"
            ])

            responses.append({
                "attempt": i,
                "status" : r.status_code,
                "size"   : len(r.content),
                "locked" : locked
            })

            status_color = GREEN if not locked else RED
            print(
                f"  Attempt {i}: "
                f"status={r.status_code} "
                f"size={len(r.content)}b "
                f"{status_color}{'[LOCKED]' if locked else ''}{RESET}"
            )

            if locked and not locked_out:
                locked_out = True
                lockout_at = i
                print(
                    f"\n  {GREEN}[✓]{RESET}"
                    f" Account lockout triggered"
                    f" after {i} attempts\n"
                )
                break

            time.sleep(0.5)

        except Exception as e:
            print(f"  Attempt {i}: {RED}error — {e}{RESET}")

    return locked_out, lockout_at, responses

def test_rate_limiting(login_url, form):
    print(f"\n  {BOLD}[ Rate Limiting Test ]{RESET}\n")
    print(
        f"  {YELLOW}[*] Sending rapid requests...{RESET}\n"
    )

    times     = []
    rate_limited = False

    for i in range(5):
        try:
            start = time.time()
            data  = {
                form["user_field"]: "test",
                form["pass_field"]: "test"
            }

            action = form["action"]
            if not action.startswith("http"):
                from urllib.parse import urlparse
                parsed = urlparse(login_url)
                action = (
                    f"{parsed.scheme}://{parsed.netloc}{action}"
                    if action.startswith("/")
                    else login_url
                )

            r = requests.post(
                action,
                data=data,
                headers=HEADERS,
                timeout=5,
                verify=False
            )
            elapsed = time.time() - start
            times.append(elapsed)

            if r.status_code == 429:
                rate_limited = True
                print(
                    f"  {GREEN}[✓]{RESET}"
                    f" Rate limiting detected (429)"
                )
                break

            print(
                f"  Request {i+1}: "
                f"{elapsed:.3f}s "
                f"status={r.status_code}"
            )

        except:
            pass

    if not rate_limited:
        avg = sum(times) / len(times) if times else 0
        print(
            f"\n  {YELLOW}[!]{RESET}"
            f" No rate limiting detected"
            f" (avg {avg:.3f}s per request)"
        )

    return rate_limited

def check_https(url):
    return url.startswith("https")

def check_password_field_security(html):
    findings = []

    if 'autocomplete="off"' not in html.lower():
        findings.append({
            "issue"   : "Password autocomplete not disabled",
            "severity": "LOW",
            "detail"  : "Add autocomplete=off to password field"
        })

    if 'type="password"' in html.lower():
        if 'minlength' not in html.lower():
            findings.append({
                "issue"   : "No minimum password length enforced",
                "severity": "MEDIUM",
                "detail"  : "Add minlength attribute to password field"
            })

    if 'csrf' not in html.lower() and 'token' not in html.lower():
        findings.append({
            "issue"   : "No CSRF token detected in form",
            "severity": "HIGH",
            "detail"  : "Login form may be vulnerable to CSRF"
        })

    return findings

def run_policy_analyser(target_url=None):
    print(f"\n{BOLD}=== Password Policy Analyser ==={RESET}\n")
    print(
        f"  {YELLOW}[!] Only use against systems"
        f" you own or have permission to test{RESET}\n"
    )

    if not target_url:
        target_url = input(
            "  Target login URL"
            " (e.g. http://192.168.1.254): "
        ).strip()

    if not target_url.startswith("http"):
        target_url = f"http://{target_url}"

    print(
        f"\n{YELLOW}[*] Locating login form"
        f" on {target_url}...{RESET}\n"
    )

    login_url, response = detect_login_url(target_url)

    if not response:
        print(
            f"  {RED}[ERROR]{RESET}"
            f" Could not reach target\n"
        )
        return

    print(f"  {GREEN}[FOUND]{RESET} Login page: {login_url}\n")

    html = response.text
    form = extract_form_details(html, login_url)

    print(f"  {BOLD}[ Form Details ]{RESET}")
    print(f"  Action     : {form['action']}")
    print(f"  Method     : {form['method']}")
    print(f"  User field : {form['user_field']}")
    print(f"  Pass field : {form['pass_field']}\n")

    findings = []

    print(f"  {BOLD}[ HTTPS Check ]{RESET}")
    if check_https(login_url):
        print(f"  {GREEN}[✓]{RESET} Login served over HTTPS")
    else:
        print(
            f"  {RED}[✗]{RESET}"
            f" Login served over HTTP — credentials sent in plaintext"
        )
        findings.append({
            "issue"   : "Login form not using HTTPS",
            "severity": "CRITICAL",
            "detail"  : "Credentials transmitted in plaintext"
        })

    print(f"\n  {BOLD}[ Form Security ]{RESET}")
    field_findings = check_password_field_security(html)
    for f in field_findings:
        color = (
            RED    if f["severity"] == "CRITICAL" else
            RED    if f["severity"] == "HIGH"     else
            YELLOW if f["severity"] == "MEDIUM"   else
            CYAN
        )
        print(
            f"  {color}[{f['severity']}]{RESET}"
            f" {f['issue']}"
        )
        findings.append(f)

    locked_out, lockout_at, responses = test_lockout_policy(
        login_url, form
    )
    if not locked_out:
        print(
            f"\n  {RED}[✗]{RESET}"
            f" No account lockout detected after"
            f" {len(responses)} attempts"
        )
        findings.append({
            "issue"   : "No account lockout policy",
            "severity": "HIGH",
            "detail"  : "Brute force attacks not mitigated"
        })
    else:
        print(
            f"  {GREEN}[✓]{RESET}"
            f" Lockout after {lockout_at} attempts"
        )

    rate_limited = test_rate_limiting(login_url, form)
    if not rate_limited:
        findings.append({
            "issue"   : "No rate limiting detected",
            "severity": "MEDIUM",
            "detail"  : "Login endpoint accepts rapid requests"
        })

    print(f"\n{BOLD}{'='*50}{RESET}")
    print(f"  Policy Analysis Summary\n")

    if findings:
        for f in sorted(
            findings,
            key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(
                x["severity"]
            )
        ):
            color = (
                RED    if f["severity"] in ["CRITICAL","HIGH"] else
                YELLOW if f["severity"] == "MEDIUM" else
                CYAN
            )
            print(
                f"  {color}[{f['severity']}]{RESET}"
                f" {f['issue']}"
            )
            print(f"  {DIM}{f['detail']}{RESET}\n")
    else:
        print(f"  {GREEN}No policy issues found{RESET}")

    print(f"{'='*50}\n")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url  = target_url.replace(
        "://","_"
    ).replace("/","_").replace(":","_")
    filepath  = (
        f"/data/data/com.termux/files/home/projects/"
        f"credx/reports/policy_{safe_url}_{timestamp}.txt"
    )
    with open(filepath, "w") as f:
        f.write(f"Password Policy Analysis Report\n")
        f.write(f"{'='*50}\n")
        f.write(f"Target  : {target_url}\n")
        f.write(
            f"Date    : "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        f.write(f"{'='*50}\n\n")
        f.write(f"Findings: {len(findings)}\n\n")
        for finding in findings:
            f.write(
                f"[{finding['severity']}]"
                f" {finding['issue']}\n"
            )
            f.write(f"  {finding['detail']}\n\n")

    print(
        f"  {GREEN}[SAVED]{RESET}"
        f" policy_{safe_url}_{timestamp}.txt\n"
    )

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    run_policy_analyser()
