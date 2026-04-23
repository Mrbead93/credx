# CredX — Credential Intelligence Toolkit

A credential intelligence and exposure toolkit built in
Python on Termux (Android). Companion tool to ReconX.

## Modules

| Option | Module                      | Description                           |
|--------|-----------------------------|---------------------------------------|
| 1      | Breach Checker              | Email breach and password pwned check |
| 2      | Default Credential Tester   | Tests default creds on open services  |
| 3      | Password Policy Analyser    | Lockout, rate limiting, CSRF, HTTPS   |
| 4      | Credential Exposure Scanner | GitHub, Pastebin, Google dorks, files |
| 5      | Full Credential Report      | Breach check and exposure in one run  |

## Launch

python3 ~/projects/credx/credx.py

## Legal

Only use against systems you own or have explicit
written permission to test.

## Built With

- Python 3.13 on Termux (Android)
- APIs: HaveIBeenPwned, LeakCheck, breachdirectory,
  GitHub, crt.sh, psbdmp
- Device: Samsung Z Fold 7 (unrooted)

## Author

Mrbead93 — github.com/Mrbead93/credx
