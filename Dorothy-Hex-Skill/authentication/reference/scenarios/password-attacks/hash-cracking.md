# Password Attacks — Hash Cracking

## When this applies

- You have access to password hashes (from credential dumping, SQLi, leaked DB).
- Goal: recover plaintext passwords for online use, lateral movement, or password-reuse testing.

## Technique

Run hash through Hashcat / John with appropriate mode and wordlist. GPU acceleration is essential for non-trivial hashes (NTLM, MD5, SHA1 fast; bcrypt, scrypt, Argon2 slow).

## Steps

### 1. Identify hash type

```bash
hashid hash.txt
hash-identifier
hashcat --example | grep <fragment>
```

Common formats:

| Mode | Format | Example |
|---|---|---|
| 0 | MD5 | `5f4dcc3b...` (32 hex) |
| 100 | SHA-1 | 40 hex |
| 1000 | NTLM | 32 hex (Windows) |
| 1400 | SHA-256 | 64 hex |
| 1700 | SHA-512 | 128 hex |
| 1800 | sha512crypt (Linux) | `$6$...` |
| 3000 | LM | 32 hex (legacy) |
| 3200 | bcrypt | `$2a$`/`$2b$`/`$2y$...` |
| 5600 | NetNTLMv2 | `user::dom:chal:resp:blob` |
| 13100 | Kerberos TGS-REP (kerberoast) | `$krb5tgs$23$...` |
| 13400 | KeePass KDBX | binary file |
| 13600 | WinZIP | binary file |
| 16500 | JWT (HS256) | `eyJ...` |
| 16900 | Ansible Vault | `$ANSIBLE_VAULT;1.1;AES256` |
| 17200 | PKZIP (compressed) | binary file |
| 18200 | Kerberos AS-REP (asrep-roast) | `$krb5asrep$23$...` |
| 10900 | PBKDF2-HMAC-SHA256 (Grafana etc.) | `sha256:<iter>:<salt_b64>:<hash_b64>` |
| 24410 | PKCS#12 PBES2 (PFX) | binary file |

**PBKDF2-HMAC-SHA256 (10900) format gotcha.** When extracting from app DBs (Grafana `user.password/salt`, Django `pbkdf2_sha256$...`, Flask-Security), the **salt is usually stored ASCII** and the **password as hex** (or its own base64). Hashcat 10900 wants both as **base64 of the raw bytes** — not base64 of the hex string, not the literal stored salt. Convert before submitting:

```python
import base64
salt_ascii = "abc...10byte"           # raw ASCII salt as stored
hash_hex   = "8a3f...64byte"          # raw hash stored as hex
salt_b64 = base64.b64encode(salt_ascii.encode()).decode()
hash_b64 = base64.b64encode(bytes.fromhex(hash_hex)).decode()
print(f"sha256:10000:{salt_b64}:{hash_b64}")
```

Iteration count varies by framework — read the source / DB schema, or try common defaults (Grafana 10000, Django < 4.0 = 260000+, Werkzeug = 260000).

### 2. Hashcat — dictionary attacks

```bash
# Basic dictionary
hashcat -m 1000 -a 0 hashes.txt rockyou.txt

# Dictionary + rules
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r rules/best64.rule
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r rules/d3ad0ne.rule

# Combinator
hashcat -m 1000 -a 1 hashes.txt words1.txt words2.txt

# Hybrid (wordlist + mask suffix)
hashcat -m 1000 -a 6 hashes.txt rockyou.txt ?d?d?d?d
```

### 3. Hashcat — mask attacks

```bash
# 8-char alphanumeric brute force
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# Pattern: 1 upper + 3 lower + 4 digits
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?d?d?d?d

# Custom charsets
hashcat -m 1000 -a 3 -1 ?l?u hashes.txt ?1?1?1?1?1?1
```

### 4. Hashcat — GPU/session/show

```bash
# GPU optimization
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -O -w 3

# Session management
hashcat -m 1000 hashes.txt rockyou.txt --session jwt_crack
hashcat --session jwt_crack --restore

# Show cracked
hashcat -m 1000 hashes.txt --show
```

### 5. John the Ripper

```bash
# Auto-detect format
john hashes.txt

# Specify format
john --format=NT hashes.txt

# Dictionary with rules
john --wordlist=rockyou.txt --rules hashes.txt

# Incremental (brute force)
john --incremental hashes.txt

# Show cracked
john --show hashes.txt

# Resume
john --restore
```

### 6. Run both in parallel for short jobs

For short jobs (AS-REP, Kerberoast, ZIP, PFX), john (CPU) often finishes faster because hashcat pays a per-run kernel-compile cost. For long jobs (large dictionaries), hashcat wins. Run both:

```bash
john --wordlist=rockyou.txt foo.hash &
hashcat -m <mode> foo.hash rockyou.txt &
wait
```

### 7. Cracking strategies

1. **Quick wins** — small wordlist (1k-most-common) first.
2. **Smart wordlists** — context-aware (CeWL on target site).
3. **Rules** — best64, d3ad0ne, KoreLogic, dive.
4. **Masks** — when you know the policy (e.g. 8 chars min, 1 upper, 1 digit, 1 special).
5. **Hybrid** — wordlist + mask suffix.
6. **GPU** — RTX 4090 hits ~1.5 TH/s on MD5; required for bcrypt at scale.

## Verifying success

- Hashcat / John outputs `<hash>:<password>`.
- The password authenticates against the source system.
- Reuse test: same password works on related accounts (lateral movement).

## Common pitfalls

- Hash type misidentified — bcrypt looks like sha512crypt to inexperienced eyes; both are slow on CPU.
- Salted hashes need both hash AND salt — `hashcat -m 1410 'hash:salt' wordlist`.
- Pure brute force on bcrypt is impractical; rely on dictionaries + rules.
- Some hashes encode the work factor / cost (`$2a$10$...`); higher = slower to crack.
- NetNTLMv2 captures must include the full session info (`user::dom:chal:resp:blob`).

## Tools

- Hashcat (GPU-accelerated; modes table above).
- John the Ripper (CPU; broader format support).
- hashid / hash-identifier (format detection).
- Wordlists: rockyou.txt, SecLists, CrackStation, HIBP top-leaked.
- Rules: best64, d3ad0ne, dive, KoreLogic, OneRuleToRuleThemAll.

## References

- MITRE ATT&CK T1110.002 (Password Cracking).
- CWE-916 (Use of Password Hash With Insufficient Computational Effort).
- Hashcat: https://hashcat.net/hashcat/
- John: https://www.openwall.com/john/
