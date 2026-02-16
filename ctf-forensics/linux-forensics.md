# CTF Forensics - Linux and Application Forensics

## Table of Contents
- [Log Analysis](#log-analysis)
- [Linux Attack Chain Forensics](#linux-attack-chain-forensics)
- [Docker Image Forensics (Pragyan 2026)](#docker-image-forensics-pragyan-2026)
- [Browser Credential Decryption](#browser-credential-decryption)
- [Firefox Browser History (places.sqlite)](#firefox-browser-history-placessqlite)
- [USB Audio Extraction from PCAP](#usb-audio-extraction-from-pcap)
- [TFTP Netascii Decoding](#tftp-netascii-decoding)
- [TLS Traffic Decryption via Weak RSA](#tls-traffic-decryption-via-weak-rsa)
- [ROT18 Decoding](#rot18-decoding)
- [Common Encodings](#common-encodings)
- [Git Directory Recovery (UTCTF 2024)](#git-directory-recovery-utctf-2024)

---

## Log Analysis

```bash
# Search for flag fragments
grep -iE "(flag|part|piece|fragment)" server.log

# Reconstruct fragmented flags
grep "FLAGPART" server.log | sed 's/.*FLAGPART: //' | uniq | tr -d '\n'

# Find anomalies
sort logfile.log | uniq -c | sort -rn | head
```

---

## Linux Attack Chain Forensics

**Pattern (Making the Naughty List):** Full attack timeline from logs + PCAP + malware.

**Evidence sources:**
```bash
# SSH session commands
grep -A2 "session opened" /var/log/auth.log

# User command history
cat /home/*/.bash_history

# Downloaded malware
find /usr/bin -newer /var/log/auth.log -name "ms*"

# Network exfiltration
tshark -r capture.pcap -Y "tftp" -T fields -e tftp.source_file
```

**Common malware pattern:** AES-ECB encrypt + XOR with same key, save as .enc

---

## Docker Image Forensics (Pragyan 2026)

**Pattern (Plumbing):** Sensitive data leaked during Docker build but cleaned in later layers.

**Key insight:** Docker image config JSON (`blobs/sha256/<config_hash>`) permanently preserves ALL `RUN` commands in the `history` array, regardless of subsequent cleanup.

```bash
tar xf app.tar
# Find config blob (not layer blobs)
python3 -m json.tool blobs/sha256/<config_hash> | grep -A2 "created_by"
# Look for RUN commands with flag data, passwords, secrets
```

**Analysis steps:**
1. Extract the Docker image tar: `tar xf app.tar`
2. Read `manifest.json` to find the config blob hash
3. Parse the config blob JSON for `history[].created_by` entries
4. Each entry shows the exact Dockerfile command that was run
5. Secrets echoed, written, or processed in any `RUN` command are preserved in the history
6. Even if a later layer `rm -f secret.txt`, the `RUN echo "flag{...}" > secret.txt` remains visible

---

## Browser Credential Decryption

**Chrome/Edge Login Data decryption (requires master_key.txt):**
```python
from Crypto.Cipher import AES
import sqlite3, json, base64

# Load master key (from Local State file, DPAPI-protected)
with open('master_key.txt', 'rb') as f:
    master_key = f.read()

conn = sqlite3.connect('Login Data')
cursor = conn.cursor()
cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
for url, user, encrypted_pw in cursor.fetchall():
    # v10/v11 prefix = AES-GCM encrypted
    nonce = encrypted_pw[3:15]
    ciphertext = encrypted_pw[15:-16]
    tag = encrypted_pw[-16:]
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    password = cipher.decrypt_and_verify(ciphertext, tag)
    print(f"{url}: {user}:{password.decode()}")
```

**Master key extraction from Local State:**
```python
import json, base64
with open('Local State', 'r') as f:
    local_state = json.load(f)
encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
# Remove DPAPI prefix (5 bytes "DPAPI")
encrypted_key = encrypted_key[5:]
# On Windows: CryptUnprotectData to get master_key
# In CTF: master_key may be provided separately
```

---

## Firefox Browser History (places.sqlite)

**Pattern (Browser Wowser):** Flag hidden in browser history URLs.

```bash
# Quick method
strings places.sqlite | grep -i "flag\|MetaCTF"

# Proper forensic method
sqlite3 places.sqlite "SELECT url FROM moz_places WHERE url LIKE '%flag%'"
```

**Key tables:** `moz_places` (URLs), `moz_bookmarks`, `moz_cookies`

---

## USB Audio Extraction from PCAP

**Pattern (Talk To Me):** USB isochronous transfers contain audio data.

**Extraction workflow:**
```bash
# Export ISO data with tshark
tshark -r capture.pcap -T fields -e usb.iso.data > audio_data.txt

# Convert to raw audio and import into Audacity
# Settings: signed 16-bit PCM, mono, appropriate sample rate
# Listen for spoken flag characters
```

**Identification:** USB transfer type URB_ISOCHRONOUS = real-time audio/video

---

## TFTP Netascii Decoding

**Problem:** TFTP netascii mode corrupts binary transfers; Wireshark doesn't auto-decode.

**Fix exported files:**
```python
# Replace netascii sequences:
# 0d 0a → 0a (CRLF → LF)
# 0d 00 → 0d (escaped CR)
with open('file_raw', 'rb') as f:
    data = f.read()
data = data.replace(b'\r\n', b'\n').replace(b'\r\x00', b'\r')
with open('file_fixed', 'wb') as f:
    f.write(data)
```

---

## TLS Traffic Decryption via Weak RSA

**Pattern (Tampered Seal):** TLS 1.2 with `TLS_RSA_WITH_AES_256_CBC_SHA` (no PFS).

**Attack flow:**
1. Extract server certificate from Server Hello packet (Export Packet Bytes -> `public.der`)
2. Get modulus: `openssl x509 -in public.der -inform DER -noout -modulus`
3. Factor weak modulus (dCode, factordb.com, yafu)
4. Generate private key: `rsatool -p P -q Q -o private.pem`
5. Add to Wireshark: Edit -> Preferences -> TLS -> RSA keys list

**After decryption:**
- Follow TLS streams to see HTTP traffic
- Export objects (File -> Export Objects -> HTTP)
- Look for downloaded executables, API calls

---

## ROT18 Decoding

ROT13 on letters + ROT5 on digits. Common final layer in multi-stage forensics:
```python
def rot18(text):
    result = []
    for c in text:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            result.append(chr((ord(c) - base + 13) % 26 + base))
        elif c.isdigit():
            result.append(str((int(c) + 5) % 10))
        else:
            result.append(c)
    return ''.join(result)
```

---

## Common Encodings

```bash
echo "base64string" | base64 -d
echo "hexstring" | xxd -r -p
# ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

---

## Git Directory Recovery (UTCTF 2024)

```bash
# Exposed .git directory on web server
gitdumper.sh https://target/.git/ /tmp/repo

# Check reflog for old commits with secrets
cat .git/logs/HEAD
# Download objects from .git/objects/XX/YYYY, decompress with zlib
```

**Tool:** `gitdumper.sh` from internetwache/GitTools is most reliable.
