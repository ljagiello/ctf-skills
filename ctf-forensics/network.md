# CTF Forensics - Network

## Table of Contents
- [tcpdump Quick Reference](#tcpdump-quick-reference)
- [TLS/SSL Decryption via Keylog File](#tlsssl-decryption-via-keylog-file)
- [Wireshark Basics](#wireshark-basics)
- [Port Scan Analysis](#port-scan-analysis)
- [Gateway/Device via MAC OUI](#gatewaydevice-via-mac-oui)
- [WordPress Reconnaissance](#wordpress-reconnaissance)
- [Post-Exploitation Traffic](#post-exploitation-traffic)
- [Credential Extraction](#credential-extraction)
- [SMB3 Encrypted Traffic](#smb3-encrypted-traffic)
- [5G/NR Protocol Analysis](#5gnr-protocol-analysis)
- [Email Headers](#email-headers)
- [USB HID Stenography/Chord PCAP (UTCTF 2024)](#usb-hid-stenographychord-pcap-utctf-2024)
- [BCD Encoding in UDP (VuwCTF 2025)](#bcd-encoding-in-udp-vuwctf-2025)
- [HTTP File Upload Exfiltration in PCAP (MetaCTF 2026)](#http-file-upload-exfiltration-in-pcap-metactf-2026)

---

## tcpdump Quick Reference

Command-line packet capture tool for quick network forensics triage.

```bash
# Basic capture on interface
sudo tcpdump -i eth0

# Capture to file
sudo tcpdump -i eth0 -w capture.pcap

# Filter by source IP
sudo tcpdump -i eth0 src 192.168.1.100

# Filter by destination port
sudo tcpdump -i eth0 dst port 80

# Combined filter with file output
sudo tcpdump -i eth0 -w packets.pcap 'src 172.22.206.250 and port 443'

# Read from file with verbose output
tcpdump -r capture.pcap -v

# Show packet contents in ASCII
tcpdump -r capture.pcap -A

# Show hex + ASCII dump
tcpdump -r capture.pcap -X

# Count total packets
tcpdump -r capture.pcap -q | wc -l
```

**Common filters:**
| Filter | Description |
|--------|-------------|
| `host 10.0.0.1` | Traffic to/from IP |
| `net 192.168.1.0/24` | Entire subnet |
| `port 80` | HTTP traffic |
| `tcp` / `udp` / `icmp` | Protocol filter |
| `src host X and dst port Y` | Combined |

**Key insight:** Use tcpdump for quick command-line triage when Wireshark is unavailable. Pipe to `strings` or `grep` for fast flag hunting: `tcpdump -r capture.pcap -A | grep -i flag`.

---

## TLS/SSL Decryption via Keylog File

To decrypt TLS traffic in Wireshark, provide either the pre-master secret or a keylog file.

**Method 1 — SSLKEYLOGFILE (client-side key logging):**

If the challenge provides a keylog file (or you can set `SSLKEYLOGFILE`):
```bash
# Set environment variable before running the client
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl https://target/secret

# Import into Wireshark:
# Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename → /tmp/sslkeys.log
```

**Keylog file format (NSS Key Log Format):**
```text
CLIENT_RANDOM <32_bytes_client_random_hex> <48_bytes_master_secret_hex>
```

**Method 2 — RSA private key (if server key is known):**

**Note:** Only works with RSA key exchange. Sessions using forward secrecy (ECDHE/DHE cipher suites) cannot be decrypted with the server's private key — use Method 1 instead. CTF challenges with weak RSA keys typically use RSA key exchange.

```bash
# Wireshark: Edit → Preferences → Protocols → TLS → RSA keys list
# IP: 127.0.0.1, Port: 443, Protocol: http, Key File: server.key

# Or via tshark:
tshark -r capture.pcap -o "tls.keys_list:127.0.0.1,443,http,server.key" -Y http
```

**Method 3 — Weak RSA key factoring (see also linux-forensics.md):**
```bash
# Extract certificate from PCAP
tshark -r capture.pcap -Y "tls.handshake.type==11" -T fields -e tls.handshake.certificate | head -1

# Factor weak modulus, generate private key with rsatool
python rsatool.py -p <p> -q <q> -e 65537 -o server.key

# Import key into Wireshark
```

**SSL handshake components needed for decryption:**
1. `client_random` — sent in ClientHello
2. `server_random` — sent in ServerHello
3. Pre-master secret (PMS) — encrypted in ClientKeyExchange with server's RSA public key

**Key insight:** Look for keylog files (`.log`, `sslkeys.txt`) in challenge artifacts. If the challenge gives you a private key, use it directly. For weak RSA keys in certificates, factor the modulus to derive the private key.

---

## Wireshark Basics

```bash
# Filters
http.request.method == "POST"
tcp.stream eq 5
frame contains "flag"

# Export files
File → Export Objects → HTTP

# tshark
tshark -r capture.pcap -Y "http" -T fields -e http.file_data
tshark -r capture.pcap --export-objects http,/tmp/http_objects
```

---

## Port Scan Analysis

```bash
# IP conversation statistics
tshark -r capture.pcap -q -z conv,ip

# Find open ports (SYN-ACK responses)
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==1" \
  -T fields -e ip.src -e tcp.srcport | sort -u
```

---

## Gateway/Device via MAC OUI

```bash
# Extract MAC addresses
tshark -r capture.pcap -Y "arp" -T fields \
  -e arp.src.hw_mac -e arp.src.proto_ipv4 | sort -u

# Vendor lookup
curl -s "https://macvendors.com/query/88:bd:09"
```

---

## WordPress Reconnaissance

**Identify WPScan:**
```bash
tshark -r capture.pcap -Y "http.user_agent contains \"WPScan\"" | head -1
```

**WordPress version:**
```bash
cat /tmp/http_objects/feed* | grep -i generator
```

**Plugins:**
```bash
tshark -r capture.pcap \
  -Y "http.response.code == 200 && http.request.uri contains \"wp-content/plugins\"" \
  -T fields -e http.request.uri | sort -u
```

**Usernames (REST API):**
```bash
cat /tmp/http_objects/*per_page* | jq '.[].name'
```

---

## Post-Exploitation Traffic

**Step 1: TCP conversations**
```bash
tshark -r capture.pcap -q -z conv,tcp
```

**Step 2: Established connections (SYN-ACK)**
```bash
tshark -r capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 1" \
  -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport | sort -u
```

**Step 3: Follow TCP stream**
```bash
tshark -r capture.pcap -q -z "follow,tcp,ascii,<stream_number>"
```

**Reverse shell indicators:**
- `bash: cannot set terminal process group`
- `bash: no job control in this shell`
- Shell prompts like `www-data@hostname:/path$`

---

## Credential Extraction

**High-value files:**
| Application | File | Format |
|-------------|------|--------|
| WordPress | `wp-config.php` | `define('DB_PASSWORD', '...')` |
| Laravel | `.env` | `DB_PASSWORD=` |
| MySQL | `/etc/mysql/debian.cnf` | `password = ` |

```bash
# Search shell stream for credentials
tshark -r capture.pcap -q -z "follow,tcp,ascii,<stream>" | grep -i "password"
```

---

## SMB3 Encrypted Traffic

**Step 1: Extract NTLMv2 hash**
```bash
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e ntlmssp.ntlmv2_response.ntproofstr \
  -e ntlmssp.auth.username
```

**Step 2: Crack with hashcat**
```bash
hashcat -m 5600 ntlmv2_hash.txt wordlist.txt
```

**Step 3: Derive SMB 3.1.1 session keys (Python)**
```python
from Cryptodome.Cipher import AES, ARC4
from Cryptodome.Hash import MD4
import hmac, hashlib

def SP800_108_Counter_KDF(Ki, Label, Context, L):
    n = (L // 256) + 1
    result = b''
    for i in range(1, n + 1):
        data = i.to_bytes(4, 'big') + Label + b'\x00' + Context + L.to_bytes(4, 'big')
        result += hmac.new(Ki, data, hashlib.sha256).digest()
    return result[:L // 8]

# Compute session key
nt_hash = MD4.new(password.encode('utf-16le')).digest()
response_key = hmac.new(nt_hash, (user.upper() + domain.upper()).encode('utf-16le'), hashlib.md5).digest()
key_exchange_key = hmac.new(response_key, ntproofstr, hashlib.md5).digest()
session_key = ARC4.new(key_exchange_key).encrypt(encrypted_session_key)

# Derive encryption keys
c2s_key = SP800_108_Counter_KDF(session_key, b"SMBC2SCipherKey\x00", preauth_hash, 128)
s2c_key = SP800_108_Counter_KDF(session_key, b"SMBS2CCipherKey\x00", preauth_hash, 128)
```

**Step 4: Decrypt (AES-128-GCM)**
```python
def decrypt_smb311(transform_data, key):
    signature = transform_data[4:20]
    nonce = transform_data[20:32]
    aad = transform_data[20:52]
    encrypted = transform_data[52:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(encrypted, signature)
```

---

## 5G/NR Protocol Analysis

**Wireshark setup:**
- Enable: NAS-5GS, RLC-NR, PDCP-NR, MAC-NR

**SMS in 5G (3GPP TS 23.040):**

| IEI | Format |
|-----|--------|
| 0x0c | iMelody (ringtone) |
| 0x0e | Large Animation (16×16) |
| 0x18 | WVG (vector graphics) |

**iMelody to Morse:**
- Notes like `c4c4c4r2` encode dots/dashes

---

## Email Headers

- Check routing information
- Look for encoded attachments (base64)
- MIME boundaries may hide data

---

## USB HID Stenography/Chord PCAP (UTCTF 2024)

**Pattern (Gibberish):** USB keyboard PCAP with simultaneous multi-key presses = stenography chording.

**Detection:** Multiple simultaneous USB HID keys (6+ at once) in interrupt transfers. Not regular typing.

**Decoding workflow:**
1. Extract HID reports from PCAP
2. Detect simultaneous key states (multiple keycodes in same report)
3. Map chords to Plover stenography dictionary
4. Install Plover, use its dictionary for translation

```bash
# Extract USB HID data
tshark -r capture.pcap -Y "usb.transfer_type == 1" -T fields -e usb.capdata
```

---

## BCD Encoding in UDP (VuwCTF 2025)

**Pattern (1.5x-engineer):** "1.5x" hints at the encoding ratio.

**BCD (Binary-Coded Decimal):** Each nibble (4 bits) encodes one decimal digit (0-9). Two digits per byte vs one ASCII digit per byte → BCD is 2x denser than ASCII decimal. The "1.5x" name refers to the challenge-specific framing: 3 BCD bytes encode 6 digits which represent 2 ASCII bytes (3:2 ratio).

**Decoding:**
```python
def bcd_decode(data):
    result = ''
    for byte in data:
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        result += f'{high}{low}'
    return result

# UDP sessions differentiated by first byte
# Session 1 = BCD-encoded ASCII metadata with flag
# Session 2 = encrypted DOCX
```

**Lesson:** Challenge name often hints at encoding ratio or technique.

---

## HTTP File Upload Exfiltration in PCAP (MetaCTF 2026)

**Pattern (Dead Drop):** Small PCAP with TCP streams containing HTTP traffic. Exfiltrated data uploaded as a file via multipart form POST.

**Quick triage:**
```bash
# Count packets and protocols
tshark -r capture.pcap -q -z io,phs

# List HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields -e http.request.method -e http.request.uri -e http.host

# Export all HTTP objects (files transferred)
tshark -r capture.pcap --export-objects http,/tmp/http_objects
ls -la /tmp/http_objects/

# Follow specific TCP streams
tshark -r capture.pcap -q -z "follow,tcp,ascii,0"
tshark -r capture.pcap -q -z "follow,tcp,ascii,1"
```

**Extraction workflow:**
1. Export HTTP objects — uploaded files are extracted automatically
2. Check for multipart form-data POST requests (file uploads)
3. Look for unusual User-Agent strings (e.g., `DeadDropBot/1.0`) indicating automated exfiltration
4. Extracted files may be images (PNG/JPEG) with flag text rendered visually — open and inspect

**Key indicators of exfiltration:**
- POST to `/upload` endpoints
- Non-standard User-Agent strings
- Small number of packets but containing file transfers
- "Dead drop" pattern: attacker uploads file to web server for later retrieval

**Lesson:** Always start with `--export-objects` to extract transferred files before deep packet analysis. The flag is often in the exfiltrated file itself.

---

See also: [network-advanced.md](network-advanced.md) for advanced network forensics techniques (packet interval timing encoding, USB HID mouse/pen drawing recovery, NTLMv2 hash cracking, TCP flag covert channels, DNS steganography, multi-layer PCAP with XOR, Brotli decompression bomb seam analysis, SMB RID recycling, Timeroasting MS-SNTP).
