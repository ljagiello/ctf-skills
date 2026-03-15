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
- [Packet Interval Timing-Based Encoding (EHAX 2026)](#packet-interval-timing-based-encoding-ehax-2026)
- [USB HID Mouse/Pen Drawing Recovery (EHAX 2026)](#usb-hid-mousepen-drawing-recovery-ehax-2026)
- [NTLMv2 Hash Cracking from PCAP (Pragyan 2026)](#ntlmv2-hash-cracking-from-pcap-pragyan-2026)
- [TCP Flag Covert Channel (BearCatCTF 2026)](#tcp-flag-covert-channel-bearcatctf-2026)
- [DNS Query Name Last-Byte Steganography (UTCTF 2026)](#dns-query-name-last-byte-steganography-utctf-2026)
- [Multi-Layer PCAP with XOR + ZIP (UTCTF 2026)](#multi-layer-pcap-with-xor--zip-utctf-2026)
- [Brotli Decompression Bomb Seam Analysis (BearCatCTF 2026)](#brotli-decompression-bomb-seam-analysis-bearcatctf-2026)

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
```
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

## Packet Interval Timing-Based Encoding (EHAX 2026)

**Pattern (Breathing Void):** Large PCAPNG with millions of packets, but only a few hundred on one interface carry data. The signal is in the **timing gaps** between identical packets, not their content.

**Identification:** Challenge mentions "breathing", "void", "silence", or timing. PCAP has many interfaces but only one has interesting traffic. Packets are identical but spaced at two distinct intervals.

**Decoding workflow:**
```python
from scapy.all import rdpcap

packets = rdpcap('challenge.pcapng')

# 1. Filter to the right interface (e.g., interface 2)
# tshark: tshark -r challenge.pcapng -Y "frame.interface_id == 2" -T fields -e frame.time_epoch

# 2. Compute inter-packet intervals
times = [float(pkt.time) for pkt in packets if pkt.sniffed_on == 'interface_2']
intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

# 3. Identify binary mapping (two distinct interval values)
# E.g., 10ms → 0, 100ms → 1 (threshold at ~50ms)
threshold = 0.05  # 50ms
bits = [0 if dt < threshold else 1 for dt in intervals]

# 4. May need to prepend a leading 0 bit (first interval has no predecessor)
bits = [0] + bits

# 5. Convert bits to bytes (MSB-first)
data = bytes(int(''.join(str(b) for b in bits[i:i+8]), 2)
             for i in range(0, len(bits) - 7, 8))
print(data.decode(errors='replace'))
```

**Key insight:** When identical packets appear on a single interface with only two practical interval values, it's almost certainly binary encoding via timing. The content is noise — the signal is in the gaps. Filter by interface and count unique intervals first.

**Scale tip:** Large PCAPs (millions of packets) often have the signal in a tiny subset. Triage with `tshark -q -z io,phs` to find which interface has the fewest packets — that's likely the data carrier.
---

## USB HID Mouse/Pen Drawing Recovery (EHAX 2026)

**Pattern (Painter):** PCAP contains USB HID interrupt transfers from a mouse/pen device. Drawing data encoded as relative movements with multiple draw modes.

**Packet format (7-byte HID reports):**
| Byte | Field | Notes |
|------|-------|-------|
| 0 | Button state | 0x01 = pressed (may be constant) |
| 1 | Mode/pad | 0=hover, 1=draw mode 1, 2=draw mode 2 |
| 2-3 | dx (int16 LE) | Relative X movement |
| 4-5 | dy (int16 LE) | Relative Y movement |
| 6 | Wheel | Usually 0 |

**Extraction and rendering:**
```python
import struct
from PIL import Image, ImageDraw

# Extract HID data
# tshark -r capture.pcap -Y "usb.transfer_type==1" -T fields -e usb.capdata

packets = []
with open('hid_data.txt') as f:
    for line in f:
        raw = bytes.fromhex(line.strip().replace(':', ''))
        if len(raw) >= 7:
            btn = raw[0]
            mode = raw[1]
            dx = struct.unpack('<h', raw[2:4])[0]
            dy = struct.unpack('<h', raw[4:6])[0]
            packets.append((btn, mode, dx, dy))

# Accumulate positions per mode
SCALE = 5
positions = {0: [], 1: [], 2: []}
x, y = 0, 0
for btn, mode, dx, dy in packets:
    x += dx
    y += dy
    positions[mode].append((x, y))

# Render each mode separately (different colors = different text layers)
for mode in [1, 2]:
    pts = positions[mode]
    if not pts:
        continue
    min_x = min(p[0] for p in pts) - 100
    min_y = min(p[1] for p in pts) - 100
    max_x = max(p[0] for p in pts) + 100
    max_y = max(p[1] for p in pts) + 100
    w = (max_x - min_x) * SCALE
    h = (max_y - min_y) * SCALE
    img = Image.new('RGB', (w, h), 'white')
    draw = ImageDraw.Draw(img)
    for i in range(1, len(pts)):
        x0 = (pts[i-1][0] - min_x) * SCALE
        y0 = (pts[i-1][1] - min_y) * SCALE
        x1 = (pts[i][0] - min_x) * SCALE
        y1 = (pts[i][1] - min_y) * SCALE
        # Skip long jumps (pen lifts)
        if abs(pts[i][0]-pts[i-1][0]) < 50 and abs(pts[i][1]-pts[i-1][1]) < 50:
            draw.line([(x0,y0),(x1,y1)], fill='black', width=3)
    img.save(f'mode_{mode}.png')
```

**Key techniques:**
- **Separate modes:** Different button/mode values draw different text layers — render each independently
- **Skip pen lifts:** Large dx/dy jumps indicate pen was lifted, not drawn — filter by distance threshold
- **High resolution:** Scale 5-8x with margins for readable handwriting
- **Time gradient:** Color points by temporal order (rainbow gradient) to trace stroke direction
- **Character segmentation:** Group consecutive same-mode points by large X gaps to isolate characters

**Alternative: AWK extraction + SVG rendering (faster pipeline):**
```bash
# Extract capdata and convert to signed deltas in one pass
tshark -r pref.pcap -Y "usb.transfer_type==0x01 && usb.endpoint_address==0x81 && usb.capdata" \
  -T fields -e usb.capdata > capdata.txt

awk '
function hexval(c){ return index("0123456789abcdef",tolower(c))-1 }
function hex2dec(h, n,i){ n=0; for(i=1;i<=length(h);i++) n=n*16+hexval(substr(h,i,1)); return n }
function s16(u){ return (u>=32768)?u-65536:u }
{ d=$1; if(length(d)!=14) next
  btn=hex2dec(substr(d,3,2))
  x=s16(hex2dec(substr(d,7,2) substr(d,5,2)))
  y=s16(hex2dec(substr(d,11,2) substr(d,9,2)))
  print btn, x, y }' capdata.txt > deltas.txt
```
Then render with SVG (Python) — filter on pen-down state (button=2), accumulate deltas, flip Y axis, draw strokes between consecutive pen-down points.

**Difference from keyboard HID:** Mouse HID uses relative movements (accumulated), keyboard uses keycodes (direct). Mouse drawing requires rendering; keyboard requires keymap lookup.

---

## NTLMv2 Hash Cracking from PCAP (Pragyan 2026)

**Pattern ($whoami):** SMB2 authentication in packet capture.

**Extraction:** From NTLMSSP_AUTH packet, extract: server challenge, NTProofStr, and blob.

**Brute-force with known password format:**
```python
import hashlib, hmac
from Crypto.Hash import MD4

def try_password(password, username, domain, server_challenge, blob, expected_proof):
    nt_hash = MD4.new(password.encode('utf-16-le')).digest()
    identity = (username.upper() + domain).encode('utf-16-le')
    ntlmv2_hash = hmac.new(nt_hash, identity, hashlib.md5).digest()
    proof = hmac.new(ntlmv2_hash, server_challenge + blob, hashlib.md5).digest()
    return proof == expected_proof
```

---

## TCP Flag Covert Channel (BearCatCTF 2026)

**Pattern (pCapsized):** Suspicious TCP packets with chaotic flag combinations (FIN+SYN, SYN+RST+PSH+URG, etc.). The 6 TCP flag bits encode base64 characters.

**Decoding:**
```python
from scapy.all import rdpcap, TCP

pkts = rdpcap('capture.pcap')
suspicious = [p for p in pkts if TCP in p and p[TCP].dport == 5748]

# Map 6-bit flag value to base64 alphabet
b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
encoded = ''.join(b64[p[TCP].flags & 0x3F] for p in suspicious)

import base64
flag = base64.b64decode(encoded).decode()
```

**Key insight:** TCP has 6 standard flag bits (FIN, SYN, RST, PSH, ACK, URG) = values 0-63, matching the base64 alphabet exactly. Unusual flag combinations on otherwise normal-looking packets indicate covert channel usage. Filter by destination port or source IP to isolate the channel.

**Detection:** Packets with nonsensical flag combinations (e.g., FIN+SYN simultaneously). Consistent destination port. Packet count is a multiple of 4 (base64 alignment).

---

## DNS Query Name Last-Byte Steganography (UTCTF 2026)

**Pattern (Last Byte Standing):** PCAP with DNS queries where data is encoded in the last byte of each query name.

**Identification:** Many DNS queries to unusual or sequential subdomains. The meaningful data is NOT in the query name itself but in the final byte/character of each name.

**Decoding workflow:**
```python
from scapy.all import rdpcap, DNS, DNSQR

packets = rdpcap('last-byte-standing.pcap')

data = []
for pkt in packets:
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode(errors='replace').rstrip('.')
        if qname:
            data.append(qname[-1])  # Last character of query name

# Reconstruct message from last bytes
message = ''.join(data)
print(message)
# May need additional decoding (hex, base64, etc.)
```

**Variants:**
- Last byte of each subdomain label (split on `.`)
- Specific character position (first, Nth, last)
- Hex-encoded bytes across multiple queries
- Subdomain labels as base32/base64 chunks (DNS tunneling)

**Key insight:** DNS exfiltration often hides data in query names. When queries look random but follow a pattern, extract specific character positions. The "last byte" pattern is simple but effective — each query contributes one byte to the message.

**Detection:** Large number of DNS queries to a single domain, queries with no legitimate purpose, sequential or patterned subdomain names.

---

## Multi-Layer PCAP with XOR + ZIP (UTCTF 2026)

**Pattern (Half Awake):** Small PCAP containing data that requires multiple decoding layers: extract raw data from packets, XOR-decrypt, then decompress (ZIP/gzip).

**Workflow:**
```python
from scapy.all import rdpcap, Raw

packets = rdpcap('half-awake.pcap')

# 1. Extract raw payload data from TCP/UDP streams
raw_data = b''
for pkt in packets:
    if pkt.haslayer(Raw):
        raw_data += pkt[Raw].load

# 2. Try XOR with common single-byte keys
for key in range(256):
    decrypted = bytes(b ^ key for b in raw_data)
    # Check for known magic bytes
    if decrypted[:2] == b'PK':  # ZIP
        with open(f'decrypted_{key}.zip', 'wb') as f:
            f.write(decrypted)
        print(f"ZIP found with XOR key {key:#04x}")
    elif decrypted[:3] == b'\x1f\x8b\x08':  # gzip
        print(f"gzip found with XOR key {key:#04x}")

# 3. Extract and search for flag
import zipfile, io
zf = zipfile.ZipFile(io.BytesIO(decrypted))
for name in zf.namelist():
    content = zf.read(name)
    if b'flag' in content.lower():
        print(f"{name}: {content}")
```

**Key insight:** Small PCAPs with seemingly random data often require multi-layer decoding. Try XOR brute-force first (only 256 keys for single-byte), then check for archive magic bytes in the decrypted output.

---

## Brotli Decompression Bomb Seam Analysis (BearCatCTF 2026)

**Pattern (Cursed Map):** HTTP download of a file that decompresses to gigabytes (decompression bomb). The flag is sandwiched between two bomb halves at a seam in the compressed data.

**Identification:** Compressed data shows a repeating block pattern (e.g., 105-byte period). One block breaks the pattern — the flag is at this discontinuity.

```python
import brotli

with open('flag.txt.br', 'rb') as f:
    data = f.read()

# Find the repeating block size
block_size = 105  # Determined by comparing adjacent blocks
for i in range(0, len(data) - block_size, block_size):
    if data[i:i+block_size] != data[i+block_size:i+2*block_size]:
        seam_offset = i + block_size
        break

# Decompress only the anomalous block
dec = brotli.Decompressor()
result = dec.process(data[seam_offset:seam_offset+block_size])
# Flag is in the decompressed output
```

**Key insight:** Decompression bombs use highly repetitive compressed data. The flag breaks this repetition, creating a detectable anomaly in the compressed stream. Compare adjacent fixed-size blocks to find the discontinuity, then decompress only that region — no need to decompress the entire multi-gigabyte output.

**Detection:** File with extreme compression ratio (MB → GB), HTTP Content-Encoding: br, or file identified as Brotli. Tools hang or OOM when trying to decompress.
