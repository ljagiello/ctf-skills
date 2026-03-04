# CTF Forensics - Network

## Table of Contents
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
