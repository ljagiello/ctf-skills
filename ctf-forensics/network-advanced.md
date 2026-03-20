# CTF Forensics - Network (Advanced)

## Table of Contents
- [Packet Interval Timing-Based Encoding (EHAX 2026)](#packet-interval-timing-based-encoding-ehax-2026)
- [USB HID Mouse/Pen Drawing Recovery (EHAX 2026)](#usb-hid-mousepen-drawing-recovery-ehax-2026)
- [NTLMv2 Hash Cracking from PCAP (Pragyan 2026)](#ntlmv2-hash-cracking-from-pcap-pragyan-2026)
- [TCP Flag Covert Channel (BearCatCTF 2026)](#tcp-flag-covert-channel-bearcatctf-2026)
- [DNS Query Name Last-Byte Steganography (UTCTF 2026)](#dns-query-name-last-byte-steganography-utctf-2026)
  - [DNS Trailing Byte Binary Encoding (UTCTF 2026)](#dns-trailing-byte-binary-encoding-utctf-2026)
- [Multi-Layer PCAP with XOR + ZIP (UTCTF 2026)](#multi-layer-pcap-with-xor--zip-utctf-2026)
- [Brotli Decompression Bomb Seam Analysis (BearCatCTF 2026)](#brotli-decompression-bomb-seam-analysis-bearcatctf-2026)
- [SMB RID Recycling via LSARPC (Midnight 2026)](#smb-rid-recycling-via-lsarpc-midnight-2026)
- [Timeroasting / MS-SNTP Hash Extraction (Midnight 2026)](#timeroasting--ms-sntp-hash-extraction-midnight-2026)
- [ICMP Payload Steganography with Byte Rotation (HackIM 2016)](#icmp-payload-steganography-with-byte-rotation-hackim-2016)
- [Packet Reconstruction via Checksum Validation (Break In 2016)](#packet-reconstruction-via-checksum-validation-break-in-2016)

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
- **Trailing byte after DNS question structure** (see below)

**Key insight:** DNS exfiltration often hides data in query names. When queries look random but follow a pattern, extract specific character positions. The "last byte" pattern is simple but effective — each query contributes one byte to the message.

**Detection:** Large number of DNS queries to a single domain, queries with no legitimate purpose, sequential or patterned subdomain names.

### DNS Trailing Byte Binary Encoding (UTCTF 2026)

**Pattern (Last Byte Standing variant):** Each DNS query packet contains a single extra byte appended AFTER the standard DNS question structure (after the null terminator + Type A + Class IN fields). The extra byte is `0x30` ('0') or `0x31` ('1'), encoding one bit per packet.

**Decoding workflow:**
```python
from scapy.all import rdpcap, DNS, DNSQR, Raw

packets = rdpcap('challenge.pcap')

bits = []
for pkt in packets:
    if pkt.haslayer(DNSQR):
        # Get raw DNS payload
        raw = bytes(pkt[DNS])
        # Standard DNS question ends at: header(12) + qname + null(1) + type(2) + class(2)
        qname = pkt[DNSQR].qname
        expected_len = 12 + len(qname) + 1 + 2 + 2  # +1 for leading length byte
        if len(raw) > expected_len:
            trailing = raw[expected_len:]
            for b in trailing:
                bits.append(chr(b))  # '0' or '1'

# Convert bit string to ASCII (MSB-first, 8-bit chunks)
bitstring = ''.join(bits)
flag = ''.join(chr(int(bitstring[i:i+8], 2)) for i in range(0, len(bitstring) - 7, 8))
print(flag)
```

**Key insight:** Data is hidden not in the DNS query name but in extra bytes padding the packet after the question record. Wireshark hex inspection reveals non-standard packet lengths. Each trailing byte represents ASCII '0' or '1', forming a binary stream that decodes to the flag.

**Detection:** DNS packets slightly larger than expected for their query name. Hex dump shows `0x30`/`0x31` bytes after the Class IN field (`00 01`). Consistent query domain across all packets.

---

## Multi-Layer PCAP with XOR + ZIP (UTCTF 2026)

**Pattern (Half Awake):** PCAP with multiple protocol layers hiding data. Requires protocol-aware extraction, XOR decryption with a key found in-band, and merging parallel data streams.

**Detailed workflow:**

1. **Inspect HTTP streams** for instructions or hints (e.g., "mDNS names are hints", "Not every TCP blob is what it pretends to be")
2. **Identify fake protocol streams:** A TCP stream labeled as TLS may actually contain a raw ZIP file (PK magic bytes `50 4b`). Check raw hex of suspicious streams
3. **Extract XOR key from mDNS:** Look for mDNS TXT records (e.g., `key.version.local`) containing the XOR key
4. **XOR-decrypt** the extracted data using the mDNS key
5. **Merge parallel datasets** using printability as selector

```python
import string
from scapy.all import rdpcap, Raw, DNS, DNSRR

packets = rdpcap('half-awake.pcap')

# 1. Extract XOR key from mDNS TXT record
xor_key = None
for pkt in packets:
    if pkt.haslayer(DNSRR):
        rr = pkt[DNSRR]
        if b'key' in rr.rrname.lower():
            xor_key = int(rr.rdata, 16)  # e.g., 0xb7

# 2. Extract fake TLS stream (look for PK header in raw TCP data)
# Use Wireshark: tcp.stream eq N → Export raw bytes
# Or extract with scapy by filtering the right stream

# 3. XOR-decrypt two datasets from ZIP contents
def xor_decrypt(data, key):
    return bytes(b ^ key for b in data)

p1 = xor_decrypt(stage1_data, xor_key)
p2 = xor_decrypt(stage2_data, xor_key)

# 4. Merge using printability: take the printable character from each position
flag = ''.join(
    chr(p1[i]) if chr(p1[i]) in string.printable and chr(p1[i]).isprintable()
    else chr(p2[i])
    for i in range(len(p1))
)
print(flag)
```

**Key insight:** When a PCAP contains two XOR-decoded byte arrays of equal length where neither alone produces readable text, merge them character-by-character using printability as the selector — take whichever byte at each position is a printable ASCII character. The XOR key is often hidden in an in-band protocol like mDNS TXT records rather than requiring brute-force.

**Indicators:**
- HTTP stream with meta-instructions ("not every TCP blob is what it pretends to be")
- TCP stream with mismatched protocol dissection (Wireshark shows TLS but raw bytes contain PK/ZIP headers)
- mDNS queries for suspicious service names (e.g., `key.version.local`)
- Two data files of identical length in extracted archive

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

---

## SMB RID Recycling via LSARPC (Midnight 2026)

**Pattern (UntilTime):** PCAP with SMB2 authentication followed by RPC calls over `\pipe\lsarpc`. The attacker enumerates Active Directory accounts by iterating RIDs (Relative Identifiers) through LSARPC functions.

**Identification:** SMB2 session setup with multiple authentication attempts (null session, Guest, random username), followed by RPC bind to LSARPC and repeated `LsaLookupSids` calls with incrementing RIDs.

**Wireshark analysis:**
```bash
# Filter SMB2 authentication attempts from attacker IP
tshark -r capture.pcapng -Y "ip.src == 198.51.100.16 && smb2.cmd == 1"

# Look for LSARPC RPC calls
tshark -r capture.pcapng -Y "dcerpc.cn_bind_to_str contains lsarpc"
```

**RPC call sequence:**
1. `LsaOpenPolicy` — opens a policy handle on the target
2. `LsaQueryInformationPolicy` — extracts the domain SID (e.g., `S-1-5-21-...`)
3. `LsaLookupSids` — resolves SIDs to account names by iterating RIDs (1000, 1001, 1002, ...)

**Key insight:** Guest account authentication (often enabled by default) grants enough access to enumerate domain accounts via LSARPC. The attacker constructs SIDs by appending incrementing RIDs to the domain SID and calling `LsaLookupSids` for each. Valid accounts return their name; invalid RIDs return errors. This technique is called **RID cycling** or **RID brute-forcing**.

**Detection indicators:**
- Multiple `LsaLookupSids` requests with sequential RIDs
- Guest authentication success followed by RPC pipe connection
- High volume of LSARPC traffic from a single source

---

## Timeroasting / MS-SNTP Hash Extraction (Midnight 2026)

**Pattern (UntilTime):** After enumerating valid machine account RIDs via RID recycling, the attacker sends NTP requests with those RIDs to extract HMAC-MD5 authentication material from the domain controller's MS-SNTP responses.

**Background:** Microsoft's MS-SNTP extends standard NTP with Netlogon authentication in Active Directory environments. The client places a domain RID in the NTP `Key Identifier` field (4 bytes, little-endian). The domain controller responds with an HMAC-MD5 signature derived from the machine account's NTLM hash — leaking crackable authentication material.

**Wireshark extraction:**
```bash
# Filter NTP traffic from attacker
tshark -r capture.pcapng -Y "ntp && ip.src == 10.16.13.13" -T fields -e udp.payload
```

**Convert Key Identifier to RID:**
```bash
# NTP Key Identifier is 4 bytes, little-endian
echo "<key_id_hex>" | sed 's/\(..\)/\1 /g' | awk '{print "0x"$4$3$2$1}' | xargs printf "%d\n"
```

**NTP response payload structure (68 bytes):**

| Offset | Length | Field |
|--------|--------|-------|
| 0-47 | 48 | Salt (NTP header + extensions) |
| 48-51 | 4 | Key Identifier (RID, little-endian) |
| 52-67 | 16 | HMAC-MD5 crypto-checksum |

**Hash reconstruction for Hashcat (mode 31300):**
```python
import sys
from struct import unpack

def to_hashcat_form(hex_payload):
    data = bytes.fromhex(hex_payload.strip())
    salt = data[:48]
    rid = unpack('<I', data[-20:-16])[0]
    md5hash = data[-16:]
    return f"{rid}:$sntp-ms${md5hash.hex()}${salt.hex()}"

if len(sys.argv) != 2:
    print("Usage: python sntp_to_hashcat.py <hex_payload>")
    sys.exit(1)

print(to_hashcat_form(sys.argv[1]))
```

**Cracking with Hashcat:**
```bash
# Mode 31300 = MS-SNTP (Timeroasting)
hashcat -m 31300 -a 0 -O hashes.txt rockyou.txt --username
```

**Example hash format:**
```text
1108:$sntp-ms$d7d0422d66705c6189c1d20aed76baa4$1c0111e900000000000a09314c4f434ced4c979d652b89f1e1b8428bffbfcd0aed4ca3bbb1338716ed4ca3bbb133cf3a
```

**Key insight:** MS-SNTP responses from domain controllers leak HMAC-MD5 authentication material tied to machine account NTLM hashes. Unlike Kerberoasting (which targets service accounts), Timeroasting targets **machine accounts** whose passwords are often weak or predictable (e.g., lowercase hostname). Any valid RID triggers a response — no special privileges required beyond network access to the DC's NTP service (UDP 123).

**Full attack chain:**
1. Authenticate to SMB as Guest
2. Enumerate valid RIDs via LSARPC RID recycling
3. Send MS-SNTP requests with discovered RIDs
4. Extract HMAC-MD5 hashes from NTP responses
5. Crack offline with Hashcat mode 31300

---

## ICMP Payload Steganography with Byte Rotation (HackIM 2016)

Data hidden in ICMP echo request/reply payloads with byte-level rotation encoding:

```python
from scapy.all import rdpcap, ICMP

packets = rdpcap('challenge.pcap')
icmp_data = b''
for pkt in packets:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Echo request
        icmp_data += bytes(pkt[ICMP].payload)

# Apply byte rotation (Caesar cipher on bytes)
SHIFT = 42
decoded = bytes((b - SHIFT) % 256 for b in icmp_data)

# Result may be base64-encoded
import base64
plaintext = base64.b64decode(decoded)
```

**Key insight:** ICMP payloads are often ignored by analysts focused on TCP/UDP. Check for non-standard payload sizes or non-zero data in ICMP packets. Common encoding layers: byte rotation -> base64 -> shell commands.

---

## Packet Reconstruction via Checksum Validation (Break In 2016)

Reconstruct corrupted/incomplete packets by using protocol checksums as validation:

1. **Identify missing bytes** from packet structure analysis (Ethernet, IP, TCP headers)
2. **Brute-force missing values** and validate against:
   - IP header checksum (16-bit ones' complement)
   - TCP checksum (includes pseudo-header)
3. **Extract data** from reconstructed payload

```python
import struct

def ip_checksum(header_bytes):
    """Compute IP header checksum"""
    words = struct.unpack('!' + 'H' * (len(header_bytes) // 2), header_bytes)
    s = sum(words)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

# Brute-force missing byte to match expected checksum
for candidate in range(256):
    header = header_template[:missing_offset] + bytes([candidate]) + header_template[missing_offset+1:]
    if ip_checksum(header) == 0:  # Valid checksum sums to 0
        print(f"Missing byte: 0x{candidate:02x}")
```

**Key insight:** Protocol checksums constrain missing data. For single missing bytes, brute-force is instant. For multiple missing bytes, use TCP sequence numbers and MAC/IP header structure to reduce the search space.

---

See also: [network.md](network.md) for basic network forensics techniques (tcpdump, TLS/SSL decryption, Wireshark, port scanning, SMB3 decryption, credential extraction, 5G protocols).
