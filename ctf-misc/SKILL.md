---
name: ctf-misc
description: Miscellaneous CTF challenge techniques. Use for trivia, automation scripts, encoding puzzles, RF/SDR signal processing, or challenges that don't fit other categories.
user-invocable: false
allowed-tools: ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "Task", "WebFetch", "WebSearch"]
---

# CTF Miscellaneous

Quick reference for misc challenges. For detailed techniques, see supporting files.

## Additional Resources

- [pyjails.md](pyjails.md) - Python jail/sandbox escape techniques
- [bashjails.md](bashjails.md) - Bash jail/restricted shell escape techniques
- [encodings.md](encodings.md) - Encodings, QR codes, audio, esolangs
- RF/SDR/IQ signal processing section below covers QAM, PSK, carrier recovery, timing sync

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

## IEEE-754 Float Encoding (Data Hiding)

**Pattern (Floating):** Numbers are float32 values hiding raw bytes.

**Key insight:** A 32-bit float is just 4 bytes interpreted as a number. Reinterpret as raw bytes → ASCII.

```python
import struct

# List of suspicious floating-point numbers
floats = [1.234e5, -3.456e-7, ...]  # Whatever the challenge gives

# Convert each float to 4 raw bytes (big-endian)
flag = b''
for f in floats:
    flag += struct.pack('>f', f)
print(flag.decode())
```

**CyberChef solution:**
1. Paste numbers (space-separated)
2. "From Float" → Big Endian → Float (4 bytes) → Space delimiter

**Variations:**
- Double (8 bytes): `struct.pack('>d', val)`
- Little-endian: `struct.pack('<f', val)`
- Mixed endianness: try both if first doesn't produce ASCII

## USB Mouse PCAP Reconstruction

**Pattern (Hunt and Peck):** USB HID mouse traffic captures on-screen keyboard typing.

**Workflow:**
1. Open PCAP in Wireshark — identify USBPcap with HID interrupt transfers
2. Identify device (Device Descriptor → manufacturer/product)
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

## Audio Challenges

```bash
sox audio.wav -n spectrogram  # Visual data
qsstv                          # SSTV decoder
```

## RF / SDR / IQ Signal Processing

### IQ File Formats
- **cf32** (complex float 32): GNU Radio standard, `np.fromfile(path, dtype=np.complex64)`
- **cs16** (complex signed 16-bit): `np.fromfile(path, dtype=np.int16).reshape(-1,2)`, then `I + jQ`
- **cu8** (complex unsigned 8-bit): RTL-SDR raw format

### Analysis Pipeline
```python
import numpy as np
from scipy import signal

# 1. Load IQ data
iq = np.fromfile('signal.cf32', dtype=np.complex64)

# 2. Spectrum analysis - find occupied bands
fft_data = np.fft.fftshift(np.fft.fft(iq[:4096]))
freqs = np.fft.fftshift(np.fft.fftfreq(4096))
power_db = 20*np.log10(np.abs(fft_data)+1e-10)

# 3. Identify symbol rate via cyclostationary analysis
x2 = np.abs(iq_filtered)**2  # squared magnitude
fft_x2 = np.abs(np.fft.fft(x2, n=65536))
# Peak in fft_x2 = symbol rate (samples_per_symbol = 1/peak_freq)

# 4. Frequency shift to baseband
center_freq = 0.14  # normalized frequency of band center
t = np.arange(len(iq))
baseband = iq * np.exp(-2j * np.pi * center_freq * t)

# 5. Low-pass filter to isolate band
lpf = signal.firwin(101, bandwidth/2, fs=1.0)
filtered = signal.lfilter(lpf, 1.0, baseband)
```

### QAM-16 Demodulation with Carrier + Timing Recovery
The key challenge is carrier frequency offset causing constellation rotation (circles instead of points).

**Decision-directed carrier recovery + Mueller-Muller timing:**
```python
# Loop parameters (2nd order PLL)
carrier_bw = 0.02  # wider BW = faster tracking, more noise
damping = 1.0
theta_n = carrier_bw / (damping + 1/(4*damping))
Kp = 2 * damping * theta_n      # proportional gain
Ki = theta_n ** 2                # integral gain

carrier_phase = 0.0
carrier_freq = 0.0

for each symbol sample:
    # De-rotate by current phase estimate
    symbol = raw_sample * np.exp(-1j * carrier_phase)

    # Find nearest constellation point (decision)
    nearest = min(constellation, key=lambda p: abs(symbol - p))

    # Phase error (decision-directed)
    error = np.imag(symbol * np.conj(nearest)) / (abs(nearest)**2 + 0.1)

    # Update 2nd order loop
    carrier_freq += Ki * error
    carrier_phase += Kp * error + carrier_freq
```

**Mueller-Muller timing error detector:**
```python
timing_error = (Re(y[n]-y[n-1]) * Re(d[n-1]) - Re(d[n]-d[n-1]) * Re(y[n-1]))
             + (Im(y[n]-y[n-1]) * Im(d[n-1]) - Im(d[n]-d[n-1]) * Im(y[n-1]))
# y = received symbol, d = decision (nearest constellation point)
```

### Key Insights for RF CTF Challenges
- **Circles in constellation** = frequency offset not corrected
- **Spirals** = frequency offset + time-varying phase
- **Blobs on grid** = correct sync, just noise
- **4-fold ambiguity**: DD carrier recovery can lock with 0°/90°/180°/270° rotation — try all 4
- **Bandwidth vs symbol rate**: BW = Rs × (1 + α), where α is roll-off factor (0 to 1)
- **RC vs RRC**: "RC pulse shaping" at TX means receiver just samples (no matched filter needed); "RRC" means apply matched RRC filter at RX
- **Cyclostationary peak at Rs** confirms symbol rate even without knowing modulation order
- **AGC**: normalize signal power to match constellation power: `scale = sqrt(target_power / measured_power)`
- **GNU Radio's QAM-16 default mapping** is NOT Gray code — always check the provided constellation map

### Common Framing Patterns
- Idle/sync pattern repeating while link is idle
- Start delimiter (often a single symbol like 0)
- Data payload (nibble pairs for QAM-16: high nibble first, low nibble)
- End delimiter (same as start, e.g., 0)
- The idle pattern itself may contain the delimiter value — distinguish by context (is it part of the 16-symbol repeating pattern?)

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
'\\141' = 'a'
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

## Hash Identification

**By constants:**
- MD5: `0x67452301`
- SHA-256: `0x6a09e667`
- MurmurHash64A: `0xC6A4A7935BD1E995`

## PyInstaller Extraction

```bash
python pyinstxtractor.py packed.exe
# Look in packed.exe_extracted/
```

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
# 0.07 → 70000000000000.0078125
# 0.14 → 140000000000000.015625
# 0.27 → 270000000000000.03125
# 0.56 → 560000000000000.0625
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
inventory = 560000000000000.0625 - 560000000000000 = 0.0625 > 0.05 fee ✓

# Now: balance >= flag_price ✓ AND inventory >= fee ✓
```

### Why It Works
- Float64 has ~15-16 significant digits precision
- `(5.0 - 0.56) * 1e15` loses precision → rounds to exact 5e15 when added
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

## Python Jail: String Join Bypass

**Pattern (better_eval):** `+` operator blocked for string concatenation.

**Bypass with `''.join()`:**
```python
# Blocked: "fl" + "ag.txt"
# Allowed: ''.join(["fl","ag.txt"])

# Full payload:
open(''.join(['fl','ag.txt'])).read()
```

**Other bypass techniques:**
- `chr()` + list comprehension: `''.join([chr(102),chr(108),chr(97),chr(103)])`
- Format strings: `f"{'flag'}.txt"` (if f-strings allowed)
- `bytes([102,108,97,103]).decode()` for "flag"

## Backdoor Detection in Source Code

**Pattern (Rear Hatch):** Hidden command prefix triggers `system()` call.

**Common patterns:**
- `strncmp(input, "exec:", 5)` → runs `system(input + 5)`
- Hex-encoded comparison strings: `\x65\x78\x65\x63\x3a` = "exec:"
- Hidden conditions in maintenance/admin functions

## Cipher Identification Workflow

1. **ROT13** - Challenge mentions "ROT", text looks like garbled English
2. **Base64** - `A-Za-z0-9+/=`, title hints "64"
3. **Base32** - `A-Z2-7=` uppercase only
4. **Atbash** - Title hints (Abash/Atbash), preserves spaces, 1:1 substitution
5. **Pigpen** - Geometric symbols on grid
6. **Keyboard Shift** - Text looks like adjacent keys pressed
7. **Substitution** - Frequency analysis applicable

**Auto-identify:** [dCode Cipher Identifier](https://www.dcode.fr/cipher-identifier)