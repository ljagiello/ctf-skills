# CTF Misc - Encodings & Media

## Table of Contents
- [Common Encodings](#common-encodings)
  - [Base64](#base64)
  - [Base32](#base32)
  - [Hex](#hex)
  - [IEEE 754 Floating Point Encoding](#ieee-754-floating-point-encoding)
  - [UTF-16 Endianness Reversal (LACTF 2026)](#utf-16-endianness-reversal-lactf-2026)
  - [BCD (Binary-Coded Decimal) Encoding (VuwCTF 2025)](#bcd-binary-coded-decimal-encoding-vuwctf-2025)
  - [Multi-Layer Encoding Detection (0xFun 2026)](#multi-layer-encoding-detection-0xfun-2026)
  - [URL Encoding](#url-encoding)
  - [ROT13 / Caesar](#rot13-caesar)
  - [Caesar Brute Force](#caesar-brute-force)
- [QR Codes](#qr-codes)
  - [Basic Commands](#basic-commands)
  - [QR Structure](#qr-structure)
  - [Repairing Damaged QR](#repairing-damaged-qr)
  - [Finder Pattern Template](#finder-pattern-template)
  - [QR Code Chunk Reassembly (LACTF 2026)](#qr-code-chunk-reassembly-lactf-2026)
- [Esoteric Languages](#esoteric-languages)
  - [Custom Brainfuck Variants (Themed Esolangs)](#custom-brainfuck-variants-themed-esolangs)
- [Verilog/HDL](#veriloghdl)
- [Binary Tree Key Encoding](#binary-tree-key-encoding)

---

## Common Encodings

### Base64
```bash
echo "encoded" | base64 -d
# Charset: A-Za-z0-9+/=
```

### Base32
```bash
echo "OBUWG32DKRDHWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I=" | base32 -d
# Charset: A-Z2-7= (no lowercase, no 0,1,8,9)
```

### Hex
```bash
echo "68656c6c6f" | xxd -r -p
```

### IEEE 754 Floating Point Encoding

Numbers that encode ASCII text when viewed as raw IEEE 754 bytes:

```python
import struct

values = [240600592, 212.2753143310547, 2.7884192016691608e+23]

# Each float32 packs to 4 ASCII bytes
for v in values:
    packed = struct.pack('>f', v)  # Big-endian single precision
    print(f"{v} -> {packed}")      # b'Meta', b'CTF{', b'fl04'

# For double precision (8 bytes per value):
# struct.pack('>d', v)
```

**Key insight:** If challenge gives a list of numbers (mix of integers, decimals, scientific notation), try packing each as IEEE 754 float32 (`struct.pack('>f', v)`) — the 4 bytes often spell ASCII text.

### UTF-16 Endianness Reversal (LACTF 2026)

**Pattern (endians):** Text "turned to Japanese" -- mojibake from UTF-16 endianness mismatch.

**Fix:** Reverse the encoding/decoding order:
```python
# If encoded as UTF-16-LE but decoded as UTF-16-BE:
fixed = mojibake.encode('utf-16-be').decode('utf-16-le')

# If encoded as UTF-16-BE but decoded as UTF-16-LE:
fixed = mojibake.encode('utf-16-le').decode('utf-16-be')
```

**Identification:** Text appears as CJK characters (Japanese/Chinese), challenge mentions "translation" or "endian".

### BCD (Binary-Coded Decimal) Encoding (VuwCTF 2025)

**Pattern:** Challenge name hints at ratio (e.g., "1.5x" = 1.5:1 byte ratio). Each nibble encodes one decimal digit.

```python
def bcd_decode(data):
    """Decode BCD: each byte = 2 decimal digits."""
    return ''.join(f'{(b>>4)&0xf}{b&0xf}' for b in data)

# Then convert decimal string to ASCII
ascii_text = ''.join(chr(int(decoded[i:i+2])) for i in range(0, len(decoded), 2))
```

### Multi-Layer Encoding Detection (0xFun 2026)

**Pattern (139 steps):** Recursive decoding with troll flags as decoys.

**Critical rule:** When data is all hex chars (0-9, a-f), decode as **hex FIRST**, not base64 (which also accepts those chars).

```python
def auto_decode(data):
    while True:
        data = data.strip()
        if data.startswith('REAL_DATA_FOLLOWS:'):
            data = data.split(':', 1)[1]
        # Prioritize hex when ambiguous
        if all(c in '0123456789abcdefABCDEF' for c in data) and len(data) % 2 == 0:
            data = bytes.fromhex(data).decode('ascii', errors='replace')
        elif set(data) <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='):
            data = base64.b64decode(data).decode('ascii', errors='replace')
        else:
            break
    return data
```

**Ignore troll flags** — check for "keep decoding" or "REAL_DATA_FOLLOWS:" markers.

### URL Encoding
```python
import urllib.parse
urllib.parse.unquote('hello%20world')
```

### ROT13 / Caesar
```bash
echo "uryyb" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
```

**ROT13 patterns:** `gur` = "the", `synt` = "flag"

### Caesar Brute Force
```python
text = "Khoor Zruog"
for shift in range(26):
    decoded = ''.join(
        chr((ord(c) - 65 - shift) % 26 + 65) if c.isupper()
        else chr((ord(c) - 97 - shift) % 26 + 97) if c.islower()
        else c for c in text)
    print(f"{shift:2d}: {decoded}")
```

---

## QR Codes

### Basic Commands
```bash
zbarimg qrcode.png           # Decode
zbarimg -S*.enable qr.png    # All barcode types
qrencode -o out.png "data"   # Encode
```

### QR Structure

**Finder patterns (3 corners):** 7x7 modules at top-left, top-right, bottom-left

**Version formula:** `(version * 4) + 17` modules per side

### Repairing Damaged QR

```python
from PIL import Image
import numpy as np

img = Image.open('damaged_qr.png')
arr = np.array(img)

# Convert to binary
gray = np.mean(arr, axis=2)
binary = (gray < 128).astype(int)

# Find QR bounds
rows = np.any(binary, axis=1)
cols = np.any(binary, axis=0)
rmin, rmax = np.where(rows)[0][[0, -1]]
cmin, cmax = np.where(cols)[0][[0, -1]]

# Check finder patterns
qr = binary[rmin:rmax+1, cmin:cmax+1]
print("Top-left:", qr[0:7, 0:7].sum())  # Should be ~25
```

### Finder Pattern Template
```python
finder_pattern = [
    [1,1,1,1,1,1,1],
    [1,0,0,0,0,0,1],
    [1,0,1,1,1,0,1],
    [1,0,1,1,1,0,1],
    [1,0,1,1,1,0,1],
    [1,0,0,0,0,0,1],
    [1,1,1,1,1,1,1],
]
```

### QR Code Chunk Reassembly (LACTF 2026)

**Pattern (error-correction):** QR code split into grid of chunks (e.g., 5x5 of 9x9 pixels), shuffled.

**Solving approach:**
1. **Fix known chunks:** Use structural patterns -- finder patterns (3 corners), timing patterns, alignment patterns -- to place ~50% of chunks
2. **Extract codeword constraints:** For each candidate payload length, use QR spec to identify which pixels are invariant across encodings
3. **Backtracking search:** Assign remaining chunks under pixel constraints until QR decodes successfully

**Tools:** `segno` (Python QR library), `zbarimg` for decoding.

---

## Esoteric Languages

| Language | Pattern |
|----------|---------|
| Brainfuck | `++++++++++[>+++++++>` |
| Whitespace | Only spaces, tabs, newlines |
| Ook! | `Ook. Ook? Ook!` |
| Malbolge | Extremely obfuscated |
| Piet | Image-based |

### Custom Brainfuck Variants (Themed Esolangs)

**Pattern:** File contains repetitive themed words (e.g., "arch", "linux", "btw") used as substitutes for Brainfuck operations. Common in Easy/Misc CTF challenges.

**Identification:**
- File is ASCII text with very long lines of repeated words
- Small vocabulary (5-8 unique words)
- One word appears as a line terminator (maps to `.` output)
- Two words are used for increment/decrement (one has many repeats per line)
- Words often relate to a meme or theme (e.g., "I use Arch Linux BTW")

**Standard Brainfuck operations to map:**
| Op | Meaning | Typical pattern |
|----|---------|-----------------|
| `+` | Increment cell | Most repeated word (defines values) |
| `-` | Decrement cell | Second most repeated word |
| `>` | Move pointer right | Short word, appears alone or with `.` |
| `<` | Move pointer left | Paired with `>` word |
| `[` | Begin loop | Appears at start of lines with `]` counterpart |
| `]` | End loop | Appears at end of same lines as `[` |
| `.` | Output char | Line terminator word |

**Solving approach:**
```python
from collections import Counter
words = content.split()
freq = Counter(words)
# Most frequent = likely + or -, line-ender = likely .

# Map words to BF ops, translate, run standard BF interpreter
mapping = {'arch': '+', 'linux': '-', 'i': '>', 'use': '<',
           'the': '[', 'way': ']', 'btw': '.'}
bf = ''.join(mapping.get(w, '') for w in words)
# Then execute bf string with a standard Brainfuck interpreter
```

**Real example (0xL4ugh CTF - "iUseArchBTW"):** `.archbtw` extension, "I use Arch Linux BTW" meme theme.

**Tips:** Try swapping `+`/`-` or `>`/`<` if output is not ASCII. Verify output starts with known flag format.

---

## Verilog/HDL

```python
# Translate Verilog logic to Python
def verilog_module(input_byte):
    wire_a = (input_byte >> 4) & 0xF
    wire_b = input_byte & 0xF
    return wire_a ^ wire_b
```

---

## Binary Tree Key Encoding

**Encoding:** `'0' → j = j*2 + 1`, `'1' → j = j*2 + 2`

**Decoding:**
```python
def decode_path(index):
    path = ""
    while index != 0:
        if index & 1:  # Odd = left ('0')
            path += "0"
            index = (index - 1) // 2
        else:          # Even = right ('1')
            path += "1"
            index = (index - 2) // 2
    return path[::-1]
```

