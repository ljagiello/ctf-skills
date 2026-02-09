# CTF Misc - Encodings & Media

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

### SHA-256 Length Extension Attack (LACTF 2026)

**Pattern (ttyspin):** MAC = `SHA-256(SECRET || message)` with known message and hash. Forge valid MAC for `SECRET || message || padding || extension`.

**Key insight:** SHA-256 (and MD5, SHA-1) are Merkle-Damgard constructions. Knowing `H(SECRET || msg)` lets you compute `H(SECRET || msg || glue_pad || ext)` without knowing SECRET.

**Attack steps:**
1. Compute glue padding: the padding SHA-256 would apply after `SECRET || msg`
2. Construct new message: `msg || glue_pad || malicious_extension`
3. Resume SHA-256 from the known hash state, feed extension bytes
4. Result is valid MAC for the new message

```bash
# Using hashpumpy or hlextend:
pip install hlextend
```
```python
import hlextend
sha = hlextend.new('sha256')
new_data = sha.extend(b'extension', b'original_message', len_secret, known_hash_hex)
new_hash = sha.hexdigest()
# new_data includes original + glue padding + extension
```

**Common in CTFs:** Game save files, session tokens, API signatures using `H(secret || data)`. Always check if the MAC construction is vulnerable to length extension (SHA-256, MD5, SHA-1 are; HMAC, SHA-3 are NOT).

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

## Audio Challenges

### Spectrogram
```bash
sox audio.wav -n spectrogram
```

### SSTV
```bash
qsstv  # GUI decoder
```

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
# 1. Identify unique words and their frequencies
from collections import Counter
words = content.split()
freq = Counter(words)
# Most frequent = likely + or -, line-ender = likely .

# 2. Map words to BF ops (educated guess from theme)
mapping = {
    'arch': '+',    # increment
    'linux': '-',   # decrement
    'i': '>',       # move right
    'use': '<',     # move left
    'the': '[',     # begin loop
    'way': ']',     # end loop
    'btw': '.',     # output
}

# 3. Translate and execute as Brainfuck
bf = ''.join(mapping.get(w, '') for w in words)

# 4. Execute BF interpreter
tape = [0] * 30000
ptr = ip = 0
output = ''
# Build loop map for [ ] matching
loop_map = {}
stack = []
for idx, ch in enumerate(bf):
    if ch == '[': stack.append(idx)
    elif ch == ']':
        start = stack.pop()
        loop_map[start] = idx
        loop_map[idx] = start

while ip < len(bf):
    c = bf[ip]
    if c == '+': tape[ptr] = (tape[ptr] + 1) % 256
    elif c == '-': tape[ptr] = (tape[ptr] - 1) % 256
    elif c == '>': ptr += 1
    elif c == '<': ptr -= 1
    elif c == '.': output += chr(tape[ptr])
    elif c == '[' and tape[ptr] == 0: ip = loop_map[ip]
    elif c == ']' and tape[ptr] != 0: ip = loop_map[ip]
    ip += 1
print(output)
```

**Real example (0xL4ugh CTF - "iUseArchBTW"):**
- File extension: `.archbtw`
- Words: `arch`=+, `linux`=--, `i`=>, `use`=<, `the`=[, `way`=], `btw`=.
- Theme: "I use Arch Linux BTW" meme

**Tips:**
- If first attempt doesn't produce readable ASCII, try swapping `+`/`-` or `>`/`<`
- The loop structure (`[`/`]`) words often appear together on the same line
- Line 1 typically initializes a cell value (just `+` operations)
- Line 2 often contains the first loop (multiplier pattern)
- Verify by checking if output starts with known flag format

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

## YARA Rules with Z3

```python
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()

# Literal bytes
for i, byte in enumerate([0x66, 0x6C, 0x61, 0x67]):
    s.add(flag[i] == byte)

# Character range
for i in range(4):
    s.add(flag[i] >= ord('A'))
    s.add(flag[i] <= ord('Z'))

if s.check() == sat:
    m = s.model()
    print(bytes([m[f].as_long() for f in flag]))
```

---

## Archive Extraction

### Nested Archives (Matryoshka)
```bash
while f=$(ls *.tar* *.gz *.bz2 *.xz *.zip *.7z 2>/dev/null|head -1) && [ -n "$f" ]; do
    7z x -y "$f" && rm "$f"
done
```

### Format Reference
```bash
7z x archive.7z
tar -xzf file.tar.gz   # Gzip
tar -xjf file.tar.bz2  # Bzip2
tar -xJf file.tar.xz   # XZ
unzip file.zip
```

---

## Hash Identification

**By magic constants:**
- MD5: `0x67452301`, `0xefcdab89`
- SHA-256: `0x6a09e667`, `0xbb67ae85`
- MurmurHash64A: `0xC6A4A7935BD1E995`

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

---

## Type Systems as Constraints

**OCaml GADTs / advanced types encode constraints.**

Don't compile - extract constraints with regex and solve with Z3:
```python
import re
from z3 import *

matches = re.findall(r"\(\s*([^)]+)\s*\)\s*(\w+)_t", source)
# Convert to Z3 constraints and solve
```

---

## memfd_create Packed Binaries

```python
from Crypto.Cipher import ARC4
cipher = ARC4.new(b"key")
decrypted = cipher.decrypt(encrypted_data)
open("dumped", "wb").write(decrypted)
```

---

## DNS-based C2

```bash
tshark -r capture.pcap -Y "dns.qry.type == 16" \
    -T fields -e dns.qry.name -e dns.txt
```

---

## PyInstaller / Bytecode

```bash
python pyinstxtractor.py packed.exe
```

### Marshal Analysis
```python
import marshal, dis
with open('file.bin', 'rb') as f:
    code = marshal.load(f)
dis.dis(code)
```

### Opcode Remapping
If decompiler fails with opcode errors:
1. Find modified `opcode.pyc`
2. Build mapping to original values
3. Patch target .pyc
4. Decompile normally
