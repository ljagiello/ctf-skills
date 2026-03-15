# CTF Forensics - Steganography

## Table of Contents
- [Quick Tools](#quick-tools)
- [Binary Border Steganography](#binary-border-steganography)
- [Multi-Layer PDF Steganography (Pragyan 2026)](#multi-layer-pdf-steganography-pragyan-2026)
- [Advanced PDF Steganography (Nullcon 2026 rdctd series)](#advanced-pdf-steganography-nullcon-2026-rdctd-series)
- [FFT Frequency Domain Steganography (Pragyan 2026)](#fft-frequency-domain-steganography-pragyan-2026)
- [SSTV Red Herring + LSB Audio Stego (0xFun 2026)](#sstv-red-herring-lsb-audio-stego-0xfun-2026)
- [SVG Animation Keyframe Steganography (UTCTF 2024)](#svg-animation-keyframe-steganography-utctf-2024)
- [PNG Chunk Reordering (0xFun 2026)](#png-chunk-reordering-0xfun-2026)
- [File Format Overlays (0xFun 2026)](#file-format-overlays-0xfun-2026)
- [Nested PNG with Iterating XOR Keys (VuwCTF 2025)](#nested-png-with-iterating-xor-keys-vuwctf-2025)
- [DotCode Barcode via SSTV (0xFun 2026)](#dotcode-barcode-via-sstv-0xfun-2026)
- [DTMF Audio Decoding](#dtmf-audio-decoding)
- [Custom Frequency DTMF / Dual-Tone Keypad Encoding (EHAX 2026)](#custom-frequency-dtmf--dual-tone-keypad-encoding-ehax-2026)
- [JPEG Unused Quantization Table LSB Steganography (EHAX 2026)](#jpeg-unused-quantization-table-lsb-steganography-ehax-2026)
- [Multi-Track Audio Differential Subtraction (EHAX 2026)](#multi-track-audio-differential-subtraction-ehax-2026)
- [BMP Bitplane QR Code Extraction + Steghide (BYPASS CTF 2025)](#bmp-bitplane-qr-code-extraction--steghide-bypass-ctf-2025)
- [Image Jigsaw Puzzle Reassembly via Edge Matching (BYPASS CTF 2025)](#image-jigsaw-puzzle-reassembly-via-edge-matching-bypass-ctf-2025)
- [Cross-Channel Multi-Bit LSB Steganography (ApoorvCTF 2026)](#cross-channel-multi-bit-lsb-steganography-apoorvctf-2026)
- [F5 JPEG DCT Coefficient Ratio Detection (ApoorvCTF 2026)](#f5-jpeg-dct-coefficient-ratio-detection-apoorvctf-2026)
- [PNG Unused Palette Entry Steganography (ApoorvCTF 2026)](#png-unused-palette-entry-steganography-apoorvctf-2026)
- [Audio FFT Musical Note Identification (BYPASS CTF 2025)](#audio-fft-musical-note-identification-bypass-ctf-2025)
- [Audio Metadata Octal Encoding (BYPASS CTF 2025)](#audio-metadata-octal-encoding-bypass-ctf-2025)
- [QR Code Tile Reconstruction (UTCTF 2026)](#qr-code-tile-reconstruction-utctf-2026)
- [Nested Tar Archive with Whitespace Encoding (UTCTF 2026)](#nested-tar-archive-with-whitespace-encoding-utctf-2026)

---

## Quick Tools

```bash
steghide extract -sf image.jpg
zsteg image.png              # PNG/BMP analysis
stegsolve                    # Visual analysis

# Steghide brute-force (0xFun 2026)
stegseek image.jpg rockyou.txt  # Faster than stegcracker
# Common weak passphrases: "simple", "password", "123456"
```

---

## Binary Border Steganography

**Pattern (Framer, PascalCTF 2026):** Message encoded as black/white pixels in 1-pixel border around image.

```python
from PIL import Image

img = Image.open('output.jpg')
w, h = img.size
bits = []

# Read border clockwise: top → right → bottom (reversed) → left (reversed)
for x in range(w): bits.append(0 if sum(img.getpixel((x, 0))[:3]) < 384 else 1)
for y in range(1, h): bits.append(0 if sum(img.getpixel((w-1, y))[:3]) < 384 else 1)
for x in range(w-2, -1, -1): bits.append(0 if sum(img.getpixel((x, h-1))[:3]) < 384 else 1)
for y in range(h-2, 0, -1): bits.append(0 if sum(img.getpixel((0, y))[:3]) < 384 else 1)

# Convert bits to ASCII
msg = ''.join(chr(int(''.join(map(str, bits[i:i+8])), 2)) for i in range(0, len(bits)-7, 8))
```

---

## Multi-Layer PDF Steganography (Pragyan 2026)

**Pattern (epstein files):** Flag hidden across multiple layers in a PDF.

**Layer checklist:**
1. `strings file.pdf | grep -i hidden` -- hidden comments in PDF objects
2. Extract hex strings, try XOR with theme-related keywords
3. Check bytes **after `%%EOF`** marker -- may contain GPG/encrypted data
4. Try ROT18 (ROT13 on letters + ROT5 on digits) as final decode layer

```bash
# Extract post-EOF data
python3 -c "
data = open('file.pdf','rb').read()
eof = data.rfind(b'%%EOF')
print(data[eof+5:].hex())
"
```

---

## Advanced PDF Steganography (Nullcon 2026 rdctd series)

Six distinct hiding techniques in a single PDF:

**1. Invisible text separators:** Underscores rendered as invisible line segments. Extract with `pdftotext -layout` and normalize whitespace to underscores.

**2. URI annotations with escaped braces:** Link annotations contain flag in URI with `\{` and `\}` escapes:
```python
import pikepdf
pdf = pikepdf.Pdf.open(pdf_path)
for page in pdf.pages:
    for annot in (page.get("/Annots") or []):
        obj = annot.get_object()
        if obj.get("/Subtype") == pikepdf.Name("/Link"):
            uri = str(obj.get("/A").get("/URI")).replace(r"\{", "{").replace(r"\}", "}")
            # Check for flag pattern
```

**3. Blurred/redacted image with Wiener deconvolution:**
```python
from skimage.restoration import wiener
import numpy as np

def gaussian_psf(sigma):
    k = int(sigma * 6 + 1) | 1
    ax = np.arange(-(k//2), k//2 + 1, dtype=np.float32)
    xx, yy = np.meshgrid(ax, ax)
    psf = np.exp(-(xx**2 + yy**2) / (2 * sigma * sigma))
    return psf / psf.sum()

img_arr = np.asarray(img.convert("L")).astype(np.float32) / 255.0
deconv = wiener(img_arr, gaussian_psf(3.0), balance=0.003, clip=False)
```

**4. Vector rectangle QR code:** Hundreds of tiny filled rectangles (e.g., 1.718x1.718 units) forming a QR code. Parse PDF content stream for `re` operators, extract centers, render as grid, decode with `zbarimg`.

**5. Compressed object streams:** Use `mutool clean -d -c -m input.pdf output.pdf` to decompress all streams, then `strings` to search.

**6. Document metadata:** Check Producer, Author, Keywords fields: `pdfinfo doc.pdf` or `exiftool doc.pdf`.

**Official writeup details (Nullcon 2026 rdctd 1-6):**
- **rdctd 1:** Flag is visible in plain text (Section 3.4)
- **rdctd 2:** Flag in hyperlink URI with escaped braces (`\{`, `\}`)
- **rdctd 3:** LSB stego in Blue channel, **bit plane 5** (not bit 0!). Use `zsteg` with all planes: `zsteg -a extracted.ppm | grep ENO`
- **rdctd 4:** QR code hidden under black redaction box. Use Master PDF Editor to remove the box, scan QR
- **rdctd 5:** Flag in FlateDecode compressed stream (not visible with `strings`):
  ```python
  import re, zlib
  pdf = open('file.pdf', 'rb').read()
  for s in re.findall(b'stream[\r\n]+(.*?)[\r\n]+endstream', pdf, re.S):
      try:
          dec = zlib.decompress(s)
          if b'ENO{' in dec: print(dec)
      except: pass
  ```
- **rdctd 6:** Flag in `/Producer` metadata field

**Comprehensive PDF flag hunt checklist:**
1. `strings -a file.pdf | grep -o 'FLAG_FORMAT{[^}]*}'`
2. `exiftool file.pdf` (all metadata fields)
3. `pdfimages -all file.pdf img` + `zsteg -a img-*.ppm`
4. Open in PDF editor, check for overlay/redaction boxes hiding content
5. Decompress FlateDecode streams and search
6. Parse link annotations for URIs with escaped characters
7. `mutool clean -d file.pdf clean.pdf && strings clean.pdf`

---

## FFT Frequency Domain Steganography (Pragyan 2026)

**Pattern (H@rDl4u6H):** Image encodes data in frequency domain via 2D FFT.

**Decoding workflow:**
```python
import numpy as np
from PIL import Image

img = np.array(Image.open("image.png")).astype(float)
F = np.fft.fftshift(np.fft.fft2(img))
mag = np.log(1 + np.abs(F))

# Look for patterns: concentric rings, dots at specific positions
# Bright peak = 0 bit, Dark (no peak) = 1 bit
cy, cx = mag.shape[0]//2, mag.shape[1]//2
radii = [100 + 69*i for i in range(21)]  # Example spacing
angles = [0, 22.5, 45, 67.5, 90, 112.5, 135, 157.5]
THRESHOLD = 13.0

bits = []
for r in radii:
    byte_val = 0
    for a in angles:
        fx = cx + r * np.cos(np.radians(a))
        fy = cy - r * np.sin(np.radians(a))
        bit = 0 if mag[int(round(fy)), int(round(fx))] > THRESHOLD else 1
        byte_val = (byte_val << 1) | bit
    bits.append(byte_val)
```

**Identification:** Challenge mentions "transform", poem about "frequency", or image looks blank/noisy. Try FFT visualization first.

---

## SSTV Red Herring + LSB Audio Stego (0xFun 2026)

**Pattern (Melodie):** WAV contains SSTV signal (Scottie 1) that decodes to "SEEMS LIKE A DEADEND". Real flag in 2-bit LSB of audio samples.

```bash
# Decode SSTV (red herring)
qsstv  # Will show decoy message

# Extract real flag from LSB
pip install stego-lsb
stegolsb wavsteg -r -i audio.wav -o out.bin -n 2 -b 1000
```

**Lesson:** Obvious signals may be decoys. Always check LSB even when another encoding is found.

---

## SVG Animation Keyframe Steganography (UTCTF 2024)

**Pattern (Insanity Check):** SVG favicon contains animation keyframes with alternating fill colors.

**Encoding:** `#FFFF` = 1, `#FFF6` = 0. Timing intervals (~0.314s or 3x0.314s) encode Morse code dots/dashes.

**Detection:** SVG files with `<animate>` tags, `keyTimes`/`values` attributes. Check favicon.svg and other vector assets. Two-value alternation patterns encode binary or Morse.

---

## PNG Chunk Reordering (0xFun 2026)

**Pattern (Spectrum):** Invalid PNG has chunks out of order.

**Fix:** Reorder to: `signature + IHDR + (ancillary chunks) + (all IDAT in order) + IEND`.

```python
import struct

with open('broken.png', 'rb') as f:
    data = f.read()

sig = data[:8]
chunks = []
pos = 8
while pos < len(data):
    length = struct.unpack('>I', data[pos:pos+4])[0]
    chunk_type = data[pos+4:pos+8]
    chunk_data = data[pos+8:pos+8+length]
    crc = data[pos+8+length:pos+12+length]
    chunks.append((chunk_type, length, chunk_data, crc))
    pos += 12 + length

# Sort: IHDR first, IEND last, IDATs in original order
ihdr = [c for c in chunks if c[0] == b'IHDR']
idat = [c for c in chunks if c[0] == b'IDAT']
iend = [c for c in chunks if c[0] == b'IEND']
other = [c for c in chunks if c[0] not in (b'IHDR', b'IDAT', b'IEND')]

with open('fixed.png', 'wb') as f:
    f.write(sig)
    for typ, length, data, crc in ihdr + other + idat + iend:
        f.write(struct.pack('>I', length) + typ + data + crc)
```

---

## File Format Overlays (0xFun 2026)

**Pattern (Pixel Rehab):** Archive appended after PNG IEND, but magic bytes overwritten with PNG signature.

**Detection:** Check bytes after IEND for appended data. Compare magic bytes against known formats.

```python
# Find IEND, check what follows
data = open('image.png', 'rb').read()
iend_pos = data.find(b'IEND') + 8  # After IEND + CRC
trailer = data[iend_pos:]
# Replace first 6 bytes with 7z magic if they match PNG sig
if trailer[:4] == b'\x89PNG':
    trailer = b'\x37\x7a\xbc\xaf\x27\x1c' + trailer[6:]
    open('hidden.7z', 'wb').write(trailer)
```

---

## Nested PNG with Iterating XOR Keys (VuwCTF 2025)

**Pattern (Matroiska):** Each PNG layer XOR-encrypted with incrementing keys ("layer2", "layer3", etc.).

**Identification:** Matryoshka/nested hints. Try incrementing key patterns for recursive extraction.

---

## DotCode Barcode via SSTV (0xFun 2026)

**Pattern (Dots):** SSTV decoding produces dot pattern image. Not QR — it's DotCode format.

**Identification:** Dot pattern that isn't a standard QR code. DotCode is a 2D barcode optimized for high-speed printing.

**Tool:** Aspose online DotCode reader (free).

---

## DTMF Audio Decoding

**Pattern (Phone Home):** Audio file contains phone dialing tones encoding data.

```bash
# Decode DTMF tones
sox phonehome.wav -t raw -r 22050 -e signed-integer -b 16 -c 1 - | \
    multimon-ng -t raw -a DTMF -
```

**Post-processing:** Phone number may contain octal-encoded ASCII after delimiter (#):
```python
# Convert octal groups to ASCII
octal_groups = ["115", "145", "164", "141"]  # M, e, t, a
flag = ''.join(chr(int(g, 8)) for g in octal_groups)
```

---

## Custom Frequency DTMF / Dual-Tone Keypad Encoding (EHAX 2026)

**Pattern (Quantum Message):** Audio with dual-tone sequences at non-standard frequencies, aligned at regular intervals (e.g., every 1 second). Hints about "harmonic oscillators" or physics point to custom frequency design.

**Identification:** Spectrogram shows two distinct frequency sets that don't match standard DTMF (697-1633 Hz). Look for evenly-spaced rows/columns of frequency tones.

**Decoding workflow:**
```python
import numpy as np
from scipy.io import wavfile

rate, audio = wavfile.read('challenge.wav')

# 1. Generate spectrogram to identify frequency grid
# Use ffmpeg: ffmpeg -i challenge.wav -lavfi showspectrumpic=s=1920x1080 spec.png

# 2. Map frequencies to keypad (custom grid, NOT standard DTMF)
# Example: rows = [301, 902, 1503, 2104] Hz, cols = [2705, 3306, 3907] Hz
# Forms 4x3 keypad -> digits 0-9 + symbols

# 3. Extract tone pairs per time window
window_size = rate  # 1 second per symbol
for i in range(0, len(audio), window_size):
    segment = audio[i:i+window_size]
    freqs = np.fft.rfftfreq(len(segment), 1/rate)
    magnitude = np.abs(np.fft.rfft(segment))
    # Find two dominant peaks -> map to row/col -> digit

# 4. Convert digit sequence to ASCII
# Split digits into variable-length groups (ASCII range 32-126)
# E.g., "72101108108111" -> [72, 101, 108, 108, 111] -> "Hello"
def digits_to_ascii(digits):
    result, i = [], 0
    while i < len(digits):
        for length in [2, 3]:  # ASCII codes are 2-3 digits
            if i + length <= len(digits):
                val = int(digits[i:i+length])
                if 32 <= val <= 126:
                    result.append(chr(val))
                    i += length
                    break
        else:
            i += 1
    return ''.join(result)
```

**Key insight:** When tones don't match standard DTMF frequencies, generate a spectrogram first to identify the custom frequency grid. The mapping is challenge-specific.

---

## JPEG Unused Quantization Table LSB Steganography (EHAX 2026)

**Pattern (Jpeg Soul):** "Insignificant" hint points to least significant bits in JPEG quantization tables (DQT). JPEG can embed DQT tables (ID 2, 3) that are never referenced by frame markers — invisible to renderers but carry hidden data.

**Detection:** JPEG has more DQT tables than components reference. Standard JPEG uses 2 tables (luminance + chrominance); extra tables with IDs 2, 3 are suspicious.

```python
from PIL import Image

img = Image.open('challenge.jpg')

# Access quantization tables (PIL exposes them as dict)
# Standard: tables 0 (luminance) and 1 (chrominance)
# Hidden: tables 2, 3 (unreferenced by SOF marker)
qtables = img.quantization

bits = []
for table_id in sorted(qtables.keys()):
    if table_id >= 2:  # Unused tables
        table = qtables[table_id]
        for i in range(64):  # 8x8 = 64 values per DQT
            bits.append(table[i] & 1)  # Extract LSB

# Convert bits to ASCII
flag = ''
for i in range(0, len(bits) - 7, 8):
    byte = int(''.join(str(b) for b in bits[i:i+8]), 2)
    if 32 <= byte <= 126:
        flag += chr(byte)
print(flag)
```

**Manual DQT extraction (when PIL doesn't expose all tables):**
```python
# Parse JPEG manually to find all DQT markers (0xFFDB)
data = open('challenge.jpg', 'rb').read()
pos = 0
while pos < len(data) - 1:
    if data[pos] == 0xFF and data[pos+1] == 0xDB:
        length = int.from_bytes(data[pos+2:pos+4], 'big')
        dqt_data = data[pos+4:pos+2+length]
        table_id = dqt_data[0] & 0x0F
        precision = (dqt_data[0] >> 4) & 0x0F  # 0=8-bit, 1=16-bit
        values = list(dqt_data[1:65]) if precision == 0 else []
        print(f"DQT table {table_id}: {values[:8]}...")
        pos += 2 + length
    else:
        pos += 1
```

**Key insight:** JPEG quantization tables are metadata — they survive recompression and most image processing. Unused table IDs (2-15) can carry arbitrary data without affecting the image.

---

## BMP Bitplane QR Code Extraction + Steghide (BYPASS CTF 2025)

**Pattern (Gold Challenge):** BMP image with QR code hidden in a specific bitplane. Extract the QR code to obtain a steghide password.

**Technique:** Extract individual bitplanes (bits 0-2) for each RGB channel, render as images, scan for QR codes.

```python
from PIL import Image
import numpy as np

img = Image.open('challenge.bmp')
pixels = np.array(img)

# Extract individual bitplanes
for ch_idx, ch_name in enumerate(['R', 'G', 'B']):
    for bit in range(3):  # Check bits 0, 1, 2
        channel = pixels[:, :, ch_idx]
        bit_plane = ((channel >> bit) & 1) * 255
        Image.fromarray(bit_plane.astype(np.uint8)).save(f'bit_{ch_name}_{bit}.png')

# Combined LSB across all channels
lsb_img = np.zeros_like(pixels)
for ch in range(3):
    lsb_img[:, :, ch] = (pixels[:, :, ch] & 1) * 255
Image.fromarray(lsb_img).save('lsb_all.png')
```

**Full attack chain:**
1. Extract bitplanes → find QR code in specific bitplane (often bit 1, not bit 0)
2. Scan QR with `zbarimg bit_G_1.png` → get steghide password
3. `steghide extract -sf challenge.bmp -p <password>` → extract hidden file

**Key insight:** Standard LSB (least significant bit) tools check bit 0 only. Hidden QR codes may be in bit 1 or bit 2 — always check multiple bitplanes systematically. BMP format preserves exact pixel values (no compression artifacts).

---

## Image Jigsaw Puzzle Reassembly via Edge Matching (BYPASS CTF 2025)

**Pattern (Jigsaw Puzzle):** Archive containing multiple puzzle piece images that must be reassembled into the original image. Reassembled image contains the flag (possibly ROT13 encoded).

**Technique:** Compute pixel intensity differences at shared edges between all piece pairs, then greedily place pieces to minimize total edge difference.

```python
from PIL import Image
import numpy as np
import os

# Load all pieces
pieces = {}
for f in sorted(os.listdir('pieces/')):
    pieces[f] = np.array(Image.open(f'pieces/{f}'))

piece_list = list(pieces.keys())
n = len(piece_list)
grid_size = int(n ** 0.5)  # e.g., 25 pieces → 5x5

# Calculate edge compatibility
def edge_diff(img1, img2, direction):
    if direction == 'right':
        return np.sum(np.abs(img1[:, -1].astype(int) - img2[:, 0].astype(int)))
    elif direction == 'bottom':
        return np.sum(np.abs(img1[-1, :].astype(int) - img2[0, :].astype(int)))

# Build compatibility matrices
right_compat = np.full((n, n), float('inf'))
bottom_compat = np.full((n, n), float('inf'))
for i in range(n):
    for j in range(n):
        if i != j:
            right_compat[i, j] = edge_diff(pieces[piece_list[i]], pieces[piece_list[j]], 'right')
            bottom_compat[i, j] = edge_diff(pieces[piece_list[i]], pieces[piece_list[j]], 'bottom')

# Greedy placement
grid = [[None] * grid_size for _ in range(grid_size)]
used = set()
for row in range(grid_size):
    for col in range(grid_size):
        best_piece, best_diff = None, float('inf')
        for idx in range(n):
            if idx in used:
                continue
            diff = 0
            if col > 0:
                diff += right_compat[grid[row][col-1], idx]
            if row > 0:
                diff += bottom_compat[grid[row-1][col], idx]
            if diff < best_diff:
                best_diff, best_piece = diff, idx
        grid[row][col] = best_piece
        used.add(best_piece)

# Reassemble
piece_h, piece_w = pieces[piece_list[0]].shape[:2]
final = Image.new('RGB', (grid_size * piece_w, grid_size * piece_h))
for row in range(grid_size):
    for col in range(grid_size):
        final.paste(Image.open(f'pieces/{piece_list[grid[row][col]]}'),
                     (col * piece_w, row * piece_h))
final.save('reassembled.png')
```

**Post-processing:** Check if reassembled image text is ROT13 encoded. Decode with `tr 'A-Za-z' 'N-ZA-Mn-za-m'`.

**Key insight:** Edge-matching works by minimizing pixel differences at shared borders. The greedy approach (place piece with smallest total edge difference to already-placed neighbors) works well for most CTF puzzles. For harder puzzles, add backtracking.

---

## Audio FFT Musical Note Identification (BYPASS CTF 2025)

**Pattern (Piano):** Identify dominant frequencies via FFT (Fast Fourier Transform), map to musical notes (A-G), then read the letter names as a word.

**Technique:** Perform FFT on audio, identify dominant frequencies, map to musical notes.

```python
import numpy as np
from scipy.io import wavfile

rate, audio = wavfile.read('challenge.wav')
if audio.ndim > 1:
    audio = audio[:, 0]  # mono

# FFT to find dominant frequencies
freqs = np.fft.rfftfreq(len(audio), 1/rate)
magnitude = np.abs(np.fft.rfft(audio))

# Find top peaks
peak_indices = np.argsort(magnitude)[-20:]
peak_freqs = sorted(set(round(freqs[i]) for i in peak_indices if freqs[i] > 20))

# Musical note frequency mapping (A4 = 440 Hz)
NOTE_FREQS = {
    'C4': 261.63, 'D4': 293.66, 'E4': 329.63, 'F4': 349.23,
    'G4': 392.00, 'A4': 440.00, 'B4': 493.88,
    'C5': 523.25, 'D5': 587.33, 'E5': 659.25, 'F5': 698.46,
    'G5': 783.99, 'A5': 880.00, 'B5': 987.77,
}

def freq_to_note(freq):
    return min(NOTE_FREQS.items(), key=lambda x: abs(x[1] - freq))[0]

notes = [freq_to_note(f) for f in peak_freqs]
# Extract letter names: B, A, D, F, A, C, E → "BADFACE"
answer = ''.join(n[0] for n in notes)
print(f"Notes: {notes}")
print(f"Answer: {answer}")
```

**Extract and examine audio metadata** using `exiftool audio.mp3` for encoded hints in comment fields (e.g., octal-separated values → base64 → decoded hint).

**Key insight:** Musical note names (A-G) can spell words. When a challenge involves music/piano, identify dominant frequencies via FFT and read the note letter names as text.

---

## Audio Metadata Octal Encoding (BYPASS CTF 2025)

**Pattern (Piano metadata):** Audio file metadata (exiftool comment field) contains underscore-separated numbers representing octal-encoded ASCII values (digits 0-7 only).

```python
# Extract and decode octal metadata
import subprocess, base64

# Get metadata comment
comment = "103_137_63_157_144_145_144_40_162_145_154_151_143"
octal_values = comment.split('_')
decoded = ''.join(chr(int(v, 8)) for v in octal_values)

# May decode to base64, requiring another layer
result = base64.b64decode(decoded).decode()
print(result)
```

**Key insight:** When metadata contains underscore-separated numbers, try octal (digits 0-7 only), decimal, or hex interpretation. Multi-layer encoding (octal → base64 → plaintext) is common.

---

## QR Code Tile Reconstruction (UTCTF 2026)

**Pattern (QRecreate):** QR code split into tiles/pieces that must be reassembled. Tiles may be scrambled, rotated, or have missing alignment patterns.

**Reconstruction workflow:**
```python
from PIL import Image
import numpy as np

# Load scrambled tiles
tiles = []
for i in range(N_TILES):
    tile = Image.open(f'tile_{i}.png')
    tiles.append(np.array(tile))

# Strategy 1: Edge matching (like jigsaw puzzle)
# Each tile edge has a unique bit pattern — match adjacent edges
def edge_signature(tile, side):
    if side == 'top': return tuple(tile[0, :].flatten())
    if side == 'bottom': return tuple(tile[-1, :].flatten())
    if side == 'left': return tuple(tile[:, 0].flatten())
    if side == 'right': return tuple(tile[:, -1].flatten())

# Strategy 2: QR structure constraints
# - Finder patterns (large squares) MUST be at 3 corners
# - Timing patterns (alternating B/W) run between finders
# - Use these as anchors to orient remaining tiles

# Strategy 3: Brute force small grids
# For 3x3 or 4x4 grids, try all permutations and scan with zbarimg
from itertools import permutations
import subprocess

grid_size = 3
tile_size = tiles[0].shape[0]
for perm in permutations(range(len(tiles))):
    img = Image.new('L', (grid_size * tile_size, grid_size * tile_size))
    for idx, tile_idx in enumerate(perm):
        row, col = divmod(idx, grid_size)
        img.paste(Image.fromarray(tiles[tile_idx]),
                  (col * tile_size, row * tile_size))
    img.save('/tmp/qr_attempt.png')
    result = subprocess.run(['zbarimg', '/tmp/qr_attempt.png'],
                          capture_output=True, text=True)
    if result.stdout.strip():
        print(f"DECODED: {result.stdout}")
        break
```

**Key insight:** QR codes have structural constraints (finder patterns, timing patterns, format info) that drastically reduce the search space. Use QR structure as anchors before brute-forcing tile positions.

---

## Nested Tar Archive with Whitespace Encoding (UTCTF 2026)

**Pattern (Silent Archive):** Deeply nested tar archives where data is encoded in whitespace characters (spaces, tabs, newlines) within file names or content.

**Detection:** Archive extracts to another archive (tar-in-tar chain). File content appears empty but contains invisible whitespace characters.

**Decoding workflow:**
```python
import tarfile
import os

# 1. Recursively extract nested tar archives
def extract_all(path, depth=0):
    if depth > 100:  # Guard against infinite nesting
        return
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as tf:
            tf.extractall(f'layer_{depth}')
            for member in tf.getmembers():
                extract_all(f'layer_{depth}/{member.name}', depth + 1)

# 2. Collect whitespace from file names or content
whitespace_data = []
for root, dirs, files in os.walk('layer_0'):
    for f in files:
        path = os.path.join(root, f)
        with open(path, 'rb') as fh:
            content = fh.read()
            # Check for whitespace-only content
            if content.strip() == b'':
                for byte in content:
                    if byte == 0x20:  # space
                        whitespace_data.append('0')
                    elif byte == 0x09:  # tab
                        whitespace_data.append('1')

# 3. Convert binary from whitespace
bits = ''.join(whitespace_data)
message = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
print(message.decode(errors='replace'))
```

**Whitespace encoding variants:**
- Space = 0, Tab = 1 (binary encoding)
- Whitespace Steganography: trailing spaces/tabs at end of lines
- Zero-width characters (U+200B, U+200C, U+FEFF) in Unicode text
- Number of spaces between words encodes data

**Key insight:** "Silent" or "invisible" hints point to whitespace encoding. Use `xxd` or `cat -A` to reveal hidden whitespace characters. Deeply nested archives are misdirection — the data is in the whitespace, not the nesting depth.

---

## Multi-Track Audio Differential Subtraction (EHAX 2026)

**Pattern (Penguin):** MKV/video file with two nearly-identical audio tracks. Hidden data is embedded as a tiny difference between the tracks, invisible when listening to either individually.

**Identification:**
- `ffprobe` reveals multiple audio streams (e.g., two stereo FLAC tracks)
- Metadata may contain a decoy flag (e.g., in comments)
- Track labels may be misleading (e.g., stereo labeled as "5.1 surround")
- `sox --info` / `sox -n stat` shows nearly identical RMS, amplitude, and frequency statistics for both tracks

**Extraction workflow:**
```bash
# 1. Extract both audio tracks
ffmpeg -i challenge.mkv -map 0:a:0 -c copy track0.flac
ffmpeg -i challenge.mkv -map 0:a:1 -c copy track1.flac

# 2. Convert to WAV for processing
ffmpeg -i track0.flac track0.wav
ffmpeg -i track1.flac track1.wav

# 3. Subtract: invert one track and mix (cancels shared content)
sox -m track0.wav "|sox track1.wav -p vol -1" diff.wav

# 4. Normalize the difference signal
sox diff.wav diff_norm.wav gain -n -3

# 5. Generate spectrogram to read the flag
sox diff_norm.wav -n spectrogram -o spectrogram.png -X 2000 -Y 1000 -z 100 -h

# 6. Optional: filter to isolate flag frequency range
sox diff_norm.wav filtered.wav sinc 5000-12000
sox filtered.wav -n spectrogram -o filtered_spec.png -X 2000 -Y 1000 -z 100 -h
```

**Key insight:** When two audio tracks are nearly identical, subtracting one from the other (phase inversion + mix) cancels shared content and isolates hidden data. The flag is typically encoded as text in the spectrogram of the difference signal, visible in a specific frequency band (e.g., 5-12 kHz).

**Common traps:**
- Decoy flags in metadata/comments — always verify
- Mislabeled channel configurations (stereo as 5.1)
- Flag may only be visible in a narrow time window — use high-resolution spectrogram (`-X 2000+`)

---

## Cross-Channel Multi-Bit LSB Steganography (ApoorvCTF 2026)

**Pattern (Beneath the Armor):** Standard LSB tools (zsteg, stegsolve) fail because different bit positions are used per RGB channel: Red channel bit 0, Green channel bit 1, Blue channel bit 2.

```python
from PIL import Image

img = Image.open("challenge.png")
pixels = img.load()
bits = []
for y in range(img.height):
    for x in range(img.width):
        r, g, b = pixels[x, y][:3]
        bits.append((r >> 0) & 1)  # Red: bit 0
        bits.append((g >> 1) & 1)  # Green: bit 1
        bits.append((b >> 2) & 1)  # Blue: bit 2

# Pack 3 bits per pixel into bytes
data = bytearray()
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    data.append(byte)
print(data.decode('ascii', errors='ignore'))
```

**Key insight:** When standard LSB tools find nothing, the data may use different bit positions per channel. The hint "cycles" or "modular" suggests cycling through bit positions (0→1→2) across channels. Always try non-standard bit combinations: R[0]G[1]B[2], R[1]G[2]B[0], R[2]G[0]B[1], etc.

**Detection:** Standard `zsteg -a` and `stegsolve` produce no results on an image that metadata hints contain hidden data.

---

## F5 JPEG DCT Coefficient Ratio Detection (ApoorvCTF 2026)

**Pattern (Engraver's Fault):** Detect F5 steganography in JPEG images by analyzing DCT coefficient distributions. F5 decrements ±1 AC coefficients toward 0, creating a measurable ratio shift.

**Detection metric — ±1/±2 AC coefficient ratio:**
```python
import numpy as np
from PIL import Image
import jpegio  # or use jpeg_toolbox

def f5_ratio(jpeg_path):
    """Ratio below 0.15 indicates F5 modification; above 0.20 indicates clean."""
    jpg = jpegio.read(jpeg_path)
    coeffs = jpg.coef_arrays[0].flatten()  # Luminance Y channel
    coeffs = coeffs[coeffs != 0]  # Remove DC/zeros
    count_1 = np.sum(np.abs(coeffs) == 1)
    count_2 = np.sum(np.abs(coeffs) == 2)
    return count_1 / max(count_2, 1)
```

**Sparse image edge case:** Images with >80% zero DCT coefficients give misleading ±1/±2 ratios. Use a secondary metric:
```python
def f5_sparse_check(jpeg_path):
    """For sparse images, ±2/±3 ratio below 2.5 indicates modification."""
    jpg = jpegio.read(jpeg_path)
    coeffs = jpg.coef_arrays[0].flatten()
    count_2 = np.sum(np.abs(coeffs) == 2)
    count_3 = np.sum(np.abs(coeffs) == 3)
    return count_2 / max(count_3, 1)

# Combined classifier:
r12 = f5_ratio(path)
r23 = f5_sparse_check(path)
is_modified = r12 < 0.15 or (r12 < 0.25 and r23 < 2.5)
```

**Key insight:** F5 steganography shifts ±1 coefficients toward 0, reducing the ±1/±2 ratio. Natural JPEGs have ratio 0.25-0.45; F5-modified drop below 0.10. Sparse images (mostly flat/white) need the secondary ±2/±3 metric because their ±1 counts are inherently low.

---

## PNG Unused Palette Entry Steganography (ApoorvCTF 2026)

**Pattern (The Gotham Files):** Paletted PNG (8-bit indexed color) hides data in palette entries that no pixel references. The image uses indices 0-199 but the PLTE chunk has 256 entries — indices 200-255 contain hidden ASCII in their red channel values.

```python
from PIL import Image
import struct

def extract_unused_plte(png_path):
    img = Image.open(png_path)
    palette = img.getpalette()  # Flat list: [R0,G0,B0, R1,G1,B1, ...]
    pixels = list(img.getdata())
    used_indices = set(pixels)

    # Extract red channel from unused palette entries
    flag = ''
    for i in range(256):
        if i not in used_indices:
            r = palette[i * 3]  # Red channel
            if 32 <= r <= 126:
                flag += chr(r)
    return flag
```

**Key insight:** PNG palette can have up to 256 entries but images typically use fewer. Unused entries are invisible to viewers but persist in the file. Metadata hints like "collector", "the entries that don't make it to the page", or "red light" point to this technique. Always check which palette indices are actually referenced vs. allocated.
