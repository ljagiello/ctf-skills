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
