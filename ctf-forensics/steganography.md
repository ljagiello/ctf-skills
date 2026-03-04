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
