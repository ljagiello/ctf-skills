# CTF Forensics - Steganography

## Table of Contents
- [Quick Tools](#quick-tools)
- [Binary Border Steganography](#binary-border-steganography)
- [Multi-Layer PDF Steganography (Pragyan 2026)](#multi-layer-pdf-steganography-pragyan-2026)
- [Advanced PDF Steganography (Nullcon 2026 rdctd series)](#advanced-pdf-steganography-nullcon-2026-rdctd-series)
- [SVG Animation Keyframe Steganography (UTCTF 2024)](#svg-animation-keyframe-steganography-utctf-2024)
- [PNG Chunk Reordering (0xFun 2026)](#png-chunk-reordering-0xfun-2026)
- [File Format Overlays (0xFun 2026)](#file-format-overlays-0xfun-2026)
- [Nested PNG with Iterating XOR Keys (VuwCTF 2025)](#nested-png-with-iterating-xor-keys-vuwctf-2025)
- [JPEG Unused Quantization Table LSB Steganography (EHAX 2026)](#jpeg-unused-quantization-table-lsb-steganography-ehax-2026)
- [BMP Bitplane QR Code Extraction + Steghide (BYPASS CTF 2025)](#bmp-bitplane-qr-code-extraction--steghide-bypass-ctf-2025)
- [Image Jigsaw Puzzle Reassembly via Edge Matching (BYPASS CTF 2025)](#image-jigsaw-puzzle-reassembly-via-edge-matching-bypass-ctf-2025)
- [F5 JPEG DCT Coefficient Ratio Detection (ApoorvCTF 2026)](#f5-jpeg-dct-coefficient-ratio-detection-apoorvctf-2026)
- [PNG Unused Palette Entry Steganography (ApoorvCTF 2026)](#png-unused-palette-entry-steganography-apoorvctf-2026)
- [QR Code Tile Reconstruction (UTCTF 2026)](#qr-code-tile-reconstruction-utctf-2026)
- [Seed-Based Pixel Permutation + Multi-Bitplane QR (L3m0nCTF 2025)](#seed-based-pixel-permutation--multi-bitplane-qr-l3m0nctf-2025)
- [JPEG Thumbnail Pixel-to-Text Mapping (RuCTF 2013)](#jpeg-thumbnail-pixel-to-text-mapping-ructf-2013)
- [Conditional LSB Extraction — Near-Black Pixel Filter (BaltCTF 2013)](#conditional-lsb-extraction--near-black-pixel-filter-baltctf-2013)
- [GIF Frame Differential + Morse Code (BaltCTF 2013)](#gif-frame-differential--morse-code-baltctf-2013)
- [GZSteg + Spammimic Text Steganography (VolgaCTF 2013)](#gzsteg--spammimic-text-steganography-volgactf-2013)
- [Spreadsheet Frequency Analysis Binary Recovery (Sharif CTF 2016)](#spreadsheet-frequency-analysis-binary-recovery-sharif-ctf-2016)
- [JPEG Slack Space Steganography (BSidesSF 2025)](#jpeg-slack-space-steganography-bsidessf-2025)
- [Nearest-Neighbor Interpolation Steganography (BSidesSF 2025)](#nearest-neighbor-interpolation-steganography-bsidessf-2025)

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

## Seed-Based Pixel Permutation + Multi-Bitplane QR (L3m0nCTF 2025)

**Pattern (Lost Signal):** Image with randomized pixel colors hides a QR code. Pixels are visited in a seed-determined permutation order, and data is interleaved across multiple bitplanes of the luminance (Y) channel.

**Extraction workflow:**
1. Convert image to YCbCr and extract Y (luminance) channel
2. Generate the pixel visit order using the known seed
3. Extract LSB bits from multiple bitplanes in interleaved order
4. Reconstruct as a binary image and scan as QR code

```python
from PIL import Image
import numpy as np

SEED = 739391  # Given or brute-forced

# 1. Extract Y channel
img = Image.open("challenge.png").convert("YCbCr")
Y = np.array(img.split()[0], dtype=np.uint8)
h, w = Y.shape

# 2. Generate deterministic pixel permutation
rng = np.random.RandomState(SEED)
perm = np.arange(h * w)
rng.shuffle(perm)

# 3. Extract bits from multiple bitplanes (interleaved)
bitplanes = [0, 1]  # LSB0 and LSB1
total_bits = h * w
bits = np.zeros(total_bits, dtype=np.uint8)

for i in range(total_bits):
    pix_idx = perm[i // len(bitplanes)]
    bp = bitplanes[i % len(bitplanes)]
    y, x = divmod(pix_idx, w)
    bits[i] = (Y[y, x] >> bp) & 1

# 4. Reconstruct QR code
qr = bits.reshape((h, w))
qr_img = Image.fromarray((255 * (1 - qr)).astype(np.uint8))
qr_img.save("recovered_qr.png")
# zbarimg recovered_qr.png
```

**Key insight:** The seed defines a deterministic pixel visit order (Fisher-Yates shuffle via `RandomState`). Without the correct seed, output is random noise. Bits from different bitplanes are interleaved (bit 0 from pixel N, bit 1 from pixel N, bit 0 from pixel N+1, ...), doubling the data density. Try the Y (luminance) channel first — it has the highest contrast for hidden binary data.

**Seed recovery:** If the seed is unknown, look for it in: EXIF metadata, filename, image dimensions, challenge description numbers, or brute-force small ranges.

**Detection:** Image appears as random colored noise but has suspicious dimensions (perfect square, power of 2). Challenge mentions "seed", "random", or "signal".

---

## JPEG Thumbnail Pixel-to-Text Mapping (RuCTF 2013)

**Pattern:** JPEG contains an embedded thumbnail where dark pixels map 1:1 to character positions in visible text on the main image.

```python
from PIL import Image
# Extract thumbnail: exiftool -b -ThumbnailImage secret.jpg > thumb.jpg
thumb = Image.open('thumb.jpg')
text_lines = ["line1 of visible text...", "line2..."]  # OCR or type from photo
result = ''
for y in range(thumb.height):
    for x in range(thumb.width):
        r, g, b = thumb.getpixel((x, y))[:3]
        if r < 100 and g < 100 and b < 100:  # Dark pixel = selected char
            result += text_lines[y][x]
```

**Key insight:** Extract thumbnails with `exiftool -b -ThumbnailImage`. Dark pixels act as a selection mask over the photographed text. Use OCR (ABBYY FineReader, Tesseract) to get the text grid, then map dark thumbnail pixels to character positions.

---

## Conditional LSB Extraction — Near-Black Pixel Filter (BaltCTF 2013)

**Pattern:** Only pixels with R<=1 AND G<=1 AND B<=1 carry steganographic data. Standard LSB tools miss the data because they process all pixels.

```python
from PIL import Image
img = Image.open('image.png')
bits = ''
for pixel in img.getdata():
    r, g, b = pixel[0], pixel[1], pixel[2]
    if not (r <= 1 and g <= 1 and b <= 1):
        continue  # Skip non-carrier pixels
    bits += str(r & 1) + str(g & 1) + str(b & 1)
# Convert bits to bytes
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
```

**Key insight:** When standard `zsteg`/`stegsolve` find nothing, try filtering pixels by value range before LSB extraction. The carrier pixels may be restricted to near-black, near-white, or specific color ranges.

---

## GIF Frame Differential + Morse Code (BaltCTF 2013)

**Pattern:** Animated GIF contains hidden dots visible only when comparing frames against originals. Dots encode Morse code.

```bash
# Extract frames from animated GIF
convert animated.gif frame_%03d.gif

# Compare each frame against its base using ImageMagick
for i in $(seq 1 100); do
    compare -fuzz 10% -compose src stego_$i.gif original_$i.gif diff_$i.gif
done

# Inspect diff images — dots appear at specific positions
# Map dot patterns to Morse: small dot = dit, large dot = dah
```

**Key insight:** `compare -fuzz 10%` reveals subtle single-pixel modifications invisible to the eye. The diff images show isolated dots whose timing/spacing encodes Morse code. Decode dots → dashes/dots → letters → flag.

---

## GZSteg + Spammimic Text Steganography (VolgaCTF 2013)

**Pattern:** Data hidden within gzip compression metadata, decoded through spammimic.com.

1. Apply GZSteg patches to gzip 1.2.4 source, compile, extract with `gzip --s` flag
2. Extracted text resembles spam email — submit to [spammimic.com](https://www.spammimic.com/) decoder
3. Decoded output is the flag

**Key insight:** GZSteg exploits redundancy in the gzip DEFLATE compression format to embed covert data. The extracted payload often uses a second steganographic layer (spammimic encodes data as innocuous-looking spam text). Look for `.gz` files larger than expected for their content.

---

## Spreadsheet Frequency Analysis Binary Recovery (Sharif CTF 2016)

When spreadsheet cells contain numbers with varying frequencies, the frequency rank may encode binary data:

1. **Count occurrences** of each unique value
2. **Sort by frequency** to create a mapping: value -> frequency rank (0-255)
3. **Replace each cell** with its frequency rank to recover raw bytes

```python
from collections import Counter

# Count frequency of each value
freq = Counter(all_cell_values)

# Create mapping: value -> index in frequency-sorted list
sorted_vals = sorted(freq.keys(), key=lambda x: freq[x])
mapping = {v: i for i, v in enumerate(sorted_vals)}

# Apply mapping to recover binary
binary = bytes(mapping[v] for v in all_cell_values)
# Result is typically an ELF binary or image
```

**Key insight:** 256 unique values suggest byte-level encoding. The frequency distribution of the mapped output should resemble typical binary file statistics.

---

## JPEG Slack Space Steganography (BSidesSF 2025)

JPEG compression pads images to 8x8 pixel block boundaries. Data hidden in the padding pixels beyond the visible image dimensions:

1. **Identify padded dimensions:** JPEG rounds up to nearest multiple of 8. A 253x195 image pads to 256x200
2. **Extract slack pixels:** Use tools to extend visible region to true block dimensions

```bash
# Extend image to see slack pixels
python3 jpeg_uncrop.py input.jpg --width 256 --height 200
# Or use ImageMagick to force full decode
magick input.jpg -define jpeg:size=256x200 extended.png
```

3. **Decode binary from slack pixels:** Black=0, white=1 in the padding region. Common encoding:
   - 2 bytes: magic number
   - 1 byte: key length
   - N bytes: encryption key
   - 1 byte: message length
   - N bytes: encrypted message

**Key insight:** Most image editors and viewers crop to the stated dimensions, hiding the padding. Use `jpegtran -crop` or raw DCT decoders to access full block data.

---

## Nearest-Neighbor Interpolation Steganography (BSidesSF 2025)

Hidden data encoded as a pixel grid at regular intervals within a high-resolution image. Downscaling with nearest-neighbor interpolation extracts only the hidden pixels:

```bash
# Hidden pixels spaced 16 apart in a 4096x3072 image
# Downscale by 16x with nearest-neighbor to recover 256x192 hidden image
magick flag.webp -interpolate nearest-neighbor -interpolative-resize 256x192 flag_visible.png
```

**Key insight:** Nearest-neighbor interpolation selects exact pixel values (no blending), preserving the hidden data. Bilinear or bicubic interpolation would average surrounding pixels, destroying the message. The challenge name or description often hints at the interpolation method.

**Detection:** Open in image viewer and zoom to see repeating pixel patterns at regular intervals. Calculate GCD of image dimensions and suspected grid spacing.
