# CTF Forensics - Advanced Steganography

## Table of Contents
- [FFT Frequency Domain Steganography (Pragyan 2026)](#fft-frequency-domain-steganography-pragyan-2026)
- [SSTV Red Herring + LSB Audio Stego (0xFun 2026)](#sstv-red-herring--lsb-audio-stego-0xfun-2026)
- [DotCode Barcode via SSTV (0xFun 2026)](#dotcode-barcode-via-sstv-0xfun-2026)
- [DTMF Audio Decoding](#dtmf-audio-decoding)
- [Custom Frequency DTMF / Dual-Tone Keypad Encoding (EHAX 2026)](#custom-frequency-dtmf--dual-tone-keypad-encoding-ehax-2026)
- [Multi-Track Audio Differential Subtraction (EHAX 2026)](#multi-track-audio-differential-subtraction-ehax-2026)
- [Cross-Channel Multi-Bit LSB Steganography (ApoorvCTF 2026)](#cross-channel-multi-bit-lsb-steganography-apoorvctf-2026)
- [Audio FFT Musical Note Identification (BYPASS CTF 2025)](#audio-fft-musical-note-identification-bypass-ctf-2025)
- [Audio Metadata Octal Encoding (BYPASS CTF 2025)](#audio-metadata-octal-encoding-bypass-ctf-2025)
- [Nested Tar Archive with Whitespace Encoding (UTCTF 2026)](#nested-tar-archive-with-whitespace-encoding-utctf-2026)
- [Audio Waveform Binary Encoding (BackdoorCTF 2013)](#audio-waveform-binary-encoding-backdoorctf-2013)
- [Audio Spectrogram Hidden QR Code (BaltCTF 2013)](#audio-spectrogram-hidden-qr-code-baltctf-2013)
- [Video Frame Accumulation for Hidden Image (ASIS CTF Finals 2013)](#video-frame-accumulation-for-hidden-image-asis-ctf-finals-2013)
- [Reversed Audio Hidden Message (ASIS CTF Finals 2013)](#reversed-audio-hidden-message-asis-ctf-finals-2013)
- [Video Frame Averaging for Hidden Content (SECCON 2015)](#video-frame-averaging-for-hidden-content-seccon-2015)
- [JPEG XL TOC Permutation Steganography (BSidesSF 2026)](#jpeg-xl-toc-permutation-steganography-bsidessf-2026)

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

## Audio Waveform Binary Encoding (BackdoorCTF 2013)

**Pattern:** WAV file contains two distinct waveform shapes representing binary 0 and 1. Group 8 bits into bytes and decode as ASCII.

```python
import wave, struct
wf = wave.open('audio.wav', 'rb')
frames = wf.readframes(wf.getnframes())
samples = struct.unpack(f'{len(frames)//2}h', frames)

# Identify two distinct wave patterns (e.g., positive peak vs flat)
# Segment audio into fixed-length windows, classify each as 0 or 1
bits = ''
window = len(samples) // num_bits
for i in range(num_bits):
    segment = samples[i*window:(i+1)*window]
    bits += '1' if max(segment) > threshold else '0'

# Decode binary to ASCII
flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-7, 8))
```

**Key insight:** Open in Audacity and zoom in — two visually distinct wave patterns alternate. Each pattern represents one bit. Count the patterns, group into 8-bit bytes, decode as ASCII.

---

## Audio Spectrogram Hidden QR Code (BaltCTF 2013)

**Pattern:** Audio file contains visual data hidden in the frequency domain, visible only in a spectrogram view.

```bash
# Generate spectrogram image
sox audio.mp3 -n spectrogram -o spec.png
# Or use Sonic Visualiser for interactive exploration

# Look for visual patterns in specific frequency bands (often 5-12 kHz)
# Extract/assemble QR code fragments from spectrogram
# Scan with: zbarimg assembled_qr.png
```

**Key insight:** Use Sonic Visualiser (Layer → Add Spectrogram) with adjustable window size and color mapping. QR codes or text often appear in the 2-15 kHz band. Multiple spectrogram fragments may need to be stitched together in an image editor before scanning.

---

## Video Frame Accumulation for Hidden Image (ASIS CTF Finals 2013)

**Pattern:** Video shows small images (icons, shapes) flashing briefly at different screen positions. Individual frames appear random, but the positions trace out a hidden pattern (QR code, text, image) when all frames are composited together.

**Extraction workflow:**

1. Extract individual frames from the video:
```bash
ffmpeg -i challenge.mp4 -vsync 0 frames/frame_%04d.png
```

2. Composite all frames by taking the maximum (or union) of all pixel values:
```python
from PIL import Image
import os

frames_dir = 'frames'
frame_files = sorted(os.listdir(frames_dir))

# Load first frame as base
base = Image.open(os.path.join(frames_dir, frame_files[0])).convert('L')

# Accumulate: take maximum pixel value across all frames
import numpy as np
accumulated = np.array(base, dtype=np.float64)
for f in frame_files[1:]:
    frame = np.array(Image.open(os.path.join(frames_dir, f)).convert('L'), dtype=np.float64)
    accumulated = np.maximum(accumulated, frame)

result = Image.fromarray(accumulated.astype(np.uint8))
result.save('accumulated.png')
```

3. Alternative: convert to GIF and delete the black background frame in GIMP to see all positions overlaid.

4. Clean up the revealed pattern (e.g., QR code) — select foreground, grow/shrink selection, flood fill, scale to expected dimensions (e.g., 21x21 for Version 1 QR):
```bash
# Scan for QR code
zbarimg accumulated.png
```

**Key insight:** When a video shows objects flashing at seemingly random positions, composite all frames together. The positions themselves encode the hidden data — each frame contributes one pixel/cell to a larger image. Convert to GIF for frame-by-frame inspection in GIMP, or use PIL/NumPy to take per-pixel maximum across all frames.

---

## Reversed Audio Hidden Message (ASIS CTF Finals 2013)

**Pattern:** Audio track (standalone or extracted from video) sounds garbled or unintelligible. Playing it in reverse reveals speech, numbers, or other meaningful content.

**Extraction and reversal:**
```bash
# Extract audio from video
ffmpeg -i challenge.mp4 -vn -acodec pcm_s16le audio.wav

# Reverse audio
sox audio.wav reversed.wav reverse
# Or: ffmpeg -i audio.wav -af areverse reversed.wav

# Play to hear hidden message
play reversed.wav
```

**Alternative:** Open in Audacity → Effect → Reverse. Listen for speech, numbers, or encoded data.

**Key insight:** Reversed audio is one of the simplest audio steganography techniques. If audio sounds like garbled speech with recognizable cadence, try reversing it first. The hidden content is often a numeric string (e.g., an MD5 hash) or instructions for the next step of the challenge. Check both the audio and video tracks of multimedia files independently.

---

## Video Frame Averaging for Hidden Content (SECCON 2015)

Extract content hidden across multiple video frames by temporal averaging:

```python
import numpy as np
from PIL import Image
import glob

frames = sorted(glob.glob('frames/*.png'))
N = len(frames)

# Accumulate frames as floating-point to preserve precision
acc = np.zeros(np.array(Image.open(frames[0])).shape, dtype=np.float64)
for f in frames:
    acc += np.array(Image.open(f), dtype=np.float64) / N

# Convert back to uint8
result = Image.fromarray(np.round(acc).astype(np.uint8))
result.save('averaged.png')
```

Use histogram equalization to enhance contrast if the averaged image is faint:

```python
from PIL import ImageOps
enhanced = ImageOps.equalize(result.convert('L'))
enhanced.save('enhanced.png')
```

**Key insight:** Content obscured by motion, noise, or rapid changes across frames becomes visible when averaged. Extract frames with `ffmpeg -i video.mp4 frames/%04d.png` first. Works for hidden QR codes, text, and watermarks.

---

## JPEG XL TOC Permutation Steganography (BSidesSF 2026)

**Pattern (image-progress):** JPEG XL's Table of Contents (TOC) supports a permutation field that reorders how AC groups (progressive scan tiles) are stored in the file. The convergence order during progressive decoding — which 256x256 tiles appear first as you truncate the file at increasing offsets — encodes the flag.

**Decoding approach:**
1. **Progressive truncation:** Truncate the JXL file at increasing byte offsets (e.g., every 1KB)
2. **Decode each truncation:** Use `djxl` to decode each truncated file
3. **Measure tile convergence:** Compare each decoded truncation against the full decode to determine which 256x256 tiles have converged (match the final image)
4. **Read convergence order:** The order in which tiles reach their final state spells the flag

```python
import subprocess
import numpy as np
from PIL import Image

# Full decode as reference
subprocess.run(['djxl', 'flag.jxl', 'full.png'])
full = np.array(Image.open('full.png'))
h, w = full.shape[:2]
tile_size = 256
tiles_x = (w + tile_size - 1) // tile_size
tiles_y = (h + tile_size - 1) // tile_size

# Track when each tile converges
converged = {}
jxl_data = open('flag.jxl', 'rb').read()

for offset in range(1000, len(jxl_data), 1000):
    # Write truncated file
    with open('/tmp/trunc.jxl', 'wb') as f:
        f.write(jxl_data[:offset])

    # Try to decode (may fail for very short truncations)
    result = subprocess.run(['djxl', '/tmp/trunc.jxl', '/tmp/trunc.png'],
                          capture_output=True)
    if result.returncode != 0:
        continue

    partial = np.array(Image.open('/tmp/trunc.png'))

    # Check which tiles match the full decode
    for ty in range(tiles_y):
        for tx in range(tiles_x):
            tile_id = ty * tiles_x + tx
            if tile_id in converged:
                continue
            y0, y1 = ty * tile_size, min((ty+1) * tile_size, h)
            x0, x1 = tx * tile_size, min((tx+1) * tile_size, w)
            if np.array_equal(partial[y0:y1, x0:x1], full[y0:y1, x0:x1]):
                converged[tile_id] = offset

# Sort tiles by convergence order
order = sorted(converged.items(), key=lambda x: x[1])
flag_chars = [chr(tile_id) for tile_id, _ in order]
print('Flag:', ''.join(flag_chars))
```

**Alternative — direct TOC extraction:**
```bash
# Modified djxl with debug prints can extract TOC permutation directly
# Look for the permutation array in the JXL frame header
# The TOC permutation maps: stored_order[i] → logical_group[i]
# Inverse gives: logical_group → stored_order (convergence priority)
```

**JPEG XL progressive structure:**
- **DC groups:** Low-frequency data (converges first, gives blurry preview)
- **AC groups:** High-frequency detail, stored per 256x256 tile
- **TOC permutation:** Reorders the storage of AC groups — controls which tiles get detail first during progressive loading
- **Lehmer code:** JXL encodes the permutation as a Lehmer code sequence in the TOC header

**Key insight:** JPEG XL's TOC permutation is a legitimate feature for progressive rendering optimization (prioritize important image regions). As a steganographic channel, it's invisible — the fully decoded image looks identical regardless of permutation. The hidden data is only revealed by observing the progressive convergence order, which requires truncating the file at multiple points.

**Detection:** JXL file where progressive rendering shows tiles appearing in an unusual order (e.g., spelling text). Challenge mentions "progressive", "convergence", or "order matters".

**References:** BSidesSF 2026 "image-progress"
