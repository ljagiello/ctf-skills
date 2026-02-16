# CTF Forensics - Signals and Hardware

## Table of Contents
- [VGA Signal Decoding](#vga-signal-decoding)
- [HDMI TMDS Decoding](#hdmi-tmds-decoding)
- [DisplayPort 8b/10b + LFSR Decoding](#displayport-8b10b-lfsr-decoding)
- [Voyager Golden Record Audio (0xFun 2026)](#voyager-golden-record-audio-0xfun-2026)
- [Flipper Zero .sub File (0xFun 2026)](#flipper-zero-sub-file-0xfun-2026)

---

## VGA Signal Decoding

**Frame structure:** 800x525 total (640x480 active + blanking). Each sample = 5 bytes: R, G, B, HSync, VSync. Color is 6-bit (0-63).

```python
import numpy as np
from PIL import Image

data = open('vga.bin', 'rb').read()

TOTAL_W, TOTAL_H = 800, 525
ACTIVE_W, ACTIVE_H = 640, 480
BYTES_PER_SAMPLE = 5  # R, G, B, hsync, vsync

# Parse raw samples
samples = np.frombuffer(data, dtype=np.uint8).reshape(-1, BYTES_PER_SAMPLE)
frame = samples.reshape(TOTAL_H, TOTAL_W, BYTES_PER_SAMPLE)

# Extract active region, scale 6-bit to 8-bit
active = frame[:ACTIVE_H, :ACTIVE_W, :3]  # RGB only
img_arr = (active.astype(np.uint16) * 4).clip(0, 255).astype(np.uint8)
Image.fromarray(img_arr).save('vga_output.png')
```

**Key lesson:** Total frame > visible area — always crop blanking. If colors look dark, check if 6-bit (multiply by 4).

---

## HDMI TMDS Decoding

**Structure:** 3 channels (R, G, B), each encoded as 10-bit TMDS symbols. Bit 9 = inversion flag, bit 8 = XOR/XNOR mode. Decode is deterministic from MSBs down.

```python
def tmds_decode(symbol_10bit):
    """Decode a 10-bit TMDS symbol to 8-bit pixel value."""
    bits = [(symbol_10bit >> i) & 1 for i in range(10)]
    # bits[9] = inversion flag, bits[8] = XOR/XNOR mode

    # Step 1: undo optional inversion (bit 9)
    if bits[9]:
        d = [1 - bits[i] for i in range(8)]
    else:
        d = [bits[i] for i in range(8)]

    # Step 2: undo XOR/XNOR chain (bit 8 selects mode)
    q = [d[0]]
    if bits[8]:
        for i in range(1, 8):
            q.append(d[i] ^ q[i-1])        # XOR mode
    else:
        for i in range(1, 8):
            q.append(d[i] ^ q[i-1] ^ 1)    # XNOR mode

    return sum(q[i] << i for i in range(8))

# Parse: read 10-bit symbols from binary, group into 3 channels
# Frame is 800x525 total, crop to 640x480 active
```

**Identification:** Binary data with 10-bit aligned structure. Challenge mentions HDMI, DVI, or TMDS.

---

## DisplayPort 8b/10b + LFSR Decoding

**Structure:** 10-bit 8b/10b symbols decoded to 8-bit data, then LFSR-descrambled. Organized in 64-column Transport Units (60 data columns + 4 overhead).

```python
# Standard 8b/10b decode table (partial — full table has 256 entries)
# Use a prebuilt table: map 10-bit symbol -> 8-bit data
# Key: running disparity tracks DC balance

# LFSR descrambler (x^16 + x^5 + x^4 + x^3 + 1)
def lfsr_descramble(data):
    """DisplayPort LFSR descrambler. Resets on control symbols (BS/BE)."""
    lfsr = 0xFFFF  # Initial state
    result = []
    for byte in data:
        out = byte
        for bit_idx in range(8):
            feedback = (lfsr >> 15) & 1
            out ^= (feedback << bit_idx)
            new_bit = ((lfsr >> 15) ^ (lfsr >> 4) ^ (lfsr >> 3) ^ (lfsr >> 2)) & 1
            lfsr = ((lfsr << 1) | new_bit) & 0xFFFF
        result.append(out & 0xFF)
    return bytes(result)

# Transport Unit layout: 64 columns per TU
# Columns 0-59: pixel data (RGB)
# Columns 60-63: overhead (sync, stuffing)
# LFSR resets on control bytes (BS=0x1C, BE=0xFB)
```

**Key lesson:** LFSR scrambler resets on control bytes — identify these to synchronize descrambling. Without reset points, output is garbled.

---

## Voyager Golden Record Audio (0xFun 2026)

**Pattern (11 Lines of Contact):** Analog image encoded as audio. Sync pulses (sharp negative spikes) delimit scan lines. Amplitude between pulses = pixel brightness.

```python
import numpy as np
from scipy.io import wavfile
from PIL import Image

rate, audio = wavfile.read('golden_record.wav')
audio = audio.astype(np.float32)

# Find sync pulses (sharp negative spikes below threshold)
threshold = np.min(audio) * 0.7
sync_indices = np.where(audio < threshold)[0]

# Group consecutive sync samples into pulse starts
pulses = [sync_indices[0]]
for i in range(1, len(sync_indices)):
    if sync_indices[i] - sync_indices[i-1] > 100:
        pulses.append(sync_indices[i])

# Extract scan lines between pulses, resample to fixed width
WIDTH = 512
lines = []
for i in range(len(pulses) - 1):
    line = audio[pulses[i]:pulses[i+1]]
    resampled = np.interp(np.linspace(0, len(line)-1, WIDTH), np.arange(len(line)), line)
    lines.append(resampled)

# Normalize and save as image
img_arr = np.array(lines)
img_arr = ((img_arr - img_arr.min()) / (img_arr.max() - img_arr.min()) * 255).astype(np.uint8)
Image.fromarray(img_arr).save('voyager_image.png')
```

---

## Flipper Zero .sub File (0xFun 2026)

RAW_Data binary -> filter noise bytes (0x80-0xFF) -> expand batch variable references -> XOR with hint text.
