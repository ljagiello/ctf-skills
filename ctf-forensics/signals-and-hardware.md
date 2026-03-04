# CTF Forensics - Signals and Hardware

## Table of Contents
- [VGA Signal Decoding](#vga-signal-decoding)
- [HDMI TMDS Decoding](#hdmi-tmds-decoding)
- [DisplayPort 8b/10b + LFSR Decoding](#displayport-8b10b-lfsr-decoding)
- [Voyager Golden Record Audio (0xFun 2026)](#voyager-golden-record-audio-0xfun-2026)
- [Side-Channel Power Analysis (EHAX 2026)](#side-channel-power-analysis-ehax-2026)
- [Saleae Logic 2 UART Decode (EHAX 2026)](#saleae-logic-2-uart-decode-ehax-2026)
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

## Side-Channel Power Analysis (EHAX 2026)

**Pattern (Power Leak):** Power consumption traces recorded during cryptographic operations. Correct key guesses cause measurably different power consumption at specific sample points.

**Data format:** Typically a multi-dimensional array: `[positions × guesses × traces × samples]`. E.g., 6 digit positions × 10 guesses (0-9) × 20 traces × 50 samples.

**Attack (Differential Power Analysis):**
```python
import numpy as np
import hashlib

# Load power traces: shape = (positions, guesses, traces, samples)
data = np.load('power_traces.npy')  # or parse from CSV/JSON
n_positions, n_guesses, n_traces, n_samples = data.shape

# For each position, find the guess with maximum power at the leak point
key_digits = []
for pos in range(n_positions):
    # Average across traces for each guess
    avg_power = data[pos].mean(axis=1)  # shape: (guesses, samples)

    # Find the sample point with maximum power variance across guesses
    # This is the "leak point" where the correct guess stands out
    variance_per_sample = avg_power.var(axis=0)
    leak_sample = np.argmax(variance_per_sample)

    # The guess with maximum power at the leak point is correct
    best_guess = np.argmax(avg_power[:, leak_sample])
    key_digits.append(best_guess)

key = ''.join(str(d) for d in key_digits)
print(f"Recovered key: {key}")

# Flag may be SHA256 of the key
flag = hashlib.sha256(key.encode()).hexdigest()
```

**Identification:** Challenge mentions "power", "side-channel", "leakage", "traces", or "measurements". Data is a multi-dimensional numeric array with axes for positions/guesses/traces/samples.

**Key insight:** The "leak point" is the sample index where correct vs incorrect guesses show the largest power difference. Average across traces first to reduce noise, then find the sample with maximum variance across guesses.

---

## Saleae Logic 2 UART Decode (EHAX 2026)

**Pattern (Baby Serial):** Saleae Logic 2 `.sal` file (ZIP archive) containing digital channel captures. Data encoded as UART serial.

**File structure:** `.sal` is a ZIP containing `digital-0.bin` through `digital-7.bin` + `meta.json`. Only channel 0 typically has data.

**Binary format (digital-*.bin):**
```
<SALEAE> magic (8 bytes)
version: u32 = 2
type: u32 = 100 (digital)
initial_state: u32 (0 or 1)
... header fields ...
Delta-encoded transitions (variable-length integers)
```

**Delta encoding:** Each value represents the number of samples between state transitions. The signal alternates between HIGH and LOW at each delta.

**UART decode from deltas:**
```python
import numpy as np

# Parse deltas from binary (after header)
# Reconstruct signal timeline
times = np.cumsum(deltas)
states = []
state = initial_state
for d in deltas:
    states.append(state)
    state ^= 1  # toggle on each transition

# UART decode: detect start bit (HIGH→LOW), sample 8 data bits at bit centers
# Baud rate detection: most common delta ≈ samples_per_bit
# At 1MHz sample rate: 115200 baud ≈ 8.7 samples/bit

def uart_decode(transitions, sample_rate=1_000_000, baud=115200):
    bit_period = sample_rate / baud
    bytes_out = []
    i = 0
    while i < len(transitions):
        # Find start bit (falling edge)
        if transitions[i] == 0:  # LOW = start bit
            byte_val = 0
            for bit in range(8):
                sample_time = (1.5 + bit) * bit_period  # center of each bit
                # Sample signal at this offset from start bit
                bit_val = get_signal_at(sample_time)
                byte_val |= (bit_val << bit)  # LSB first
            bytes_out.append(byte_val)
        i += 1
    return bytes(bytes_out)
```

**Common pitfalls:**
- **Inverted polarity:** UART idle is HIGH (mark). If initial_state=1, the encoding may be inverted — try both
- **Baud rate guessing:** Check common rates: 9600, 19200, 38400, 57600, 115200, 230400
- **Output format:** Decoded bytes may be base64-encoded (containing a PNG image or text)
- **Saleae internal format ≠ export format:** The `.sal` internal binary uses a different encoding than CSV/binary export. Parse the raw delta transitions directly

**Quick approach:** Install Saleae Logic 2, open the `.sal` file, add UART analyzer with auto-baud detection, export decoded data.

---

## Flipper Zero .sub File (0xFun 2026)

RAW_Data binary -> filter noise bytes (0x80-0xFF) -> expand batch variable references -> XOR with hint text.
