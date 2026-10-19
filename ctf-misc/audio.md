# CTF Misc - Audio Steganography and Signal Analysis

Audio steganography and signal analysis techniques for CTF challenges. Covers Morse code extraction from audio channels, spectrogram analysis, SSTV decoding, and related methods.

See also: [encodings-advanced.md](encodings-advanced.md) — DTMF audio decoding with multi-tap keypad, music note interval steganography
See also: [rf-sdr.md](rf-sdr.md) — RF/SDR IQ signal processing for radio/air-gapped signals

## Table of Contents

- [Prerequisites](#prerequisites)
- [Spectrogram Analysis](#spectrogram-analysis)
- [SSTV Decoding](#sstv-decoding)
- [Morse Code in Audio Channel](#morse-code-in-audio-channel)
- [Future Techniques](#future-techniques)

---

## Prerequisites

```bash
pip install numpy
# Optional: scipy for signal processing (not required for Morse extraction below)
# System tools
apt install sox qsstv
```

---

## Spectrogram Analysis

**Pattern:** Audio file contains hidden text or images rendered in the frequency domain. Visible only in spectrogram view.

```bash
# Static spectrogram image
sox audio.wav -n spectrogram -o spec.png

# Higher resolution for narrow frequency features
sox audio.wav -n spectrogram -o spec.png -x 2048 -y 1025 -z 120

# With focused frequency range (e.g., 0-8kHz)
sox audio.wav -n spectrogram -o spec.png -y 513 -z 120
```

**Key insight:** Hidden data often appears in upper frequency bands (15–22 kHz) invisible to human hearing but captured in full-spectrum recordings. Use Audacity's spectrogram view for interactive exploration — adjust the frequency scale to examine specific bands. Look for text shapes, QR codes, or binary bar patterns rendered across time.

---

## SSTV Decoding

**Pattern:** Audio file is a Slow Scan Television (SSTV) transmission — an image encoded as frequency-modulated audio tones, commonly used in amateur radio and CTF challenges.

```bash
# Launch qsstv GUI — play audio through system output and use pulseaudio loopback
qsstv

# Alternative: pipe WAV file directly via virtual audio cable
# Use pavucontrol to route audio output to qsstv input
paplay audio.wav &
qsstv
```

**Common SSTV modes:** Martin (M1/M2), Scottie (S1/S2), Robot (36/72). The VIS (Vertical Interval Signaling) code at the start of transmission identifies the mode automatically in most decoders.

**Key insight:** SSTV transmissions often repeat — record a full cycle and ensure clean audio without clipping. If decoding fails, verify the audio is not resampled; SSTV timing is sensitive to sample rate changes.

---

## Morse Code in Audio Channel

**Pattern:** A WAV file where Morse code (telegraph beeps) is encoded as amplitude-modulated tones on **one specific audio channel** (left, right, or mono), while other channels may contain cover audio (music, noise) or silence. The flag is recovered by:

1. Separating all audio channels
2. Identifying which channel carries the Morse signal
3. Detecting beep envelopes and classifying dot/dash durations
4. Using gap timing to group dots/dashes into characters
5. Decoding via standard Morse dictionary

### Key Insight

- **Stereo WAV interleaving:** Samples are stored as `L0,R0,L1,R1,...` — left channel = even indices (0::2), right channel = odd indices (1::2). Mono WAV has no interleaving.
- **Auto-detect the Morse channel:** Compute the RMS envelope for each channel independently. The Morse channel has a high **peak-to-mean ratio** (loud beeps alternating with near-silent gaps produce a bursty envelope), while music/noise channels have a continuous envelope with a lower ratio (typically ~1.5–3× vs ~8–20× for Morse). Pick the channel with the highest `max(env) / mean(env)`.
- **RMS envelope detection:** Square the signal, convolve with a rectangular window (~50ms), take the square root. This smooths out the carrier frequency oscillations and reveals the beep/silence pattern.
- **Timing classification:** Dots are short (~100–150ms), dashes are long (~250–350ms). Intra-character gaps are very short (~20–70ms), inter-character gaps are much longer (~10–50× intra-character gap). The bimodal gap distribution makes classification robust.
- **Fallback:** If the auto-detected channel produces garbled output, manually try each channel by setting `best_channel_idx = 0` or `1`.

### Complete Python Extraction Script

```python
import wave
import struct
import numpy as np

# ============================================================
# 1. Load WAV and separate all channels
# ============================================================
wav_path = "stego100.wav"  # change to your file
w = wave.open(wav_path)
sample_rate = w.getframerate()
n_channels = w.getnchannels()
n_frames = w.getnframes()

print(f"Sample rate: {sample_rate} Hz, Channels: {n_channels}, Frames: {n_frames}")

# Unpack to signed ints (handle 8/16/32-bit WAV)
sampwidth = w.getsampwidth()
type_char = {1: 'B', 2: 'h', 4: 'i'}[sampwidth]  # B=unsigned byte, h=short, i=int
raw = w.readframes(n_frames)
w.close()

# Endianness prefix goes first, then repeated type chars
samples = struct.unpack('<' + type_char * (len(raw) // sampwidth), raw)

# Separate channels
channels = []
for ch in range(n_channels):
    channels.append(np.array(samples[ch::n_channels], dtype=np.float64))

# ============================================================
# 2. Auto-detect which channel carries the Morse signal
# ============================================================
def compute_envelope(signal, window_ms=50):
    """RMS envelope of a signal using a sliding window."""
    half = int(window_ms / 1000 * sample_rate / 2)
    if half < 1:
        half = 1
    # Square the signal, then smooth with a boxcar window
    power = signal ** 2
    kernel = np.ones(2 * half + 1) / (2 * half + 1)
    envelope = np.sqrt(np.convolve(power, kernel, mode='same'))
    return envelope

# Compute envelope for each channel and pick the Morse channel
# Morse channel has high peak-to-mean ratio (bursty beeps + silence vs continuous audio)
envelopes = [compute_envelope(ch) for ch in channels]
ratios = [np.max(env) / max(np.mean(env[env > 0.1]), 0.01) for env in envelopes]
best_channel_idx = int(np.argmax(ratios))

print(f"Channel peak-to-mean ratios: {[f'{r:.1f}' for r in ratios]}")
print(f"Selected channel: {best_channel_idx} (Morse signal)")

signal = channels[best_channel_idx]
envelope = envelopes[best_channel_idx]

# ============================================================
# 3. Threshold and segment beeps / gaps
# ============================================================
# Threshold as fraction of max envelope (robust against varying levels)
threshold = np.max(envelope) * 0.15
is_beep = envelope > threshold

# Debounce: ignore dropouts shorter than 10ms
min_gap_samples = int(0.010 * sample_rate)
state = 0  # 0 = silence, 1 = beep
beeps = []     # list of (duration_ms)
gaps = []      # list of (duration_ms)
current_start = 0
last_end = None

for i in range(len(is_beep)):
    if state == 0 and is_beep[i]:
        state = 1
        current_start = i
        if last_end is not None:
            gap_ms = (i - last_end) / sample_rate * 1000
            if gap_ms > 10:  # ignore micro-gaps
                gaps.append(gap_ms)
    elif state == 1 and not is_beep[i]:
        # Check ahead — is this a brief dropout?
        look_ahead = min(min_gap_samples, len(is_beep) - i)
        if np.any(is_beep[i:i + look_ahead]):
            continue  # brief dropout, re-merge
        state = 0
        last_end = i
        beep_ms = (i - current_start) / sample_rate * 1000
        if beep_ms > 10:
            beeps.append(beep_ms)

# Catch trailing beep
if state == 1:
    beep_ms = (len(is_beep) - current_start) / sample_rate * 1000
    if beep_ms > 10:
        beeps.append(beep_ms)

print(f"Detected {len(beeps)} beeps, {len(gaps)} gaps")

# ============================================================
# 4. Classify beeps as dots/dashes and gaps as intra/inter-char
# ============================================================
# Adjust these thresholds based on your challenge's timing
DOT_MAX_MS = 200      # below = dot, above = dash
GAP_MAX_MS = 500      # below = intra-char, above = inter-char

# Diagnostic: print duration distributions
beep_arr = np.array(beeps)
gap_arr = np.array(gaps) if gaps else np.array([])
print(f"Beep durations (ms): min={beep_arr.min():.0f}, max={beep_arr.max():.0f}, "
      f"median={np.median(beep_arr):.0f}")
if len(gap_arr) > 0:
    print(f"Gap durations (ms):  min={gap_arr.min():.0f}, max={gap_arr.max():.0f}, "
          f"median={np.median(gap_arr):.0f}")

# Build Morse character groups
morse_chars = []
current_char = []

for i, beep_ms in enumerate(beeps):
    symbol = '.' if beep_ms < DOT_MAX_MS else '-'
    current_char.append(symbol)

    if i < len(gaps) and gaps[i] > GAP_MAX_MS:
        morse_chars.append(''.join(current_char))
        current_char = []

# Last character
if current_char:
    morse_chars.append(''.join(current_char))

print(f"Decoded {len(morse_chars)} Morse characters")

# ============================================================
# 5. Decode Morse to text
# ============================================================
MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9',
}

decoded = ''
for seq in morse_chars:
    decoded += MORSE.get(seq, f'[{seq}]')

print(f"\nDecoded message: {decoded}")
print(f"Flag: flag{{{decoded}}}")
```

### Parameter Tuning

If the decoded output is garbled or contains `[bracketed]` unknown sequences, adjust these parameters:

| Parameter | Default | When to Adjust |
|-----------|---------|----------------|
| `DOT_MAX_MS` | 200ms | If dots and dashes have different durations in your challenge — check the printed beep duration statistics and set the threshold midway between the two clusters |
| `GAP_MAX_MS` | 500ms | Check printed gap statistics — set the threshold between the short-gap cluster (intra-character) and the long-gap cluster (inter-character) |
| `window_ms` (envelope) | 50ms | Larger = smoother but blurs short beeps; smaller = preserves edges but noisier. If very short dots are missed, reduce window |
| `threshold` multiplier | 0.15 × max | If faint beeps are missed, lower to 0.05; if noise triggers false beeps, raise to 0.3 |
| `min_gap_samples` | 10ms | Debounce dropout length — increase if a single beep is split into multiple segments |

**Diagnostic tip:** Run the script and examine the printed beep/gap duration stats. The beep durations should form two clear clusters (dots vs dashes), and the gaps should similarly cluster. If they don't, the channel selection or threshold may be wrong — manually force a different channel by setting `best_channel_idx = 0` or `1`.

### Variations

- **FSK (Frequency-Shift Keying) Morse:** Instead of amplitude on/off keying, two different audio tones represent dot and dash (e.g., 800Hz for dot, 1200Hz for dash). Requires spectrogram or bandpass filter analysis rather than amplitude envelope detection. Use `sox` spectrogram to identify the two tone frequencies, then apply Goertzel filters or short-time FFT per segment.
- **Mono WAV:** No channel separation needed — process the single channel directly. The auto-detection still works (peak-to-mean ratio is computed on the only channel).
- **Different sample widths:** The script handles 8-bit, 16-bit, and 32-bit PCM via `get_sampwidth()`. Non-PCM formats (e.g., float32 WAV) need adjustments to the unpacking.
- **Multiple channels with different messages:** Run the extraction on each channel independently — some challenges encode different parts of the flag on different channels.
- **Inverted polarity:** If beeps are near-zero and silence is loud, the Morse is encoded as amplitude DIPS. Use `signal = np.abs(signal)` (already done) or invert: `signal = -signal`.

### Reference

This technique was used to solve **stego100** (NyanCat-themed audio stego, ~2015-era CTF), where the flag was hidden as Morse code in the left channel of a stereo WAV while the right channel played the Nyan Cat song. Auto-detection correctly identifies the left channel by its higher peak-to-mean ratio (~8.2 vs ~1.6 for the music channel).

---

## Future Techniques

Techniques documented elsewhere or to be added:

- **LSB Audio Steganography:** Least-significant-bit encoding in raw PCM samples — extract LSB plane from each sample to recover hidden text/files. Tools: `stegolsb`, `wavsteg`, `steganoWAV`.
- **Phase Encoding:** Hidden data in phase differences between consecutive audio frames. Recover by computing phase spectrum of each short-time FFT window.
- **Echo Hiding:** Data encoded as imperceptible echo delays. Recover via cepstrum analysis (cepstral peak at echo delay).
- **Spread Spectrum:** Data spread across a wide frequency band below the noise floor. Recover by correlating with the known spreading code.
- **SilentEye / DeepSound:** General-purpose audio steganography tools — try these when standard techniques fail.
- **DTMF (Phone Keypad) Tones:** Audio file contains dual-tone multi-frequency signaling. Decode to digits, then apply multi-tap keypad mapping. See [encodings-advanced.md](encodings-advanced.md#dtmf-audio-with-multi-tap-phone-keypad-decoding-h4ckc0n-2017).
- **Music Note Interval Steganography:** Note pairs encode nibbles via scale-degree mapping. See [encodings-advanced.md](encodings-advanced.md#music-note-interval-steganography-defcamp-2017).
- **SSTV (Slow Scan Television):** Image-over-audio common in amateur radio challenges. See [SSTV Decoding](#sstv-decoding) section above.
- **Bytebeat Synth Recognition:** Generative music one-liners where the song title is the flag. Play the code as audio and identify the song. See [games-and-vms-4.md](games-and-vms-4.md).
