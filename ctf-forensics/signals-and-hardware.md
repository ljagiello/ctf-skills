# CTF Forensics - Signals and Hardware

## Table of Contents
- [Hardware Signal Decoding (0xFun 2026)](#hardware-signal-decoding-0xfun-2026)
- [Voyager Golden Record Audio (0xFun 2026)](#voyager-golden-record-audio-0xfun-2026)
- [Flipper Zero .sub File (0xFun 2026)](#flipper-zero-sub-file-0xfun-2026)

---

## Hardware Signal Decoding (0xFun 2026)

**VGA:** Raw 800x525 frame (includes blanking), 5 bytes/sample (R,G,B + sync). 6-bit color (0-63) -> expand to 8-bit. Crop to 640x480 active region.

**HDMI TMDS:** 10-bit symbols per channel. Bit 9 = inversion flag, bit 8 = XOR/XNOR mode. Reverse encoding to get 8-bit pixels. 800x525 -> crop 640x480.

**DisplayPort 8b/10b + LFSR:** 10-bit 8b/10b symbols -> 8-bit data. 64-column transport units (60 data + 4 overhead). LFSR descrambler resets on control bytes.

**Key lesson:** VGA total frame > visible area (always crop blanking). TMDS is deterministic decode from MSBs. DisplayPort LFSR resets are the key to offline descrambling.

---

## Voyager Golden Record Audio (0xFun 2026)

**Pattern (11 Lines of Contact):** Analog image encoded as audio. Sync pulses (sharp negative spikes) delimit scan lines. Amplitude between pulses = pixel brightness.

**Decoding:** Stack resampled lines to reconstruct image. The Voyager Golden Record format is well-documented.

---

## Flipper Zero .sub File (0xFun 2026)

RAW_Data binary -> filter noise bytes (0x80-0xFF) -> expand batch variable references -> XOR with hint text.
