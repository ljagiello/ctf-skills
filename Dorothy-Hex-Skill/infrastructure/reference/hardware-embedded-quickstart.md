# Hardware / Embedded Exploitation Quickstart

**Attack Surface**: Logic captures, serial protocols (UART/CAN/SPI/I2C), legacy CPUs, side-channel leakage, firmware ROMs.

## 1. Logic Capture Files (Saleae `.sal`)

A `.sal` file is a ZIP containing `analog-N.bin`, `digital-N.bin`, `meta.json`. The internal binary format is **not publicly documented** — do not try to parse it by hand.

**Workaround — drive the official GUI headless**:
```bash
# macOS path — adjust per OS. gRPC listens on port 10430.
"/Applications/Saleae Logic.app/Contents/MacOS/Logic" --automation &
```
```python
from saleae import automation
with automation.Manager.connect(port=10430) as mgr:
    cap = mgr.load_capture(filepath="trace.sal")
    # IMPORTANT: only request channels marked isHidden:false in meta.json
    # (rowsSettings); otherwise gRPC raises InvalidRequestError.
    cap.export_raw_data_csv(directory="out/", digital_channels=[0, 1])
```
CSV output: `Time [s], Channel 0, Channel 1, ...` — one row per transition.

`meta.json` keys worth reading first:
- `data.captureSettings.connectedDevice.settings.sampleRate.{digital,analog}` — sample rates
- `data.captureProgress.processedInterval.{begin,end}` — capture span (s)
- `data.rowsSettings[].isHidden` — which channels actually have data

## 2. Serial Protocol Decoding from Transitions

### UART parameter brute-force

When given a stream of `0`/`1` chars (one per bit-time, no oversampling) or transition timings, the decoder parameters are usually unknown. Brute-force the small grid:
- **data bits**: 7 or 8
- **parity**: None / Even / Odd
- **stop bits**: 1 or 2
- **bit order**: LSB-first (standard) or MSB-first
- **line polarity**: idle-high (TTL, normal) or idle-low (inverted/RS-232-translated)

Frame length = `1 (start) + n_data + (1 if parity else 0) + n_stop`. Score each combo by % printable ASCII; the right one usually jumps to >95%.

**Trap**: 8E1 (8 data + even parity + 1 stop = **11-bit** frame) and 8N1 (10-bit) produce nearly identical "mostly-printable" output if you only try 10-bit frames — the parity bit slips into the data and corrupts every byte by ~1 bit. If decode is 90% printable but not clean text, re-try assuming an extra bit per frame.

Always reject frames where the stop-bit position is `0` (framing error) — keeps alignment honest.

### CAN bus from logic capture

- **Common bit rates**: 125 kbps (8 µs/bit, low-speed CAN), 250/500 kbps, 1 Mbps. Check the smallest delta between transitions to derive bit time.
- **Idle = recessive (1)**. **SOF = first dominant (0) bit** following ≥ ~7 bit-times of idle (interframe space).
- **Standard frame**: `SOF(1) | ID(11) | RTR(1) | IDE(1) | r0(1) | DLC(4) | Data(0–8 B) | CRC(15) | CRC_DEL(1) | ACK(1) | ACK_DEL(1) | EOF(7×1)`.
- **Bit stuffing** (SOF through CRC): after 5 same-polarity bits, a complementary stuff bit is inserted — **must be removed before parsing fields**.
- **Sampling**: bit center = SOF + (n + 0.5) × bit_time.

Once decoded, dump frames grouped by CAN ID. Repeated payloads on a single ID with high printable-ASCII content commonly carry the flag/VIN/identifier (broadcast frames are sent many times per second).

## 3. Side-Channel Recovery of Char-by-Char Password Checks

**Pattern**: target compares an input against a secret with early termination, and the loop's runtime/power/electromagnetic emission is observable. Each correct prefix character makes the verifier do strictly more work.

**Anchor-baseline byte-at-a-time recovery** (the diff-vs-completely-wrong-baseline approach saturates and stops discriminating once the prefix is correct):

1. Fix `recovered = ""` plus a known **wrong** char `W` (pick one almost certainly not in the alphabet).
2. **Anchor trace** = average of N traces for `recovered + W + padding`.
3. For each candidate `c` in the charset, average M traces for `recovered + c + padding` and compute `score(c) = sum(|trace_c - anchor|)`.
4. The correct char's score is sharply higher than all others (typical gap: ~10×). If `top1/top2 < 1.4`, re-average the top few with more samples.
5. Append the winner, re-anchor with a new wrong char at the new position, repeat.

**Practical**: parallelize with `ThreadPoolExecutor(max_workers=8–10)`, fresh socket per query. 6–10 traces per candidate is usually enough; bump to 25–40 only on ambiguous positions. Restrict the charset to expected (printable ASCII + `{}_!`); recovery time scales linearly with `|charset|`.

Once a clear prefix forms (e.g., `FLAG{`, dictionary words), **predict and submit early** — don't burn cycles recovering the closing brace.

## 4. Legacy CPU Hardware Bugs

When a challenge supplies a "buggy" assembler/CPU and asks you to fix code, suspect a documented errata. Replace the buggy instruction with an equivalent sequence using only safe addressing modes.

### MOS 6502 — `JMP ($XXFF)` page-boundary bug
`JMP (indirect)` reads the **low** byte from `$XXFF` and the **high** byte from `$XX00` (same page!) instead of `$(XX+1)00`. Fixed in 65C02; the original 6502 is buggy.

Workaround — load both halves with absolute addressing (no bug), stash in zero page, then indirect-jump through an address that doesn't cross a page:
```asm
        lda $40ff       ; correct low byte
        sta $00
        lda $4100       ; correct high byte (no bug, absolute addressing)
        sta $01
        jmp ($0000)     ; safe indirect — pointer fully inside page 0
```

Other classic CPU errata to check when stuck: 6502 BRK pushes PC+2 not PC+1; Z80 `LD A,I/R` parity bit; early 8086 `MOV CS,*` etc.

## 5. Cross-Architecture Tooling on ARM macOS / Linux

CTF challenges often ship i386 ELF tools (e.g., AS65 6502 assembler). Run them via Docker without installing qemu-user:

```bash
docker run --rm -v "$PWD:/work" -w /work --platform linux/386 \
    i386/debian:bullseye-slim /work/as65 -h0 src.a65 -odst.rom
```

Works for any old 32-bit Linux binary. First invocation pulls the image (~30 MB); subsequent runs are instant. Same trick with `--platform linux/amd64` for x86-64-only tools on Apple Silicon.

## 6. Common Service Protocols for "Send ROM, Run, Read" Challenges

Pattern:
- `FLASH <hex>` — load firmware/ROM bytecode into target memory
- `RUN <N>` — execute N opcodes/cycles
- `CONSOLE` / `OUTPUT` — read accumulated UART/console buffer

The flag is usually a stream of space-separated hex bytes printed to the console — always `bytes.fromhex(...).decode()` the captured region. Check for ANSI color escape codes (`\x1b[94m...\x1b[0m`) wrapping the payload and strip them before decoding.
