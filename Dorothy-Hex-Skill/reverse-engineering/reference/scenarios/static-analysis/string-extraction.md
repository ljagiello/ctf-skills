# String Extraction and Decoded-String Analysis

## When this applies

- You need to find embedded strings in a binary: error messages, prompts, paths, URLs, key constants, success/failure markers.
- Strings may be plaintext, UTF-16, base64, XOR-encoded, stack strings, or built at runtime from chunks.
- Trigger: triage of any unknown binary — strings are the highest-yield signal per minute spent.

## Technique

Layered extraction: plain `strings` first, then decoded-string tools (FLOSS), then targeted dynamic resolution if obfuscation is present.

## Steps

### 1. Plain ASCII / UTF-8

```bash
strings -n 8 binary > plain.txt
strings -a -n 8 binary > all_sections.txt   # include non-loadable sections
```

`-n 8` prunes most noise; `-n 6` for sparse string sets.

### 2. Wide strings (UTF-16LE — common in Windows)

```bash
strings -el -n 8 binary > wide.txt          # little-endian 16-bit
```

Windows binaries store many strings as UTF-16; missing `-el` halves the haul.

### 3. FLOSS — decoded strings

Stack strings and obfuscated strings won't show in `strings`. FLOSS (FLARE Obfuscated String Solver, FireEye) emulates code that builds strings:

```bash
floss binary.exe -o floss-out.txt
# Outputs:
#   FLOSS static strings (same as `strings`)
#   FLOSS decoded strings (built by emulating constructor functions)
#   FLOSS stack strings (chars built one-at-a-time on stack)
#   FLOSS tight strings (built in tight loops)
```

For malware especially, FLOSS reveals C2 URLs, registry keys, and mutex names that plain `strings` misses entirely.

### 4. Custom encoding heuristics

If you suspect XOR-encoded strings:

```bash
# Single-byte XOR brute force
for k in $(seq 1 255); do
    python3 -c "
import sys
b = open('binary','rb').read()
key = $k
out = bytes(c ^ key for c in b)
sys.stdout.buffer.write(out)" | strings -n 8 > xor_$k.txt
done
grep -l 'http\|cmd.exe\|flag{' xor_*.txt
```

For multi-byte XOR (key length 2-16): use `xortool`:

```bash
xortool binary -c 0x20    # most-common-byte = 0x20 (space) heuristic
```

### 5. Cross-references in disassembler

After extraction, cross-reference each interesting string back to its use site:

```python
# Ghidra script
for s in currentProgram.listing.getDefinedData(True):
    if s.dataType.name in ('string', 'unicode'):
        for ref in getReferencesTo(s.address):
            print(s.value, '->', ref.fromAddress)
```

The use site is usually the function whose purpose the string describes.

### 6. Stack strings — when FLOSS misses

Stack strings appear as:

```asm
mov    byte ptr [rbp-0x10], 'h'
mov    byte ptr [rbp-0xf],  'e'
mov    byte ptr [rbp-0xe],  'l'
mov    byte ptr [rbp-0xd],  'l'
mov    byte ptr [rbp-0xc],  'o'
mov    byte ptr [rbp-0xb],  0
```

In Ghidra: select the block, right-click, "Auto Create Structure" or manually concatenate.

### 7. Obfuscated string decoders

If FLOSS yields nothing but you know strings should be there, look for a decoder function: a small routine called many times with a buffer + index that returns a string pointer. Hook it (Frida) or simulate it (Unicorn) to dump all decoded strings in one pass.

```python
# Unicorn-based: emulate decoder with each call site's args, dump output
# See: https://github.com/williballenthin/floss-style-decoder for a template
```

## Verifying success

- You can correlate each interesting string with a function that uses it.
- C2 / config / key-derivation strings are visible (for malware).
- Success/fail markers are extracted (for CTF challenges).

## Common pitfalls

- **Forgetting wide strings.** `strings` defaults to ASCII; pass `-el` for UTF-16 or you'll miss half the strings on Windows.
- **Trusting `strings` for packed binaries.** Packed binaries decode strings at runtime; static `strings` shows only the unpacker stub. Run FLOSS or unpack first.
- **Encoding false positives.** Random bytes occasionally form readable English; verify by xref-ing to a use site.
- **Ignoring resources.** `.rsrc` (PE) and `.rodata`/`.data` (ELF) hold strings — `strings -a` includes all sections.

## Tools

- `strings` (binutils) — universal, fast, but misses stack/decoded strings.
- `FLOSS` (Mandiant/FireEye) — emulates decoders, finds stack strings.
- `xortool` — multi-byte XOR key recovery.
- `unicorn-engine` (Python) — emulate decoder functions.
- `frida` (dynamic) — hook decoder, dump every plaintext.
- Disassembler scripts (Ghidra/IDA) for cross-reference automation.
