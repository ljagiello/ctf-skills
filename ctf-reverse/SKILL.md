---
name: ctf-reverse
description: Reverse engineering techniques for CTF challenges. Use when analyzing binaries, game clients, obfuscated code, esoteric languages, custom VMs, anti-debugging, WASM, .NET, APK, Python bytecode, Ghidra, GDB, radare2, or extracting flags from compiled executables.
license: MIT
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Reverse Engineering

Quick reference for RE challenges. For detailed techniques, see supporting files.

## Additional Resources

- [tools.md](tools.md) - Tool-specific commands (GDB, Ghidra, radare2, IDA)
- [patterns.md](patterns.md) - Core binary patterns: custom VMs, anti-debugging, nanomites, self-modifying code, XOR ciphers, mixed-mode stagers, LLVM obfuscation, S-box/keystream, SECCOMP/BPF, exception handlers, memory dumps, byte-wise transforms, x86-64 gotchas, hidden emulator opcodes, LD_PRELOAD key extraction, SPN static extraction, image XOR smoothness, byte-at-a-time cipher
- [languages.md](languages.md) - Language/platform-specific: Python bytecode & opcode remapping, Python version-specific bytecode, DOS stubs, Unity IL2CPP, Brainfuck/esolangs, UEFI, transpilation to C, code coverage side-channel, OPAL functional reversing, non-bijective substitution

---

## Problem-Solving Workflow

1. **Start with strings extraction** - many easy challenges have plaintext flags
2. **Try ltrace/strace** - dynamic analysis often reveals flags without reversing
3. **Map control flow** before modifying execution
4. **Automate manual processes** via scripting (r2pipe, Python)
5. **Validate assumptions** by comparing decompiler outputs

## Quick Wins (Try First!)

```bash
# Plaintext flag extraction
strings binary | grep -E "flag\{|CTF\{|pico"
strings binary | grep -iE "flag|secret|password"
rabin2 -z binary | grep -i "flag"

# Dynamic analysis - often captures flag directly
ltrace ./binary
strace -f -s 500 ./binary

# Hex dump search
xxd binary | grep -i flag

# Run with test inputs
./binary AAAA
echo "test" | ./binary
```

## Initial Analysis

```bash
file binary           # Type, architecture
checksec --file=binary # Security features (for pwn)
chmod +x binary       # Make executable
```

## Memory Dumping Strategy

**Key insight:** Let the program compute the answer, then dump it.

```bash
gdb ./binary
start
b *main+0x198           # Break at final comparison
run
# Enter any input of correct length
x/s $rsi                # Dump computed flag
x/38c $rsi              # As characters
```

## Decoy Flag Detection

**Pattern:** Multiple fake targets before real check.

**Identification:**
1. Look for multiple comparison targets in sequence
2. Check for different success messages
3. Trace which comparison is checked LAST

**Solution:** Set breakpoint at FINAL comparison, not earlier ones.

## GDB PIE Debugging

PIE binaries randomize base address. Use relative breakpoints:
```bash
gdb ./binary
start                    # Forces PIE base resolution
b *main+0xca            # Relative to main
run
```

## Comparison Direction (Critical!)

**Two patterns:**
1. `transform(flag) == stored_target` - Reverse the transform
2. `transform(stored_target) == flag` - Flag IS the transformed data!

**Pattern 2 solution:** Don't reverse - just apply transform to stored target.

## Common Encryption Patterns

- XOR with single byte - try all 256 values
- XOR with known plaintext (`flag{`, `CTF{`)
- RC4 with hardcoded key
- Custom permutation + XOR
- XOR with position index (`^ i` or `^ (i & 0xff)`) layered with a repeating key

## Quick Tool Reference

```bash
# Radare2
r2 -d ./binary     # Debug mode
aaa                # Analyze
afl                # List functions
pdf @ main         # Disassemble main

# Ghidra (headless)
analyzeHeadless project/ tmp -import binary -postScript script.py

# IDA
ida64 binary       # Open in IDA64
```

## Binary Types

### Python .pyc
```python
import marshal, dis
with open('file.pyc', 'rb') as f:
    f.read(16)  # Skip header
    code = marshal.load(f)
    dis.dis(code)
```

### WASM
```bash
wasm2c checker.wasm -o checker.c
gcc -O3 checker.c wasm-rt-impl.c -o checker

# WASM patching (game challenges):
wasm2wat main.wasm -o main.wat    # Binary → text
# Edit WAT: flip comparisons, change constants
wat2wasm main.wat -o patched.wasm # Text → binary
```

**WASM game patching (Tac Tic Toe, Pragyan 2026):** If proof generation is independent of move quality, patch minimax (flip `i64.lt_s` → `i64.gt_s`, change bestScore sign) to make AI play badly while proofs remain valid. See ctf-misc SKILL.md for full pattern.

### Android APK
```bash
apktool d app.apk -o decoded/   # Best - decodes resources
jadx app.apk                     # Decompile to Java
grep -r "flag" decoded/res/values/strings.xml
```

### .NET
- dnSpy - debugging + decompilation
- ILSpy - decompiler

### Packed (UPX)
```bash
upx -d packed -o unpacked
```

## Anti-Debugging Bypass

Common checks:
- `IsDebuggerPresent()` (Windows)
- `ptrace(PTRACE_TRACEME)` (Linux)
- `/proc/self/status` TracerPid
- Timing checks

Bypass: Set breakpoint at check, modify register to bypass conditional.

## S-Box / Keystream Patterns

**Xorshift32:** Shifts 13, 17, 5
**Xorshift64:** Shifts 12, 25, 27
**Magic constants:** `0x2545f4914f6cdd1d`, `0x9e3779b97f4a7c15`

## Custom VM Analysis

1. Identify structure: registers, memory, IP
2. Reverse `executeIns` for opcode meanings
3. Write disassembler mapping opcodes to mnemonics
4. Often easier to bruteforce than fully reverse
5. Look for the bytecode file loaded via command-line arg

See [patterns.md](patterns.md#custom-vm-reversing) for VM workflow, opcode tables, and state machine BFS.

## Python Bytecode Reversing

XOR flag checkers with interleaved even/odd tables are common. See [languages.md](languages.md#python-bytecode-reversing-disdis-output) for bytecode analysis tips and reversing patterns.

## Signal-Based Binary Exploration

Binary uses UNIX signals as binary tree navigation; hook `sigaction` via `LD_PRELOAD`, DFS by sending signals. See [patterns.md](patterns.md#signal-based-binary-exploration).

## Malware Anti-Analysis Bypass via Patching

Flip `JNZ`/`JZ` (0x75/0x74), change sleep values, patch environment checks in Ghidra (`Ctrl+Shift+G`). See [patterns.md](patterns.md#malware-anti-analysis-bypass-via-patching).

## Expected Values Tables

**Locating:**
```bash
objdump -s -j .rodata binary | less
# Look near comparison instructions
# Size matches flag length
```

## x86-64 Gotchas

**Sign extension:** `0xffffffc7` behaves differently in XOR vs addition
```python
# For XOR: use low byte
esi_xor = esi & 0xff

# For addition: use full value with overflow
result = (r13 + esi) & 0xffffffff
```

## Iterative Solver Pattern

```python
for pos in range(flag_length):
    for c in range(256):
        computed = compute_output(c, current_state)
        if computed == EXPECTED[pos]:
            flag.append(c)
            update_state(c, computed)
            break
```

**Uniform transform shortcut:** if changing one input byte only changes one output byte,
build a 0..255 mapping by repeating a single byte across the whole input, then invert.

## Unicorn Emulation (Complex State)

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
# Map segments, set up stack
# Hook to trace register changes
mu.emu_start(start_addr, end_addr)
```

**Mixed-mode pitfall:** if a 64-bit stub jumps into 32-bit code via `retf/retfq`, you must
switch to a UC_MODE_32 emulator and copy **GPRs, EFLAGS, and XMM regs**; missing XMM state
will corrupt SSE-based transforms.

## Multi-Stage Shellcode Loaders

Nested shellcode with XOR decode loops; break at `call rax`, bypass ptrace with `set $rax=0`, extract flag from `mov` instructions. See [patterns.md](patterns.md#multi-stage-shellcode-loaders).

## Timing Side-Channel Attack

Validation time varies per correct character; measure elapsed time per candidate to recover flag byte-by-byte. See [patterns.md](patterns.md#timing-side-channel-attack).

## Godot Game Asset Extraction

Use KeyDot to extract encryption key from executable, then gdsdecomp to extract .pck package. See [languages.md](languages.md#godot-game-asset-extraction).

## Roblox Place File Analysis

Query Asset Delivery API for version history; parse `.rbxlbin` chunks (INST/PROP/PRNT) to diff script sources across versions. See [languages.md](languages.md#roblox-place-file-analysis).

## Unstripped Binary Information Leaks

**Pattern (Bad Opsec):** Debug info and file paths leak author identity.

**Quick checks:**
```bash
strings binary | grep "/home/"    # Home directory paths
strings binary | grep "/Users/"   # macOS paths
file binary                       # Check if stripped
readelf -S binary | grep debug    # Debug sections present?
```

## Custom Mangle Function Reversing

Binary mangles input 2 bytes at a time with running state; extract target from `.rodata`, write inverse function. See [patterns.md](patterns.md#custom-mangle-function-reversing).

## Rust serde_json Schema Recovery

Disassemble serde `Visitor` implementations to recover expected JSON schema; field names in order reveal flag. See [languages.md](languages.md#rust-serde_json-schema-recovery).

## Position-Based Transformation Reversing

Binary adds/subtracts position index; reverse by undoing per-index offset. See [patterns.md](patterns.md#position-based-transformation-reversing).

## Hex-Encoded String Comparison

Input converted to hex, compared against constant. Decode with `xxd -r -p`. See [patterns.md](patterns.md#hex-encoded-string-comparison).
