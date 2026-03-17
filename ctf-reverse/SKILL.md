---
name: ctf-reverse
description: Provides reverse engineering techniques for CTF challenges. Use when analyzing binaries, game clients, obfuscated code, esoteric languages, custom VMs, anti-debugging, WASM, .NET, APK, Python bytecode, Ghidra, GDB, radare2, or extracting flags from compiled executables.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Reverse Engineering

Quick reference for RE challenges. For detailed techniques, see supporting files.

## Additional Resources

- [tools.md](tools.md) - Tool-specific commands (GDB, Ghidra, radare2, IDA, Binary Ninja, dogbolt.org, RISC-V with Capstone)
- [patterns.md](patterns.md) - Foundational binary patterns: custom VMs, anti-debugging, nanomites, self-modifying code, XOR ciphers, mixed-mode stagers, LLVM obfuscation, S-box/keystream, SECCOMP/BPF, exception handlers, memory dumps, byte-wise transforms, x86-64 gotchas, signal-based exploration, malware anti-analysis, multi-stage shellcode, timing side-channel, multi-thread anti-debug with decoy + signal handler MBA
- [patterns-ctf.md](patterns-ctf.md) - Competition-specific patterns (Part 1): hidden emulator opcodes, LD_PRELOAD key extraction, SPN static extraction, image XOR smoothness, byte-at-a-time cipher, mathematical convergence bitmap, Windows PE XOR bitmap OCR, two-stage RC4+VM loaders, GBA ROM meet-in-the-middle, Sprague-Grundy game theory, kernel module maze solving, multi-threaded VM channels, backdoored shared library detection via string diffing
- [patterns-ctf-2.md](patterns-ctf-2.md) - Competition-specific patterns (Part 2): multi-layer self-decrypting brute-force, embedded ZIP+XOR license, stack string deobfuscation, prefix hash brute-force, CVP/LLL lattice for integer validation, decision tree function obfuscation, GLSL shader VM, GF(2^8) Gaussian elimination, Z3 single-line Python circuit, sliding window popcount
- [languages.md](languages.md) - Language/platform-specific: Python bytecode & opcode remapping, Python version-specific bytecode, DOS stubs, Unity IL2CPP, Brainfuck/esolangs, UEFI, transpilation to C, code coverage side-channel, OPAL functional reversing, non-bijective substitution, Android JNI RegisterNatives, Ruby/Perl polyglot, Electron ASAR extraction + native binary analysis, Node.js npm runtime introspection

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
    # Header size varies by Python version:
    # 8 bytes (2.x), 12 (3.0-3.6), 16 (3.7+)
    f.read(16)  # 16 for Python 3.7+; adjust for older versions
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

**WASM game patching (Tac Tic Toe, Pragyan 2026):** If proof generation is independent of move quality, patch minimax (flip `i64.lt_s` → `i64.gt_s`, change bestScore sign) to make AI play badly while proofs remain valid. Invoke `/ctf-misc` for full game patching patterns (games-and-vms).

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
pwntools patch: `elf.asm(elf.symbols.ptrace, 'ret')` to replace function with immediate return. See [patterns.md](patterns.md#pwntools-binary-patching-crypto-cat).

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

Sign extension and 32-bit truncation pitfalls. See [patterns.md](patterns.md#x86-64-gotchas) for details and code examples.

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

## Embedded ZIP + XOR License Decryption

Binary with named symbols (`EMBEDDED_ZIP`, `ENCRYPTED_MESSAGE`) in `.rodata` → extract ZIP containing license, XOR encrypted message with license bytes to recover flag. No execution needed. See [patterns-ctf-2.md](patterns-ctf-2.md#embedded-zip--xor-license-decryption-metactf-2026).

## Stack String Deobfuscation (.rodata XOR Blob)

Binary mmaps `.rodata` blob, XOR-deobfuscates, uses it to validate input. Reimplement verification loop with pyelftools to extract blob. Look for `0x9E3779B9`, `0x85EBCA6B` constants and `rol32()`. See [patterns-ctf-2.md](patterns-ctf-2.md#stack-string-deobfuscation-from-rodata-xor-blob-nullcon-2026).

## Prefix Hash Brute-Force

Binary hashes every prefix independently. Recover one character at a time by matching prefix hashes. See [patterns-ctf-2.md](patterns-ctf-2.md#prefix-hash-brute-force-nullcon-2026).

## Mathematical Convergence Bitmap

**Pattern:** Binary classifies coordinate pairs by Newton's method convergence (e.g., z^3-1=0). Grid of pass/fail results renders ASCII art flag. Key: the binary is a classifier, not a checker — reverse the math and visualize. See [patterns-ctf.md](patterns-ctf.md#mathematical-convergence-bitmap-ehax-2026).

## RISC-V Binary Analysis

Statically linked, stripped RISC-V ELF. Use Capstone with `CS_MODE_RISCVC | CS_MODE_RISCV64` for mixed compressed instructions. Emulate with `qemu-riscv64`. Watch for fake flags and XOR decryption with incremental keys. See [tools.md](tools.md#risc-v-binary-analysis-ehax-2026).

## Sprague-Grundy Game Theory Binary

Game binary plays bounded Nim with PRNG for losing-position moves. Identify game framework (Grundy values = pile % (k+1), XOR determines position), track PRNG state evolution through user input feedback. See [patterns-ctf.md](patterns-ctf.md#sprague-grundy-game-theory-binary-dicectf-2026).

## Kernel Module Maze Solving

Rust kernel module implements maze via device ioctls. Enumerate commands dynamically, build DFS solver with decoy avoidance, deploy as minimal static binary (raw syscalls, no libc). See [patterns-ctf.md](patterns-ctf.md#kernel-module-maze-solving-dicectf-2026).

## Multi-Threaded VM with Channels

Custom VM with 16+ threads communicating via futex channels. Trace data flow across thread boundaries, extract constants from GDB, watch for inverted validity logic, solve via BFS state space search. See [patterns-ctf.md](patterns-ctf.md#multi-threaded-vm-with-channel-synchronization-dicectf-2026).

## CVP/LLL Lattice for Constrained Integer Validation (HTB ShadowLabyrinth)

Binary validates flag via matrix multiplication with 64-bit coefficients; solutions must be printable ASCII. Use LLL reduction + CVP in SageMath to find nearest lattice point in the constrained range. Two-phase pattern: Phase 1 recovers AES key, Phase 2 decrypts custom VM bytecode with another linear system (mod 2^32). See [patterns-ctf-2.md](patterns-ctf-2.md#cvplll-lattice-for-constrained-integer-validation-htb-shadowlabyrinth).

## Decision Tree Function Obfuscation (HTB WonderSMS)

~200+ auto-generated functions routing input through polynomial comparisons. Script extraction via Ghidra headless rather than reversing each function manually. Constraint propagation from known output format cascades through arithmetic constraints. See [patterns-ctf-2.md](patterns-ctf-2.md#decision-tree-function-obfuscation-htb-wondersms).

## Android JNI RegisterNatives Obfuscation (HTB WonderSMS)

`RegisterNatives` in `JNI_OnLoad` hides which C++ function handles each Java native method (no standard `Java_com_pkg_Class_method` symbol). Find the real handler by tracing `JNI_OnLoad` → `RegisterNatives` → `fnPtr`. Use x86_64 `.so` from APK for best Ghidra decompilation. See [languages.md](languages.md#android-jni-registernatives-obfuscation-htb-wondersms).

## Multi-Layer Self-Decrypting Binary

N-layer binary where each layer decrypts the next using user-provided key bytes + SHA-NI. Use oracle (correct key → valid code with expected pattern). JIT execution with fork-per-candidate COW isolation for speed. See [patterns-ctf-2.md](patterns-ctf-2.md#multi-layer-self-decrypting-binary-dicectf-2026).

## GLSL Shader VM with Self-Modifying Code

**Pattern:** WebGL2 fragment shader implements Turing-complete VM on a 256x256 RGBA texture (program memory + VRAM). Self-modifying code (STORE opcode) patches drawing instructions. GPU parallelism causes write conflicts — emulate sequentially in Python to recover full output. See [patterns-ctf-2.md](patterns-ctf-2.md#glsl-shader-vm-with-self-modifying-code-apoorvctf-2026).

## GF(2^8) Gaussian Elimination for Flag Recovery

**Pattern:** Binary performs Gaussian elimination over GF(2^8) with the AES polynomial (0x11b). Matrix + augmentation vector in `.rodata`; solution vector is the flag. Look for constant `0x1b` in disassembly. Addition is XOR, multiplication uses polynomial reduction. See [patterns-ctf-2.md](patterns-ctf-2.md#gf28-gaussian-elimination-for-flag-recovery-apoorvctf-2026).

## Z3 for Single-Line Python Boolean Circuit

**Pattern:** Single-line Python (2000+ semicolons) with walrus operator chains validates flag as big-endian integer via boolean circuit. Obfuscated XOR `(a | b) & ~(a & b)`. Split on semicolons, translate to Z3 symbolically, solve in under a second. See [patterns-ctf-2.md](patterns-ctf-2.md#z3-for-single-line-python-boolean-circuit-bearcatctf-2026).

## Sliding Window Popcount Differential Propagation

**Pattern:** Binary validates input via expected popcount for each position of a 16-bit sliding window. Popcount differences create a recurrence: `bit[i+16] = bit[i] + (data[i+1] - data[i])`. Brute-force ~4000-8000 valid initial 16-bit windows; each determines the entire bit sequence. See [patterns-ctf-2.md](patterns-ctf-2.md#sliding-window-popcount-differential-propagation-bearcatctf-2026).

## Ruby/Perl Polyglot Constraint Satisfaction

**Pattern:** Single file valid in both Ruby and Perl, each imposing different constraints on a key. Exploits `=begin`/`=end` (Ruby block comment) vs `=begin`/`=cut` (Perl POD) to run different code per interpreter. Intersect constraints from both languages to recover the unique key. See [languages.md](languages.md#rubyperl-polyglot-constraint-satisfaction-bearcatctf-2026).

## Backdoored Shared Library Detection

Binary works in GDB but fails when run normally (suid)? Check `ldd` for non-standard libc paths, then `strings | diff` the suspicious vs. system library to find injected code/passwords. See [patterns-ctf.md](patterns-ctf.md#backdoored-shared-library-detection-via-string-diffing-hacklu-ctf-2012).
