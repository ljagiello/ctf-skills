---
name: ctf-reverse
description: Provides reverse engineering techniques for CTF challenges. Use when analyzing binaries, game clients, obfuscated code, esoteric languages, custom VMs, anti-debugging, anti-analysis bypass, WASM, .NET, APK (including Flutter/Dart AOT with Blutter), HarmonyOS HAP/ABC, Python bytecode, Go/Rust/Swift/Kotlin binaries, VMProtect/Themida, Ghidra, GDB, radare2, Frida, angr, Qiling, Triton, binary diffing, macOS/iOS Mach-O, embedded firmware, kernel modules, game engines, or extracting flags from compiled executables.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Reverse Engineering

Quick reference for RE challenges. For detailed techniques, see supporting files.

## Additional Resources

- [tools.md](tools.md) - Static analysis tools (GDB, Ghidra, radare2, IDA, Binary Ninja, dogbolt.org, RISC-V with Capstone, Unicorn emulation, Python bytecode, WASM, Android APK, .NET, packed binaries)
- [tools-dynamic.md](tools-dynamic.md) (includes Intel Pin instruction-counting side channel for movfuscated binaries, opcode-only trace reconstruction) - Dynamic analysis tools: Frida (hooking, anti-debug bypass, memory scanning, Android/iOS), angr symbolic execution (path exploration, constraints, CFG), lldb (macOS/LLVM debugger), x64dbg (Windows), Qiling (cross-platform emulation with OS support), Triton (dynamic symbolic execution)
- [tools-advanced.md](tools-advanced.md) - Advanced tools: VMProtect/Themida analysis, binary diffing (BinDiff, Diaphora), deobfuscation frameworks (D-810, GOOMBA, Miasm), Rizin/Cutter, RetDec, advanced GDB (Python scripting, conditional breakpoints, watchpoints, reverse debugging with rr, pwndbg/GEF), advanced Ghidra scripting, patching (Binary Ninja API, LIEF)
- [anti-analysis.md](anti-analysis.md) - Comprehensive anti-analysis: Linux anti-debug (ptrace, /proc, timing, signals, direct syscalls), Windows anti-debug (PEB, NtQueryInformationProcess, heap flags, TLS callbacks, HW/SW breakpoint detection, exception-based, thread hiding), anti-VM/sandbox (CPUID, MAC, timing, artifacts, resources), anti-DBI (Frida detection/bypass), code integrity/self-hashing, anti-disassembly (opaque predicates, junk bytes), MBA identification/simplification, bypass strategies
- [patterns.md](patterns.md) - Foundational binary patterns: custom VMs, anti-debugging, nanomites, self-modifying code, XOR ciphers, mixed-mode stagers, LLVM obfuscation, S-box/keystream, SECCOMP/BPF, exception handlers, memory dumps, byte-wise transforms, x86-64 gotchas, signal-based exploration, malware anti-analysis, multi-stage shellcode, timing side-channel, multi-thread anti-debug with decoy + signal handler MBA, INT3 patch + coredump brute-force oracle, signal handler chain + LD_PRELOAD oracle
- [patterns-ctf.md](patterns-ctf.md) - Competition-specific patterns (Part 1): hidden emulator opcodes, LD_PRELOAD key extraction, SPN static extraction, image XOR smoothness, byte-at-a-time cipher, mathematical convergence bitmap, Windows PE XOR bitmap OCR, two-stage RC4+VM loaders, GBA ROM meet-in-the-middle, Sprague-Grundy game theory, kernel module maze solving, multi-threaded VM channels, backdoored shared library detection via string diffing, custom binfmt kernel module with RC4 flat binaries, hash-resolved imports / no-import ransomware, ELF section header corruption for anti-analysis
- [patterns-ctf-2.md](patterns-ctf-2.md) - Competition-specific patterns (Part 2): multi-layer self-decrypting brute-force, embedded ZIP+XOR license, stack string deobfuscation, prefix hash brute-force, CVP/LLL lattice for integer validation, decision tree function obfuscation, GLSL shader VM, GF(2^8) Gaussian elimination, Z3 single-line Python circuit, sliding window popcount, keyboard LED Morse code via ioctl
- [languages.md](languages.md) - Language-specific: Python bytecode & opcode remapping, Python version-specific bytecode, Pyarmor static unpack, DOS stubs, Unity IL2CPP, HarmonyOS HAP/ABC, Brainfuck/esolangs (+ BF character-by-character static analysis, BF side-channel read count oracle, BF comparison idiom detection), UEFI, transpilation to C, code coverage side-channel, OPAL functional reversing, non-bijective substitution, FRACTRAN program inversion
- [languages-platforms.md](languages-platforms.md) - Platform/framework-specific: Roblox place file analysis, Godot game asset extraction, Rust serde_json schema recovery, Android JNI RegisterNatives obfuscation, Frida Firebase Cloud Functions bypass, Verilog/hardware RE, prefix-by-prefix hash reversal, Ruby/Perl polyglot constraint satisfaction, Electron ASAR extraction + native binary analysis, Node.js npm runtime introspection
- [languages-compiled.md](languages-compiled.md) - Go binary reversing (GoReSym, goroutines, memory layout, channel ops, embed.FS, Go binary UUID patching for C2 enumeration), Rust binary reversing (demangling, Option/Result, Vec, panic strings), Swift binary reversing (demangling, protocol witness tables), Kotlin/JVM (coroutine state machines), C++ (vtable reconstruction, RTTI, STL patterns)
- [platforms.md](platforms.md) - Platform-specific RE: macOS/iOS (Mach-O, code signing, Objective-C runtime, Swift, dyld, jailbreak bypass), embedded/IoT firmware (binwalk, UART/JTAG/SPI extraction, ARM/MIPS, RTOS), kernel drivers (Linux .ko, eBPF, Windows .sys), game engines (Unreal Engine, Unity, anti-cheat, Lua), automotive CAN bus
- [platforms-hardware.md](platforms-hardware.md) - Hardware and advanced architecture RE: HD44780 LCD controller GPIO reconstruction, RISC-V advanced (custom extensions, privileged modes, debugging), ARM64/AArch64 reversing and exploitation (calling convention, ROP gadgets, qemu-aarch64-static emulation)

---

## Problem-Solving Workflow

1. **Start with strings extraction** - many easy challenges have plaintext flags
2. **Try ltrace/strace** - dynamic analysis often reveals flags without reversing
3. **Try Frida hooking** - hook strcmp/memcmp to capture expected values without reversing
4. **Try angr** - symbolic execution solves many flag-checkers automatically
5. **Try Qiling** - emulate foreign-arch binaries or bypass heavy anti-debug without artifacts
6. **Map control flow** before modifying execution
7. **Automate manual processes** via scripting (r2pipe, Frida, angr, Python)
8. **Validate assumptions** by comparing decompiler outputs (dogbolt.org for side-by-side)

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

**Key insight:** Let the program compute the answer, then dump it. Break at final comparison (`b *main+OFFSET`), enter any input of correct length, then `x/s $rsi` to dump computed flag.

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
Disassemble with `marshal.load()` + `dis.dis()`. Header: 8 bytes (2.x), 12 (3.0-3.6), 16 (3.7+). See [languages.md](languages.md#python-bytecode-reversing-disdis-output).

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
`apktool d app.apk -o decoded/` for resources; `jadx app.apk` for Java decompilation. Check `decoded/res/values/strings.xml` for flags. See [tools.md](tools.md#android-apk).

### Flutter APK (Dart AOT)
If `lib/arm64-v8a/libapp.so` + `libflutter.so` present, use [Blutter](https://github.com/worawit/blutter): `python3 blutter.py path/to/app/lib/arm64-v8a out_dir`. Outputs reconstructed Dart symbols + Frida script. See [tools.md](tools.md#flutter-apk-blutter).

### .NET
- dnSpy - debugging + decompilation
- ILSpy - decompiler

### Packed (UPX)
```bash
upx -d packed -o unpacked
```
If unpacking fails, inspect UPX metadata first: verify UPX section names, header fields, and version markers are intact. If metadata looks tampered or uncertain, review UPX source on GitHub to identify likely modification points. 

### Tauri Packed Desktop Apps
Tauri embeds Brotli-compressed frontend assets in the executable. Find `index.html` xrefs to locate asset index table, dump blobs, Brotli decompress. Reference: `tauri-codegen/src/embedded_assets.rs`.

## Anti-Debugging Bypass

Common checks:
- `IsDebuggerPresent()` / PEB.BeingDebugged / NtQueryInformationProcess (Windows)
- `ptrace(PTRACE_TRACEME)` / `/proc/self/status` TracerPid (Linux)
- TLS callbacks (run before main — check PE TLS Directory)
- Timing checks (`rdtsc`, `clock_gettime`, `GetTickCount`)
- Hardware breakpoint detection (DR0-DR3 via GetThreadContext)
- INT3 scanning / code self-hashing (CRC over .text section)
- Signal-based: SIGTRAP handler, SIGALRM timeout, SIGSEGV for real logic
- Frida/DBI detection: `/proc/self/maps` scan, port 27042, inline hook checks

Bypass: Set breakpoint at check, modify register to bypass conditional.
pwntools patch: `elf.asm(elf.symbols.ptrace, 'ret')` to replace function with immediate return. See [patterns.md](patterns.md#pwntools-binary-patching-crypto-cat).

For comprehensive anti-analysis techniques and bypasses (30+ methods with code), see [anti-analysis.md](anti-analysis.md).

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

**Sequential key-chain brute-force:** When a VM validates input in small blocks (e.g., 3 bytes = 2^24 candidates) with each block's output key feeding the next, brute-force each block sequentially with OpenMP parallelization. Compile solver with `gcc -O3 -march=native -fopenmp`. See [patterns-ctf-2.md](patterns-ctf-2.md#vm-sequential-key-chain-brute-force-midnight-flag-2026).

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

Try each byte (0-255) per position, match against expected output. **Uniform transform shortcut:** if one input byte only changes one output byte, build 0..255 mapping then invert. See [patterns.md](patterns.md) for full implementation.

## Unicorn Emulation (Complex State)

`from unicorn import *` -- map segments, set up stack, hook to trace. **Mixed-mode pitfall:** 64-bit stub jumping to 32-bit via `retf` requires switching to UC_MODE_32 and copying GPRs + EFLAGS + XMM regs. See [tools.md](tools.md#unicorn-emulation).

## Multi-Stage Shellcode Loaders

Nested shellcode with XOR decode loops; break at `call rax`, bypass ptrace with `set $rax=0`, extract flag from `mov` instructions. See [patterns.md](patterns.md#multi-stage-shellcode-loaders).

## Timing Side-Channel Attack

Validation time varies per correct character; measure elapsed time per candidate to recover flag byte-by-byte. See [patterns.md](patterns.md#timing-side-channel-attack).

## Godot Game Asset Extraction

Use KeyDot to extract encryption key from executable, then gdsdecomp to extract .pck package. See [languages-platforms.md](languages-platforms.md#godot-game-asset-extraction).

## Roblox Place File Analysis

Query Asset Delivery API for version history; parse `.rbxlbin` chunks (INST/PROP/PRNT) to diff script sources across versions. See [languages-platforms.md](languages-platforms.md#roblox-place-file-analysis).

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

Disassemble serde `Visitor` implementations to recover expected JSON schema; field names in order reveal flag. See [languages-platforms.md](languages-platforms.md#rust-serde_json-schema-recovery).

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

`RegisterNatives` in `JNI_OnLoad` hides which C++ function handles each Java native method (no standard `Java_com_pkg_Class_method` symbol). Find the real handler by tracing `JNI_OnLoad` → `RegisterNatives` → `fnPtr`. Use x86_64 `.so` from APK for best Ghidra decompilation. See [languages-platforms.md](languages-platforms.md#android-jni-registernatives-obfuscation-htb-wondersms).

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

**Pattern:** Single file valid in both Ruby and Perl, each imposing different constraints on a key. Exploits `=begin`/`=end` (Ruby block comment) vs `=begin`/`=cut` (Perl POD) to run different code per interpreter. Intersect constraints from both languages to recover the unique key. See [languages-platforms.md](languages-platforms.md#rubyperl-polyglot-constraint-satisfaction-bearcatctf-2026).

## Verilog/Hardware RE

**Pattern:** Verilog HDL source for state machines with hidden conditions gated on shift register history. Analyze `always @(posedge clk)` blocks and `case` statements to find correct input sequences. See [languages-platforms.md](languages-platforms.md#veriloghardware-reverse-engineering-srdnlenctf-2026).

## Custom binfmt Kernel Module with RC4 Flat Binaries (BSidesSF 2026)

**Pattern:** Kernel module registers binfmt handler for encrypted flat binaries. Reverse the `.ko` to find RC4 key (in `movabs` immediates), decrypt the flat binary, import at the fixed virtual address from the module's `vm_mmap` call. See [patterns-ctf.md](patterns-ctf.md#custom-binfmt-kernel-module-with-rc4-flat-binaries-bsidessf-2026).

## Hash-Resolved Imports / No-Import Ransomware (BSidesSF 2026)

**Pattern:** Binary with zero visible imports resolves APIs via symbol name hashing at runtime. Skip the hash reversing — hook OpenSSL functions via `LD_PRELOAD` in Docker to capture AES keys directly. See [patterns-ctf.md](patterns-ctf.md#hash-resolved-imports--no-import-ransomware-bsidessf-2026).

## ELF Section Header Corruption for Anti-Analysis (BSidesSF 2026)

**Pattern:** Corrupted section headers crash analysis tools but program headers are intact so binary runs normally. Patch `e_shoff` to zero or use `readelf -l` (program headers only). Flag hidden after corrupted sections with magic marker + XOR. See [patterns-ctf.md](patterns-ctf.md#elf-section-header-corruption-for-anti-analysis-bsidessf-2026).

## Brainfuck Character-by-Character Static Analysis (BSidesSF 2026)

**Pattern:** BF programs validating input have `,` (read char) followed by `+` operations whose count = expected ASCII value. Extract increment counts per input position to recover expected input without execution. See [languages.md](languages.md#brainfuck-character-by-character-static-analysis-bsidessf-2026).

## Brainfuck Side-Channel via Read Count Oracle (BSidesSF 2026)

**Pattern:** BF input validators read more bytes when a character is correct. Count `,` operations per candidate — highest read count = correct byte. Character-by-character recovery. See [languages.md](languages.md#brainfuck-side-channel-via-read-count-oracle-bsidessf-2026).

## Brainfuck Comparison Idiom Detection (BSidesSF 2026)

**Pattern:** Compiled BF uses fixed idioms for equality checks (`<[-<->] +<[>-<[-]]>[-<+>]`). Instrument interpreter to detect patterns and extract comparison operands (expected flag bytes). See [languages.md](languages.md#brainfuck-comparison-idiom-detection-bsidessf-2026).

## Backdoored Shared Library Detection

Binary works in GDB but fails when run normally (suid)? Check `ldd` for non-standard libc paths, then `strings | diff` the suspicious vs. system library to find injected code/passwords. See [patterns-ctf.md](patterns-ctf.md#backdoored-shared-library-detection-via-string-diffing-hacklu-ctf-2012).

## Go Binary Reversing

Large static binary with `go.buildid`? Use GoReSym to recover function names (works even on stripped binaries). Go strings are `{ptr, len}` pairs — not null-terminated. Look for `main.main`, `runtime.gopanic`, channel ops (`runtime.chansend1`/`chanrecv1`). Use Ghidra golang-loader plugin for best results. See [languages-compiled.md](languages-compiled.md#go-binary-reversing).

## Go Binary UUID Patching for C2 Enumeration (BSidesSF 2026)

**Pattern:** Go C2 client with UUID from `-ldflags -X`. Binary-patch UUID bytes (same length), register with C2, enumerate clients/files via API. See [languages-compiled.md](languages-compiled.md#go-binary-uuid-patching-for-c2-client-enumeration-bsidessf-2026).

## Rust Binary Reversing

Binary with `core::panicking` strings and `_ZN` mangled symbols? Use `rustfilt` for demangling. Panic messages contain source paths and line numbers — `strings binary | grep "panicked"` is the fastest approach. Option/Result enums use discriminant byte (0=None/Err, 1=Some/Ok). See [languages-compiled.md](languages-compiled.md#rust-binary-reversing).

## Frida Dynamic Instrumentation

Hook runtime functions without modifying binary. `frida -f ./binary -l hook.js` to spawn with instrumentation. Hook `strcmp`/`memcmp` to capture expected values, bypass anti-debug by replacing `ptrace` return value, scan memory for flag patterns, replace validation functions. See [tools-dynamic.md](tools-dynamic.md#frida-dynamic-instrumentation).

## Frida Firebase Cloud Functions Bypass (BSidesSF 2026)

**Pattern:** Android app validates via Firebase Cloud Functions. Post-login Frida hook constructs valid payload (UID + value + timestamp) and calls Cloud Function directly, bypassing QR/payment validation. See [languages-platforms.md](languages-platforms.md#frida-firebase-cloud-functions-bypass-bsidessf-2026).

## angr Symbolic Execution

Automatic path exploration to find inputs satisfying constraints. Load binary with `angr.Project`, set find/avoid addresses, call `simgr.explore()`. Constrain input to printable ASCII and known prefix for faster solving. Hook expensive functions (crypto, I/O) to prevent path explosion. See [tools-dynamic.md](tools-dynamic.md#angr-symbolic-execution).

## Qiling Emulation

Cross-platform binary emulation with OS-level support (syscalls, filesystem). Emulate Linux/Windows/ARM/MIPS binaries on any host. No debugger artifacts — bypasses all anti-debug by default. Hook syscalls and addresses with Python API. See [tools-dynamic.md](tools-dynamic.md#qiling-framework-cross-platform-emulation).

## VMProtect / Themida Analysis

VMProtect virtualizes code into custom bytecode. Identify VM entry (pushad-like), find handler table (large indirect jump), trace handlers dynamically. For CTF, focus on tracing operations on input rather than full devirtualization. Themida: dump at OEP with ScyllaHide + Scylla. See [tools-advanced.md](tools-advanced.md#vmprotect-analysis).

## Binary Diffing

BinDiff and Diaphora compare two binaries to highlight changes. Essential when challenge provides patched/original versions. Export from IDA/Ghidra, diff to find vulnerability or hidden functionality. See [tools-advanced.md](tools-advanced.md#binary-diffing).

## Advanced GDB (pwndbg, rr)

pwndbg: `context`, `vmmap`, `search -s "flag{"`, `telescope $rsp`. GEF alternative. Reverse debugging with `rr record`/`rr replay` — step backward through execution. Python scripting for brute-force and automated tracing. See [tools-advanced.md](tools-advanced.md#advanced-gdb-techniques).

## macOS / iOS Reversing

Mach-O binaries: `otool -l` for load commands, `class-dump` for Objective-C headers. Swift: `swift demangle` for symbols. iOS apps: decrypt FairPlay DRM with frida-ios-dump, bypass jailbreak detection with Frida hooks. Re-sign patched binaries with `codesign -f -s -`. See [platforms.md](platforms.md#macos--ios-reversing).

## Embedded / IoT Firmware RE

`binwalk -Me firmware.bin` for recursive extraction. Hardware: UART/JTAG/SPI flash for firmware dumps. Filesystems: SquashFS (`unsquashfs`), JFFS2, UBI. Emulate with QEMU: `qemu-arm -L /usr/arm-linux-gnueabihf/ ./binary`. See [platforms.md](platforms.md#embedded--iot-firmware-re).

## Kernel Driver Reversing

Linux `.ko`: find ioctl handler via `file_operations` struct, trace `copy_from_user`/`copy_to_user`. Debug with QEMU+GDB (`-s -S`). eBPF: `bpftool prog dump xlated`. Windows `.sys`: find `DriverEntry` → `IoCreateDevice` → IRP handlers. See [platforms.md](platforms.md#kernel-driver-reversing).

## Game Engine Reversing

Unreal: extract .pak with UnrealPakTool, reverse Blueprint bytecode with FModel. Unity Mono: decompile Assembly-CSharp.dll with dnSpy. Anti-cheat (EAC, BattlEye, VAC): identify system, bypass specific check. Lua games: `luadec`/`unluac` for bytecode. See [platforms.md](platforms.md#game-engine-reversing).

## Swift / Kotlin Binary Reversing

Swift: `swift demangle` symbols, protocol witness tables for dispatch, `__swift5_*` sections. Kotlin/JVM: coroutines compile to state machines in `invokeSuspend`, `jadx` with Kotlin mode for best decompilation. Kotlin/Native: LLVM backend, looks like C++ in disassembly. See [languages-compiled.md](languages-compiled.md#swift-binary-reversing).

## INT3 Patch + Coredump Brute-Force Oracle (Pwn2Win 2016)

Patch `0xCC` (INT3) after transform output, enable core dumps, brute-force each input character by extracting computed state from coredump via `strings`. Avoids full reverse of transformation. See [patterns.md](patterns.md#int3-patch--coredump-brute-force-oracle-pwn2win-2016).

## Signal Handler Chain + LD_PRELOAD Oracle (Nuit du Hack 2016)

Binary uses signal handler chains for per-character password validation. Hook `signal()` via LD_PRELOAD -- the call to install the next handler confirms the current character is correct. See [patterns.md](patterns.md#signal-handler-chain--ld_preload-oracle-nuit-du-hack-2016).

## FRACTRAN Program Inversion (Boston Key Party 2016)

Esoteric language using iterated fraction multiplication. Invert by swapping numerator/denominator in fraction table, run output backward. I/O encoded as prime factorization exponents. See [languages.md](languages.md#fractran-program-inversion-boston-key-party-2016).

## Opcode-Only Trace Reconstruction (0CTF 2016)

Execution traces with only opcodes (no data) still leak info through branch decisions. Sorting algorithm comparisons reveal element ordering. Reconstruct by deduplicating trace, splitting into basic blocks. See [tools-dynamic.md](tools-dynamic.md#opcode-only-trace-reconstruction-0ctf-2016).
