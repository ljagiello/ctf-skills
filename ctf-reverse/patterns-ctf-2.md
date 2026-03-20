# CTF Reverse - Competition-Specific Patterns (Part 2)

## Table of Contents
- [Multi-Layer Self-Decrypting Binary (DiceCTF 2026)](#multi-layer-self-decrypting-binary-dicectf-2026)
- [Embedded ZIP + XOR License Decryption (MetaCTF 2026)](#embedded-zip--xor-license-decryption-metactf-2026)
- [Stack String Deobfuscation from .rodata XOR Blob (Nullcon 2026)](#stack-string-deobfuscation-from-rodata-xor-blob-nullcon-2026)
- [Prefix Hash Brute-Force (Nullcon 2026)](#prefix-hash-brute-force-nullcon-2026)
- [CVP/LLL Lattice for Constrained Integer Validation (HTB ShadowLabyrinth)](#cvplll-lattice-for-constrained-integer-validation-htb-shadowlabyrinth)
- [Decision Tree Function Obfuscation (HTB WonderSMS)](#decision-tree-function-obfuscation-htb-wondersms)
- [GLSL Shader VM with Self-Modifying Code (ApoorvCTF 2026)](#glsl-shader-vm-with-self-modifying-code-apoorvctf-2026)
- [GF(2^8) Gaussian Elimination for Flag Recovery (ApoorvCTF 2026)](#gf28-gaussian-elimination-for-flag-recovery-apoorvctf-2026)
- [Z3 for Single-Line Python Boolean Circuit (BearCatCTF 2026)](#z3-for-single-line-python-boolean-circuit-bearcatctf-2026)
- [Sliding Window Popcount Differential Propagation (BearCatCTF 2026)](#sliding-window-popcount-differential-propagation-bearcatctf-2026)
- [Morse Code from Keyboard LEDs via ioctl (PlaidCTF 2013)](#morse-code-from-keyboard-leds-via-ioctl-plaidctf-2013)
- [C++ Destructor-Hidden Validation (Defcamp 2015)](#c-destructor-hidden-validation-defcamp-2015)
- [VM Sequential Key-Chain Brute-Force (Midnight Flag 2026)](#vm-sequential-key-chain-brute-force-midnight-flag-2026)
- [Syscall Side-Effect Memory Corruption (Hack.lu 2015)](#syscall-side-effect-memory-corruption-hacklu-2015)
- [MFC Dialog Event Handler Location (WhiteHat 2015)](#mfc-dialog-event-handler-location-whitehat-2015)

---

## Multi-Layer Self-Decrypting Binary (DiceCTF 2026)

**Pattern (another-onion):** Binary with N layers (e.g., 256), each reading 2 key bytes, deriving keystream via SHA-256 NI instructions, XOR-decrypting the next layer, then jumping to it. Must solve within a time limit (e.g., 30 minutes).

**Oracle for correct key:** Wrong key bytes produce garbage code. Correct key bytes produce code with exactly 2 `call read@plt` instructions (next layer's reads). Brute-force all 65536 candidates per layer using this oracle.

**JIT execution approach (fastest):**
```c
// Map binary's memory at original virtual addresses into solver process
// Compile solver at non-overlapping address: -Wl,-Ttext-segment=0x10000000
void *text = mmap((void*)0x400000, text_size, PROT_RWX, MAP_FIXED|MAP_PRIVATE, fd, 0);
void *bss = mmap((void*)bss_addr, bss_size, PROT_RW, MAP_FIXED|MAP_SHARED, shm_fd, 0);

// Patch read@plt to inject candidate bytes instead of reading stdin
// Patch tail jmp/call to next layer with ret/NOP to return from layer

// Fork-per-candidate: COW gives isolated memory without memcpy
for (int candidate = 0; candidate < 65536; candidate++) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child: remap BSS as MAP_PRIVATE (COW from shared file)
        mmap(bss_addr, bss_size, PROT_RW, MAP_FIXED|MAP_PRIVATE, shm_fd, 0);
        inject_key(candidate >> 8, candidate & 0xff);
        ((void(*)())layer_addr)();  // Execute layer as function call
        // Check: does decrypted code contain exactly 2 call read@plt?
        if (count_read_calls(next_layer_addr) == 2) signal_found(candidate);
        _exit(0);
    }
}
```

**Performance tiers:**
| Approach | Speed | 256-layer estimate |
|----------|-------|--------------------|
| Python subprocess | ~2/s | days |
| Ptrace fork injection | ~119/s | 6+ hours |
| JIT + fork-per-candidate | ~1000/s | 140 min |
| JIT + shared BSS + 32 workers | ~3500/s | **~17 min** |

**Shared BSS optimization:** BSS (16MB+) stored in `/dev/shm` as `MAP_SHARED` in parent. Children remap as `MAP_PRIVATE` for COW. Reduces fork overhead from 16MB page-table setup to ~4KB.

**Key insight:** Multi-layer decryption challenges are fundamentally about building fast brute-force engines. JIT execution (mapping binary memory into solver, running code directly as function calls) is orders of magnitude faster than ptrace. Fork-based COW provides free memory isolation per candidate.

**Gotchas:**
- Real binary may use `call` (0xe8) instead of `jmp` (0xe9) for layer transitions — adjust tail patching
- BSS may extend beyond ELF MemSiz via kernel brk mapping — map extra space
- SHA-NI instructions work even when not advertised in `/proc/cpuinfo`

---

## Embedded ZIP + XOR License Decryption (MetaCTF 2026)

**Pattern (License To Rev):** Binary requires a license file as argument. Contains an embedded ZIP archive with the expected license, and an XOR-encrypted flag.

**Recognition:**
- `strings` reveals `EMBEDDED_ZIP` and `ENCRYPTED_MESSAGE` symbols
- Binary is not stripped — `nm` or `readelf -s` shows data symbols in `.rodata`
- `file` shows PIE executable, source file named `licensed.c`

**Analysis workflow:**
1. **Find data symbols:**
```bash
readelf -s binary | grep -E "EMBEDDED|ENCRYPTED|LICENSE"
# EMBEDDED_ZIP at offset 0x2220, 384 bytes
# ENCRYPTED_MESSAGE at offset 0x21e0, 35 bytes
```

2. **Extract embedded ZIP:**
```python
import struct
with open('binary', 'rb') as f:
    data = f.read()
# Find PK\x03\x04 magic in .rodata
zip_start = data.find(b'PK\x03\x04')
# Extract ZIP (size from symbol table or until next symbol)
open('embedded.zip', 'wb').write(data[zip_start:zip_start+384])
```

3. **Extract license from ZIP:**
```bash
unzip embedded.zip  # Contains license.txt
```

4. **XOR decrypt the flag:**
```python
license = open('license.txt', 'rb').read()
enc_msg = open('encrypted_msg.bin', 'rb').read()  # Extract from .rodata
flag = bytes(a ^ b for a, b in zip(enc_msg, license))
print(flag.decode())
```

**Key insight:** No need to run the binary or bypass the expiry date check. The embedded ZIP and encrypted message are both in `.rodata` — extract and XOR offline.

**Disassembly confirms:**
- `memcmp(user_license, decompressed_embedded_zip, size)` — license validation
- Date parsing with `sscanf("%d-%d-%d")` on `EXPIRY_DATE=` field
- XOR loop: `ENCRYPTED_MESSAGE[i] ^ license[i]` → `putc()` per byte

**Lesson:** When a binary has named symbols (`EMBEDDED_*`, `ENCRYPTED_*`), extract data directly from the binary without execution. XOR with known plaintext (the license) is trivially reversible.

---

## Stack String Deobfuscation from .rodata XOR Blob (Nullcon 2026)

**Pattern (stack_strings_1/2):** Binary mmaps a blob from `.rodata`, XOR-deobfuscates it, then uses the blob to validate input. Flag is recovered by reimplementing the verification loop.

**Recognition:**
- `mmap()` call followed by XOR loop over `.rodata` data
- Verification loop with running state (`eax`, `ebx`, `r9`) updated with constants like `0x9E3779B9`, `0x85EBCA6B`, `0xA97288ED`
- `rol32()` operations with position-dependent shifts
- Expected bytes stored in deobfuscated buffer

**Approach:**
1. Extract `.rodata` blob with pyelftools:
   ```python
   from elftools.elf.elffile import ELFFile
   with open(binary, "rb") as f:
       elf = ELFFile(f)
       ro = elf.get_section_by_name(".rodata")
       blob = ro.data()[offset:offset+size]
   ```
2. Recover embedded constants (length, magic values) by XOR with known keys from disassembly
3. Reimplement the byte-by-byte verification loop:
   - Each iteration: compute two hash-like values from running state
   - XOR them together and with expected byte to recover input byte
   - Update running state with constant additions

**Variant (stack_strings_2):** Adds position permutation + state dependency on previous character:
- Position permutation: byte `i` may go to position `pos[i]` in the output
- State dependency: `need = (expected - rol8(prev_char, 1)) & 0xFF`
- Must track `state` variable that updates to current character each iteration

**Key constants to look for:**
- `0x9E3779B9` (golden ratio fractional, common in hash functions)
- `0x85EBCA6B` (MurmurHash3 finalizer constant)
- `0xA97288ED` (related hash constant)
- `rol32()` with shift `i & 7`

---

## Prefix Hash Brute-Force (Nullcon 2026)

**Pattern (Hashinator):** Binary hashes every prefix of the input independently and outputs one digest per prefix. Given N output digests, the flag has N-1 characters.

**Attack:** Recover input one character at a time:
```python
for pos in range(1, len(target_hashes)):
    for ch in charset:
        candidate = known_prefix + ch + padding
        hashes = run_binary(candidate)
        if hashes[pos] == target_hashes[pos]:
            known_prefix += ch
            break
```

**Key insight:** If each prefix hash is independent (no chaining/HMAC), the problem decomposes into `N` x `|charset|` binary executions. This is the hash equivalent of byte-at-a-time block cipher attacks.

**Detection:** Binary outputs multiple hash lines. Changing last character only changes last hash. Different input lengths produce different numbers of output lines.

---

## CVP/LLL Lattice for Constrained Integer Validation (HTB ShadowLabyrinth)

**Pattern:** Binary validates flag via matrix multiplication where grouped input characters are multiplied by coefficient matrices and checked against expected 64-bit results. Standard algebra fails because solutions must be printable ASCII (32-126). Lattice-based CVP (Closest Vector Problem) with LLL reduction solves this efficiently.

**Identification:**
1. Binary groups input characters (e.g., 4 at a time)
2. Each group is multiplied by a coefficient matrix
3. Results compared against hardcoded 64-bit values
4. Need integer solutions in a constrained range (printable ASCII)

**SageMath CVP solver:**
```python
from sage.all import *

def solve_constrained_matrix(coefficients, targets, char_range=(32, 126)):
    """
    coefficients: list of coefficient rows (e.g., 4 values per group)
    targets: expected output values
    char_range: valid character range (printable ASCII)
    """
    n = len(coefficients[0])  # characters per group
    mid = (char_range[0] + char_range[1]) // 2

    # Build lattice: [coeff_matrix | I*scale]
    # The target vector includes adjusted targets
    M = matrix(ZZ, n + len(targets), n + len(targets))
    scale = 1000  # Weight to constrain character range

    for i, row in enumerate(coefficients):
        for j, c in enumerate(row):
            M[j, i] = c
        M[n + i, i] = 1  # padding

    for j in range(n):
        M[j, len(targets) + j] = scale

    target_vec = vector(ZZ, [t - sum(c * mid for c in row)
                              for row, t in zip(coefficients, targets)]
                        + [0] * n)

    # LLL + CVP
    L = M.LLL()
    closest = L * L.solve_left(target_vec)  # or use Babai
    solution = [closest[len(targets) + j] // scale + mid for j in range(n)]
    return bytes(solution)
```

**Two-phase validation pattern:**
1. **Phase 1 (matrix math):** Solve via CVP/LLL → recovers first N characters
2. First N characters become AES key → decrypt `file.bin` (XOR last 16 bytes + AES-256-CBC + zlib decompress)
3. **Phase 2 (custom VM):** Decrypted bytecode runs in custom VM, validates remaining characters via another linear system (mod 2^32)

**Modular linear system solving (Phase 2 — VM validation):**
```python
import numpy as np
from sympy import Matrix

# M * x = v (mod 2^32)
M_mod = Matrix(coefficients) % (2**32)
v_mod = Matrix(targets) % (2**32)
# Gaussian elimination in Z/(2^32)
solution = M_mod.solve(v_mod)  # Returns flag characters
```

**Key insight:** When a binary validates input through linear combinations with large coefficients and the solution must be in a small range (printable ASCII), this is a lattice problem in disguise. LLL reduction + CVP finds the nearest lattice point, recovering the constrained solution. Cross-reference: invoke `/ctf-crypto` for LLL/CVP fundamentals (advanced-math.md in ctf-crypto).

**Detection:** Binary performs matrix-like operations on grouped input, compares against 64-bit constants, and a brute-force search space is too large (e.g., 256^4 per group × 12 groups).

---

## Decision Tree Function Obfuscation (HTB WonderSMS)

**Pattern:** Binary routes input through ~200+ auto-generated functions, each computing a polynomial expression from input positions, comparing against a constant, and branching left/right. The tree makes static analysis impractical without scripted extraction.

**Identification:**
1. Large number of similar functions with random-looking names (e.g., `f315732804`)
2. Each function computes arithmetic on specific input positions
3. Functions call other tree functions or a final validation function
4. Decompiled code shows `if (expr cmp constant) call_left() else call_right()`

**Ghidra headless scripting for mass extraction:**
```python
# Extract comparison constants from all tree functions
# Run via: analyzeHeadless project/ tmp -import binary -postScript extract_tree.py
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *

fm = currentProgram.getFunctionManager()
results = []
for func in fm.getFunctions(True):
    name = func.getName()
    if name.startswith('f') and name[1:].isdigit():
        # Find CMP instruction and extract immediate constant
        inst_iter = currentProgram.getListing().getInstructions(func.getBody(), True)
        for inst in inst_iter:
            if inst.getMnemonicString() == 'CMP':
                operand = inst.getOpObjects(1)
                if operand:
                    results.append((name, int(operand[0].getValue())))
```

**Constraint propagation from known output format:**
1. Start from known output bytes (e.g., `http://HTB{...}`) → fix several input positions
2. Fixed positions cascade through arithmetic constraints → determine dependent positions
3. Tree root equation pins down remaining free variables
4. Recognize English words in partial flag to disambiguate multiple solutions

**Key insight:** Auto-generated decision trees look overwhelming but are repetitive by construction. Script the extraction (Ghidra, Binary Ninja, radare2) rather than reversing each function manually. The tree is just a dispatcher — the real logic is in the leaf function and its constraints.

**Detection:** Binary with hundreds of similarly-structured functions, 3-5 input position references per function, branching to two other functions or a common leaf.

---

## GLSL Shader VM with Self-Modifying Code (ApoorvCTF 2026)

**Pattern (Draw Me):** A WebGL2 fragment shader implements a Turing-complete VM on a 256x256 RGBA texture. The texture is both program memory and display output.

**Texture layout:**
- **Row 0:** Registers (pixel 0 = instruction pointer, pixels 1-32 = general purpose)
- **Rows 1-127:** Program memory (RGBA = opcode, arg1, arg2, arg3)
- **Rows 128-255:** VRAM (display output)

**Opcodes:** NOP(0), SET(1), ADD(2), SUB(3), XOR(4), JMP(5), JNZ(6), VRAM-write(7), STORE(8), LOAD(9). 16 steps per frame.

**Self-modifying code:** Phase 1 (decryption) uses STORE opcode to XOR-patch program memory that Phase 2 (drawing) then executes. The decryption overwrites SET instructions with correct pixel color values before the drawing code runs.

**Why GPU rendering fails:** The GPU runs all pixels in parallel per frame, but the shader tracks only ONE write target per pixel per frame. With multiple VRAM writes per frame, only the last survives — losing 75%+ of pixels. Similarly, STORE patches conflict during parallel decryption.

**Solve via sequential emulation:**
```python
from PIL import Image
import numpy as np

img = Image.open('program.png').convert('RGBA')
state = np.array(img, dtype=np.int32).copy()
regs = [0] * 33

# Phase 1: Trace decryption — apply all STORE patches sequentially
x, y = start_x, start_y
while True:
    r, g, b, a = state[y][x]
    opcode = int(r)
    if opcode == 1: regs[g] = b & 255           # SET
    elif opcode == 4: regs[g] = regs[b] ^ regs[a]  # XOR
    elif opcode == 8:                              # STORE — patches program memory
        tx, ty = regs[g], regs[b]
        state[ty][tx] = [regs[a], regs[a+1], regs[a+2], regs[a+3]]
    elif opcode == 5: break                        # JMP to drawing phase
    x += 1
    if x > 255: x, y = 0, y + 1

# Phase 2: Execute drawing code — all VRAM writes preserved
vram = np.zeros((128, 256), dtype=np.uint8)
# ... trace with opcode 7 writing to vram[ty][tx] = color
Image.fromarray(vram, mode='L').save('output.png')
```

**Key insight:** GLSL shaders are Turing-complete but GPU parallelism causes write conflicts. Self-modifying code (STORE patches) compounds the problem — patches from parallel executions overwrite each other. Sequential emulation in Python recovers the full output. The program.png file IS the bytecode.

**Detection:** WebGL/shader challenge with a PNG "program" file, challenge says "nothing renders" or output is garbled. Look for custom opcode tables in GLSL source.

---

## GF(2^8) Gaussian Elimination for Flag Recovery (ApoorvCTF 2026)

**Pattern (Forge):** Stripped binary performs Gaussian elimination over GF(2^8) (Galois Field with 256 elements, using the AES polynomial). A matrix and augmentation vector are embedded in `.rodata`. The solution vector is the flag.

**GF(2^8) arithmetic with AES polynomial (x^8+x^4+x^3+x+1 = 0x11b):**
```python
def gf_mul(a, b):
    """Multiply in GF(2^8) with AES reduction polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b  # Reduction: x^8 = x^4+x^3+x+1
        b >>= 1
    return p

def gf_inv(a):
    """Brute-force multiplicative inverse (fine for 256 elements)."""
    if a == 0: return 0
    for x in range(1, 256):
        if gf_mul(a, x) == 1:
            return x
    return 0
```

**Solving the linear system:**
```python
# Extract N×N matrix + N-byte augmentation from binary .rodata
N = 56  # Flag length
# Build augmented matrix: N rows × (N+1) cols

for col in range(N):
    # Find non-zero pivot
    pivot = next((r for r in range(col, N) if aug[r][col] != 0), -1)
    if pivot != col:
        aug[col], aug[pivot] = aug[pivot], aug[col]
    # Scale pivot row by inverse
    inv = gf_inv(aug[col][col])
    aug[col] = [gf_mul(v, inv) for v in aug[col]]
    # Eliminate column in all other rows
    for row in range(N):
        if row == col: continue
        factor = aug[row][col]
        if factor == 0: continue
        aug[row] = [v ^ gf_mul(factor, aug[col][j]) for j, v in enumerate(aug[row])]

flag = bytes(aug[i][N] for i in range(N))
```

**Key insight:** GF(2^8) is NOT regular integer arithmetic — addition is XOR, multiplication uses polynomial reduction. The AES polynomial (0x11b) is the most common; look for the constant `0x1b` in disassembly. The binary may encrypt the result with AES-GCM afterward, but the raw solution vector (pre-encryption) is the flag.

**Detection:** Binary with a large matrix in `.rodata` (N² bytes), XOR-based row operations, constants `0x1b` or `0x11b`, and flag length matching sqrt of matrix size.

---

## Z3 for Single-Line Python Boolean Circuit (BearCatCTF 2026)

**Pattern (Captain Morgan):** Single-line Python (2000+ semicolons) validates flag via walrus operator chains decomposing input as a big-endian integer, with bitwise operations producing a boolean circuit.

**Identification:**
- Single-line Python with semicolons separating statements
- Walrus operator `:=` chains: `(x := expr)`
- Obfuscated XOR: `(x | i) & ~(x & i)` instead of `x ^ i`
- Input treated as a single large integer, decomposed via bit-shifting

**Z3 solution:**
```python
from z3 import *

n_bytes = 29  # Flag length
ari = BitVec('ari', n_bytes * 8)

# Parse semicolon-separated statements
# Model walrus chains as LShR(ari, shift_amount)
# Evaluate boolean expressions symbolically
# Final assertion: result_var == 0

s = Solver()
s.add(bfu == 0)  # Final validation variable
if s.check() == sat:
    m = s.model()
    val = m[ari].as_long()
    flag = val.to_bytes(n_bytes, 'big').decode('ascii')
```

**Key insight:** Single-line Python obfuscation creates a boolean circuit over input bits. The walrus operator chains are just variable assignments — split on semicolons and translate each to Z3 symbolically. Obfuscated XOR `(a | b) & ~(a & b)` is just `a ^ b`. Z3 solves these circuits in under a second. Look for `__builtins__` access or `ord()`/`chr()` calls to identify the input→integer conversion.

**Detection:** Single-line Python with 1000+ semicolons, walrus operators, bitwise operations, and a final comparison to 0 or True.

---

## Sliding Window Popcount Differential Propagation (BearCatCTF 2026)

**Pattern (Treasure Hunt 4):** Binary validates input via expected popcount (number of set bits) for each position of a 16-bit sliding window over the input bits.

**Differential propagation:**
When the window slides by 1 bit:
```text
popcount(window[i+1]) - popcount(window[i]) = bit[i+16] - bit[i]
```
So: `bit[i+16] = bit[i] + (data[i+1] - data[i])`

```python
expected = [...]  # 337 expected popcount values
total_bits = 337 + 15  # = 352

# Brute-force the initial 16-bit window (must have popcount = expected[0])
for start_val in range(0x10000):
    if bin(start_val).count('1') != expected[0]:
        continue

    bits = [0] * total_bits
    for j in range(16):
        bits[j] = (start_val >> (15 - j)) & 1

    valid = True
    for i in range(len(expected) - 1):
        new_bit = bits[i] + (expected[i + 1] - expected[i])
        if new_bit not in (0, 1):
            valid = False
            break
        bits[i + 16] = new_bit

    if valid:
        # Convert bits to bytes
        flag_bytes = bytes(int(''.join(map(str, bits[i:i+8])), 2)
                          for i in range(0, total_bits, 8))
        if b'BCCTF' in flag_bytes or flag_bytes[:5].isascii():
            print(flag_bytes.decode(errors='replace'))
            break
```

**Key insight:** Sliding window popcount differences create a recurrence relation: each new bit is determined by the bit 16 positions back plus the popcount delta. Only the first 16 bits are free (constrained by initial popcount). Brute-force the ~4000-8000 valid initial windows — for each, the entire bit sequence is deterministic. Runs in under a second.

**Detection:** Binary computing popcount/hamming weight on fixed-size windows. Expected value array with length ≈ input_bits - window_size + 1. Values in array are small integers (0 to window_size).

---

---

## Morse Code from Keyboard LEDs via ioctl (PlaidCTF 2013)

**Pattern:** Binary uses `ioctl(fd, KDSETLED, value)` to blink keyboard LEDs (Num/Caps/Scroll Lock). Timing patterns encode Morse code.

```bash
# Step 1: Bypass ptrace anti-debug
# Patch ptrace call at offset with NOP (0x90)
python3 -c "
data = open('binary','rb').read()
data = data[:0x72b] + b'\x90'*5 + data[:0x730]  # NOP the ptrace call
open('patched','wb').write(data)
"

# Step 2: Run under strace, capture ioctl calls
strace -e ioctl ./patched 2>&1 | grep KDSETLED > leds.txt

# Step 3: Decode timing patterns
# Short blink (250ms) = dit (.), long blink (750ms) = dah (-)
# Inter-character pause = 3x, inter-word pause = 7x
```

```python
# Parse strace output to extract Morse
import re
morse_map = {'.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E',
             '..-.':'F', '--.':'G', '....':'H', '..':'I', '.---':'J',
             '-.-':'K', '.-..':'L', '--':'M', '-.':'N', '---':'O',
             '.--.':'P', '--.-':'Q', '.-.':'R', '...':'S', '-':'T',
             '..-':'U', '...-':'V', '.--':'W', '-..-':'X', '-.--':'Y',
             '--..':'Z', '-----':'0', '.----':'1'}
# Map LED on-durations to dots/dashes, group by pauses
```

**Key insight:** `KDSETLED` controls physical keyboard LEDs on Linux (`/dev/console`). The binary must run with console access. Use `strace -e ioctl` to capture all LED state changes without needing physical observation. Timing between calls determines dot vs dash.

---

## C++ Destructor-Hidden Validation (Defcamp 2015)

Validation logic may hide in C++ destructors that execute after `main()` returns. The `__cxa_atexit` mechanism registers destructor callbacks:

1. **Locate destructors:** Search for `__cxa_atexit` calls in `.init_array`/constructor sections
2. **Static analysis:** Identify global objects whose destructors perform flag checking
3. **Dynamic verification:** Set breakpoints on `__cxa_finalize` to trace post-main execution

```bash
# In IDA/Ghidra: look for atexit registrations
__cxa_atexit(destructor_func, object_ptr, dso_handle);

# Destructor contains actual validation:
# - Regex pattern matching on 4-byte blocks (8 sequential checks)
# - Arithmetic: v2 += -3 * s[i] + 36 + (s[i] ^ 0x2FCFBA)
# - Modular verification of accumulated sum
```

**Key insight:** When `main()` appears trivial or incomplete, check destructors of global/static C++ objects. The `.fini_array` section and `__cxa_atexit` registrations reveal hidden post-main logic.

---

## Syscall Side-Effect Memory Corruption (Hack.lu 2015)

The `rt_sigprocmask` syscall writes a `sigset_t` structure to its output pointer. When input parsing passes a pointer near a security-critical variable:

1. Certain input characters (e.g., `:` to `@` range, values 0x3A-0x40) trigger `rt_sigprocmask` as a side effect
2. The syscall zeros out bytes at the output address, which may overlap adjacent variables
3. In little-endian layout, zeroing the MSB of an adjacent integer variable effectively sets it to a small value

```c
// Memory layout (no ASLR):
// 0x603390: input_buffer[4]
// 0x603394: security_check_var

// Input ':' triggers: rt_sigprocmask(SIG_BLOCK, NULL, (sigset_t*)0x603397, ...)
// This zeros bytes at 0x603397+, corrupting security_check_var's high bytes
```

**Key insight:** Audit how input validation functions interact with syscalls. Character-to-syscall mappings in hex conversion routines can produce unintended memory writes via kernel-space operations.

---

## MFC Dialog Event Handler Location (WhiteHat 2015)

To find event handlers in MFC (Microsoft Foundation Class) applications:

1. **Break on SendMessageW:** Set breakpoint on `user32!SendMessageW` to intercept dialog messages
2. **Filter for WM_COMMAND:** Message ID 0x111 indicates button clicks and control events
3. **Trace message map:** Follow the MFC message dispatch from `CWnd::OnWndMsg` → `CCmdTarget::OnCmdMsg` → handler function
4. **OnInitDialog:** Often contains decryption or validation setup; triggered by WM_INITDIALOG (0x110)

```asm
# WinDbg/x64dbg:
bp user32!SendMessageW ".if (poi(@esp+8)==0x111) {} .else {gc}"
# Or in IDA: find cross-references to AFX_MSGMAP_ENTRY structures
```

**Key insight:** MFC applications route messages through dispatch tables. Identify the `AFX_MSGMAP` structure to enumerate all handled messages without runtime analysis.

---

## VM Sequential Key-Chain Brute-Force (Midnight Flag 2026)

**Pattern (67):** Custom VM validates input in N-byte blocks. Each block's output key feeds as input to the next block, preventing parallel solving. Per-block search space is small enough to brute-force (2^24 for 3-byte blocks).

**Recognition signs:**
- Bytecode with XOR-obfuscated opcodes (all bytes XOR'd with a constant, producing ASCII-looking bytecode)
- Iterative transformation loop (xorshift + multiply, repeated 1000+ times) making algebraic inversion impractical
- CHECK opcodes comparing accumulated state against embedded constants
- Large `.data` section with repetitive bytecode patterns

**Solving approach:**
1. Parse bytecode to extract CHECK values (expected key after each block)
2. For each block sequentially, brute-force the input bytes that produce the expected key
3. Use the CHECK value as the key for the next block

```c
// OpenMP-parallelized per-block brute-force
uint32_t process(uint32_t val) {
    for (int i = 0; i < 1000; i++) {
        val ^= (val << 13);
        val ^= (val >> 17);
        val ^= (val << 5);
        val *= 0x2545f491;
    }
    return val;
}

int solve_block(uint32_t old_key, uint32_t expected_key, unsigned char *out) {
    int found = 0;
    #pragma omp parallel for shared(found)
    for (int v = 0; v < 0x1000000; v++) {
        if (found) continue;
        uint32_t input_val = ((v >> 16) << 16) | (v & 0xFF) | ((v >> 8 & 0xFF) << 8);
        uint32_t saved = input_val ^ old_key;
        uint32_t final_val = process(saved);
        if ((final_val ^ saved) == expected_key) {
            #pragma omp critical
            { if (!found) { out[0]=v>>16; out[1]=(v>>8)&0xFF; out[2]=v&0xFF; found=1; } }
        }
    }
    return found;
}
// Compile: gcc -O3 -march=native -fopenmp -o solve solve.c
```

**Key insight:** When a transformation is intentionally non-invertible (iterated hash-like function), brute-force is the intended solution. OpenMP parallelization is critical — 287 blocks x 16.7M candidates each takes minutes parallelized vs hours single-threaded. The sequential key dependency means blocks must be solved in order, but each individual block search is embarrassingly parallel.

---

See also: [patterns-ctf.md](patterns-ctf.md) for Part 1 (hidden emulator opcodes, SPN static extraction, image XOR smoothness, byte-at-a-time cipher, mathematical convergence bitmap, Windows PE XOR bitmap OCR, two-stage RC4+VM loaders, GBA ROM meet-in-the-middle, Sprague-Grundy game theory, kernel module maze solving, multi-threaded VM channels).
