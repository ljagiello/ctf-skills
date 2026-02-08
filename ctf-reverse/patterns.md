# CTF Reverse - Patterns & Techniques

## Custom VM Reversing

### Analysis Steps
1. Identify VM structure: registers, memory, instruction pointer
2. Reverse `executeIns`/`runvm` function for opcode meanings
3. Write a disassembler to parse bytecode
4. Decompile disassembly to understand algorithm

### Common VM Patterns
```c
switch (opcode) {
    case 1: *R[op1] *= op2; break;      // MUL
    case 2: *R[op1] -= op2; break;      // SUB
    case 3: *R[op1] = ~*R[op1]; break;  // NOT
    case 4: *R[op1] ^= mem[op2]; break; // XOR
    case 5: *R[op1] = *R[op2]; break;   // MOV
    case 7: if (R0) IP += op1; break;   // JNZ
    case 8: putc(R0); break;            // PRINT
    case 10: R0 = getc(); break;        // INPUT
}
```

### RVA-Based Opcode Dispatching
- Opcodes are RVAs pointing to handler functions
- Handler performs operation, reads next RVA, jumps
- Map all handlers by following RVA chain

### State Machine VMs (90K+ states)
```java
// BFS for valid path
var agenda = new ArrayDeque<State>();
agenda.add(new State(0, ""));
while (!agenda.isEmpty()) {
    var current = agenda.remove();
    if (current.path.length() == TARGET_LENGTH) {
        println(current.path);
        continue;
    }
    for (var transition : machine.get(current.state).entrySet()) {
        agenda.add(new State(transition.getValue(),
                            current.path + (char)transition.getKey()));
    }
}
```

---

## Anti-Debugging Techniques

### Common Checks
- `IsDebuggerPresent()` (Windows)
- `ptrace(PTRACE_TRACEME)` (Linux)
- `/proc/self/status` TracerPid
- Timing checks (`rdtsc`, `time()`)
- Registry checks (Windows)

### Bypass Technique
1. Identify `test` instructions after debug checks
2. Set breakpoint at the `test`
3. Modify register to bypass conditional

```bash
# In radare2
db 0x401234          # Break at test
dc                   # Run
dr eax=0             # Clear flag
dc                   # Continue
```

### LD_PRELOAD Hook
```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/ptrace.h>

long int ptrace(enum __ptrace_request req, ...) {
    long int (*orig)(enum __ptrace_request, pid_t, void*, void*);
    orig = dlsym(RTLD_NEXT, "ptrace");
    // Log or modify behavior
    return orig(req, pid, addr, data);
}
```

Compile: `gcc -shared -fPIC -ldl hook.c -o hook.so`
Run: `LD_PRELOAD=./hook.so ./binary`

---

## Nanomites

### Linux (Signal-Based)
- `SIGTRAP` (`int 3`) → Custom operation
- `SIGILL` (`ud2`) → Custom operation
- `SIGFPE` (`idiv 0`) → Custom operation
- `SIGSEGV` (null deref) → Custom operation

### Windows (Debug Events)
- `EXCEPTION_DEBUG_EVENT` → Main handler
- Parent modifies child via `PTRACE_POKETEXT`
- Magic markers: `0x1337BABE`, `0xDEADC0DE`

### Analysis
1. Check for `fork()` + `ptrace(PTRACE_TRACEME)`
2. Find `WaitForDebugEvent` loop
3. Map EAX values to operations
4. Log operations to reconstruct algorithm

---

## Self-Modifying Code

### Pattern: XOR Decryption
```asm
lea     rax, next_block
mov     dl, [rcx]        ; Input char
xor_loop:
    xor     [rax+rbx], dl
    inc     rbx
    cmp     rbx, BLOCK_SIZE
    jnz     xor_loop
jmp     rax              ; Execute decrypted
```

**Solution:** Known opcode at block start reveals XOR key (flag char).

---

## Known-Plaintext XOR (Flag Prefix)

**Pattern:** Encrypted bytes given; flag format known (e.g., `0xL4ugh{`).

**Approach:**
1. Assume repeating XOR key.
2. Use known prefix (and any hint phrase) to recover key bytes.
3. Try small key lengths and validate printable output.

```python
enc = bytes.fromhex("...")  # ciphertext
known = b"0xL4ugh{say_yes_to_me"
for klen in range(2, 33):
    key = bytearray(klen)
    ok = True
    for i, b in enumerate(known):
        if i >= len(enc):
            break
        ki = i % klen
        v = enc[i] ^ b
        if key[ki] and key[ki] != v:
            ok = False
            break
        key[ki] = v
    if not ok:
        continue
    pt = bytes(enc[i] ^ key[i % klen] for i in range(len(enc)))
    if all(32 <= c < 127 for c in pt):
        print(klen, key, pt)
```

**Note:** Challenge hints often appear verbatim in the flag body (e.g., "say_yes_to_me").

### Variant: XOR with Position Index
**Pattern:** `cipher[i] = plain[i] ^ key[i % k] ^ i` (or `^ (i & 0xff)`).

**Symptoms:**
- Repeating-key XOR almost fits known prefix but breaks at later positions
- XOR with known prefix yields a “key” that changes by +1 per index

**Fix:** Remove index first, then recover key with known prefix.
```python
enc = bytes.fromhex("...")
known = b"0xL4ugh{say_yes_to_me"
for klen in range(2, 33):
    key = bytearray(klen)
    ok = True
    for i, b in enumerate(known):
        if i >= len(enc):
            break
        ki = i % klen
        v = (enc[i] ^ i) ^ b  # strip index XOR
        if key[ki] and key[ki] != v:
            ok = False
            break
        key[ki] = v
    if not ok:
        continue
    pt = bytes((enc[i] ^ i) ^ key[i % klen] for i in range(len(enc)))
    if all(32 <= c < 127 for c in pt):
        print(klen, key, pt)
```

---

## Mixed-Mode (x86-64 ↔ x86) Stagers

**Pattern:** 64-bit ELF jumps into a 32-bit blob via far return (`retf`/`retfq`), often after anti-debug.

**Identification:**
- Bytes `0xCB` (retf) or `0xCA` (retf imm16), sometimes preceded by `0x48` (retfq)
- 32-bit disasm shows SSE ops (`psubb`, `pxor`, `paddb`) in a tight loop
- Computed jumps into the 32-bit region

**Gotchas:**
- `retf` pops **6 bytes**: 4-byte EIP + 2-byte CS (not 8)
- 32-bit blob may rely on inherited **XMM state** and **EFLAGS**
- Missing XMM/flags transfer when switching emulators yields wrong output

**Bypass/Emulation Tips:**
1. Create a UC_MODE_32 emulator, copy memory + GPRs, **EFLAGS**, and **XMM regs**
2. Run 32-bit block, then copy memory + regs back to 64-bit
3. If anti-debug uses `fork/ptrace` + patching, emulate parent to log POKEs and apply them in child

---

## LLVM Obfuscation (Control Flow Flattening)

### Pattern
```c
while (1) {
    if (i == 0xA57D3848) { /* block */ }
    if (i != 0xA5AA2438) break;
    i = 0x39ABA8E6;  // Next state
}
```

### De-obfuscation
1. GDB script to break at `je` instructions
2. Log state variable values
3. Map state transitions
4. Reconstruct true control flow

---

## S-Box / Keystream Generation

### Fisher-Yates Shuffle (Xorshift32)
```python
def gen_sbox():
    sbox = list(range(256))
    state = SEED
    for i in range(255, -1, -1):
        state = ((state << 13) ^ state) & 0xffffffff
        state = ((state >> 17) ^ state) & 0xffffffff
        state = ((state << 5) ^ state) & 0xffffffff
        j = state % (i + 1) if i > 0 else 0
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox
```

### Xorshift64* Keystream
```python
def gen_keystream():
    ks = []
    state = SEED_64
    mul = 0x2545f4914f6cdd1d
    for _ in range(256):
        state ^= (state >> 12)
        state ^= (state << 25)
        state ^= (state >> 27)
        state = (state * mul) & 0xffffffffffffffff
        ks.append((state >> 56) & 0xff)
    return ks
```

### Identifying Patterns
- Xorshift32: shifts 13, 17, 5
- Xorshift64: shifts 12, 25, 27
- Magic: `0x2545f4914f6cdd1d`, `0x9e3779b97f4a7c15`

---

## SECCOMP/BPF Filter Analysis

```bash
seccomp-tools dump ./binary
```

### BPF Analysis
- `A = sys_number` followed by comparisons
- `mem[N] = A`, `A = mem[N]` for memory ops
- Map to constraint equations, solve with z3

```python
from z3 import *
flag = [BitVec(f'c{i}', 32) for i in range(14)]
s = Solver()
s.add(flag[0] >= 0x20, flag[0] < 0x7f)
# Add constraints from filter
if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[c].as_long()) for c in flag))
```

---

## Exception Handler Obfuscation

### RtlInstallFunctionTableCallback
- Dynamic exception handler registration
- Handler installs new handler, modifies code
- Use x64dbg with exception handler breaks

### Vectored Exception Handlers (VEH)
- `AddVectoredExceptionHandler` installs handler
- Handler decrypts code at exception address
- Step through, dump decrypted code

---

## Memory Dump Analysis

### When Binary Dumps Memory
- Check for `/proc/self/maps` reads
- Check for `/proc/self/mem` reads
- Heap data often appended to dump

### Known Plaintext Attack
```python
prologue = bytes([0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5])
encrypted = data[func_offset:func_offset+8]
partial_key = bytes(a ^ b for a, b in zip(encrypted, prologue))
```

---

## Byte-Wise Uniform Transforms

**Pattern:** Output buffer depends on each input byte independently (no cross-byte coupling).

**Detection:**
- Change one input position → only one output position changes
- Fill input with a single byte → output buffer becomes constant

**Solve:**
1. For each byte value 0..255, run the program with that byte repeated
2. Record output byte → build mapping and inverse mapping
3. Apply inverse mapping to static target bytes to recover the flag

---

## x86-64 Gotchas

### Sign Extension
```python
esi = 0xffffffc7  # NOT -57

# For XOR: low byte only
esi_xor = esi & 0xff  # 0xc7

# For addition: full 32-bit with overflow
r12 = (r13 + esi) & 0xffffffff
```

### Loop Boundary State Updates
Assembly often splits state updates across loop boundaries:
```asm
    jmp loop_middle        ; First iteration in middle!

loop_top:                   ; State for iterations 2+
    mov  r13, sbox[a & 0xf]
    ; Uses OLD 'a', not new!

loop_middle:
    ; Main computation
    inc  a
    jne  loop_top
```

---

## Python Bytecode Reversing (dis.dis output)

### Common Pattern: XOR Validation with Split Indices

Challenge gives raw CPython bytecode (dis.dis disassembly). Common pattern:
1. Check flag length
2. XOR chars at even indices with key1, compare to list p1
3. XOR chars at odd indices with key2, compare to list p2

**Reversing:**
```python
# Given: p1, p2 (expected values), key1, key2 (XOR keys)
flag = [''] * flag_length
for i in range(len(p1)):
    flag[2*i] = chr(p1[i] ^ key1)      # Even indices
    flag[2*i+1] = chr(p2[i] ^ key2)    # Odd indices
print(''.join(flag))
```

### Bytecode Analysis Tips
- `LOAD_CONST` followed by `COMPARE_OP` reveals expected values
- `BINARY_XOR` identifies the transformation
- `BUILD_TUPLE`/`BUILD_LIST` with constants = expected output array
- Loop structure: `FOR_ITER` + `BINARY_SUBSCR` = iterating over flag chars
- `CALL_FUNCTION` on `ord` = character-to-int conversion

---

## Python Opcode Remapping

### Identification
Decompiler fails with opcode errors.

### Recovery
1. Find modified `opcode.pyc` in PyInstaller bundle
2. Compare with original Python opcodes
3. Build mapping: `{new_opcode: original_opcode}`
4. Patch target .pyc
5. Decompile normally

---

## DOS Stub Analysis

PE files can hide code in DOS stub:
1. Check for large DOS stub in Ghidra/IDA
2. Run in DOSBox
3. Load in IDA as 16-bit DOS
4. Look for `int 16h` (keyboard input)

---

## Unity IL2CPP Games

- Use Il2CppDumper to dump symbols
- Look for `Start()` functions
- Key derivation: `key = SHA256(companyName + "\n" + productName)`
- Decrypt server responses with derived key

---

## Brainfuck/Esolangs

- Check if compiled with known tools (BF-it)
- Understand tape/memory model
- Static analysis of cell operations

---

## UEFI Binary Analysis

```bash
7z x firmware.bin -oextracted/
file extracted/* | grep "PE32+"
```

- Bootkit replaces boot loader
- Custom VM protects decryption
- Lift VM bytecode to C

---

## Transpilation to C

For heavily obfuscated code:
```python
for opcode, args in instructions:
    if opcode == 'XOR':
        print(f"r{args[0]} ^= r{args[1]};")
    elif opcode == 'ADD':
        print(f"r{args[0]} += r{args[1]};")
```

Compile with `-O3` for constant folding.

---

## Code Coverage Side-Channel Attack

**Pattern (Coverup, Nullcon 2026):** PHP challenge provides XDebug code coverage data alongside encrypted output.

**How it works:**
- PHP code uses `xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE | XDEBUG_CC_BRANCH_CHECK)`
- Encryption uses data-dependent branches: `if ($xored == chr(0)) ... if ($xored == chr(1)) ...`
- Coverage JSON reveals which branches were executed during encryption
- This leaks the set of XOR intermediate values that occurred

**Exploitation:**
```python
import json

# Load coverage data
with open('coverage.json') as f:
    cov = json.load(f)

# Extract executed XOR values from branch coverage
executed_xored = set()
for line_no, hit_count in cov['encrypt.php']['lines'].items():
    if hit_count > 0:
        # Map line numbers to the chr(N) value in the if-statement
        executed_xored.add(extract_value_from_line(line_no))

# For each position, filter candidates
for pos in range(len(ciphertext)):
    candidates = []
    for key_byte in range(256):
        xored = plaintext_byte ^ key_byte  # or reverse S-box lookup
        if xored in executed_xored:
            candidates.append(key_byte)
    # Combined with known plaintext prefix, this uniquely determines key
```

**Key insight:** Code coverage is a powerful oracle — it tells you which conditional paths were taken. Any encryption with data-dependent branching leaks information through coverage.

**Mitigation detection:** Look for branchless/constant-time crypto implementations that defeat this attack.

---

## Functional Language Reversing (OPAL)

**Pattern (Opalist, Nullcon 2026):** Binary compiled from OPAL (Optimized Applicative Language), a purely functional language.

**Recognition markers:**
- `.impl` (implementation) and `.sign` (signature) source files
- `IMPLEMENTATION` / `SIGNATURE` keywords
- Nested `IF..THEN..ELSE..FI` structures
- Functions named `f1`, `f2`, ... `fN` (numeric naming)
- Heavy use of `seq[nat]`, `string`, `denotation` types

**Reversing approach:**
1. Pure functions are mathematically invertible — reverse each step in the pipeline
2. Identify the transformation chain: `f_final(f_n(...f_2(f_1(input))...))`
3. For each function, build the inverse

**Aggregate brute-force for scramble functions:**
When a transformation accumulates state that depends on original (unknown) values:
```python
# Example: f8 adds cumulative offset based on parity of original bytes
# offset contribution per element depends on whether pre-scramble value is even/odd
# Total offset S = sum of contributions, but S mod 256 has only 256 possibilities

decoded = base64_decode(target)
for total_offset_S in range(256):
    candidate = [(b - total_offset_S) % 256 for b in decoded]
    # Verify: recompute S from candidate values
    recomputed_S = sum(contribution(i, candidate[i]) for i in range(len(candidate))) % 256
    if recomputed_S == total_offset_S:
        # Apply remaining inverse steps
        result = apply_inverse_substitution(candidate)
        if all(32 <= c < 127 for c in result):
            print(bytes(result))
```

**Key lesson:** When a scramble function has a chicken-and-egg dependency (result depends on original, which is unknown), brute-force the aggregate effect (often mod 256 = 256 possibilities) rather than all possible states (exponential).

---

## Non-Bijective Substitution Cipher Reversing

**Pattern (Coverup, Nullcon 2026):** S-box/substitution table has collisions (multiple inputs map to same output).

**Detection:**
```python
sbox = [...]  # substitution table
if len(set(sbox)) < len(sbox):
    print("Non-bijective! Collisions exist.")
```

**Building reverse lookup:**
```python
from collections import defaultdict
rev_sub = defaultdict(list)
for i, v in enumerate(sbox):
    rev_sub[v].append(i)
# rev_sub[output] = [list of possible inputs]
```

**Disambiguation strategies:**
1. Known plaintext format (e.g., `ENO{`, `flag{`) fixes key bytes at known positions
2. Side-channel data (code coverage, timing) eliminates impossible candidates
3. Printable ASCII constraint (32-126) reduces candidate space
4. Re-encrypt candidates and verify against known ciphertext
