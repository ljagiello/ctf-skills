# Hash-Dispatcher Chain — Z3 Reconstruction of Constraint-Gated Output

## When this applies

- A binary contains hundreds of small "dispatcher" functions, each of shape:
  `compute polynomial-hash(input_bytes); compare hash to constants; tail-call next dispatcher (or error)`.
- All dispatchers share a single input pointer; each loads specific byte offsets and computes a quadratic/affine combination of them.
- The chain terminates in a function that builds an output (URL, key, response) from those same input bytes via deterministic byte transformations (XOR with constant, +/- offsets, case-shift via XOR 0x20).
- The flag/secret IS the output — not embedded as a string anywhere, only constructible at runtime.
- Trigger keywords: "polynomial hash chain", "input gating", "dispatcher tail-calls",
  symbol names like `_ZN9processor11f2937252410EPKc` (random-numbered functions all sharing a class).

## Technique

Don't try to traverse hundreds of dispatchers manually or emulate the binary. Instead:
1. Identify ALL hash equations along ONE valid path through the chain (each adds polynomial constraints).
2. Identify ALL byte-arithmetic equations in the terminator function (each adds linear constraints).
3. Identify the output construction as a function `output[i] = f(input[j])` per position.
4. Use Z3 to solve the full system. Often the constraint set has a UNIQUE solution for most input bytes;
   the few "free" bytes are intentionally chosen by the author to make a meaningful flag.
5. The output structure (e.g., `HTB{...}` prefix) provides additional constraints.
6. The remaining free bytes typically encode an English phrase the SMS/input was meant to look like —
   guess by choosing a natural-language template for the input and verifying it satisfies the printable constraints.

## Steps

### 1. Map the dispatcher chain

```bash
# Symbols reveal the architecture
objdump --dynamic-syms libapp.so | grep -E "f[0-9]+EPKc" | wc -l   # how many dispatchers
objdump --dynamic-syms libapp.so | grep "check_extension\|build_url\|terminate"   # terminator
```

For each dispatcher, disassemble and identify:
- Which input offsets are loaded (`ldrb wN, [x1, #OFFSET]`)
- The polynomial expression (`madd`, `mul`, `add`, `sub`, `neg`)
- The constants it compares against (each compare → branch to next dispatcher or error)

```python
# Example pattern in ARM64
# 6c638: ldrb w8, [x1, #0x3]   ; b3
# 6c63c: ldrb w9, [x1, #0x5]   ; b5
# 6c648: mul  w8, w9, w8        ; b3*b5
# 6c654: neg  w8, w8            ; -b3*b5
# 6c658: madd w8, w11, w10, w8  ; b1*b1b - b3*b5
# 6c65c: madd w8, w12, w9, w8   ; + b11*bb
# Equation: b1*b1b - b3*b5 + b11*bb == constant
```

### 2. Pick ONE valid path through the chain

The chain is a tree — multiple hash values lead to different next dispatchers. Pick the path that
ends at the terminator (the function building output). All paths terminating at the SAME terminator
produce the SAME output, but each adds different gate equations. You only need ONE complete path.

### 3. Extract terminator's byte-arithmetic and output formula

```python
# Look in terminator for additional equations (load multiple bytes, sum/diff/product, compare)
# These are usually printable-byte checks like:
#   b[0xd] - b[7] + b[5] == 0x50

# And the OUTPUT formula — for each output position, which input byte and transformation:
#   buf[0x0e] = b[0xa] ^ 0x5d
#   buf[0x07] = b[8] ^ 0x20
#   buf[0x0d] = b[9] + 2
```

### 4. Solve with Z3

```python
import z3
s = z3.Solver()
b8  = {i: z3.BitVec(f'r{i}', 8)  for i in range(N)}
b32 = {i: z3.ZeroExt(24, b8[i]) for i in range(N)}

# Printable input range (whatever the loader validates)
for i in range(N):
    s.add(z3.Or(b8[i] == 0x20, z3.And(b8[i] >= 0x61, b8[i] <= 0x7a)))

# All chain gate equations
s.add(b32[1]*b32[0x1b] + b32[0x11]*b32[0xb] - b32[3]*b32[5] == 0x38f7)
# ... one per dispatcher on the chosen path

# Terminator byte-arith equations
s.add(b32[0x11] + b32[1] - b32[7] == 0x6a)
# ...

# Output prefix constraints (e.g., "http://HTB{")
def buf(i): return ...   # the i-th output position as f(b8)
PREFIX = b"http://HTB{"
for i, c in enumerate(PREFIX):
    s.add(buf(i) == c)
```

### 5. Enumerate to confirm uniqueness

```python
# Block each found assignment, look for another
solutions = []
while s.check() == z3.sat and len(solutions) < 50:
    m = s.model()
    sol = {i: m[b8[i]].as_long() for i in range(N)}
    solutions.append(sol)
    s.add(z3.Or(*[b8[i] != sol[i] for i in CONSTRAINED_INDICES]))
```

If the constrained byte set has a UNIQUE solution, only the truly-free bytes remain.
The author chose these free bytes to spell an English phrase — work out the input template that
fits all the fixed positions (e.g., for an SMS-app challenge, the body might read
"your authentication token is: <OTP>" and the fixed positions match exactly).

### 6. Build the output and submit

Apply the output formula to the full byte vector. The result is the flag/URL/secret.

## Verifying success

- Z3 returns SAT for the full system.
- The constrained-byte set is uniquely determined (a follow-up `s.check()` after blocking is UNSAT).
- The output starts with the expected prefix (e.g., `HTB{` or `http://`).
- The chain executes in your emulator (Unicorn) producing the same output for the same input.

## Common pitfalls

- **Multiple valid paths through the chain.** Each non-error branch defines a separate set of
  hash equations. Picking inconsistent equations (mixing branches from different paths) → UNSAT.
- **Signed vs unsigned.** ARM64 uses 32-bit registers for byte-arithmetic; some compares are
  signed (`cmn`, `b.gt`, `b.lt`). Use 32-bit Z3 BitVecs and signed comparison operators.
- **Encoding selector.** The terminator may have a switch on `b[i] - b[j] + b[k]` selecting
  different downstream behavior; encode as `Or([... == v for v in {valid_set}])`.
- **Reused free bytes.** A "free" byte often appears in the output AT MULTIPLE positions
  (sometimes XOR'd, sometimes raw). The same byte produces multiple flag chars — the author
  exploits this for compact flag patterns like "unicorn" where positions 1 and 6 must be the same letter.
- **Missing equations.** A printable-bytes check loop in the JNI/loader (`for i in 0..N: assert b[i] in printable`)
  is easy to miss. Without it, Z3 finds non-printable solutions that aren't the intended flag.
- **Output positions you missed.** Triple-check the output formula by re-running every
  `strb wX, [x0, #OFFSET]` in the terminator and noting which register held what.

## Real example: HTB WonderSMS (HTB ID 609)

- 259 dispatchers in `libaudio.so`; chain: `f315732804 → f1100030004 → check_extension`.
- 4 polynomial hash equations + 5 byte-arithmetic equations in `check_extension`.
- Output is a 40-byte URL `http://HTB{...}` whose content comes from XOR/offset of input bytes.
- Z3 found UNIQUE values for 14 of 30 input bytes; URL prefix forced 5 more; remaining 6 free
  bytes encoded the SMS template "your authentication token is: <OTP>".
- Flag URL: `http://HTB{I_g3t_angr_3as1lY_aT_unicorn}` (reads "I get angry easily at unicorn").
- Key insight for the free bytes: segment 6 ("F X' A' c o r X'" with X' duplicated) UNIQUELY
  matches "unicorn" among 7-letter English words; segment 4 ("3 Z s 1 E+5 Y") UNIQUELY
  matches "easilY" among 6-letter Y-ending words with 's' at index 2 — these constraints alone
  forced all but one free byte.

## Tools

- `objdump -d` / Ghidra / IDA — disassemble dispatchers and terminator
- `z3` (Python) — solve the polynomial + linear system
- `unicorn` — sanity-check by emulating the chain with the recovered input
- `lief` — to load the .so for register-tracing tooling
