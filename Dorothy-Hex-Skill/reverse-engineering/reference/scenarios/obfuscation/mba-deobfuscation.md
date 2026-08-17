# MBA Deobfuscation — Mixed Boolean-Arithmetic Operator Recovery

## When this applies

- Individual arithmetic / boolean operators (`+`, `-`, `&`, `|`, `^`, `*`) are wrapped in functions full of junk `not/and/or/imul`-with-primes operations.
- Each wrapper function is 50-200 bytes of meaningless-looking code that still implements a simple operation.
- Sometimes accompanied by `rand()` calls or per-call constants for additional noise.
- Trigger keywords: "MBA", "mixed boolean arithmetic", "operator obfuscation", "Tigress", "OLLVM".

## Technique

MBA expressions use identities like `a + b = (a ^ b) + 2*(a & b)` or `a + b = (a | b) + (a & b)` to disguise an addition. Functions implementing such identities, possibly stacked 3-5 deep with constant masking, can be **probed with small inputs** to identify the underlying operation. The identity is purely behavioral — match input/output table against known operations.

## Steps

### 1. Identify candidate wrapper functions

After **callfuscation linearization** (see neighbor file), look for:
- Functions that take 2 arguments and return 1 result.
- Function bodies of 50-200 bytes.
- Heavy use of `imul` with prime constants, `not`, `and`, `or`, `xor`.
- Same function pattern used many times throughout the binary.

```python
candidates = []
for f in functions:
    if num_args(f) == 2 and 50 <= f.size <= 200:
        if has_imul_with_prime(f) or counts(f, ('not', 'and', 'or')) > 5:
            candidates.append(f)
```

### 2. Probe with small inputs

Run each candidate with all (a, b) pairs from a small set, e.g. `{0, 1, 2, 3, 4, 5, 6, 7}`. That's 64 input pairs producing 64 outputs.

```python
import unicorn   # or qiling
mu = Unicorn(...)
def probe(func_addr, a, b):
    mu.reg_write(UC_X86_REG_RDI, a)
    mu.reg_write(UC_X86_REG_RSI, b)
    mu.emu_start(func_addr, end_addr)
    return mu.reg_read(UC_X86_REG_RAX)

table = [[probe(f, a, b) for b in range(8)] for a in range(8)]
```

### 3. Match against known operations

```python
candidates = {
    '+': lambda a, b: (a + b) & 0xFFFFFFFF,
    '-': lambda a, b: (a - b) & 0xFFFFFFFF,
    '*': lambda a, b: (a * b) & 0xFFFFFFFF,
    '^': lambda a, b: a ^ b,
    '&': lambda a, b: a & b,
    '|': lambda a, b: a | b,
    'a': lambda a, b: a,                       # passthrough first arg
    'b': lambda a, b: b,                       # passthrough second arg
    '0': lambda a, b: 0,                       # constant zero
}

def match(table, func):
    return all(table[a][b] == func(a, b) for a in range(8) for b in range(8))

for op, fn in candidates.items():
    if match(table, fn):
        print(f"Function implements: {op}")
        break
```

If none match, the function may be `(a OP b) + const` — try with a constant offset:
```python
const = table[0][0] - candidates[op](0, 0)
# verify rest of table matches with +const
```

### 4. Substitute in the analysis

Once each wrapper is labeled, replace calls in the disassembly / decompilation with the underlying operator. In Ghidra, change the function signature to `int op_xor(int, int)` and rename — the decompiler will pretty-print `op_xor(x, y)` (which you read mentally as `x ^ y`). Or write a script to substitute calls with inline ops in a derived listing.

### 5. Handle higher-arity / parametric wrappers

Some wrappers take more args (e.g. an extra "key" parameter). Probe over larger input sets, or try parametric matching: for each known operation, fit a constant `k` such that `wrapper(a, b, k)` matches.

### 6. Recognize SiMBA-style patterns

Public MBA-deobfuscation tools — `SiMBA`, `MBA-Solver`, `arybo`, `MBA-Blast` — accept symbolic expressions (extracted from the wrapper via Triton or angr) and simplify to canonical form. Use them when probing alone doesn't suffice (e.g. wrappers with control flow).

## Verifying success

- Each labeled wrapper, called with random inputs, produces results matching the proposed operation.
- After substitution, the surrounding code looks comprehensible.
- Cross-checked: a different set of test inputs (larger range, edge cases like 0xFFFFFFFF) still match.

## Common pitfalls

- **Modular width mismatch.** A wrapper masking to `0xFFFFFFFF` won't match unmasked `+` in a 64-bit world. Probe in the same width as the wrapper outputs.
- **Wrapper has state.** Some wrappers maintain state (counter, stash). Probe with fresh emulator instances per call.
- **Random noise.** If `rand()` is called inside the wrapper, output changes per call. Stub `rand()` to a constant before probing.
- **Stacked wrappers.** `+` inside `^` inside `&` — probe the *outer* function; the inner ones are irrelevant for solving.
- **Wrapper for not-actually-an-op.** Sometimes a "wrapper" is dead code dropped by the obfuscator with no functional output. Verify the result actually flows into a usable register.

## Tools

- `Unicorn` (Python) — most flexible probe environment.
- `qiling` — Unicorn wrapper with cleaner Python API.
- `Triton` — symbolic execution; produces simplified expressions automatically.
- `angr` — heavier, sometimes overkill.
- `SiMBA`, `MBA-Solver`, `MBA-Blast` — published academic tools for MBA simplification.
- `arybo` — Quarkslab's Boolean-arithmetic algebra library.
