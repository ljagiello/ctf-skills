# D Fiber-Based Callfuscation — Pattern-Dispatch Tree

## When this applies

- D-language compiled PE/ELF binary (look for strings like `core.thread.fiber`, `std.concurrency.Generator`, `core.internal.newaa`).
- Hundreds of similar-shaped functions, each with a `cmp dword [<data_slot>], 0xffffffff; je init; ...; init: mov dword [<slot>], <N>; ...` lazy-init guard.
- Each function reads an associative array of patterns (e.g., "00","01","10","11") and dispatches to one of N continuations based on input substring match.
- A separate `result_array[N]` of dwords (initialized -1) tracks which functions have been visited.
- Final lambda iterates the array, prints "Failed!" for each `-1` slot, then "Success!" unconditionally.

## Technique

The check is implemented as a deterministic finite automaton (DFA) whose states are functions and transitions are determined by N-bit chunks of input. The input bit-string drives a walk through the DFA. Success requires visiting all N states (Hamiltonian-path problem) before chain terminates.

## Steps

### 1. Identify the entry point

D-main reads `Enter flag:`, calls `byte→bit-string` converter (`for j=7..0: out += '1' if byte>>j & 1 else '0'`), then passes string + entry function pointer to a fiber-spawn routine.

```python
# In D-main, look for:
# lea r8, [entry_check_fn]   ; the dispatch tree root
# call fiber_spawn(arg=0, &bitstring, &entry_fn)
```

### 2. Locate the result array

Find the final lambda (xref to "Success!" and "Failed!" strings):
```python
# Pattern: loop  i = 0..N
#   cmp dword [array + i*4], 0xffffffff
#   jne skip  ; if !=  -1, slot was visited (good)
#   print "Failed!"  ; otherwise
# print "Success!"  ; unconditionally at end
```

### 3. Extract function-to-slot mapping

Each function has `cmp dword [array + slot*4], -1` near its entry. Bytes `83 3d <disp32> ff` encode this. Scan `.text` for the pattern and map slot index back to function VA.

```python
target_lo = ARRAY_VA   # e.g., 0x1400d9aa0
target_hi = ARRAY_VA + N*4

fn_map = {}  # slot -> function VA
for paddr in range(len(text_data) - 7):
    if text_data[paddr] == 0x83 and text_data[paddr+1] == 0x3d and text_data[paddr+6] == 0xff:
        disp32 = int.from_bytes(text_data[paddr+2:paddr+6], 'little', signed=True)
        rip = text_va + paddr + 7
        target = rip + disp32
        if target_lo <= target < target_hi:
            slot = (target - target_lo) // 4
            # Walk back for prologue 55 48 8b ec
            for back in range(8, 60):
                if text_data[paddr-back:paddr-back+4] == b'\x55\x48\x8b\xec':
                    fn_va = text_va + paddr - back
                    if slot not in fn_map:
                        fn_map[slot] = fn_va
                    break
```

### 4. Extract the pattern AA contents

Find the function that builds the AA — usually at very start of `.text`. It does:
```
mov ecx, X        ; key
lea r8, [AA_VAR]
call aaInsert
lea rdx, [pattern_X]  ; value string
mov qword [rax], length
mov qword [rax+8], rdx
```

Patterns are typically `"00"`, `"01"`, `"10"`, `"11"` for 2-bit dispatch.

### 5. Extract per-function transitions

Each function does N pattern compares. For each pattern_i match:
- SUCCESS: `lea r8, [next_fn]` followed by `call dispatcher`
- FAIL: `lea rdx, [yield_fn]` followed by `call spawn_fn`

Use Ghidra headless decompilation OR scan-and-pattern-match.

### 6. Search for path

The DFA is typically large (200+ states). Two paths:

**(a) Hamiltonian-path search (if "visit all states" is required):**
- DFS with backtracking
- Warnsdorff heuristic (try lowest-out-degree neighbor first)
- Randomized restarts
- For N>100 nodes, may need SAT/MILP encoding

**(b) Path-to-flag-emit search (if a specific terminator emits the flag):**
- BFS/DFS to find any path reaching the terminator function

### 7. Convert path back to input bytes

```python
# Each transition idx i (in 0..3) maps to bit-pair: ["00","01","10","11"][i]
bits = "".join(["00","01","10","11"][idx] for slot, idx in path[1:])
# Convert bits (MSB-first) to bytes
input_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
```

### 8. The AA dictionary is PERMUTED between chunks (resolution key)

The global AA dict (e.g., `0x1400f29a0`) starts as the natural ordering `{0:"00", 1:"01", 2:"10", 3:"11"}`. After every custom slot completes its chunk (state mod M = const), the global AA is **overwritten** with that slot's inline AA mapping (the 4 lea-rdx-loads at the slot's prologue).

Consequence: bits 16-31 at chunk 2 are interpreted via chunk-1-end's AA permutation, bits 32-47 via chunk-2-end's, and so on. Each chunk effectively runs in its own AA "namespace".

```python
# Pure-Python simulator (≈67k sims/sec) — drives chunk-by-chunk extension search
aa = {0:"00", 1:"01", 2:"10", 3:"11"}      # initial
for slot in path:
    state += sha_be(slot)
    if slot in custom_slots and state % M == const[slot]:
        aa = inline_aa[slot]                # PERMUTE on chunk completion
        state = 0
    bits = bitstring[offset:offset+2]; offset += 2
    k = next(k for k,v in aa.items() if v == bits)
    slot = graph[slot][k]                   # FAIL kills the run
```

### 9. Iterative greedy chunk extension

With the simulator, brute-forcing 2-byte extensions per chunk is cheap:

```python
prefix = "<FLAG_PREFIX>"; done = N_DONE     # e.g. 4-char prefix completes 2 chunks
while done < N_CHUNKS:
    best = [(prefix+a+b, sim(prefix+a+b)) for a in printable for b in printable]
    best = [c for c, n in best if n > done]
    prefix = best[0]; done += 1             # branch-and-bound: keep all if needed
```

Filter final candidates by flag-format brackets (`...}`) to disambiguate the 4 sibling solutions (free low-2-bits of the second byte per chunk).

## Pitfalls

- **Wrong AA value extraction.** The patterns are built at runtime by the FIRST function called, not statically. They live in BSS-style `0x1400f29a0`-style data slots populated by an init function (often at very low addresses like `0x140001000`).
- **Lazy-init guard sets slot value.** Even the FAIL path sets `slot[i] = i` because the guard fires before the pattern check. So slot init happens on EVERY visit — only the chain CONTINUATION differs based on match.
- **Revisit = chain termination.** If a function is visited twice, the wrapper fires `FUN_140048a10(1, yield_fn)` and returns. Caller also returns. The chain unwinds.
- **D's `std.concurrency.Generator` indirection.** The yield is `FUN_140048a10` which is `Fiber.spawn(delegate)`. Different from a simple `yield`/`return`.
- **Don't extract AAs by `mov edx, imm32` alone.** Key 0 is `xor edx, edx` (opcode `31 d2`), key 1/2/3 are `mov edx, imm32` (`ba XX XX XX XX`). Missing key 0 → wrong per-slot permutation. ALWAYS prefer Capstone linear sweep over byte-scan regex; the latter eats into operand bytes of nearby instructions (e.g., `48 8b 15 ...` contains `0xba`/`0xb9` in displacement).
- **Don't extract graph by AA-string ordering.** When dumping branches as `{0:..., 1:..., 2:..., 3:...}`, those indices must be the **KEY** (the integer arg to the AA-lookup call), not the alphanumeric order of the AA value strings. Capstone-track `last_ecx` across instructions, set it via `xor ecx,ecx` / `mov ecx, imm`, and read it RIGHT BEFORE each `call <AA_LOOKUP>`.
- **No flag in the binary.** The FLAG IS THE INPUT STRING that drives the chain through all N states. The platform's submission accepts the input value formatted as `HTB{...}`.
- **BigInt accumulator gating beyond Hamiltonian.** Some variants add a **second** constraint: on a subset of "custom" slots (28 in our reference case), the dispatcher does `state mod M == hardcoded_const` BEFORE branching. If unequal → hard FAIL regardless of input bits. State is updated at every slot via `state += <operand>`. The visit order must hit each custom slot's expected constant — N simultaneous BigInt equations. Tractable when combined with the AA-permutation model below; no SAT/CP needed.
- **The BigInt operand is SHA-256-derived (CRITICAL pattern).** The per-slot BigInt operand is NOT the slot byte itself — it's `SHA-256(byte) as 256-bit BE integer`. Fingerprint: look for a 13-qword template at a .data offset containing SHA-256 IV `{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}` stored LE-per-uint32. Each slot's dispatcher: (1) `mov byte [rax], <slot_num>` writes the slot index to a 1-byte buffer, (2) calls a SHA-256 wrapper (`fcn.140049930`), (3) hex-encodes the 32-byte hash to 64 uppercase ASCII chars (`fcn.140049a00` / `fcn.140049a40`, using the table `"0123456789ABCDEF"` at some `.data` offset), (4) concats with `"0x"` prefix via `fcn.14003f770`, (5) parses the resulting `"0x<HEX64>"` as a D `BigInt` via `fcn.140049b90` → `fcn.1400512b0`, and (6) passes the parsed value to the state-update function (`fcn.14004ae30`). State update is `state += operand` (sign-aware, via `fcn.1400522a0` → `fcn.1400523a0`).
- **State equality gate uses BigInt mod a shared 256-bit modulus.** A single shared BigInt at a fixed `.data` address (e.g., `0x1400d9e60` in dudidudida — len=8 uint32 limbs, value `0xdb126f29a64916ce... 99089084303615564604299164577467875201620560316554682033474737847169855277679` in decimal) is the modulus. At each custom slot, after the SHA-256-derived addition, the dispatcher calls `fcn.14004b1c0(state, output, modulus)` which computes `state mod modulus` (one-iteration via `fcn.140052250` zero-test + conditional subtract) and compares the output to the slot's hardcoded 76-77-digit decimal constant via `fcn.14003f8a0`. The 28 decimal constants live at consecutive `.data` offsets stride `0x50`, each ASCII-encoded with 77-byte slot.
- **Wine 11.0 on Lima/Ubuntu x86_64 runs the binary further than expected, but crashes at `std/concurrency.d:2503` (linked-list-remove) — patching the offending `mov rax, [rcx]` to `xor rax, rax` (`48 8b 01` → `48 31 c0`, 3 bytes each) moves the crash to the next vtable-indirect call. The D `Generator` fiber implementation has Wine-specific TLS/list-corruption issues that cascade — single-instruction patches don't suffice. The cleaner path is to **replace `fcn.140048a10` (yield) and `fcn.14004afa0` (dispatch) with non-fiber stubs** that store the yield value to a global and use direct calls.
- **Verify operand chain via native D compilation, not just disasm.** When unsure if D's `BigInt("0x" ~ hex_of_sha256(byte))` produces the value you think — actually run it. `ldc2 1.42.0` on Linux x86_64 compiles+runs in seconds. This eliminates ambiguity about endianness, hex-case, padding, etc. (See `projects/ctf/260513_dudidudida/scripts/test_bigint.d` for the recipe.) **Lesson learned**: spent 6+ rounds of analysis assuming the operand was sha_be(byte); native D confirmed it definitively in one compile, removing the operand from the search space.
- **Static-only walk fails when SHA-of-slot doesn't satisfy any pairwise constraint between expected constants.** The wrinkle is rarely in the SHA/add formula — it's almost always in the **AA dictionary semantics** (see Technique §8 below). If 756 pairwise tests give 0 hits, stop guessing operand formulas; pivot to runtime observation.
- **Wine on Apple-Silicon (M1+) breaks D-runtime fibers.** Both Lima/qemu-user-x86_64 and scottyhardy/docker-wine fail at `dlls/ntdll/unix/virtual.c:267 anon_mmap_fixed: !((UINT_PTR)start & host_page_mask)` because macOS uses 16K pages and the D runtime mmaps fiber stacks at 4K-aligned fixed addresses. Workarounds: (a) real x86_64 Linux box / cloud VM, (b) Lima Ubuntu x86_64 VM with native Wine 11.0 — fiber start-up does work after patching the offending `mov rax, [rcx]` (`48 8b 01` → `48 31 c0`) and follow-up cascade sites, (c) Unicorn-emulate just the dispatcher chain (skip D runtime — hook AA lookup + yield + dispatch helper, treat BigInt operands as Python ints).
- **Wine watchdog prints `Timeout!` for the correct flag too.** D's `core.thread.osthread` watchdog fires after a few hundred ms; Wine's emulation overhead means the post-dispatch `Success!` print never executes. **Stdout grep is unreliable in Wine** — validate by counting state→0 resets observed via `/proc/<PID>/mem` instead. N resets including initial = correct flag.
- **High-frequency state polling is required.** `/proc/<wine_loader_pid>/mem` open + tight-loop `os.lseek + os.read` of the state struct at the known `.data` VA captures state transitions; sample rate ≥250 Hz (Python tight loop without `time.sleep`) is needed to catch all chunk completions — slower polling drops chunks between samples and reports false-negative validation.
- **Graph extraction MUST track `ecx` linearly, not by lex-order of yield targets.** Bug pattern: dumping `{0:..., 1:..., 2:..., 3:...}` by the order in which `lea r8, [rip+...]` appears in the function gives slot→next mappings that are silently swapped at custom slots whose `lea r8` order differs from `ecx` order. The CORRECT extractor walks instructions sequentially (`objdump --no-show-raw-insn` parses cleanly), updates `current_ecx` on every `xor ecx,ecx` / `mov ecx, imm8`, captures it on every `call <AA_LOOKUP>`, then attributes the NEXT `lea r8` (yield target) or `mov ecx,1;call <YIELD>` (FAIL) to that captured ecx.

## Sample fingerprints

- 224 lazy-init guards each writing slot index 0..223 to a 224-dword array
- `core.thread.fiber.Fiber`, `std.concurrency.Generator`, `std.concurrency.FiberScheduler` D-runtime strings
- Function prologue `55 48 8b ec 48 81 ec d8 01 00 00 53 56 57` (push rbp; mov rbp,rsp; sub rsp,0x1d8; push rbx,rsi,rdi) — large stack frame for the runtime string construction

## Related

- `callfuscation.md` — simpler pop/body/call chunking
- `hash-dispatcher-chain.md` — Z3-solvable variant
