---
tags:
  - heap-buffer-overflow
  - alpha-shellcode
  - got-overwrite
platform: pwnable.tw
points: 350
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: no
pie: no
references:
  - https://pwnable.tw/challenge/
description: "An out-of-bounds index write allows overwriting the free GOT entry to jump to a sequence of chained 3-byte alphanumeric shellcode fragments stored across heap note chunks."
proof-of-concept: no
---

# Alive Note — pwnable.tw (350 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> The last 23 days, write down your shellcode.
>
> `nc chall.pwnable.tw 10300`
>
> Flag: `FLAG{Sh3llcoding_in_th3_n0t3_ch4in}`

## Challenge Overview

A 32-bit i386 note-taking binary (No PIE, Partial RELRO, Stack Canary, **NX disabled / RWX heap**). The player can add, show, and delete "names" stored in a notes array. Each name is `strdup()`'d to the heap (max 8 bytes), and its content is validated to be **alphanumeric + space only**. An upgrade from the "Death Note" challenge — same GOT overwrite via negative index, but with a much stricter character set.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX unknown           # GNU_STACK missing
  PIE:      No PIE (0x8048000)
  RWX:      Has RWX segments     # READ_IMPLIES_EXEC → heap is executable
```

The `GNU_STACK` program header is set to RWE. On i386 Linux, this enables the `READ_IMPLIES_EXEC` personality flag, making **all readable pages (including heap) executable**. This is the fundamental enabler for running shellcode from heap-allocated notes.

## Vulnerabilities

### V1 — Negative Index OOB Write/Read (Primary, Exploitable)

**Root Cause:** The index bounds check only validates the **upper bound** (`idx > 10`), allowing negative indices to access memory before the `notes[]` array.

```c
// Simplified add_note / del_note
read_int();  // reads index via atoi()
if (idx > 10) { puts("Out of bound !!"); exit(0); }
notes[idx] = strdup(name_buf);  // negative idx → write before notes[]
// or
free(notes[idx]);               // negative idx → free arbitrary GOT entry's value
```

**Key offsets:**

```
notes[]   @ 0x0804a080   (11 slots, index 0..10)
free@GOT  @ 0x0804a014
atoi@GOT  @ 0x0804a034
```

```
index_free = (0x0804a014 - 0x0804a080) / 4 = -27
index_atoi = (0x0804a034 - 0x0804a080) / 4 = -19
```

**Impact:**
- `add_note(-27, shellcode)` → `strdup()` allocates a heap chunk containing the shellcode, and the chunk's address is written into `free@GOT`.
- `delete_note(-27)` → calls `free(notes[-27])`, which resolves through `free@GOT` (now pointing to the heap chunk) → **jumps into the shellcode on the heap**.
- At entry, `eax` holds the pointer to the freed chunk (i.e., the shellcode base address), which is critical for self-modifying code.

### V2 — Alphanumeric-Only Content Filter

**Root Cause:** `add_note` validates each byte of the name using `__ctype_b_loc()` with the `_ISalnum` (0x08) flag. Only bytes in `[0-9A-Za-z ]` (ASCII `0x20`, `0x30-0x39`, `0x41-0x5a`, `0x61-0x7a`) pass.

```c
// check() — per-byte validation
if (c == ' ') ok;
else if (__ctype_b_loc()[c] & 0x08) ok;  // _ISalnum
else return 0;  // "It must be a alnum name !!" → exit(-1)
```

**Impact:** Standard shellcode bytes like `\xcd\x80` (`int 0x80`), `\x2f` (`/` in `/bin/sh`), `\x0b` (`SYS_execve`) are forbidden. The shellcode must be constructed entirely from alphanumeric bytes, requiring self-modifying techniques.

### V3 — 8-Byte Note Size Limit

Each `strdup()` copies at most 8 bytes (7 useful + NUL terminator). With the heap allocator's minimum chunk size of `0x10`, consecutive notes are spaced `0x10` bytes apart on the heap. The shellcode must be split into 6-byte fragments chained together with 2-byte jumps.

## Key Data Structures

### Heap Chunk Layout

Each note allocation via `strdup()` creates a `0x10`-byte chunk:

```
+0x00: prev_size (4 bytes)
+0x04: size = 0x11 (4 bytes, includes PREV_INUSE bit)
+0x08: user data (up to 8 bytes of alphanumeric shellcode)
```

Consecutive chunks are at `base + N*0x10`. The 8-byte chunk header between notes is **not executable code**, so jumps must skip over them.

### Jump Chaining

Each 8-byte note holds ~6 bytes of useful shellcode + a 2-byte conditional jump to reach the next note:

```
[6 bytes shellcode] [jne/jno/jae +0x38]
```

Common jump opcodes used (all alphanumeric):
- `\x75\x38` — `jne +0x38` (opcode `u8`, jumps `0x3a` bytes forward = skip 3 chunk headers + 2 bytes to next note's code)
- `\x71\x38` — `jno +0x38`
- `\x73\x38` — `jae +0x38`
- `\x74\x39` — `je +0x39`

The jump condition (ZF=0 after `free` setup or prior XOR ops) ensures the conditional branch is always taken.

## Exploit Paths

All solutions exploit V1 (negative index GOT overwrite) combined with alphanumeric shellcode on the executable heap. They diverge on the shellcode construction strategy.

---

### Path A — Self-Modifying Alphanumeric Shellcode Chain → `read()` Stager → `execve()` (Dominant)

**Used by:** ~90% of solutions (59, 278, 370, 550, 583, 644, 821, 1172, 1780, 2524, 3498, 5002, 7905, 8153, 14106, 17704, 25916, 36997, and exp.py)

**Strategy:** Write a chain of alphanumeric shellcode fragments across heap chunks, connected by conditional jumps. The chain self-modifies to patch `int 0x80` (`\xcd\x80`) into a downstream chunk, then executes `read(0, buf, N)` to pull in unrestricted stage-2 shellcode (`execve("/bin/sh", 0, 0)`).

**Steps:**

1. **Overwrite `free@GOT`:** `add_note(-27, stage1_chunk0)` — the `strdup`'d chunk address overwrites `free@GOT`.

2. **Place shellcode fragments:** `add_note(0..N, fragment)` — each fragment is 6 bytes of alphanumeric machine code + 2-byte jump. Spacer notes (3-4 dummy allocations) fill the gap between meaningful chunks.

3. **Trigger execution:** `delete_note(-27)` — calls `free(notes[-27])`, which jumps to chunk0 on the heap.

4. **Shellcode chain executes:**
   - Set `ecx` = chunk base (via `push eax; pop ecx` — `eax` = freed pointer)
   - Set `edx` = read count (e.g., `push 0x7a; pop edx`)
   - Patch `int 0x80`: use `xor byte ptr [ecx+offset], al` with computed values to transform alphanumeric bytes (e.g., `0x74 0x39`) into `\xcd\x80`
   - Set `eax` = 3 (`SYS_read`): via `push imm8; pop eax; xor al, imm8`
   - Execute patched `int 0x80` → `read(0, heap_base, 0x7a)`

5. **Send stage-2:** NOP sled (`\x90` or `\x41`=`inc ecx`) + raw `execve("/bin/sh", 0, 0)` shellcode. Read writes over the heap starting at the chain base; execution falls through the sled into the real shellcode.

**Example chain (from exp.py):**

```python
STAGE1 = [
    (-27, b"PYjzZSu8"),   # push eax; pop ecx; push 0x7a; pop edx; push ebx; jne
    (0,   b"4F0A5Su8"),   # xor al,0x46; xor [ecx+0x35],al; push ebx; jne
    (1,   b"fuck"),       # spacer (never executed)
    (2,   b"X4340t9"),    # pop eax; xor al,0x33; xor al,0x30; je (patched to int 0x80)
    (3,   b"XH0AFu6"),   # pop eax; dec eax; xor [ecx+0x46],al; jne
    (4,   b"0A60AWua"),   # xor [ecx+0x36],al; xor [ecx+0x57],al; jne
]
```

**Patching `int 0x80`:** The bytes `0x74 0x39` (at chunk2 offset +5,+6) are XORed in-place:
- `0x74 ^ 0xb9 = 0xCD` and `0x39 ^ 0xb9 = 0x80` → produces `\xcd\x80`
- The value `0xb9` is obtained via `xor al, 0x46` on `0xff` (from `dec eax` on 0)

**Stage 2:** `b"A" * 0x37 + execve_shellcode` — the `A` bytes (`0x41` = `inc ecx`) serve as a NOP sled, landing execution precisely at the `execve` payload.

---

### Path B — `popad` Frame Construction → `int 0x80` via Memory XOR

**Used by:** Solutions 278, 5002, 3498

**Variant** of Path A that uses `popad` (`0x61`, alphanumeric!) to bulk-load registers from a carefully constructed stack frame:

1. Push register values onto the stack in the correct order for `popad` (EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX).
2. Use `xor [reg+offset], ax/eax` to patch `int 0x80` into memory.
3. Execute `popad` to set all registers at once, then fall through to patched `int 0x80`.

This approach is more complex but avoids individual register setup.

---

### Path C — Leak libc via `show_note` + System Call via GOT Overwrite

**Used by:** Solutions 100, 956

**Strategy:** Instead of building a `read()` stager, leak libc addresses and call `system()` directly.

1. **Leak libc:** `show_note(-N)` reads memory before `notes[]`, hitting GOT entries or other libc pointers. Parse the leaked bytes to compute libc base.

2. **Overwrite `free@GOT`** with heap shellcode that swaps registers and jumps to `system()`.

3. **Trigger with crafted input:** `delete_note` passes `system()` address + `"sh"` string through `atoi`/`read_int` tricks, or the alphanumeric shellcode on heap sets up `call [eax]` with `eax = system`.

**Downside:** More fragile — relies on specific libc offsets and register state at call time.

---

### Path D — `strlen@GOT` Overwrite to Bypass Alphanumeric Check

**Used by:** Solution 3148

**Strategy:** Instead of writing alphanumeric shellcode, neutralize the character filter by overwriting `strlen@GOT`.

1. **Exhaust heap** with many dummy `strdup` allocations until the wilderness chunk's size field contains useful byte sequences (e.g., `\xc3\x41` = `ret; inc ecx`).

2. **Overwrite `strlen@GOT`** (index -22) to point to a heap address containing `ret` — making `strlen()` always return quickly without actually validating the string.

3. **With the filter bypassed**, write arbitrary (non-alphanumeric) shellcode bytes to heap notes.

4. **Overwrite `free@GOT`** or `atoi@GOT` with shellcode address, trigger execution.

**Downside:** Requires precise heap grooming (thousands of allocations to get the right top-chunk size).

---

### Path E — Direct `execve` via `popad` + `xor` patching (No Read Stager)

**Used by:** Solutions 5002, 25916

**Strategy:** Build the entire `execve("/bin/sh", 0, 0)` syscall using only alphanumeric shellcode, without a `read()` stager. Uses `xor` to patch `/bin/sh` string and `int 0x80` into memory, then `popad` to load all registers:

1. Construct `/bin/sh\x00` string byte-by-byte via `push` + `xor`.
2. Construct `\xcd\x80` via XOR patching.
3. Set `eax=0xb`, `ebx=ptr_to_binsh`, `ecx=0`, `edx=0`.
4. Execute patched `int 0x80`.

**Downside:** Requires many more shellcode chunks (15-50+), much more complex chain.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| GOT overwrite (`free`, `atoi`, `strlen`) | V1: Negative index OOB | Deterministic |
| Heap code execution | RWX heap (READ_IMPLIES_EXEC) | Deterministic (i386 only) |
| Self-modifying shellcode | XOR patching `int 0x80` | Deterministic |
| `read()` stager (stage 1) | Alphanumeric chain → `read(0, buf, N)` | Deterministic |
| `execve("/bin/sh")` (stage 2) | Unrestricted shellcode via `read()` | Deterministic |
| libc leak | `show_note` with negative index | Deterministic |

## Alphanumeric Instruction Reference

Key x86 instructions that have alphanumeric encodings:

| Instruction | Bytes | ASCII |
|------------|-------|-------|
| `push eax` | `50` | `P` |
| `push ecx` | `51` | `Q` |
| `push edx` | `52` | `R` |
| `push ebx` | `53` | `S` |
| `push esp` | `54` | `T` |
| `push ebp` | `55` | `U` |
| `pop eax` | `58` | `X` |
| `pop ecx` | `59` | `Y` |
| `pop edx` | `5a` | `Z` |
| `push imm8` | `6a xx` | `j` + alnum |
| `inc ecx` | `41` | `A` |
| `inc edx` | `42` | `B` |
| `inc ebx` | `43` | `C` |
| `dec eax` | `48` | `H` |
| `dec ebx` | `4b` | `K` |
| `xor al, imm8` | `34 xx` | `4` + alnum |
| `xor [ecx+off], al` | `30 41 xx` | `0A` + alnum |
| `xor ax, imm16` | `66 35 xx xx` | `f5` + alnum |
| `jne rel8` | `75 xx` | `u` + alnum |
| `jno rel8` | `71 xx` | `q` + alnum |
| `jae rel8` | `73 xx` | `s` + alnum |
| `popad` | `61` | `a` |

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | A | `jno` chain, XOR self-modify, NASM annotated | Includes full assembly source |
| `100.md` | C | libc leak via show, system() via register swap | No read stager — direct system call |
| `185.md` | A | `popad` + `xor word [edx+eax*2+0x38],cx` | Uses computed addressing mode |
| `278.md` | B | `popad` frame + XOR patch int 0x80 | Ruby exploit |
| `370.md` | A | Minimal — "same as Death Note, just jumping" | 2 lines of explanation |
| `550.md` | A | `popad` based, elaborate register chain | Uses negative indices for spacers |
| `583.md` | A | XOR `[ecx+off]` to patch `int 0x80` | Clean Python exploit |
| `644.md` | A | 7 stage chain, `jae` jumps | Well-documented stages |
| `821.md` | A | `xor [ecx+0x31]` patching, `jne` | Assembly + exploit script |
| `956.md` | C | `atoi@GOT` overwrite, libc leak, execve | Heap exhaustion approach |
| `1172.md` | A | `PYjAXGq8` chain, 5 notes | Minimal chain |
| `1780.md` | A | `jno 0x40` jumps, `xor byte` patches | Clean separation of stages |
| `2524.md` | A | `jae` jumps, 9 stages | Incremental `inc edx` for syscall nr |
| `3148.md` | D | `strlen@GOT` bypass, heap exhaustion | Bypasses alnum check entirely |
| `3498.md` | A | Enumerated valid bytes, `popad` + XOR | Most thorough valid-byte analysis |
| `5002.md` | E | Full `popad` frame, no read stager | Constructs `int 0x80` + `/bin/sh` in-place |
| `7905.md` | A | Detailed writeup with Unicorn verification | Best-documented solution |
| `8153.md` | A | Chinese writeup, XOR patching explained | Step-by-step register/memory trace |
| `14106.md` | A | Minimal `jne 0x48` chain | Concise strategy description |
| `17704.md` | A | `jno 0x39` chain, 9 fragments | Uses `dec edx; push edx; pop eax` |
| `25916.md` | A | `jno` chain, many XOR patches | Extended chain with separate XOR stages |
| `36997.md` | A | `jne` chain, `pop ecx` stager | References external writeup for learning |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (self-contained, no pwntools dependency) |
| `desc.txt` | Challenge description |
| `artifacts/alive_note` | Original challenge binary (i386, not stripped) |
| `solution/*.md` | Community write-ups (87 solutions) |
