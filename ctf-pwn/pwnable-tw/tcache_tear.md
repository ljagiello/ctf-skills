---
tags:
  - double-free
  - tcache-poisoning
  - arbitrary-write
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A double-free in tcache memory allows linking arbitrary memory addresses into the tcache list, forging chunks over __free_hook to execute system."
proof-of-concept: no
---

# Tcache Tear — pwnable.tw (200 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10207`
>
> Flag: `FLAG{tc4ch3_1s_34sy_f0r_y0u}`

## Challenge Overview

A simple heap note program (x86-64, No PIE, Full RELRO, NX, Canary, FORTIFY) built against **glibc 2.27** (tcache-enabled). The binary provides four operations: malloc+write, free, info (print name), and exit. The program stores a 0x20-byte "Name" in a BSS buffer at `0x602060`, then enters a menu loop with a single heap pointer tracked globally.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO            # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)     # fixed addresses in BSS
  FORTIFY:  Enabled
```

### Menu Operations

| Choice | Action |
|--------|--------|
| 1 — Malloc | `malloc(size)` where `size <= 0xFF`, reads `size` bytes into the chunk, stores pointer at `0x602088` |
| 2 — Free | `free(ptr)` — frees the chunk at `0x602088`, does **not** NULL the pointer |
| 3 — Info | Prints 0x20 bytes from the Name buffer at `0x602060` via `write(1, name, 0x20)` |
| 4 — Exit | Calls `exit(0)` |

### Key BSS Layout

```
0x602040  stdout (pointer to _IO_2_1_stdout_)
0x602060  Name buffer (0x20 bytes, written once at start)
0x602080  [padding]
0x602088  last_malloc_ptr (the single tracked heap pointer)
```

## Vulnerabilities

### V1 — Tcache Double-Free (Primary, Exploitable)

**Root Cause:** The free operation does **not** NULL out the global pointer at `0x602088` after freeing. glibc 2.27's tcache has no double-free detection (no key/count checks), so the same chunk can be freed twice.

```c
// Pseudocode for free operation
void do_free() {
    free(*(void **)0x602088);  // frees chunk
    // pointer NOT zeroed — still points to freed chunk
}
```

**Impact:** Classic tcache double-free → tcache poisoning. After double-free, the same chunk appears twice in the tcache freelist. Allocating it back lets the attacker overwrite its `fd` pointer with an arbitrary address, causing subsequent allocations to return controlled addresses.

### V2 — Heap Overflow on Small Sizes (Exploitable)

**Root Cause:** The malloc operation reads `size` bytes of data into the chunk, but when `size < 0x10`, the actual allocation is still `malloc(size)` (minimum chunk size 0x20). The `read` call uses the **user-supplied size** rather than the actual chunk size. However, the initial `read` for the name buffer and the data read both allow writing more than the nominal size in certain code paths.

More critically, several solutions exploit that calling `malloc(0)` or very small sizes followed by writing large payloads works because the `read(0, buf, size)` with size=0 returns immediately, but the data buffer at `0x602088` still points to the chunk — and subsequent operations (especially crafting fake chunks in BSS) rely on the fixed BSS layout rather than the heap overflow itself.

**Impact:** Enables writing large payloads (fake chunk headers, padding) needed to set up unsorted bin chunks in BSS.

### V3 — Fixed BSS Address (Name Buffer as Fake Chunk) (Enabler)

**Root Cause:** No PIE means the Name buffer at `0x602060` and the pointer at `0x602088` are at **fixed, known addresses**. The attacker can:
1. Write fake chunk metadata into the Name buffer at program start
2. Use tcache poisoning to allocate chunks overlapping the Name buffer
3. Forge large (unsorted-bin-sized) chunks in BSS to get libc pointers written there

```c
// At startup:
write(1, "Name:", 5);
read(0, name_buf, 0x20);  // name_buf = 0x602060
// Attacker writes: p64(0) + p64(0x501)  → fake chunk header
```

## Exploit Paths

All solutions exploit V1 (tcache double-free) for tcache poisoning. They diverge on **how they leak libc** and **what they overwrite for code execution**.

---

### Path A — Tcache Poisoning → Fake Unsorted Bin Chunk in BSS → Leak libc → `__free_hook`

**Used by:** Most solutions (exp.py, 138, 1177, 1297, 1316, 1351, 1763, 10178, 11631, 11699, 13060, 14032, 14334, 14479, 14826, 15522, 16609, and many more)

This is the dominant approach (~90% of solutions).

**Steps:**

1. **Set up fake chunk header in Name buffer.** At the "Name:" prompt, send `p64(0) + p64(0x501)` (or similar large size like `0x421`, `0x511`, `0x531`). This places a fake chunk header at `0x602060` with a size larger than the tcache maximum (0x408 for glibc 2.27), ensuring it goes to the unsorted bin when freed.

2. **Tcache poison to get allocation at BSS.** Use double-free on a tcache-sized chunk:
   ```python
   malloc(0x80, "A")
   free()              # chunk goes to tcache
   free()              # same chunk in tcache again (double-free)
   malloc(0x80, p64(target_bss_addr))  # overwrite fd with BSS address
   malloc(0x80, "dummy")               # consume first copy
   malloc(0x80, payload)               # returns BSS address — write fake chunk body
   ```

3. **Write fake chunk body + next-chunk headers.** The payload placed at the BSS address must include:
   - The fake chunk body (padding to fill the declared size)
   - A valid "next chunk" with `PREV_INUSE` set (to pass `free()`'s consolidation checks)
   - Overwrite `last_malloc_ptr` (`0x602088`) to point to the fake chunk at `0x602060+0x10`

4. **Free the fake chunk.** Since its size exceeds tcache max, it enters the **unsorted bin**. glibc writes `main_arena+96` into the chunk's `fd` and `bk` fields — which now overlap the Name buffer.

5. **Leak libc via Info.** Call Info (choice 3) which prints 0x20 bytes from the Name buffer. The `fd`/`bk` pointers (at offset `+0x10` from the name start) contain `main_arena+96`. Calculate: `libc_base = leaked_value - 0x3ebca0`.

6. **Tcache poison to overwrite `__free_hook`.** Use another double-free on a different tcache bin:
   ```python
   malloc(0x50, "A"); free(); free()
   malloc(0x50, p64(libc + __free_hook))
   malloc(0x50, "dummy")
   malloc(0x50, p64(libc + system))  # or one_gadget
   ```

7. **Trigger shell.**
   - `malloc(0x30, "/bin/sh\x00"); free()` → calls `system("/bin/sh")` via the hooked `free`.
   - Or write `one_gadget` to `__free_hook`/`__malloc_hook` and trigger.

**Reliability:** 100% deterministic — no ASLR brute-forcing needed since BSS addresses are fixed.

---

### Path B — Tcache Poisoning → `_IO_2_1_stdout_` FSOP Leak → `__free_hook`

**Used by:** Solutions 11968, 13424

This variant leaks libc by corrupting `stdout`'s FILE structure instead of forging unsorted bin chunks.

**Steps:**

1. **Tcache poison targeting `stdout` pointer.** Use double-free to allocate a chunk at `0x602040` (the `stdout` GOT-like pointer in BSS). Overwrite the low byte of `_IO_2_1_stdout_`'s address to redirect it, or poison the tcache to allocate directly at `_IO_2_1_stdout_`.

2. **Corrupt `_IO_2_1_stdout_` flags and write pointers.** Write:
   ```python
   p64(0xFBAD1800) +  # _flags: _IO_MAGIC | _IO_IS_APPENDING | _IO_CURRENTLY_PUTTING
   p64(0) * 3 +       # _IO_read_ptr, _IO_read_end, _IO_read_base = 0
   b'\x00'             # partial overwrite of _IO_write_base → leak from lower address
   ```

3. **Receive libc leak.** The next `write` through stdout leaks data from the libc data segment, giving a libc pointer.

4. **Same finish as Path A:** `__free_hook = system`, then `free("/bin/sh")`.

**Reliability:** May require partial byte brute-force (~1/16) if ASLR randomizes the `_IO_2_1_stdout_` address nibble.

---

### Path C — Tcache Poisoning → `printf` via `__free_hook` → Format String → `system`

**Used by:** Solution 13424

A creative two-stage approach:

1. **Partial overwrite of `stderr` pointer** in BSS to point near `__free_hook` (requires 1-byte brute-force on ASLR).
2. **Write `printf@plt` to `__free_hook`** via tcache poisoning.
3. **`malloc` a chunk containing a format string** (`%23$lx`), then `free()` it → `printf("%23$lx")` leaks a libc return address from the stack.
4. **Parse the leak**, compute `system` address, overwrite `__free_hook` again with `system`.
5. **`free("/bin/sh\x00")` → shell.**

**Reliability:** ~1/16 due to 4-bit ASLR brute-force.

---

### Path D — Heap Overflow + Unsorted Bin Attack (Variant)

**Used by:** Solution 1324

Some solutions skip tcache poisoning to BSS and instead use a heap buffer overflow from small-sized allocations to corrupt adjacent tcache chunks' metadata, then pivot into unsorted bin leak.

**Steps:**
1. Allocate chunks of different sizes to create adjacent tcache entries.
2. Use the overflow from a small allocation to corrupt `fd` pointers of adjacent freed chunks.
3. Redirect allocations to BSS or other controlled areas.
4. Proceed with libc leak and `__free_hook` overwrite.

---

### Path E — Tcache Struct Manipulation

**Used by:** Solution 138

This advanced approach overwrites the **tcache_perthread_struct** (the per-thread tcache metadata at the start of the heap) to manipulate bin counts and entries directly:

1. Tcache-poison to allocate at the tcache struct.
2. Set a bin's count to a high value (making tcache think it's "full").
3. Subsequent frees of that size go to fastbins/unsorted bin instead of tcache → leak `main_arena` pointers.
4. Further FSOP tricks with `_IO_2_1_stdout_` to leak libc.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Tcache double-free | V1: no pointer NULL after free | Deterministic |
| Tcache poisoning (arbitrary alloc) | V1 + glibc 2.27 no tcache checks | Deterministic |
| Fake unsorted bin chunk in BSS | V3: No PIE + Name buffer | Deterministic |
| libc leak via unsorted bin fd/bk | Fake chunk free → Info | Deterministic |
| libc leak via `_IO_2_1_stdout_` | FSOP partial overwrite | ~1/16 brute |
| `__free_hook` overwrite | Tcache poisoning to hook addr | Deterministic |
| Code execution | `free("/bin/sh")` → `system` | Deterministic |

## Offsets (Remote libc, glibc 2.27)

```python
# libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so
main_arena  = 0x3EBC40    # main_arena+96 = 0x3EBCA0
__free_hook = 0x3ED8E8
__malloc_hook = 0x3EBC30
system      = 0x4F440
one_gadgets = [0x4F2C5, 0x4F322, 0x10A38C]

# BSS (No PIE)
name_buf    = 0x602060
last_ptr    = 0x602088
stdout_ptr  = 0x602040
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `exp.py` | A | tcache dup → fake 0x421 chunk in BSS → leak → `__free_hook` = one_gadget | Clean reference exploit |
| `138.md` | E | tcache struct manipulation → FSOP stdout leak | Ruby; most complex approach |
| `1177.md` | A | fake 0x701 chunk → unsorted bin leak → `__free_hook` = system | Standard approach |
| `1297.md` | A | fake 0x91 chunk at BSS+0x98 → leak → `__free_hook` = one_gadget | Compact |
| `1316.md` | A | fake 0x431 chunk → cyclic padding → `__free_hook` = system | Detailed comments |
| `1324.md` | D | heap overflow to corrupt tcache fd → BSS fake chunk | Overflow variant |
| `1351.md` | A | fake 0x501 chunk → one_gadget | Minimal |
| `1763.md` | A | fake 0x511 chunk → `__free_hook` = system | Minimal |
| `10178.md` | A | fake 0x501 chunk → `__free_hook` = system | Uses ptrlib |
| `11631.md` | A | fake 0x501 chunk → `__free_hook` = one_gadget | Standard |
| `11968.md` | B | stdout overwrite → FSOP libc leak → `__free_hook` = system | No fake chunk needed |
| `13060.md` | A | tcache dup → fake 0x421 chunk → one_gadget | Clean |
| `13424.md` | C | stderr brute → `printf@plt` in free_hook → fmt string leak → system | Two-stage; creative |
| `14032.md` | A | fake 0x111 chunk → one_gadget | Small fake chunk |
| `14334.md` | A | 0x500 unsorted chunk → detailed walkthrough | Best commented solution |
| `14479.md` | A | fake 0x531 chunk → one_gadget | Standard with flag |
| `14826.md` | A | fake 0x461 chunk → `__free_hook` = system | Uses `malloc(0, payload)` |
| `15522.md` | A | fake 0x501 chunk → one_gadget | Standard |
| `16609.md` | A | fake 0x418 chunk → system | Well-structured |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (no pwntools dependency) |
| `desc.txt` | Challenge description |
| `artifacts/tcache_tear` | Original challenge binary (stripped, x86-64) |
| `solution/*.md` | Community write-ups (128 solutions) |
