---
tags:
  - double-free
  - fastbin-dup
  - one-gadget
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A double-free vulnerability on flower nodes enables fastbin duplication to allocate a chunk over __malloc_hook and execute a one_gadget."
proof-of-concept: no
---

# Secret Garden — pwnable.tw (350 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10203`
>
> Flag: `FLAG{FastBiN_C0rruption_t0_BUrN_7H3_G4rd3n}`

## Challenge Overview

A menu-based heap challenge binary (x86-64, Full RELRO, PIE, NX, Stack Canary) built against glibc 2.23. The program manages an array of "flower" structs on the heap — each flower has a name buffer (user-controlled size via `malloc`), a 24-byte color string, and an in-use flag. The menu provides: (1) Raise a flower, (2) Visit the garden, (3) Remove a flower, (4) Clean the garden, (5) Leave.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## Program Structure

### Flower Struct (0x28 bytes, malloc'd)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `in_use` | `uint32_t` (1 = alive, 0 = removed) |
| `0x08` | `name` | `char *` (malloc'd, user-controlled size) |
| `0x10` | `color` | `char[24]` (inline, scanf `%23s`) |

### Global State

- `flower_array[100]` — BSS array of `flower *` pointers (max 100 flowers)
- `flower_count` — total flowers raised

### Menu Operations

1. **Raise** — `malloc(0x28)` for struct, `malloc(size)` for name, reads name via `read()`, color via `scanf`, sets `in_use = 1`.
2. **Visit** — iterates array, prints name and color for flowers with `in_use != 0`.
3. **Remove** — `free(flower->name)`, sets `flower->in_use = 0`. **Does NOT null the name pointer, does NOT null the array slot, does NOT free the struct.**
4. **Clean** — iterates array, for flowers with `in_use == 0`: `free(flower_struct)`, nulls the array slot.

## Vulnerabilities

### V1 — Use-After-Free / Double-Free on Name Buffer (Primary, Exploitable)

**Root Cause:** The "Remove" operation frees the flower's name buffer but does not clear the `name` pointer or the array slot. The `in_use` flag is set to 0, but the flower struct remains accessible. This enables:

- **Use-After-Free**: After Remove, "Visit" still prints the name pointer's contents (now freed memory containing heap metadata — fd/bk pointers).
- **Double-Free**: Remove the same flower twice → the name buffer is freed twice, corrupting the fastbin freelist.

```c
// Remove (simplified pseudocode)
void remove_flower(int idx) {
    if (flower_array[idx] != NULL) {
        free(flower_array[idx]->name);   // free name buffer
        flower_array[idx]->in_use = 0;   // mark as removed
        // BUG: name pointer NOT cleared
        // BUG: array slot NOT nulled
        // BUG: struct NOT freed
    }
}
```

**Impact:** The freed name buffer's `fd` pointer (in fastbins) or `fd`/`bk` pointers (in unsorted/small bins) are leaked via Visit. Double-free enables fastbin duplication for arbitrary write.

### V2 — Partial Write on Name Buffer (Enabler)

**Root Cause:** When raising a flower, the name is read via `read(0, name_buf, size)`. Since `read()` does not NUL-terminate, and the `calloc`/`malloc`'d buffer may contain residual heap metadata, writing fewer bytes than the allocated size preserves existing data (libc pointers from freed chunks).

```c
// Raise (simplified)
flower->name = malloc(size);
read(0, flower->name, size);  // partial write preserves old fd/bk at offset 8+
```

**Impact:** Allocate into a chunk that previously held unsorted bin pointers, write only 8 bytes → the libc `main_arena+0x58` pointer at offset 8 survives → leaked via Visit.

## Exploit Paths

All solutions exploit V1 (UAF/double-free). They diverge in the leak strategy and the code execution technique.

---

### Path A — Unsorted Bin Leak + Fastbin Dup → `__malloc_hook` Overwrite

**Used by:** exp.py, solutions 2311, 2605, 821 (method 2), 1351, and majority of write-ups

This is the canonical, most common approach.

**Steps:**

1. **libc Leak via Unsorted Bin:**
   - Raise flower A (size > 0x80, e.g. 0x100) and flower B (barrier to prevent top chunk consolidation).
   - Remove A → name buffer enters unsorted bin → `fd`/`bk` = `main_arena+0x58`.
   - Clean → frees A's struct into fastbin, nulls slot.
   - Raise A' with same size → struct reuses fastbin, name reuses the exact unsorted chunk.
   - Write only 8 bytes → libc pointer at offset 8 survives.
   - Visit → read `main_arena+0x58` → `libc_base = leak - 0x3c3b78`.

2. **Fastbin Duplication (Double-Free):**
   - Raise D and E with size 0x60 (chunk size 0x70 → fastbin index 5).
   - Remove D, Remove E, Remove D → fastbin: `D → E → D` (circular).
   - Raise with `p64(__malloc_hook - 0x23)` as name → overwrites D's `fd`.
   - Raise twice more to consume E and D.
   - Next 0x70 alloc returns fake chunk at `__malloc_hook - 0x23`.
     - The byte at `__malloc_hook - 0x1b` is the MSB of a libc pointer = `0x7f`, which serves as a valid fake chunk size (0x70 fastbin with IS_MMAPPED set).

3. **Write one_gadget to `__malloc_hook`:**
   - The fake chunk starts 0x23 bytes before `__malloc_hook`.
   - Write `\x00 * 0x13 + p64(one_gadget)` → overwrites `__malloc_hook`.

4. **Trigger:**
   - Double-free any flower → glibc detects corruption → `malloc_printerr` → `abort` backtrace → calls `malloc` → `__malloc_hook` fires → `execve("/bin/sh")`.
   - Alternative: just call Raise (menu 1) again to trigger `malloc`.

**one_gadget offsets (glibc 2.23):**
```python
0x45216   # rax == NULL
0x4526a   # [rsp+0x30] == NULL
0xef6c4   # [rsp+0x50] == NULL  (most commonly used)
0xf0567   # [rsp+0x70] == NULL
```

**Reliability:** Deterministic heap layout. Nearly 100% reliable.

---

### Path B — Fastbin Dup → Arbitrary Read (Fake Flower Struct) → Stack ROP

**Used by:** Solutions 8, 10, 59, 78, 184, 644, 821 (method 1)

This approach builds an arbitrary read primitive and then overwrites a stack return address.

**Steps:**

1. **Heap Leak via Fastbin:**
   - Raise and remove flowers of the same size to populate fastbins.
   - Raise a new flower whose struct overlaps a freed name → Visit leaks `fd` pointer → heap base.

2. **libc Leak:**
   - Either via unsorted bin (same as Path A), or by using the heap leak + arbitrary read to reach a libc pointer on the heap.

3. **Stack Leak via `environ`:**
   - Use fastbin dup to create overlapping flower struct + name buffer.
   - Forge a fake flower struct where `name` points to `libc.sym['environ']`.
   - Visit → prints contents of `environ` → stack address.

4. **Fastbin Dup to Stack:**
   - Find a stack address where `[addr+8]` contains `0x7f` (a valid fastbin size byte). Typically at `environ_value - 0x18b` or similar offset.
   - Double-free 0x70-size chunks, plant fake `fd` pointing to that stack address.
   - Final alloc returns a buffer on the stack.
   - Write a ROP chain (`pop rdi; ret` → `/bin/sh` → `system`) overwriting `read()`'s return address (since the name buffer `read()` call returns into the vulnerable stack frame).

**Reliability:** Deterministic. Does not require one_gadget constraints.

---

### Path C — Fastbin Dup → `_IO_list_all` / `stdout` vtable Hijack

**Used by:** Solutions 78 (variant), 138, 278, 365, 370 (variant), 100, 1172, 1236

This approach targets the FILE stream vtable mechanism in glibc 2.23.

**Steps:**

1. **libc + Heap Leak:** Same as Path A/B.

2. **Fastbin Dup into `_IO_list_all` or `stdout`:**
   - Target `_IO_list_all - 0x23` (has a `0x7f` size byte) or `stdout + 0xd8 - 0x3b` (similar).
   - Double-free 0x70 chunks, plant fake `fd` to the target.

3. **Overwrite `_IO_list_all`** to point to a controlled heap region containing:
   - A crafted fake `_IO_FILE` struct with specific field constraints.
   - A fake vtable where the `__overflow` / `xsputn` function pointer = `one_gadget` or `system`.

4. **Trigger via `exit(0)` (menu 5) or `abort`:**
   - `exit` → `__run_exit_handlers` → `_IO_cleanup` → `_IO_flush_all_lockp` → walks `_IO_list_all` → calls vtable function → one_gadget/system.
   - Or: any malloc error (double-free) → `malloc_printerr` → `abort` → `_IO_flush_all_lockp` → same path.

**Reliability:** Requires careful struct crafting. Works on glibc 2.23 (vtable checks not yet enforced).

---

### Path D — Fastbin Dup → `main_arena` Top Chunk Overwrite → `__free_hook`

**Used by:** Solution 550

An unusual approach that overwrites `main_arena.top` to redirect future allocations.

**Steps:**

1. **Leak libc + heap** via UAF.
2. **Fastbin dup into `main_arena`** (using a heap address with a valid size byte in the right position).
3. **Overwrite `main_arena.top`** with `__free_hook - 0xb58` (an address with non-zero data serving as the new top chunk's size).
4. **Repeatedly allocate** to advance the top chunk toward `__free_hook`.
5. **Overwrite `__free_hook`** with `system`.
6. **Free a chunk** containing `"/bin/sh"` → `system("/bin/sh")`.

**Reliability:** Works but requires many allocations to reach `__free_hook`. Fragile.

---

### Path E — Unsorted Bin Attack → `global_max_fast` → Large Fastbin → `__free_hook`

**Used by:** Solution 821 (method 1)

1. **Unsorted bin attack** to write `main_arena+0x58` to `global_max_fast`, making all chunk sizes treated as fastbins.
2. **Free a large chunk** → it goes into a "fastbin" slot that maps to a useful address.
3. **Allocate from that fastbin** to get a chunk near `__free_hook`.
4. **Overwrite `__free_hook`** with `system`.

**Reliability:** Complex setup, less commonly used.

---

### Path F — `__realloc_hook` + `__malloc_hook` Combo

**Used by:** Solutions 2311, 2605

A variant of Path A that handles one_gadget constraint failures:

1. Same fastbin dup to `__malloc_hook - 0x23`.
2. Write `one_gadget` to `__realloc_hook` and `__libc_realloc + 20` to `__malloc_hook`.
3. When `malloc` is called → `__malloc_hook` → `__libc_realloc(+20)` → `__realloc_hook` → `one_gadget`.
4. The extra `realloc` stack frame adjusts `rsp` alignment so the one_gadget constraints are satisfied.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc leak (unsorted bin fd/bk) | V1: UAF read after free into unsorted bin | Deterministic |
| Heap leak (fastbin fd) | V1: UAF read after free into fastbin | Deterministic |
| Fastbin duplication | V1: double-free same name buffer | Deterministic |
| Arbitrary write (fastbin dup) | Fake fd → alloc at target address | Deterministic (needs valid size byte) |
| Stack leak | Arbitrary read via forged flower struct → `environ` | Deterministic after arb read |
| Code execution | `__malloc_hook`, `__free_hook`, vtable, or stack ROP | Deterministic |

## Key Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
main_arena      = 0x3c3b20
main_arena_top  = 0x3c3b78   # main_arena + 0x58 (unsorted bin head)
__malloc_hook   = 0x3c3b10
__realloc_hook  = 0x3c3b08
__free_hook     = 0x3c57a8
_IO_list_all    = 0x3c4520
_IO_2_1_stdout  = 0x3c4620
environ         = 0x3c5f38   # (in some solutions: __libc_argv = 0x3c82f8)
system          = 0x45390
bin_sh          = 0x18c177
pop_rdi         = 0x21102    # pop rdi; ret
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `8.md` | B | fastbin dup → stack ROP via environ leak | Full arbitrary read chain; leaks heap, libc, stack, canary |
| `10.md` | B | fastbin dup → stack ROP via TLS/mmap leak | Unusual: leaks libc via TLS region from mmap'd chunk |
| `59.md` | B | fastbin dup → stack ROP | Clean approach; leaks libc, stack via environ |
| `60.md` | B | unsorted bin split → stack ROP | Leaks libc via remainder chunk metadata |
| `78.md` | C | fastbin dup → `_IO_2_1_stdout_` vtable | Overwrites stdout vtable pointer to fake vtable |
| `100.md` | C | fastbin dup → `_IO_list_all` → exit trigger | Crafts fake IO stream, triggers via exit(0) |
| `138.md` | C | fastbin dup → `_IO_list_all` | Ruby exploit; IO_flush_all to one_gadget |
| `184.md` | B | fastbin dup → stack ROP via `__libc_argv` | Leaks stack from __libc_argv instead of environ |
| `278.md` | C | fastbin dup → stdout vtable hijack | Overwrites stdout vtable to fake vtable with one_gadget |
| `331.md` | A | unsorted bin leak → fastbin dup → `__malloc_hook` | First doubles as libc+heap leak then overwrites malloc_hook |
| `365.md` | C | fastbin dup → `_IO_list_all` + fake IO | Constructs full fake FILE struct on heap |
| `370.md` | A | fastbin dup → `__malloc_hook` via IO_list vtable | Variant: overwrites IO stdout vtable to one_gadget |
| `550.md` | D | fastbin dup → `main_arena.top` overwrite → `__free_hook` | Unusual: hijacks top chunk to reach __free_hook |
| `644.md` | B | fastbin dup → stack ROP via environ | Classic: leak stack, ROP into read() return address |
| `821.md` | E + A | unsorted bin attack → `global_max_fast` + fastbin → `__free_hook` | Three different exploit methods in one writeup |
| `1172.md` | A | fastbin dup → `__malloc_hook` | Concise; standard approach |
| `1236.md` | A | fastbin dup → `_IO_2_1_stdout_` vtable | Overwrite stdout vtable to one_gadget |
| `1351.md` | C | fastbin dup → stdout vtable | Ruby; one_gadget via vtable |
| `2311.md` | F | fastbin dup → `__realloc_hook` + `__malloc_hook` combo | Uses realloc to fix rsp alignment for one_gadget |
| `2605.md` | A | fastbin dup → `__malloc_hook` | Standard approach with detailed heap manipulation |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (fastbin dup → `__malloc_hook` → one_gadget) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original challenge binary + libc |
| `solution/*.md` | Community write-ups (128 solutions) |
