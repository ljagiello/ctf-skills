---
tags:
  - out-of-bounds-write
  - information-leak
  - house-of-orange
  - io-file-exploit
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "An off-by-null write during book author naming leaks heap addresses, and overwriting the top chunk size triggers House of Orange _IO_FILE vtable exploitation via _IO_flush_all_lockp."
proof-of-concept: no
---

# BookWriter — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10304`
>
> Flag: `FLAG{Th3r3_4r3_S0m3_m4gic_in_t0p}`

## Challenge Overview

A heap note-taking binary (x86-64, Full RELRO, NX, Stack Canary, PIE disabled) built against glibc 2.23. The program manages an "author" name and up to 8 pages of dynamically allocated text. There is **no free/delete** operation — the only way to get chunks into the free lists is via the House of Orange technique (corrupting the top chunk size to trick `sysmalloc` into freeing the old top).

Based on BKP CTF 2017's "memo" challenge with bug fixes and control flow modifications.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)    # .bss addresses are fixed
```

## Global Data Layout (BSS)

```
0x602040  num_pages         (uint32_t, max 8)
0x602060  author[0x40]      (char, NO NUL terminator if fully filled)
0x6020A0  page_ptrs[8]      (char *[8])
0x6020E0  page_sizes[8]     (uint64_t[8])
```

Note that `page_ptrs[8]` (at `0x6020E0`) aliases `page_sizes[0]`. This is the key to the off-by-one index trick.

## Vulnerabilities

### V1 — `strlen`-Based Size Update in `edit()` (Primary, Heap Overflow)

**Root Cause:** After `edit()` calls `read_n(page, page_size)`, it updates the stored size with `page_size = strlen(page)`. If the page content has no NUL byte, `strlen` walks past the chunk boundary into the next chunk's metadata.

```c
// edit() pseudocode
void edit(int idx) {
    read_n(page_ptrs[idx], page_sizes[idx]);  // fill to exact capacity
    page_sizes[idx] = strlen(page_ptrs[idx]); // BUG: strlen walks into next chunk
}
```

**Trigger:** Allocate a page of size N and fill it with N non-NUL bytes. `strlen` reads past the chunk data into the following chunk's `size` field (which is non-zero), returning a value larger than N. A second `edit()` now writes up to this inflated size, overflowing into the adjacent chunk.

**Impact:** Overwrite the **top chunk's size** field. This enables House of Orange: set the top chunk size to a value that satisfies `sysmalloc`'s page-alignment checks, then `malloc` a request larger than the corrupted top chunk → `sysmalloc` calls `_int_free()` on the old top, placing it into the unsorted bin.

### V2 — Off-by-One Index in `add()` (Page Count Overflow)

**Root Cause:** The `add()` function scans `page_ptrs[0..8]` (9 elements) for a free slot, but the array only has 8 entries. Index 8 of `page_ptrs` aliases `page_sizes[0]`.

```c
// add() pseudocode
for (int i = 0; i <= 8; i++) {   // BUG: should be i < 8
    if (page_ptrs[i] == NULL) {
        page_ptrs[i] = malloc(size);
        page_sizes[i] = size;
        break;
    }
}
```

**Trigger:** Fill all 8 page slots (indices 0-7). The next `add()` writes the `malloc` return value into `page_ptrs[8]`, which is actually `page_sizes[0]`. Now `page_sizes[0]` contains a **heap pointer** (a very large value), making `edit(0)` an enormous arbitrary heap write.

**Prerequisite for trick:** If `page_sizes[0]` is 0 (page 0 was allocated with size 0), then `page_ptrs[0]` appears NULL to the scan, so `add()` at index 0 replaces it, and `page_sizes[0]` gets set to the new `malloc` return value. Either way, `page_sizes[0]` becomes huge.

### V3 — Author Buffer Information Leak (Heap Leak)

**Root Cause:** The author buffer at `0x602060` is 0x40 bytes. If filled completely (no NUL terminator), the `information()` function prints it with `printf("%s", author)`, which continues reading into `page_ptrs[0]` — a heap address.

```c
// set author
read_n(author, 0x40);  // no NUL terminator if 0x40 bytes sent

// information()
printf("Author : %s\n", author);  // leaks page_ptrs[0] after the 0x40 author bytes
```

**Impact:** Leak the heap base address by reading past the author buffer into `page_ptrs[0]`.

### V4 — No `free()` Operation

The program provides no delete/free function. This means:
- Standard UAF/double-free attacks are impossible.
- The **only** way to get chunks into free lists is House of Orange (V1 → corrupt top chunk → `sysmalloc` frees old top).

## Exploit Paths

All 90 solutions use the **House of Orange** technique. They diverge on the specific FSOP layout and the mechanism to trigger the fake `_IO_FILE` execution.

---

### Path A — House of Orange → FSOP via `_IO_list_all` Unsorted Bin Attack (Standard)

**Used by:** ~95% of solutions (138, 185, 194, 1172, 1177, 1303, 1351, 1689, 1829, 1922, 1980, 10840, 17006, 18324, 21260, etc.)

**Steps:**

1. **Heap leak (V3):** Send 0x40 non-NUL bytes as author. Call `information()` → author string leaks into `page_ptrs[0]` → heap base.

2. **Top chunk corruption (V1):** Allocate a page adjacent to the top chunk (e.g., size 0x18 or 0x28). Edit it twice: first to grow the stored size via `strlen`, second to overwrite the top chunk's size to a carefully chosen value (e.g., `0xfc1`, `0xfe1`, `0x0fc1`, `0x0ed1`). The new size must satisfy:
   - `old_top + new_size` is page-aligned
   - `new_size > MINSIZE`
   - `prev_inuse` bit set

3. **Trigger `sysmalloc` (House of Orange):** `add(0x1000, ...)` — the request exceeds the corrupted top chunk size → `sysmalloc` frees the old top into the **unsorted bin** and mmaps a new region.

4. **libc leak:** Allocate a small chunk from the freed old-top (now in unsorted bin). The leftover unsorted chunk has `fd`/`bk` pointing to `main_arena+88`. Read it with `view()` → libc base.

5. **Off-by-one index trick (V2):** Fill remaining page slots. The 9th `add()` writes a heap pointer into `page_sizes[0]` → `edit(0)` becomes an enormous heap write.

6. **Build fake `_IO_FILE` + unsorted bin attack:** Using the huge `edit(0)`, write:
   - A fake `_IO_FILE_plus` structure with `flags = "/bin/sh\x00"`, `_IO_buf_size = 0x61` (to land in `smallbin[4]`), `bk = &_IO_list_all - 0x10`.
   - The vtable pointer set to a controlled heap region containing `system` at the `__overflow` offset.
   - `_IO_write_ptr > _IO_write_base` and `_mode <= 0` to pass `_IO_flush_all_lockp` checks.

7. **Trigger:** Call `add()` with a size that causes `malloc` to traverse the unsorted bin. The unsorted bin attack writes `main_arena+0x58` to `_IO_list_all`. During the sort, the fake chunk lands in `smallbin[4]`, reachable as `_IO_list_all->_chain->_chain`. When `_IO_flush_all_lockp` walks the chain (via `exit()` or `malloc_printerr`), it calls `_IO_OVERFLOW(fake_file)` → `system("/bin/sh")`.

**Trigger variants:**
- **`exit()` (menu choice 5):** The exp.py uses this — cleaner, no abort needed.
- **`malloc_printerr`:** Most solutions trigger an unsorted bin corruption that calls `abort()` → `_IO_flush_all_lockp`. In glibc 2.23, `abort()` flushes IO. Some libc builds (like the pwnable.tw one) do NOT flush on abort, requiring `exit()` instead.

---

### Path B — House of Orange with Extended Top Chunk Manipulation

**Used by:** Solutions 194, 1297, 1316, 1395, 1986

Some solvers avoid the off-by-one index trick entirely by repeatedly growing the top chunk corruption to reach further into the heap:

1. Perform House of Orange as above.
2. After getting the unsorted bin, **extend the old top chunk size again** via a second `strlen` trick to overlap additional chunks.
3. Use the overlapping region to write the fake `_IO_FILE` directly, without needing the index-8 alias.

This variant is more complex but avoids reliance on V2.

---

### Path C — House of Orange → Unsorted Bin Attack → `__malloc_hook` Overwrite

**Used by:** Solutions 1177, 1303

Instead of FSOP, some solutions use the unsorted bin attack to overwrite a different target:

1. Perform House of Orange and get libc leak.
2. Use the unsorted bin attack to corrupt `__malloc_hook` (or a nearby location) with a controlled pointer.
3. Place a `one_gadget` address at `__malloc_hook`.
4. Trigger `malloc` → `one_gadget` → shell.

This requires more careful heap layout since the unsorted bin attack only writes `main_arena+0x58` (not an arbitrary value). Solvers chain it with additional corruption to get the `one_gadget` into `__malloc_hook`.

---

### Path D — Author Buffer as Fake Chunk / Vtable Host

**Used by:** Solutions 138, 194, 1177

Since the author buffer is at a fixed BSS address (`0x602060`), some solutions:

1. Use `information()` with "change author" to write controlled data into the author buffer.
2. Point the fake `_IO_FILE`'s vtable to `0x602060` (author buffer).
3. Place `system` at the correct vtable offset within the author buffer.

This leverages the no-PIE property for a predictable vtable address without heap-relative calculations.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Heap address leak | V3: author `printf` overflow into `page_ptrs[0]` | Deterministic |
| Top chunk size corruption | V1: `strlen`-based size growth in `edit()` | Deterministic |
| Free old top into unsorted bin | House of Orange via `sysmalloc` | Deterministic (with correct size) |
| libc leak | Read `fd`/`bk` from unsorted bin chunk | Deterministic |
| Huge heap write | V2: off-by-one index, `page_sizes[0]` = heap ptr | Deterministic |
| `_IO_list_all` overwrite | Unsorted bin attack (`bk->fd = main_arena+0x58`) | Deterministic |
| Code execution | FSOP: `_IO_OVERFLOW` → `system("/bin/sh")` | Deterministic |

## Key Constraints for Top Chunk Size

When corrupting the top chunk size, it must satisfy (`sysmalloc` checks):

```
1. (old_top + old_size) must be page-aligned (0x1000)
2. old_size > MINSIZE (0x20)
3. old_size has PREV_INUSE bit set (LSB = 1)
4. old_size < requested_size (so sysmalloc triggers)
```

Common values used across solutions (depending on allocation offset):

| Chunk offset from page | Top chunk size | Notes |
|------------------------|---------------|-------|
| `0x30` (size 0x18+meta) | `0xfd1` | Most common |
| `0x30` | `0xfe1` | Alternate alignment |
| `0x20` (size 0x18) | `0xfe1` | |
| `0x120` | `0xed1` | After larger initial alloc |
| `0x220` | `0xde1` | |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
main_arena_off  = 0x3c3b20    # main_arena (unsorted bin = main_arena + 0x58 + 0x10)
__malloc_hook   = 0x3c3b10
_IO_list_all    = 0x3c4520
system          = 0x45390
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# unsorted bin leak: leaked_ptr - 0x3c4188 = libc_base  (or - 0x3c3b78 depending on chunk)
```

## Solution Write-ups

| File | Path | Key Technique | Notes |
|------|------|---------------|-------|
| `138.md` | A + D | FSOP, vtable in heap, `_wide_data` trick | Ruby; uses author for vtable data |
| `185.md` | A | FSOP via `_IO_list_all`, size-0 index trick | Clean Python2; references angelboy blog |
| `194.md` | B | Extended top chunk, no index-8 trick | Large initial alloc for second top corruption |
| `1172.md` | A | Standard FSOP, `page_sizes[0]` trick | Concise; good comments on constraints |
| `1177.md` | A + C | Unsorted bin → author buffer as fake chunk → `__malloc_hook` | Uses BSS address for fake chunk fd/bk |
| `1297.md` | B | Repeated top extension, overlap multiple chunks | Complex multi-stage heap manipulation |
| `1303.md` | A + C | FSOP + `one_gadget` via `__malloc_hook` | Uses unsorted bin corruption chain |
| `1316.md` | B | Large alloc for overlap, `_IO_str_jumps` vtable | Uses `_IO_str_jumps-8` for vtable bypass |
| `1351.md` | A | Standard FSOP, leading NUL byte for size reset | |
| `1689.md` | A | FSOP via direct heap overlap | Compact; inline vtable construction |
| `1829.md` | A | FSOP with custom `_wide_data` | |
| `1922.md` | A | Standard FSOP | Clean, good logging |
| `1980.md` | A | FSOP, detailed `_IO_FILE` field annotations | Educational: labels every struct field |
| `1986.md` | A | FSOP, notes `scanf` internal malloc usage | Tip: `scanf` calls malloc internally |
| `2121.md` | A | FSOP with vtable at heap+offset | |
| `10840.md` | A | Clean Python3 exploit | |
| `17006.md` | A | Compact FSOP | |
| `18324.md` | A | FSOP, notes reliability issues | |
| `21260.md` | A | FSOP, detailed vtable calculation | |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (self-contained, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/bookwriter` | Challenge binary (x86-64, stripped) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (90 solutions) |
