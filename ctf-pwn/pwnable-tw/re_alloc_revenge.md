---
tags:
  - use-after-free
  - double-free
  - tcache-poisoning
  - io-file-exploit
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.29
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "Exploiting realloc(ptr, 0) double free with only two allocation slots allows tcache poisoning to corrupt _IO_2_1_stdout_ and hijack __free_hook."
proof-of-concept: no
---

# Re-alloc Revenge — pwnable.tw (350 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10310`
>
> Flag: `FLAG{r3alloc_the_heap_r3alloc_the_file_Str34m_r3alloc_my_lif3}`

## Challenge Overview

A heap-menu binary (x86-64, Full RELRO, PIE, NX, Canary, FORTIFY) linked against **glibc 2.29** (Ubuntu 2.29-0ubuntu2). The program provides only two heap slots (`heap[0]`, `heap[1]`), allocations capped at `0x78` bytes, and **no view/print functionality**. All allocation uses `realloc()` under the hood — even the "free" operation is `realloc(ptr, 0)`.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO          # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## Program Logic

| Menu | Action | Behavior |
|------|--------|----------|
| 1 Alloc | `allocate(idx, size, data)` | Requires `heap[idx] == NULL`; `size <= 0x78`; `malloc(size)` + `read_input` |
| 2 Realloc | `reallocate(idx, size, data)` | Requires `heap[idx] != NULL`; `size <= 0x78`; `realloc(ptr, size)` |
| 3 Free | `rfree(idx)` | `realloc(heap[idx], 0)` then `heap[idx] = NULL` |
| 4 Exit | | |

## Vulnerabilities

### V1 — `realloc(ptr, 0)` UAF / Dangling Pointer (Primary)

**Root Cause:** The `reallocate` function (menu option 2) calls `realloc(heap[idx], size)`. When `size == 0`, glibc's `realloc` behaves as `free(ptr)` and returns `NULL`. The program checks the return value — since it's `NULL`, it treats this as a "failure" and **does not clear `heap[idx]`**:

```c
// reallocate (simplified)
void *p = realloc(heap[idx], size);
if (p == NULL) {
    // "failure" path — heap[idx] NOT cleared
    return;
}
heap[idx] = p;  // only reached if realloc succeeded
```

In contrast, the clean `rfree` (menu option 3) also calls `realloc(ptr, 0)` but **unconditionally** sets `heap[idx] = 0`.

**Impact:** After `realloc(idx, 0)`, `heap[idx]` holds a dangling pointer to a freed chunk. This enables:
- **UAF write**: `realloc(idx, original_size, data)` writes into the freed chunk (editing its `fd` pointer in tcache).
- **Double-free**: `realloc(idx, 0)` again frees the same chunk a second time (after clearing the tcache `key` field to bypass glibc 2.29's double-free check).

### V2 — Off-by-One NULL in `allocate` (Minor, Enabler)

The `allocate` function's `read_input` appends a NUL byte at `buf[nread]`. When exactly `size` bytes are sent (no newline), this writes a `\x00` one byte past the chunk's usable area — a **poison null byte** that can corrupt the size field of the next chunk.

## Key Constraints

- **Only 2 slots** (`heap[0]`, `heap[1]`) — severely limits heap manipulation. Requires creative use of `realloc` to resize/split/merge chunks.
- **Max size 0x78** — all allocations fit in tcache bins (0x20–0x80). Getting libc pointers requires forcing chunks into unsorted/smallbins.
- **No output primitive** — no "view" or "print" function. Leak must come from FSOP (overwriting `_IO_2_1_stdout_`).
- **Full RELRO** — GOT is read-only. Must target hooks (`__free_hook`, `__malloc_hook`, `__realloc_hook`).
- **glibc 2.29** — tcache has a `key` field for double-free detection (bypass by overwriting it via UAF).

## Key Technique: Tcache Poisoning with 2 Slots

The fundamental write-what-where primitive with only 2 slots:

```python
alloc(0, 0x78)                      # allocate chunk P (tcache bin 0x80)
realloc(0, 0)                       # free P → tcache[0x80] = [P], heap[0] = P (dangling)
realloc(0, 0x78, p64(target_addr))  # UAF write: P.fd = target_addr
alloc(1, 0x78)                      # pop P from tcache; entries[0x80] = target_addr
realloc(1, 0x28)                    # shrink P to 0x30, remainder goes to different bin
free(1)                             # free P(0x30) → tcache[0x30]; heap[1] = NULL
alloc(1, 0x78, payload)             # pops target_addr from tcache[0x80] → write payload there
```

The trick: after popping P, shrink it to a **different size** before freeing, so tcache[0x80]'s head stays pointing at `target_addr`.

## Exploit Paths

All 51 solutions share the same core strategy (V1 UAF → tcache poison → stdout leak → hook overwrite), differing mainly in how they obtain libc pointers.

---

### Path A — Fake Large Chunk → Unsorted Bin → Partial Overwrite stdout (Most Common)

**Used by:** Solutions 821, 2972, 3025, 3148, 6923, 7905, 8153, 9074, 9251, 9448, 15522, 17006, 20719, 26250, 31599, 34817, exp.py

**Steps:**

1. **Craft a fake large chunk** (size `0x421`–`0x811`) by writing a fake size field into an adjacent chunk via `realloc` resizing. The fake chunk must be large enough to bypass tcache (> 0x408 bytes or fill tcache count to 7).

2. **Free the fake chunk** so it enters the **unsorted bin**. This writes `main_arena` pointers (libc addresses) into the chunk's `fd`/`bk` fields.

3. **Partial overwrite** the `fd` pointer (low 2 bytes) to redirect it to `_IO_2_1_stdout_` (or `stdout - 8`). Since libc is page-aligned, the 4th nibble (bits 12–15) is random → **1/16 bruteforce**.

4. **Allocate at stdout** and overwrite its `_flags` to `0xfbad1800` and clear `_IO_read_ptr`, `_IO_read_end`, `_IO_read_base` to zero. The next `puts()` call (menu output) then leaks libc memory.

5. **Compute libc base** from the leak: `libc_base = leaked_ptr - 0x1e7570`.

6. **Tcache poison** a bin to point at `__free_hook - 8` (or `__realloc_hook`). Write `"/bin/sh\0" + p64(system)` there.

7. **Trigger**: `free(idx)` → `realloc(heap[idx], 0)` → `__realloc_hook(heap[idx], 0)` = `system("/bin/sh")`.

**Variant — Fake Chunk via Fill tcache + `malloc_consolidate`:** Some solutions fill the tcache for a given bin size to 7 entries (using repeated `realloc(0)/realloc(size)` UAF), then trigger `malloc_consolidate` by sending a long input (`"1" * 0x400`) to the menu. This merges fastbin chunks into smallbin, providing libc pointers without needing a fake large chunk.

---

### Path B — Tcache `perthread_struct` Poisoning (1/16 or 1/256)

**Used by:** Solutions 821, 3480, 6247, 15522 (1/256 variant), 34817

**Steps:**

1. **Double-free** via UAF to get a tcache chunk whose `fd` can be overwritten.

2. **Partial overwrite `fd`** with `\x10\x60` (or `\x10\x90`, `\x10\xa0` depending on heap layout) to point at the **`tcache_perthread_struct`** (heap offset ~0x10). This is a 1/16 bruteforce on the heap ASLR nibble.

3. **Allocate the tcache struct** as a regular chunk → gain full control over all tcache bin counts and entry pointers.

4. **Set all counts to 0xff** (or 0x07) → freeing any chunk now bypasses tcache and goes to unsorted bin (since tcache appears "full").

5. **Free the tcache struct itself** → goes to unsorted bin → libc pointers land in the struct.

6. **Partial overwrite** the unsorted bin `fd` to point at `_IO_2_1_stdout_` → FSOP leak (another 1/16 bruteforce, making total 1/256 for this path).

7. Same finish as Path A: hook overwrite → shell.

---

### Path C — Fill Tcache via Repeated UAF + Smallbin Consolidation

**Used by:** Solutions 9251, 26250, 34817

A cleaner variant that avoids fake chunk sizes entirely:

1. **Fill tcache** for a specific bin size to 7 entries using repeated `realloc(0)` + `realloc(size)` UAF cycles (each cycle frees the same chunk, but the `key` is cleared between frees).

2. **Trigger `malloc_consolidate`** by sending an oversized menu input (`sla("choice: ", "1"*0x400)`). Fastbin chunks merge into smallbin → libc pointers appear.

3. **UAF edit** the smallbin `fd` → partial overwrite to stdout → FSOP leak.

4. Same finish: hook overwrite → shell.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| UAF / Dangling pointer | V1: `realloc(ptr, 0)` returns NULL, slot not cleared | Deterministic |
| Tcache fd overwrite | UAF + `realloc(idx, size, payload)` | Deterministic |
| Double-free | UAF + clear `key` field + `realloc(idx, 0)` again | Deterministic |
| Unsorted/smallbin libc pointers | Fake large chunk or fill tcache + consolidate | Deterministic (heap groom) |
| Stdout FSOP leak | Partial overwrite fd → `_IO_2_1_stdout_` | **1/16 bruteforce** |
| Tcache struct control | Partial overwrite fd → `tcache_perthread_struct` | **1/16 bruteforce** |
| Arbitrary write | Tcache poisoning with 2-slot shrink trick | Deterministic after leak |
| Code execution | `__free_hook = system` or `__realloc_hook = system/one_gadget` | Deterministic after arb write |

## Offsets (glibc 2.29, Ubuntu 2.29-0ubuntu2)

```python
_IO_2_1_stdout_  = 0x1e5760
_IO_file_jumps   = 0x1e7570   # common leak delta
system           = 0x52fd0
__free_hook      = 0x1e75a8
__realloc_hook   = 0x1e4c28
__malloc_hook    = 0x1e4c30
main_arena_top   = 0x1e4ca0
one_gadgets      = [0xe21ce, 0xe21d1, 0xe21d4, 0xe237f, 0xe2383, 0x106ef8]
```

## Hook Targets Comparison

| Target | How Triggered | Argument |
|--------|--------------|----------|
| `__free_hook` | `rfree(idx)` → `realloc(heap[idx], 0)` internally calls `free()` | `heap[idx]` (set to `"/bin/sh"`) |
| `__realloc_hook` | Any `realloc()` call | `(heap[idx], size)` — first arg is the pointer |
| `__malloc_hook` | `alloc(idx, size)` triggers `malloc()` | `size` argument (less useful) |

Most solutions target `__free_hook - 8` and write `"/bin/sh\0" + p64(system)`, then `free(idx)` calls `system("/bin/sh")`. Some target `__realloc_hook` with a one_gadget instead.

## Solution Write-ups

| File | Path | Bruteforce | Key Technique |
|------|------|-----------|---------------|
| `exp.py` | A | 1/16 | Fake 0x431 chunk → unsorted bin → stdout partial overwrite |
| `821.md` | B | 1/16 | Tcache struct poison → unsorted bin → stdout |
| `1763.md` | A | 1/16 | Minimal tcache poison → stdout |
| `2972.md` | A | 1/16 | Fake 0x4d1 chunk → partial overwrite stdout |
| `3025.md` | A | 1/16 | Fake chunk + partial write `__free_hook` |
| `3148.md` | A | 1/16 | Standard fake chunk + stdout FSOP |
| `3480.md` | B | 1/16 | Tcache struct → unsorted bin → stdout; also 1/256 variant |
| `6247.md` | A | 1/16 | Chunk spray + fake 0x811 → partial overwrite |
| `6249.md` | A | 1/16 | Tcache struct control + fake unsorted chunk |
| `6923.md` | A | 1/16 | Tcache struct + `__free_hook` overwrite |
| `7905.md` | A | 1/16 | Detailed writeup with Chinese analysis; fake 0x431, stdout FSOP |
| `8153.md` | A | 1/16 | Tricks writeup; 1/16 and 1/256 variants documented |
| `9074.md` | A | 1/16 | Fake 0x91/0x81 chunk gymnastics → unsorted bin |
| `9251.md` | A | 1/16 | tcache perthread struct + stdout overwrite |
| `9448.md` | B | 1/256 | Double bruteforce: heap + libc nibbles |
| `15522.md` | B | 1/256 | Tcache struct + unsorted bin + partial write |
| `20719.md` | A | 1/16 | Fake 0xa1 chunk + fill tcache via UAF |
| `26250.md` | C | 1/16 | Solve detailed with 0xe7 stdout offset |
| `31599.md` | A | 1/16 | Clean solve, same struct as 3025 |
| `34817.md` | C | 1/16 | Fill tcache + `malloc_consolidate` via long menu input |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (sockets-only, no pwntools, auto-retry bruteforce) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original binary and libc |
| `solution/*.md` | Community write-ups (51 solutions) |
