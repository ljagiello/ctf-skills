---
tags:
  - off-by-null
  - heap-consolidation
  - fastbin-dup
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "An off-by-null byte in secret note creation allows clearing the prev_inuse bit, triggering backward heap consolidation into an active chunk to overwrite __malloc_hook."
proof-of-concept: no
---

# Secret Of My Heart — pwnable.tw (400 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10302`
>
> Flag: `FLAG{It_just_4_s3cr3t_on_the_h34p}`

## Challenge Overview

A heap menu binary (x86-64, Full RELRO, PIE, NX, Canary) built against glibc 2.23. The player can add, show, and delete "secrets". Each secret metadata struct (0x30 bytes) lives in a random `mmap`'d region (seeded by `srand(time(0))`); its content buffer is `malloc`'d on the main heap. Max content size is 0x100, no edit primitive.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO         # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## Key Data Structures

### Secret Struct (0x30 bytes, in mmap region)

```c
struct heart {            // 0x30 bytes, at mmap'd address
    size_t size;          // +0x00
    char   name[0x20];   // +0x08   read 0x20 bytes, NO NUL terminator
    char  *secret;        // +0x28   malloc(size), on main heap
};
```

The secret metadata array is at a random `mmap`'d address. Up to 100 entries. The `secret` pointer points to a `malloc`'d heap chunk where the actual content is stored.

## Vulnerabilities

### V1 — Off-by-One NULL Byte (Poison Null Byte) — Primary

**Root Cause:** When creating a secret, content is read with `read_n(buf, size)` and then a NUL terminator is placed at `buf[bytes_read]`. If exactly `size` bytes are sent (no trailing newline), `bytes_read == size`, so a NUL byte is written at `buf[size]` — one byte past the allocated region.

```c
// ADD function (decompiled)
chunk[5] = (size_t)malloc(size);
printf("secret of my heart :");
result = (_BYTE *)(chunk[5] + (int)read_F((void *)chunk[5], size));
*result = 0;   // <-- off-by-one NULL at buf[size]
```

**Impact:** When `size == chunksize - 8` (e.g., `size = 0xf8` → chunk `0x100`, or `size = 0x88` → chunk `0x90`), the NUL byte overwrites the **lowest byte of the next chunk's size field**, clearing its `prev_inuse` bit (`0x101 → 0x100`). This is the classic **poison null byte** primitive enabling heap chunk overlapping via backward consolidation.

### V2 — Name Info Leak (Heap Pointer)

**Root Cause:** The `name` field is read with `read_F(name, 0x20)` which does **not** NUL-terminate. The `name[0x20]` buffer is immediately followed by the `secret` pointer (a heap address). `Show` uses `printf("Name : %s\n", name)` which reads past the 0x20 bytes into the heap pointer.

```c
printf("Name : %s\n", (const char *)(unk_202018 + 48LL * idx + 8));
//                     name[0x20] || secret_ptr  ← leaked
```

**Impact:** Fill name with 0x20 non-NUL bytes → `Show` leaks the `secret` heap pointer → **heap base**.

### V3 — Predictable mmap Address (`srand(time(0))`)

**Root Cause:** The secret metadata array address is derived from `rand() & 0xfffff000` seeded with `srand(time(0))`. An attacker can predict this by calling `srand(time(0))` locally at the same time.

```c
srand(time(0));
do { addr = rand() & 0xfffff000; } while (addr <= 0x10000);
secrets = mmap(addr, ...);
```

**Impact:** Knowing the mmap base lets attackers craft fake chunks in the metadata region and perform fastbin attacks targeting it (e.g., overwriting a secret's `secret` pointer to achieve arbitrary read/write).

### V4 — Hidden Command (0x1305)

Sending `4869` (= `0x1305`) as the menu choice prints the mmap base address and exits. Not useful in practice since it terminates the connection, but confirms the mmap address.

## Exploit Paths

All solutions use V1 (poison null byte) for chunk overlapping. They diverge on the specific heap layout, leak strategy, and final hijack target.

---

### Path A — Poison Null Byte → Chunk Overlap → Unsorted Bin Leak → Fastbin Dup → `__malloc_hook`

**Used by:** ~80% of solutions (exp.py, 8153, 13204, 25916, 34817, 37983, 7905, 18331, etc.)

This is the dominant approach:

1. **Leak heap base (V2):** Allocate a secret with name filled to 0x20 bytes. `Show` leaks the adjacent `secret` pointer → derive heap base.

2. **Poison null byte (V1):** Allocate chunks A, B, C in sequence. Free B, then free and re-allocate A with `size = chunksize-8` bytes to trigger the off-by-one NULL, clearing B's `prev_inuse` bit in C's size field. Place a fake `prev_size` in the padding so that `free(C)` triggers backward consolidation, merging C with B and creating a large free chunk that **overlaps** a still-allocated small chunk D (allocated between B and C before freeing).

3. **Leak libc:** The overlapping chunk D's data now coincides with freed unsorted bin metadata. `Show(D)` reads the `fd` pointer → `main_arena + 0x58` → subtract offset → **libc base**.

4. **Fastbin dup / fastbin attack:** Using the overlap, modify a freed fastbin chunk's `fd` to point to `__malloc_hook - 0x23` (the classic 0x7f size trick in glibc 2.23). After two `malloc(0x68)` calls, the third returns a pointer near `__malloc_hook`.

5. **Overwrite `__malloc_hook`:**
   - **Simple:** Write `one_gadget` directly to `__malloc_hook`.
   - **Realloc trick:** Write `one_gadget` to `__realloc_hook` and `realloc + offset` to `__malloc_hook`. When malloc fires, it jumps to realloc which adjusts `rsp` (via extra `push` instructions) before `call __realloc_hook`, satisfying the one_gadget's `[rsp+0x30]==NULL` constraint.

6. **Trigger:** Any operation that calls `malloc` (e.g., add a new secret, or trigger `malloc_printerr` via double-free) → one_gadget → shell.

**Realloc hook trick detail:**

```python
# user data starts at __malloc_hook - 0x13
payload = b'\x00' * 0x0b       # padding to reach __realloc_hook
payload += p64(one_gadget)      # __realloc_hook
payload += p64(realloc + 0xc)   # __malloc_hook
# Flow: malloc → jmp __malloc_hook (= realloc+0xc)
#       → push rbx; sub rsp,0x38; ... call __realloc_hook
#       → one_gadget with adjusted rsp
```

---

### Path B — Poison Null Byte + Predictable mmap (V3) → Fastbin to mmap Region → Arbitrary R/W

**Used by:** Solutions 370, 8, 59, 821, 1303, 2277, 3498, 34817

This variant uses the predictable mmap address to craft fake chunks in the metadata region:

1. **Predict mmap base (V3):** Call `srand(time(0)); rand() & 0xfffff000` locally.

2. **Leak heap base (V2):** Same as Path A.

3. **Poison null byte → overlap:** Same as Path A.

4. **Fastbin attack targeting mmap region:** Point a corrupted fastbin `fd` at the mmap metadata area (which contains the secret structs). After malloc returns a chunk in the metadata region, overwrite a secret struct's `secret` pointer to point at an arbitrary address.

5. **Arbitrary read:** Point `secret` at a heap address containing unsorted bin `fd` → `Show` leaks libc.

6. **Arbitrary write:** Point `secret` at `__malloc_hook`, `__free_hook`, or `__environ` → overwrite or leak as needed.

7. **Hijack:**
   - `__free_hook = system` → free a secret containing `"/bin/sh"`.
   - `__malloc_hook = one_gadget` → trigger malloc.

---

### Path C — Poison Null Byte → Stack Leak via `__environ` → ROP on Stack

**Used by:** Solutions 8, 59, 3498

1. **Same overlap + libc leak** as Path A/B.
2. **Leak stack:** Point a secret's `secret` pointer at `libc.__environ` → `Show` leaks a stack address.
3. **Fastbin attack on stack:** Use the stack address to find a 0x7f byte near the return address of `read_n()`. Place a fake fastbin chunk there.
4. **ROP chain:** Overwrite `read_n()`'s return address with `pop rdi; ret; "/bin/sh"; system`.

---

### Path D — House of Orange / FSOP (`_IO_list_all` overwrite)

**Used by:** Solutions 138, 278, 1006

Instead of targeting hooks, this approach corrupts the `_IO_list_all` / `_IO_2_1_stdout_` vtable:

1. **Same overlap + libc leak.**
2. **Fastbin attack targeting `stdout`:** Overwrite the FILE struct's vtable pointer to a fake vtable on the heap containing `system` or `one_gadget` in the `xsputn` slot.
3. **Trigger:** Any `printf`/`puts` call invokes the corrupted vtable → shell.

Alternatively, corrupt `_IO_list_all` to point to a fake FILE struct on the heap with `system` as the overflow handler, then trigger `malloc_printerr` → `_IO_flush_all_lockp` → shell.

---

### Path E — House of Einherjar (Direct)

**Used by:** Solutions 821, 3498

Uses the poison null byte differently — rather than standard backward consolidation, carefully crafts `prev_size` so that consolidation merges chunks all the way back to a fake chunk placed in the mmap metadata region or at a controlled heap address, allowing direct control of allocations at arbitrary locations.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Off-by-one NULL byte | V1: `buf[size] = 0` in add | Deterministic |
| Heap base leak | V2: name[0x20] not NUL-terminated | Deterministic |
| mmap base prediction | V3: `srand(time(0))` | ~1s timing window |
| Chunk overlapping | V1 + backward consolidation | Deterministic |
| libc leak (unsorted bin fd) | Overlapping chunk reads freed metadata | Deterministic |
| Fastbin dup / poisoning | Overlapping → double view of same chunk | Deterministic |
| `__malloc_hook` write | Fastbin attack to `malloc_hook - 0x23` | Deterministic |
| Code execution | `one_gadget` via `__malloc_hook` or `__free_hook` | Deterministic |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
__malloc_hook   = 0x3c3b10
__realloc_hook  = 0x3c3b08
__free_hook     = 0x3c57a8
__libc_realloc  = 0x83b10
main_arena + 88 = 0x3c3b78   # unsorted bin fd leak value
system          = 0x45390
environ         = 0x3c5f38
bin_sh          = 0x18c177
_IO_list_all    = 0x3c4520
stdout          = 0x3c4620

# Fake fastbin chunk for __malloc_hook
fake_chunk      = __malloc_hook - 0x23   # *(fake+8) = 0x7f from adjacent relocation

# one_gadgets
one_gadgets     = [0x4526a, 0xef6c4, 0xf0567]

# realloc trick offsets (realloc + N skips N bytes of push prologue)
realloc_offsets = [0x0, 0x2, 0x4, 0x6, 0xb, 0xc, 0xd]
# Winning combo: __malloc_hook = realloc+0xc, __realloc_hook = 0x4526a
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | B | mmap predict + fastbin to mmap → vtable attack | `_IO_2_1_stdout_` vtable overwrite |
| `8.md` | B + C | mmap predict + fastbin → environ → stack ROP | Full chain: heap → libc → stack |
| `59.md` | B + C | mmap predict + poison null → environ → stack ROP | Uses numpy for rand prediction |
| `138.md` | D | House of Orange / FSOP via `_IO_list_all` | Ruby exploit; fake FILE struct |
| `278.md` | D | Fastbin → stdout vtable overwrite | Ruby; corrupts `_IO_2_1_stdout_` |
| `550.md` | A | Poison null → overlap → unlink → libc → fastbin → `__free_hook` | Classic unlink + top chunk trick |
| `821.md` | B + E | mmap predict + House of Einherjar → `__free_hook` | Two-script setup for rand server |
| `1006.md` | A | Poison null → overlap → fastbin dup → `__malloc_hook` | Standard with heap leak first |
| `1303.md` | B | mmap predict → fastbin to mmap → `__malloc_hook` | C helper for srand/rand |
| `2277.md` | B | mmap predict → fastbin to mmap → `__free_hook` | Uses unsorted bin attack |
| `3498.md` | B + E | mmap predict + Einherjar → fastbin → `__free_hook` | Detailed struct analysis |
| `7905.md` | A | Poison null → overlap → unlink → libc leak → fastbin → `__malloc_hook` | Clean structured exploit |
| `8153.md` | A | Poison null → overlap → fastbin dup → `__malloc_hook` | Realloc hook trick |
| `13204.md` | A | Poison null → overlap → `__malloc_hook` + one_gadget | Detailed writeup (Chinese) |
| `18331.md` | A | Standard poison null → fastbin → `__malloc_hook` | Concise |
| `25916.md` | A | Poison null → overlap → fastbin → `__malloc_hook` | Double-free trigger |
| `34817.md` | B + A | mmap predict + poison null → fastbin → `__malloc_hook` | Realloc trick |
| `37983.md` | B + E | mmap predict + Einherjar → alloc to mmap → `__malloc_hook` | Realloc trick, detailed comments |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (self-contained, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/secret_of_my_heart` | Original challenge binary (stripped, PIE) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (99 solutions) |
