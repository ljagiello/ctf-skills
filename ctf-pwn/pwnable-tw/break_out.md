---
tags:
  - use-after-free
  - information-leak
  - fastbin-dup
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
description: "A use-after-free in cell note management allows leaking heap and libc pointers, followed by fastbin duplication to overwrite __malloc_hook."
proof-of-concept: no
---

# Break Out — pwnable.tw (350 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10400`

## Challenge Overview

A prison management binary (x86-64, PIE, Full RELRO, NX, Stack Canary) built against glibc 2.23 (no tcache). It loads a prisoner database from a colon-separated file, and provides commands to `list` prisoners, write a `note` for a prisoner (using `realloc`), and `punish` a prisoner (frees the note). The key defense mechanism is `secure_read()`: it parses `/proc/self/maps` at startup to build a whitelist of writable regions, and every `read()` into a note buffer is validated against this whitelist — only writes into the **[heap]** region are permitted. This means a naive heap overflow can never directly touch libc/GOT/hooks.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

Two binaries are provided: `breakout` (the main binary) and `prisoner` (the database file).

## Key Data Structures

### Prisoner Struct (0x40 bytes, linked list)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `risk` | `char *` (points to static string) |
| `0x08` | `name` | `char *` |
| `0x10` | `nickname` | `char *` |
| `0x14` | `age` | `int32_t` |
| `0x18` | `cell` | `int32_t` |
| `0x20` | `sentence` | `char *` |
| `0x28` | `note_size` | `int32_t` |
| `0x2c` | `pad` | `int32_t` |
| `0x30` | `note` | `char *` (realloc'd) |
| `0x38` | `next` | `struct prisoner *` |

Prisoners are stored in a singly-linked list. The `note` command calls `realloc(prisoner->note, size)` and writes into it via `secure_read`. The `punish` command calls `free(prisoner->note)` **without clearing the pointer** — classic dangling pointer.

### Whitelist (`secure_read` defense)

At startup, `secure_self()` parses `/proc/self/maps` and stores the `[heap]` region's base and end in BSS globals (`dst_whitelist`). Every `secure_read()` call validates that the destination buffer falls within this range. This prevents direct writes to libc, stack, or BSS.

## Vulnerabilities

### V1 — Use-After-Free / Dangling Pointer in `punish`

**Root Cause:** `punish(cell)` calls `free(prisoner->note)` but does **not** set `prisoner->note = NULL` or `prisoner->note_size = 0`.

**Impact:**
- **UAF read:** After freeing, `list` still prints the note content, leaking heap metadata (fd/bk pointers from freed chunks).
- **UAF write via realloc overlap:** Since the struct pointer array and note buffers are both on the heap, `realloc` on one prisoner's note can allocate memory overlapping a freed prisoner struct, giving full control over another prisoner's fields (name, note pointer, next pointer, note_size).

### V2 — Fake Prisoner via `next` Pointer Manipulation

**Root Cause:** After achieving V1 overlap, an attacker can set a prisoner's `next` pointer to any heap address containing controlled data. The `list` command follows the linked list and prints fields from the fake prisoner, including its `note` pointer (used for reading) and `name`/`risk` (used for display — leak primitives).

**Impact:** By pointing `next` at a crafted fake prisoner struct:
- Set `note` to an arbitrary address → `list` leaks its contents
- Set `note_size` to a controlled value → subsequent `note` command writes to the arbitrary `note` address
- This yields **arbitrary read/write within the heap**, and with further tricks, outside it.

## Exploit Paths

All solutions start with V1 (UAF) to gain heap control, then diverge on how they **bypass `secure_read`** to write outside the heap.

---

### Path A — Unsorted Bin Attack → Overwrite `dst_whitelist` → `__realloc_hook` = `system`

**Used by:** Solutions 59, 278, 408, exp.py variant

**Steps:**

1. **Leak heap base:** Free a prisoner struct via `punish`, then use `note` on another prisoner to allocate into the freed struct. `list` reveals heap pointers from the overlapping struct fields.

2. **Leak PIE base:** Use the fake prisoner technique (V2) to read the `risk` field of a known prisoner — it points to a string in the binary like `"High"` at a known offset → PIE base.

3. **Leak libc base:** With PIE base, point the fake prisoner's `note` at a GOT entry (e.g., `got["mprotect"]`) → `list` leaks the resolved address → libc base.

4. **Bypass `secure_read` via unsorted bin attack:**
   - Forge a fake prisoner whose `next` points into BSS near `dst_whitelist`.
   - Use the unsorted bin attack (overwrite unsorted bin chunk's `bk` to `&dst_whitelist - 0x10`) to write a `main_arena` address over `dst_whitelist`.
   - Now `secure_read` thinks the entire libc data section is writable.

5. **Overwrite `__realloc_hook`:** Point a fake prisoner's `note` at `__realloc_hook`, write `system` via `note`.

6. **Trigger:** A prisoner whose note contains `"/bin/sh\0"` — calling `realloc` on it invokes `__realloc_hook(system)` → shell.

---

### Path B — House of Orange (FSOP via `_IO_list_all`)

**Used by:** Solutions 57, 186, 1303, 1980, 2233, 2972, 3025, 3917, 8153, 9251

**Steps:**

1. **Leak heap + libc:** Same as Path A steps 1-3 (UAF overlap → fake prisoner → read pointers).

2. **Forge unsorted bin chunk on heap:** Use the fake prisoner's `note` write to craft a fake unsorted bin chunk with:
   - `fd = 0` (crash unsorted bin iteration)
   - `bk = &_IO_list_all - 0x10` (unsorted bin attack target)
   - Size field set to `0x61` (matches smallbin[4])
   - First 8 bytes = `"/bin/sh\0"`

3. **Craft fake `_IO_FILE_plus` struct:** Embedded after the chunk header:
   - `_IO_write_ptr > _IO_write_base` (triggers overflow path)
   - `_mode = 0` or `_mode = -1`
   - `vtable` → points to fake vtable on heap
   - Fake vtable's `__overflow` slot → `system`

4. **Trigger:** Any `malloc` that sorts the unsorted bin (or `exit()`) → glibc iterates `_IO_list_all` → finds the fake FILE → calls `vtable->__overflow(file)` → `system("/bin/sh")`.

**Note:** This only requires heap writes, so it completely bypasses `secure_read` — no need to corrupt the whitelist.

---

### Path C — Fastbin Attack → `__malloc_hook` Overwrite

**Used by:** Solutions 6923, 21490, 31599, exp.py

**Steps:**

1. **Leak heap + libc:** Same UAF techniques.

2. **Fastbin grooming:** Create overlapping chunks via the fake prisoner note pointer manipulation. Free a `0x70`-sized chunk, then use the write primitive to overwrite its `fd` pointer to `__malloc_hook - 0x23` (the classic glibc 2.23 `0x7f` fake-size trick).

3. **Allocate through the fastbin:** Two `malloc(0x60)` calls — the second returns the fake chunk at `__malloc_hook - 0x23`.

4. **Write the hooks:** Pad 0x13 bytes to reach `__realloc_hook`, then write:
   - `__realloc_hook = one_gadget` (e.g., `0xf0567`)
   - `__malloc_hook = __libc_realloc + 0xb` (the `push rbp` entry, which adjusts the stack so `[rsp+0x70] == NULL` for the one_gadget constraint)

5. **Trigger:** Next `malloc` → `__malloc_hook` → `realloc(+0xb)` → `__realloc_hook` → one_gadget → shell.

**Whitelist bypass:** The key insight is that `realloc` first copies old content to the new chunk. By pre-placing the payload in the old note (which is on the heap, passing `secure_read`), then triggering `realloc` to a size that allocates at `__malloc_hook`, the copy operation writes the payload into libc memory — bypassing `secure_read` because `realloc`'s internal `memcpy` doesn't go through the whitelist check.

---

### Path D — `_IO_file_jumps` / stdout vtable Overwrite

**Used by:** Solutions 363, 786

**Steps:**

1. **Leak libc:** Via UAF + fake prisoner reading.

2. **Forge a fake prisoner** whose `next` points to `_IO_file_jumps(stdout) - 0x30` in libc. This overlaps the fake prisoner's `note_size`/`note` fields with the stdout vtable pointer area.

3. **Overwrite the vtable pointer** of `stdout` to point to a heap-controlled fake vtable where the `__xsputn` or `__overflow` slot is set to a one_gadget or `system`.

4. **Trigger:** Any `puts`/`printf` output (e.g., `list`) uses the corrupted vtable → shell.

---

### Path E — Large Bin Attack → `_dl_open_hook` + ROP

**Used by:** Solution 8033

**Steps:**

1. **Leak all addresses:** heap, PIE, libc via standard UAF chain.

2. **Large bin attack:** Create large bin chunks, then corrupt the `bk_nextsize` of a large bin chunk to point to `_dl_open_hook - 0x10`. On the next large bin insertion, `_dl_open_hook` is overwritten with a heap address.

3. **Prepare ROP chain on heap:** Use `setcontext+53` as a stack pivot gadget, with a ROP chain calling `execve("/bin/sh", NULL, NULL)`.

4. **Trigger `abort`:** Corrupt a chunk's metadata to cause a glibc assertion failure → `abort()` → uses `_dl_open_hook` → jumps to heap → stack pivot → ROP chain → shell.

---

### Path F — `__free_hook` via `note_size = malloc_size` Trick

**Used by:** Solution 3917

**Steps:**

1. **Forge a fake prisoner** whose `next` points to `__free_hook - 0x28`. In the fake prisoner layout, the `note_size` field overlaps with the upper bytes of `__free_hook`, and the `note` field overlaps with `__free_hook`.

2. **Write `one_gadget` to `__free_hook`** by calling `note` on the fake cell — `realloc` is called with `size = note_size` (which is the upper bits of the hook address, interpreted as an integer). This causes a large allocation → the old note is freed → `__free_hook` triggers.

3. **Alternative:** Write the one_gadget address 2 bytes at a time by using `note(cell, oneshot_low16, "A")` which calls `realloc(note, low16)` — the size IS the address fragment, written into `note_size` at the position overlapping `__free_hook`.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Heap pointer leak | V1: UAF + `list` reads freed chunk metadata | Deterministic |
| PIE base leak | V2: Fake prisoner `risk`/`name` → binary string pointer | Deterministic |
| libc leak | V2: Fake prisoner `note` → GOT entry, or unsorted bin fd/bk | Deterministic |
| Arbitrary heap R/W | V2: Fake prisoner with controlled `note`/`note_size` | Deterministic |
| Whitelist bypass (House of Orange) | Path B: Only needs heap writes, no whitelist corruption | ~50% (heap alignment) |
| Whitelist bypass (unsorted bin attack) | Path A: Overwrites `dst_whitelist` in BSS | Deterministic |
| Whitelist bypass (fastbin + realloc copy) | Path C: `realloc` memcpy bypasses `secure_read` | Deterministic |
| Code execution | `__realloc_hook`/`__malloc_hook`/`__free_hook` or FSOP | Deterministic after bypass |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
__malloc_hook  = 0x3c3b10
__realloc_hook = 0x3c3b08
__free_hook    = 0x3c57a8
_IO_list_all   = 0x3c4520
system         = 0x45390
one_gadgets    = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# realloc + 0xb (push rbp trampoline for one_gadget stack fix)
realloc_tramp  = 0x83b1b
# Binary offsets
str_High       = 0x1c28       # "High" string in .rodata
whitelist_bss  = 0x203030     # dst_whitelist pointer in .bss
got_mprotect   = 0x202ed8
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `57.md` | B (House of Orange) | UAF → fake prisoner → forge unsorted bin → FSOP | Needs negative libc base low bits |
| `59.md` | A (Unsorted bin) | UAF → leak all → unsorted bin overwrites whitelist → `__realloc_hook` | Detailed bug explanation |
| `186.md` | B (House of Orange) | Simple House of Orange via heap-only writes | Retry loop for reliability |
| `278.md` | A (Unsorted bin) | Ruby exploit; UAF → whitelist bypass → `__realloc_hook = system` | Clean struct manipulation |
| `363.md` | D (stdout vtable) | Overwrite `_IO_file_jumps` ptr of stdout → one_gadget | No heap tricks needed |
| `408.md` | A (Unsorted bin) | UAF → unsorted bin `bk` → whitelist → `__realloc_hook` | Heap massage for binmap |
| `786.md` | D (stdout vtable) | Fake prisoner `next` → libc FILE vtable area → one_gadget | Application-logic only |
| `1303.md` | B (House of Orange) | Full FSOP with detailed fake `_IO_FILE_plus` layout | Remote heap offset pain |
| `1980.md` | C (Fastbin) | UAF → stack leak → PIE leak → fastbin attack → one_gadget | Leaks via `environ` |
| `2121.md` | C (Fastbin) | Classic fastbin to `__malloc_hook - 0x23` | Standard 0x7f trick |
| `2233.md` | B (House of Orange) | Unsorted bin → `_IO_list_all` → FSOP → `system("/bin/sh")` | |
| `2972.md` | B (House of Orange) | Compact House of Orange implementation | |
| `3025.md` | B (House of Orange) | "ez challenge, hard to get shell in remote env" | Remote heap offset issues |
| `3917.md` | F (`__free_hook`) | Fake prisoner `next` → `__free_hook - 0x28` → write one_gadget 2 bytes at a time | Creative `note_size` abuse |
| `6923.md` | C (Fastbin) | UAF → overlapping chunks → fastbin fd → `__malloc_hook` → one_gadget | |
| `8033.md` | E (Large bin) | Large bin attack → `_dl_open_hook` → `setcontext` stack pivot → ROP | Most complex path |
| `8153.md` | B (House of Orange) | FSOP with `_IO_list_all` | Chinese writeup |
| `9251.md` | B (House of Orange) | UAF → fake prisoner → House of Orange FSOP | |
| `13344.md` | B (House of Orange) | FSOP via fake FILE; leak all via `environ` | Clean Python3 exploit |
| `21490.md` | C (Fastbin) | Fastbin + realloc copy bypass of `secure_read` | `realloc`'s `memcpy` is the key |
| `31599.md` | C (Fastbin) | UAF → fastbin → `__malloc_hook` → `realloc_tramp` + one_gadget | Standard hook chain |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (fastbin + realloc hook chain) |
| `desc.txt` | Challenge description |
| `artifacts/breakout` | Challenge binary (stripped, PIE) |
| `artifacts/prisoner` | Prisoner database file |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (72 solutions) |
