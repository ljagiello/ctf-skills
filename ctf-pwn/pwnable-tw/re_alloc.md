---
tags:
  - use-after-free
  - tcache-poisoning
  - got-overwrite
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.29
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Passing a zero size to realloc frees the chunk without clearing the pointer, enabling tcache poisoning in glibc 2.29 to overwrite GOT entries with system."
proof-of-concept: no
---

# Re-alloc — pwnable.tw (200 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10106`

## Challenge Overview

A heap menu challenge (x86-64, Partial RELRO, NX, Stack Canary, **No PIE**, FORTIFY) built against **glibc 2.29**. The program provides allocate, reallocate, and free operations on two heap slots (`heap[0]` and `heap[1]`), using `realloc()` as the core allocator. The key insight is that `realloc(ptr, 0)` is equivalent to `free(ptr)` in glibc 2.29, but the program **does not clear the pointer** from the heap table — creating a Use-After-Free.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
  FORTIFY:  Enabled
```

## Program Logic (Pseudocode)

```c
void *heap[2];  // global pointer table at 0x4040B0

void allocate() {
    int idx = read_long();           // idx must be 0 or 1
    if (heap[idx]) { puts("..."); return; }
    long size = read_long();
    heap[idx] = realloc(NULL, size); // equivalent to malloc(size)
    read_input(heap[idx], size);     // read_input has off-by-null
}

void reallocate() {
    int idx = read_long();
    if (!heap[idx]) { puts("..."); return; }
    long size = read_long();
    heap[idx] = realloc(heap[idx], size);  // size=0 → free, but ptr stays!
    if (heap[idx])
        read_input(heap[idx], size);
}

void rfree() {
    int idx = read_long();
    if (!heap[idx]) { puts("..."); return; }
    realloc(heap[idx], 0);   // free, BUT heap[idx] NOT cleared!
    heap[idx] = NULL;        // ... wait, it IS cleared here
}

// read_long uses __read_chk → atoll(buf) to parse integers
```

## Vulnerabilities

### V1 — Use-After-Free via `realloc(ptr, 0)` in Reallocate

**Root Cause:** In glibc 2.29, `realloc(ptr, 0)` frees the chunk and returns `NULL`. In `reallocate()`, the return value (`NULL`) is stored back into `heap[idx]`, zeroing the slot. However, `rfree()` also calls `realloc(ptr, 0)` — the crucial difference is that `reallocate()` **can be called again on the same index** because after the free, `heap[idx] = NULL`, and a subsequent `realloc(NULL, new_size)` is equivalent to `malloc(new_size)`.

The UAF arises from this sequence:
```
alloc(0, 0x18, "AAAA")       // heap[0] = chunk_A
realloc(0, 0)                 // free(chunk_A), heap[0] = NULL
                              // chunk_A is now in tcache[0x20]
realloc(0, 0x18, payload)    // realloc(NULL, 0x18) = malloc(0x18)
                              // returns chunk_A (from tcache)
                              // heap[0] = chunk_A again
                              // payload overwrites tcache fd pointer
```

Since `alloc` checks `if (heap[idx])` to prevent double-allocation, but `realloc(0,0)` clears `heap[idx]`, you can effectively free a chunk while another slot still references the same memory (via careful slot juggling), achieving a classic **tcache poisoning** UAF.

**Impact:** Arbitrary write via tcache fd pointer corruption → write to any address (e.g., GOT entries).

### V2 — `atoll` GOT is Writable (Partial RELRO + No PIE)

**Root Cause:** With Partial RELRO and no PIE, the GOT is at fixed known addresses. The `read_long()` function calls `atoll()` to convert user input strings to integers. By overwriting `atoll@GOT` with `printf@PLT`, every subsequent `read_long()` call becomes `printf(user_input)` — turning integer inputs into **format string attacks**.

```
Key GOT/PLT addresses (fixed, no PIE):
  atoll@GOT   = 0x404048
  printf@PLT  = 0x401070
  realloc@GOT = 0x404058
  heap table  = 0x4040B0
```

### V3 — Off-by-Null in `read_input` (Minor)

The `read_input` function null-terminates at `buf[size]`, writing one byte past the allocated region. This is generally not needed for the primary exploit but noted by some solvers.

## Exploit Paths

All solutions follow a two-phase strategy: (1) use tcache poisoning to overwrite GOT, (2) leverage the GOT overwrite for leaks and shell.

---

### Path A — Tcache Poison → `atoll@GOT = printf` → Format String Leak → `atoll@GOT = system` → `system("/bin/sh")`

**Used by:** ~90% of solutions (1006, 1832, 16991, 17048, 17704, 18324, 18331, 18416, 19131, 21490, 21778, 22377, 25572, 26467, 28302, exp.py)

**Phase 1: Tcache Poisoning to Overwrite `atoll@GOT`**

1. Allocate a chunk on slot 0, free it via `realloc(0, 0)`, then `realloc(0, same_size, p64(atoll_got))` to overwrite the tcache fd pointer with `atoll@GOT`.
2. Allocate on slot 1 to consume the original chunk from tcache.
3. Clean up both slots (realloc to different sizes + free to move chunks to other bins).
4. Now tcache for that size class has `atoll@GOT` as the next entry.
5. Allocate again — the second allocation from this tcache returns a pointer to `atoll@GOT`.
6. Write `printf@PLT` (0x401070) to `atoll@GOT`.

Many solutions repeat this for **two different size classes** (e.g., 0x20 and 0x50 tcache bins) to have a clean second overwrite available later.

**Phase 2: Format String Leak**

With `atoll@GOT` pointing to `printf`, every `read_long()` call now executes `printf(user_input)`:
```python
# Trigger printf as "atoll" — leak libc via format string
free("%3$p")       # printf("%3$p") leaks a stack value
# or
free("%21$p")      # leaks __libc_start_main return address
# or
free("%23$p")      # another common offset for libc leak
```

Common leak offsets from the stack:
- `%3$p` → `__read_chk` return (offset `0x12e009` from libc base)
- `%21$p` / `%23$p` → `__libc_start_main+235` (offset `0x26b6b` from libc base)
- `%9$s` + GOT address → arbitrary read via `%s` format

**Phase 3: Overwrite `atoll@GOT` with `system`**

After leaking libc, overwrite `atoll@GOT` again with `system()`:

```python
# Since atoll is now printf, we need to carefully craft inputs
# that make printf return the right values for idx/size
alloc("", "%88c", p64(libc.sym['system']))  # or similar trick
```

The tricky part: `printf` is now the index/size parser, so its **return value** (number of chars printed) becomes the parsed integer. Solvers use format strings of specific lengths to control the "index" and "size" values.

**Phase 4: Shell**

```python
# Any call to read_long() with "/bin/sh" now calls system("/bin/sh")
free("/bin/sh")   # → system("/bin/sh")
```

---

### Path B — Tcache Poison → `realloc@GOT = printf` → Format String → ROP

**Used by:** Solutions 1006 (variant), 27939

Instead of overwriting `atoll@GOT`, overwrite `realloc@GOT` with `printf@PLT`. This makes every `reallocate()` call a format string attack, but requires more complex control flow since `realloc` is called with the heap pointer as the first argument (acting as the format string).

Some solutions overwrite `realloc@GOT` with `atoll@PLT` (making realloc return a pointer based on the ASCII content at the heap address), enabling creative GOT pivoting.

One advanced variant (27939) uses this to pivot the stack via `leave; ret` gadgets and execute a full ROP chain.

---

### Path C — Tcache Poison → GOT Overwrite → `__malloc_hook = one_gadget`

**Used by:** Solutions 18331, 18324

After the initial `atoll → printf` overwrite, use `%n` format string writes to overwrite `__malloc_hook` with a one_gadget address. This avoids needing a second tcache poison:

```python
# Use %hn writes to set __malloc_hook byte-by-byte
free("%{}c%{}$hn".format(low_2bytes, offset))   # write 2 bytes at a time
```

Then trigger `malloc` to jump to the one_gadget.

---

### Path D — `atoll → printf` + `%n` to Clear Heap Table → Second Tcache Poison

**Used by:** exp.py (provided exploit)

1. First tcache poison: `atoll@GOT = printf@PLT`.
2. Use `printf("%9$n", ...)` format strings to **zero out** the `heap[0]`/`heap[1]` table entries and tcache metadata, resetting the allocator state.
3. Perform a **second** tcache poison (now with `printf` as `atoll`, using raw bytes for index/size).
4. Overwrite `atoll@GOT` with `system`.
5. `free("/bin/sh")` → `system("/bin/sh")`.

This approach is more complex but fully deterministic since it doesn't rely on `printf` return value tricks.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Use-After-Free | V1: `realloc(ptr, 0)` in reallocate | Deterministic |
| Tcache fd poisoning | UAF → overwrite freed chunk's fd | Deterministic |
| Arbitrary GOT write | Tcache returns pointer to GOT | Deterministic (no PIE) |
| Format string (leak) | `atoll@GOT = printf` → `printf(user_input)` | Deterministic |
| Format string (write) | `%n` / `%hn` writes via printf | Deterministic |
| Code execution | `atoll@GOT = system` → `system("/bin/sh")` | Deterministic |

## Key Addresses (No PIE)

```python
# Binary (fixed)
atoll_got    = 0x404048
printf_plt   = 0x401070
printf_got   = 0x404038
realloc_got  = 0x404058
alarm_got    = 0x404040
heap_table   = 0x4040B0   # heap[0], heap[1]

# Libc offsets (glibc 2.29, pwnable.tw)
__libc_start_main = 0x26B6B   # offset for %21$p leak
__read_chk_ret    = 0x12E009  # offset for %3$p leak
system            = 0x52FD0
__malloc_hook     = 0x1E4C30
__free_hook       = 0x1E6E48
one_gadgets       = [0xE6E73, 0xE6E76, 0xE6E79, 0x106EF8]
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `1006.md` | A | tcache poison → printf → one_gadget via realloc GOT | Uses GOT table as format string buffer |
| `1763.md` | — | "Same exploit with re-alloc-revenge" | Reference only |
| `1832.md` | A | tcache poison → printf leak → system | Clean approach with `%15$p` leak |
| `16609.md` | A | prepare() helper for clean tcache state | Well-structured helper functions |
| `16991.md` | A | Two-bin tcache poison + `%9$s` GOT read | Reads GOT entries directly via `%s` |
| `17048.md` | B | Overwrites alarm/atoll/signal/realloc GOT simultaneously | Creative multi-GOT overwrite |
| `17704.md` | A | `atoll → printf`, `%15$p` leak, system overwrite | Compact; overwrites realloc GOT to regain control |
| `18324.md` | A+C | `%n` format writes to `__malloc_hook` | Byte-by-byte one_gadget write |
| `18331.md` | A | Concise vuln analysis + exploit | Notes off-by-null and UAF |
| `18416.md` | A | Two-size-class tcache poison | Double tcache attack for 0x20 and 0x50 bins |
| `19131.md` | A | `%9$s` to read GOT, then system | Direct GOT leak via format string |
| `21490.md` | A | Standard approach | Clear code |
| `21778.md` | A | Notes "preparation" difficulty | Honest about copying the tcache setup |
| `22377.md` | A | Two-bin poison (0x30 + 0x60) | `%3$p` leak at offset 0x12e009 |
| `25572.md` | A | Stack leak enumeration loop | Scans all stack offsets to find libc |
| `26467.md` | A | `%p` chain leak, `%15c` for size control | Minimal approach |
| `27939.md` | B | GOT pivot + stack pivot + ROP chain | Most complex; full ROP via leave/ret |
| `28302.md` | A | Format string GOT overwrite + `%n` | Detailed stack offset analysis |
| `exp.py` | D | `%n` to clear state → second tcache poison | Most robust; fully deterministic |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (tcache poison + fmt string + second poison) |
| `desc.txt` | Challenge description |
| `artifacts/re-alloc` | Challenge binary (x86-64, glibc 2.29) |
| `solution/*.md` | Community write-ups (83 solutions) |
