---
tags:
  - stack-exhaustion
  - heap-overlap
  - arbitrary-write
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
description: "Exhausting mmap-allocated split-stack segments forces libgcc morestack to overlap dynamic stack allocations with heap buffers, enabling return address overwrite."
proof-of-concept: no
---

# BabyAllocator — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10404`
>
> Flag: `FLAG{Spl1t_st4ck_spl1t_h34p_th3n_spl1t_7h3_sh3ll}`

## Challenge Overview

A stripped x86-64 binary compiled with GCC's **`-fsplit-stack`** feature, linked against glibc 2.23. The split-stack mechanism uses `__morestack` / `__morestack_allocate_stack_space` from `libgcc/generic-morestack.c` to dynamically allocate stack segments via `mmap` when the current segment is exhausted. The binary presents a menu-driven "allocator" interface:

1. **Allocate on stack** — `alloca()` with size `[0x80, 0xFFF]`, reads a 15-byte name via `scanf("%15s")`
2. **Allocate on heap** — `malloc()` with size `> 0xFF`, reads a 15-byte name
3. **Write data** — writes to the current allocation buffer
4. **New allocator** — recursive call into the menu function (pushes a new stack frame, possibly triggering `__morestack` to allocate a new stack segment)
5. **Release** — returns from the current recursive call (pops back to the previous frame/segment)
6. **Exit**

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO            # GOT not writable
  Stack:    No canary
  NX:       NX enabled
  PIE:      No PIE (base 0x3fe000/0x400000)
```

## Vulnerabilities

### V1 — `scanf` Corrupts Split-Stack Segment Metadata (Primary, Exploitable)

**Root Cause:** The split-stack mechanism stores per-segment metadata (a `struct stack_segment`) at the base (lowest address) of each mmap'd stack page. When libc functions like `__isoc99_scanf` are called, they are **not compiled with `-fsplit-stack`** and are unaware of the split-stack segment boundaries. `scanf`'s large local variables (internal buffers, `_IO_FILE` pointers to `stdin`/`stdout`) can underflow past the current stack frame and **overwrite the `struct stack_segment` header** at the page base.

```c
// From gcc/libgcc/generic-morestack.c
struct stack_segment {
    struct stack_segment *next;    // +0x00
    struct stack_segment *prev;    // +0x08
    size_t size;                   // +0x10
    void *old_stack;               // +0x18
    void *old_stack_limit;         // +0x20
    struct dynamic_allocation_blocks *free_dynamic_allocation;  // +0x28
    ...
};

struct dynamic_allocation_blocks {
    struct dynamic_allocation_blocks *next;
    size_t size;
    void *block;   // <-- returned by __morestack_allocate_stack_space
};
```

**Trigger:** By carefully controlling recursion depth (option 4) and `alloca` sizes (option 1), the attacker positions `$rsp` so that when `scanf` is called during the next `alloca`, its internal local variables land exactly on top of the `stack_segment` header. Key corruptions:

- **`free_dynamic_allocation`** (`+0x28`) gets overwritten with a pointer to `_IO_2_1_stdin_` (a libc address left on the stack by `scanf`'s internals).
- **`size`** (`+0x10`) gets overwritten with a large value, or **`prev`**/**`next`** pointers are corrupted.

**Impact:** On the next call to `__morestack_allocate_stack_space`, it checks `free_dynamic_allocation`. Since this now points to `stdin`, it interprets `stdin`'s fields as a `dynamic_allocation_blocks` struct:
- `stdin->_flags` (0xfbad208b) → `.next`
- bytes at `stdin+0x08` → `.size` (some large value)
- bytes at `stdin+0x10` → `.block` (an address near `_IO_2_1_stdin_+0x84..0x90`)

If `.size >= requested_size`, it returns `.block` — giving the attacker **a write primitive into libc's `_IO_2_1_stdin_` structure** and surrounding memory (including `__malloc_hook`, `__free_hook`, and `_IO_2_1_stdout_`).

### V2 — `scanf` Corrupts Segment `prev`/`next` Pointers (Alternative Corruption Target)

Same root cause as V1, but different fields are targeted. By adjusting the stack alignment differently, `scanf`'s local variables can overwrite:

- **`prev`** — causes `release()` to pop to a wrong segment, potentially one whose content the attacker controls
- **`next`** — causes subsequent segment pushes to use a fake segment header
- **`size`** — inflates the segment size, allowing subsequent `alloca` to return a pointer past the segment boundary into older stack frames

### V3 — Segment Size Corruption → Stack Frame Overlap (Alternative)

If `scanf` overwrites the `size` field of a segment to a very large value, then on returning to that segment, `alloca` can allocate beyond the real segment boundary. This overlaps with **older stack frames** from previous recursion levels, allowing the attacker to overwrite saved return addresses → ROP.

## Key Data Structures

### `struct stack_segment` (at base of each mmap'd stack page)

| Offset | Field | Description |
|--------|-------|-------------|
| `+0x00` | `next` | Next segment in linked list |
| `+0x08` | `prev` | Previous segment |
| `+0x10` | `size` | Usable size of this segment |
| `+0x18` | `old_stack` | Saved RSP from before segment switch |
| `+0x20` | `old_stack_limit` | Saved stack limit |
| `+0x28` | `free_dynamic_allocation` | Linked list of dynamically allocated blocks |

### `struct dynamic_allocation_blocks` (pointed to by `free_dynamic_allocation`)

| Offset | Field | Description |
|--------|-------|-------------|
| `+0x00` | `next` | Next block in free list |
| `+0x08` | `size` | Size of this block |
| `+0x10` | `block` | Pointer returned by `__morestack_allocate_stack_space` |

## Exploit Paths

---

### Path A — `free_dynamic_allocation` → `stdin` → Write `__malloc_hook` / FSOP

**Used by:** exp.py, solutions 1351, 1980, 8153, 31599, 32010, 35917, 37983

**Steps:**

1. **Deep recursion** to push RSP onto mmap'd stack segments (3× `alloca(0xFFF)` + many `recurse()`).
2. **Precise `alloca` size** positions RSP so `scanf`'s locals overwrite `free_dynamic_allocation` with `&_IO_2_1_stdin_`.
3. **`release()` + `alloca(large)`** — the corrupted `free_dynamic_allocation` makes `__morestack_allocate_stack_space` return `stdin+0x90` (or similar offset), giving a **write primitive into libc data**.
4. **Overwrite `_IO_2_1_stdout_`** to craft a stdout FILE struct with `_IO_write_base` pointing to a GOT entry → stdout flush leaks a resolved libc address → **libc base**.
5. **Overwrite `stdin` vtable** pointer to a fake vtable where `__underflow` = `one_gadget`.
6. **Trigger `scanf`** (recurse + option 1) → `__uflow` dispatches through fake vtable → **shell**.

**Variant (31599, 32010, 35917):** Instead of vtable hijack, overwrite `__malloc_hook` with `one_gadget` or a `puts` gadget. Trigger via `malloc()` (option 2, heap allocation). Some solutions use `__malloc_hook → puts_gadget` for a two-stage leak, then rewrite `__malloc_hook → one_gadget`.

**Reliability:** Deterministic once the correct recursion depth and alloca sizes are found. The offset calibration differs between local and remote (usually a small constant adjustment).

---

### Path B — Segment `size` / `prev` Corruption → Stack Frame Overlap → ROP

**Used by:** Solutions 59, 363, 550, 821, 1194, 1458, 1980, 2673, 5586, 6748, 9251, 10102, 14523, 26957

The most common approach. Instead of targeting `free_dynamic_allocation`, this path corrupts segment metadata to achieve a **stack buffer overflow** in a previous frame.

**Steps:**

1. **Create adjacent stack segments** through careful recursion and `alloca` patterns. Optionally interleave large `malloc` (heap) allocations to control mmap layout and create gaps.
2. **Trigger `scanf` corruption** of the segment's `size` field (inflated) or `prev` pointer (redirected).
3. **Return to the corrupted segment** via repeated `release()`. The inflated `size` means subsequent `alloca` in that frame can write **past the real segment boundary** into an older frame's stack.
4. **Overwrite saved RBP/RIP** of a return frame with a **ROP chain**.
5. **ROP to leak libc** (e.g., `puts(GOT_entry)` or `write(1, GOT_entry, 8)`) → compute libc base.
6. **Second ROP stage**: `read` into BSS → `system("/bin/sh")`, or `mprotect` + `read` shellcode → jump to shellcode, or direct `one_gadget`.

**Common ROP gadgets (No PIE binary):**
```python
pop_rdi     = 0x40194e
pop_rsi     = 0x4016df
pop_rdx_rax = 0x4026c5  # pop rdx; pop rax; add rsp, 8; pop rbp; ret
mprotect    = 0x400e98   # PLT
read_plt    = 0x400e48
puts_plt    = 0x400e10
write_plt   = 0x400e18
```

**Variant (821, "memory gap"):** Create stacks A–D, use mmap'd heap to create a gap between segments, free the heap to leave the gap, allocate new segments into the gap at higher addresses, use `scanf` to corrupt the lower segment's `size`, then overflow downward into older frames.

**Variant (14523, "fake prev"):** Overwrite segment A's `prev` pointer to point to a fake segment header between A and B. The fake header's `prev` is partially overwritten (1/16 brute force) to point to segment D. Popping through the fake chain skips segments, landing in C where the attacker can overwrite return addresses.

**Reliability:** Most variants are deterministic. Solution 14523 requires 1/16 brute force for partial `prev` overwrite.

---

### Path C — TLS Corruption → `_call_tls_dtors` Hijack

**Used by:** Solution 9251

An exotic path that targets the thread-local storage (TLS) area adjacent to stack segments:

1. **Position stack segments adjacent to `fs_base`** (TLS segment) via deep recursion.
2. **Corrupt `fs:[-0x108]`** (a `__call_tls_dtors` linked list pointer) with a stack address pointing to attacker-controlled data.
3. **Corrupt `fs:[0x30]`** (the pointer guard used for `PTR_DEMANGLE`) with `value ^ read_gadget_addr`.
4. **Call `exit()`** (via invalid input to size prompt) → `_call_tls_dtors` → demangled function pointer → `read` gadget → reads ROP chain from socket → `puts(GOT)` → libc leak → `system("/bin/sh")`.

**Reliability:** ~15/16 (depends on libc address not having 0xf nibble at a specific position).

---

### Path D — Heap Spray + `__malloc_hook` Overwrite

**Used by:** Solution 8153

1. **Spray heap** with 0xFF large `malloc(0x20000)` allocations, each filled with `p64(target_gadget)` to create a "gadget sled" in memory.
2. **Trigger `scanf` corruption** to get a write pointer near `stdin`.
3. **Overwrite `__malloc_hook`** with address of a `puts` gadget via the write primitive.
4. **Trigger malloc** with `size = GOT_entry` → `puts(GOT_entry)` leaks libc.
5. **Overwrite `__malloc_hook`** with `one_gadget` → trigger `malloc` → shell.

**Reliability:** ~1/32 (heap spray hit probability for landing in correct page).

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| `scanf` corrupts segment metadata | V1: split-stack + libc stack usage | Deterministic with correct depth/size |
| Write into `stdin`/`stdout`/hooks | V1 → `free_dynamic_allocation` = `&stdin` | Deterministic |
| Stack frame overlap (ROP) | V2/V3: corrupted `size`/`prev` | Deterministic (most variants) |
| libc leak via stdout FSOP | Crafted stdout `_IO_write_base` = GOT | Deterministic |
| libc leak via `puts(GOT)` ROP | Stack overlap → ROP chain | Deterministic |
| Code execution | `one_gadget` / `__malloc_hook` / ROP → `system` | Deterministic |
| TLS hijack | Stack-adjacent-to-TLS corruption | ~15/16 |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
# Binary (No PIE)
pop_rdi         = 0x40194e
pop_rsi         = 0x4016df
pop_rdx_rax     = 0x4026c5   # pop rdx; pop rax; add rsp, 8; pop rbp; ret
pop_rsp_r13     = 0x401ee1
mprotect_plt    = 0x400e98
read_plt        = 0x400e48
puts_plt        = 0x400e10
write_plt       = 0x400e18
GOT_puts        = 0x603f40

# libc
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
system          = 0x45390
__malloc_hook   = 0x3c3b10
__free_hook     = 0x3c57a8
stdin           = 0x3c38e0   # _IO_2_1_stdin_
stdout          = 0x3c4620   # _IO_2_1_stdout_
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | B | Brute-force stack alignment → ROP | "Solved with pure luck"; later understood scanf corruption |
| `363.md` | B | mprotect + read shellcode → ROP | "I don't understand my solution" |
| `550.md` | B | `free_dynamic_allocation` → stack addr → ROP | Clear explanation of the core vulnerability |
| `821.md` | B | Memory gap trick → stack overlap → ROP + one_gadget | Detailed mmap layout manipulation |
| `1194.md` | B | scanf fake `heap_alloca` buffer → ROP | Uses `ret2csu` for clean ROP |
| `1351.md` | B | Deep recursion → mprotect + shellcode | Concise; clean gadget chain |
| `1458.md` | A | `free_dynamic_allocation` → stdin → `__malloc_hook` | Two-stage: malloc_hook → leak, then → one_gadget |
| `1980.md` | B | scanf header corruption → alloca to stack → ROP | Documented the vulnerability mechanism |
| `2673.md` | B | Leave fake stack addr at `[rbx+0x28]` → ROP | Brief but effective |
| `2972.md` | B | 251 recurse + release pattern → ROP | Minimal explanation; heavy trial-and-error |
| `5586.md` | B | 57× stack fills + multiple releases → ROP | Uses `ret2csu` pattern |
| `6748.md` | B | Massive recurse (0x10×alloca + 0x60 bare) + releases → ROP | Trial-and-error alignment |
| `8153.md` | D | Heap spray 0xFF × malloc(0x20000) + `__malloc_hook` | ~1/32 reliability; spray-based |
| `9251.md` | C | TLS corruption → `_call_tls_dtors` → read gadget → ROP | Most exotic path; ~15/16 reliability |
| `10102.md` | B | Overwrite segment `prev` → fake segment chain → stack overlap | 1/16 brute force for `prev` partial overwrite |
| `14523.md` | B | Adjacent mmap stacks via heap gap → scanf `size` corruption | Detailed 8-attempt journal of failed approaches |
| `26957.md` | B | Overwrite segment header `+0x00` with low addr → alloca overflow | Concise |
| `31599.md` | A | `free_dynamic_allocation` → stdin → `__malloc_hook` → leak + one_gadget | Clean two-stage exploit |
| `32010.md` | A | stdin write → stdout FSOP leak → stdout vtable → one_gadget | FSOP approach with vtable `call [rax+0x38]` |
| `35917.md` | A | stdin+0x90 write → `__malloc_hook` → puts leak → one_gadget | Detailed; includes `realloc` alignment trick |
| `37983.md` | B | mmap ordering abuse → adjacent stacks → scanf → ROP | Local-only; includes IDA script for scanf offset analysis |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (Path A: FSOP stdin/stdout vtable hijack) |
| `desc.txt` | Challenge description |
| `artifacts/babyallocator` | Original challenge binary (x86-64, stripped, -fsplit-stack) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (21 solutions) |
