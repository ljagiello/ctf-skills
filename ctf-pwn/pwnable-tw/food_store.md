---
tags:
  - heap-buffer-overflow
  - unsorted-bin-attack
  - house-of-orange
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.24
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A heap buffer overflow in recipe parsing corrupts heap metadata to trigger House of Orange and overwrite _IO_FILE jump tables in glibc 2.24."
proof-of-concept: no
---

# Food Store — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10406`
>
> Flag: `FLAG{C4ptur3_th3_Fl4g_c4ptuR3_the_f00d}`

## Challenge Overview

A menu-driven "food store" game binary (x86-64, PIE, Full RELRO, NX, Stack Canary) running on Ubuntu 17.04 with glibc 2.24 (no tcache). The player manages recipes, cooks dishes, buys/sells ingredients at a shop, completes NPC assignments, and earns levels/power/money. A seccomp sandbox restricts syscalls to `open`/`read`/`write`/`close`/`mmap`/`munmap`/`exit` — no `execve`.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO            # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  Seccomp:  open/read/write/close/mmap/munmap/exit only
```

### Key Structures

```c
struct recipe {            // 0x90 bytes (malloc'd)
    char name[24];         // +0x00  (scanf "%23s")
    ingredient *ings[13];  // +0x18  (pointers to ingredient structs)
    recipe *next;          // +0x80  (singly-linked list)
};

struct ingredient {        // 0x30 bytes (calloc'd or custom)
    char name[32];         // +0x00
    int price;             // +0x20
    int quantity;          // +0x24
};

struct dish {              // 0x40 bytes (malloc'd when cooking)
    char name[24];         // +0x00
    int price;             // +0x18
    int energy;            // +0x1c
    dish *next;            // +0x20  (singly-linked list)
};
```

## Vulnerabilities

### V1 — Uninitialized `recipe->next` Pointer (Primary, Exploitable)

**Root Cause:** When `add_recipe()` allocates a new recipe struct via `malloc(0x90)`, the `next` pointer at offset `+0x80` is **never initialized**. If the chunk was previously used and freed, stale heap metadata (fd/bk pointers) or user-controlled data persists in that region.

```c
// add_recipe (simplified)
recipe *r = malloc(sizeof(recipe));  // 0x90 bytes
scanf("%23s", r->name);             // name is written
// ... ingredient pointers are set ...
// r->next is NEVER set to NULL
recipe_head->next = r;              // inserted into linked list with stale next
```

**Impact:** By carefully sequencing allocations and frees so that the 0x90-byte chunk is reused with controlled data at offset `+0x80`, an attacker can make `recipe->next` point to an arbitrary address. This gives:

- **Fake linked-list entries**: `show_recipe()` and `remove_recipe()` traverse the corrupted list, reading/freeing attacker-controlled addresses.
- **Arbitrary free**: `remove_recipe()` frees the fake recipe chunk at the attacker-chosen address.
- **Heap/libc/stack leaks**: Recipe names and ingredient data from fake list entries are printed, leaking pointers.

### V2 — Overlapping Allocation Sizes (Enabler)

Dish structs are 0x40 bytes and recipe structs are 0x90 bytes. By cooking dishes then freeing them, and then allocating recipes (or vice versa), chunks of different sizes can be arranged so that a recipe's `next` field overlaps with data written into a previously-freed dish or ingredient chunk.

### V3 — Ingredient Type Confusion via Shop (Minor, Money/Power)

When making a custom ingredient and then buying the same slot, the custom ingredient (with a random high price) replaces the standard one. Cooking a recipe with this ingredient produces a dish worth enormous money and energy, enabling the grind needed for further allocations.

## Exploit Paths

All solutions require significant "game grind" to accumulate levels, power, and money needed to perform enough allocations. The flag file is pre-opened as fd 3 by the binary, and seccomp blocks `execve`, so all paths end with an ORW (open/read/write) ROP chain reading the flag.

---

### Path A — Uninitialized `next` → Heap/Libc Leak → `__free_hook` = `setcontext` → ORW ROP

**Used by:** Solutions 370, 8153, 31599, 37709

**Steps:**

1. **Grind:** Cook, eat, complete assignments to reach level 4+ with enough money.
2. **Heap leak:** Sequence allocations/frees so a recipe's uninitialized `next` points to a freed chunk containing a heap address. `show_recipe()` or the cook menu prints this as a recipe title → **heap base**.
3. **Libc leak:** Point a fake recipe's ingredient list at a freed large/unsorted bin chunk that contains `main_arena` pointers. The ingredient display or recipe title leaks a libc address → **libc base**.
4. **ORW ROP layout:** Create multiple recipes whose 24-byte names each hold 2 ROP gadgets + an `add rsp, 0x60; pop; pop; pop; ret` slide to chain them.
5. **Overwrite `__free_hook`:** Link `__free_hook - 0x80` into the recipe list via the uninitialized-next trick. When `remove_recipe()` "unlinks" this fake recipe, it writes a heap pointer to `__free_hook`, which is then overwritten with `setcontext+0x35`.
6. **Trigger:** Free a chunk whose `+0xa0` field points to the ROP chain. `setcontext` pivots rsp → ORW ROP runs → `read(3, buf, 0x100)` + `write(1, buf, 0x100)` → flag on stdout.

---

### Path B — Uninitialized `next` → `_dl_open_hook` Hijack → `gets` → ORW ROP

**Used by:** Solutions 2311, 22319, 31599 (alternative)

1. **Heap + libc leak:** Same as Path A (uninitialized `next` → bin pointer leaks).
2. **Write-what-where:** The uninitialized-next primitive gives the ability to write a heap pointer to any address containing a zero. Target `_dl_open_hook` (a function pointer table used during `dlopen`/abort).
3. **Trigger abort:** Free an invalid/fake chunk address → glibc detects corruption → calls `__libc_message` → `backtrace` → `_dl_open_hook->dlopen_mode()` → controlled call.
4. **Pivot + `gets`:** The controlled call targets a gadget like `call [rax+0x48]` with `gets` at that offset. `gets()` reads an ORW ROP chain onto the stack/heap → flag.

---

### Path C — Uninitialized `next` → `__realloc_hook` = `leave; ret` → Stack Pivot → ORW ROP

**Used by:** Solutions 8153, 37709

1. **Leak heap + libc** via the same uninitialized-next technique.
2. **Link `__realloc_hook - 0x80` into the recipe list.** Use `remove_recipe()` unlink to write `leave; ret` gadget to `__realloc_hook`.
3. **Prepare ROP payload** in a heap region (recipe names + `gets` address).
4. **Trigger `realloc(ptr, 0)`:** The `remove_recipe` internally calls `realloc` → `__realloc_hook` fires → `leave; ret` pivots rsp to a heap-based ROP chain containing `gets`.
5. **`gets` reads the final ORW ROP** → `read(3, heap, 0x100)` + `write(1, heap, 0x100)` → flag.

---

### Path D — Unsorted Bin Attack → Corrupt `stdin->_IO_buf_end` → Stack Overwrite → ORW ROP

**Used by:** Solutions 1351, 755

1. **Leak heap + libc** via uninitialized-next.
2. **Unsorted bin attack:** Corrupt unsorted bin `bk` to point to `stdin->_IO_buf_end - 0x10`. Next allocation from the unsorted bin writes `main_arena` address over `_IO_buf_end`, extending stdin's internal buffer to cover a large writable region.
3. **Stack leak:** Use the extended stdin buffer or read `__environ` via fake recipe to leak a stack address.
4. **Overwrite stack via stdin:** The next `scanf` reads past the original buffer boundary, writing directly onto the stack. Inject a `leave; ret` + ORW ROP chain into the return address region.
5. **Return → ROP → flag.**

---

### Path E — FSOP via `fclose` on Flag FILE → `_IO_str_overflow` → `setcontext` → ORW ROP

**Used by:** Solutions 821, 36997, 2972

1. **Leak heap + libc** via uninitialized-next.
2. **Free the flag FILE struct:** Point the fake recipe list at the `FILE *` for the pre-opened flag (on the heap). `remove_recipe()` frees it into the unsorted bin.
3. **Reallocate over the freed FILE:** Use `make_ingredient` (shop menu) to allocate chunks that overlap the freed FILE struct. Forge a fake `_IO_FILE_plus` with:
   - Vtable pointing to `_IO_str_jumps - 0x10` (so `__overflow` slot → `setcontext+0x35`)
   - `_IO_buf_base` set to heap address containing ROP chain
4. **Trigger `fclose` or `exit`:** The program calls `fclose(f_flag)` on exit → `_IO_OVERFLOW` dispatches through the fake vtable → `setcontext` pivots stack → ORW ROP → flag.

---

### Path F — Modify `stdin->fd` from 0 to 3 → `scanf` Reads Flag Directly

**Used by:** Solution 408

1. **Leak heap + libc** via uninitialized-next + ingredient type confusion.
2. **Corrupt ingredient pointer:** Make an ingredient whose address overlaps with `stdin->fd - 0x24` (so that the ingredient's `quantity` field aliases `stdin->fd`).
3. **Increment `stdin->fd`:** Visit the shop to trigger a "restock" operation that increments the quantity field, changing fd from 0 to 3.
4. **`scanf("%23s")` in `add_recipe`** now reads from fd 3 (the flag file) instead of stdin → flag becomes the recipe name → printed by `show_recipe()`.

**Elegance:** This path avoids ROP entirely — one byte change to `stdin->fd` makes the flag appear as a recipe title.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Uninitialized `recipe->next` | V1: stale heap data in malloc'd 0x90 chunk | Deterministic (with careful heap feng shui) |
| Arbitrary address in linked list | V1 applied: control `next` via prior allocation | After heap layout control |
| Heap address leak | Fake list entry → printed as recipe title | Deterministic |
| Libc leak | Unsorted/large bin fd/bk in fake recipe | Deterministic |
| Arbitrary free | `remove_recipe()` on fake list entry | After list corruption |
| Code execution | `__free_hook`/`__realloc_hook`/`_dl_open_hook`/FSOP | Deterministic after leaks |
| Flag read | ORW ROP (seccomp blocks execve) | Deterministic |

## Offsets (Ubuntu 17.04 libc 2.24-9ubuntu2.2)

```python
main_arena       = 0x3C1B00
__free_hook      = 0x3C3788
__realloc_hook   = 0x3C3778  # (also __memalign_hook - 0x10)
_dl_open_hook    = 0x3C6F48
setcontext       = 0x48045   # mov rsp, [rdi+0xa0]; ...; ret
pop_rdi          = 0x1FD7A
pop_rsi          = 0x1FCBD
pop_rdx          = 0x1B92
pop_rax          = 0x3A998
syscall_ret      = 0xBC765   # syscall; cmp rax, -0xfff; jae; ret
add_rsp_0x60_pop3 = 0xF8766  # add rsp, 0x60; pop rbx; pop rbp; pop r12; ret
leave_ret        = 0x424A5
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | A | Uninit next → large bin leak → `__realloc_hook` + `setcontext` → ORW | Uses ctypes to predict RNG for assignment timing |
| `821.md` | E | Uninit next → free flag FILE → FSOP `_IO_str_overflow` → `setcontext` | Frees `f_flag` FILE struct, forges vtable |
| `2311.md` | B | Uninit next → `_dl_open_hook` → abort trigger → `gets` → ORW | Writes heap ptr to `_dl_open_hook`, triggers via bad free |
| `755.md` | D | Uninit next → unsorted bin attack → corrupt `stdin->_IO_buf_end` → stack ROP | Extends stdin buffer to overwrite stack |
| `408.md` | F | Ingredient type confusion → modify `stdin->fd` 0→3 → scanf reads flag | Elegant: no ROP, flag becomes recipe title |
| `1351.md` | D | Uninit next → unsorted bin attack → stdin corruption → stack overwrite | Similar to 755 with different layout |
| `8033.md` | A | Uninit next → `__free_hook` = `gets` → stack pivot → ORW | Overwrites `__free_hook` with `gets`, then reads ROP |
| `8153.md` | A | Uninit next → `__free_hook` = `setcontext` → ORW | Clean implementation of Path A |
| `9251.md` | B + C | Uninit next → `_dl_open_hook` → `setcontext` → `gets` → ORW | Uses `authdes_marshal` gadget for call primitive |
| `22319.md` | B | Uninit next → `_dl_open_hook` → `setcontext+53` → `gets` → ORW | Leaked libc from `_IO_2_1_stderr_` on heap |
| `31599.md` | A | Uninit next → large bin leak → `__free_hook` via unlink → `setcontext` → ORW | Detailed, creates ORW spread across recipe titles |
| `36134.md` | B | Uninit next → `_dl_open_hook` → `gets` → ORW | Made custom ingredient for high price/power exploit |
| `36997.md` | E | Uninit next → free flag FILE → FSOP → `setcontext` → ORW | `_IO_str_overflow` with fake vtable |
| `37709.md` | C | Uninit next → `__realloc_hook` = `leave; ret` → heap pivot → `gets` → ORW | Stack pivot via `leave; ret` in `__realloc_hook` |
| `2972.md` | E | Uninit next → free flag FILE → FSOP `_IO_str_overflow` → `setcontext` | Similar to 821, heap spray for FILE overlap |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (socket-based, pipelined for 60s alarm) |
| `desc.txt` | Challenge description |
| `artifacts/food_store` | Original challenge binary |
| `solution/*.md` | Community write-ups (15 solutions) |
