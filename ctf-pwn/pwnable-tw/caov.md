---
tags:
  - use-after-free
  - type-confusion
  - fastbin-dup
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.23
relro: full
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Reusing dangling object pointers across C++ key-value edit routines causes heap type confusion, enabling fastbin corruption to overwrite the fake vtable."
proof-of-concept: no
---

# CAOV — pwnable.tw (350 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10306`
>
> Flag: `FLAG{CAOV_stands_f0r_C0py_Ass1gnment_Operat0r_Vuln3rabil1ty_r3memb3r_alway5_r3turn_r3ference_typ3}`

## Challenge Overview

A C++ key-value database program (x86-64, Full RELRO, NX, No PIE, No Canary) compiled with g++ against glibc 2.23. The program manages a single `Data` object on the heap via a global pointer `D`. Users can set a name (stored in a 160-byte BSS buffer), create a key-value pair, and edit it up to 10 times. The name is "CAOV" — **Copy Assignment Operator Vulnerability**.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
```

Source code is provided (`caov.cpp`).

## Vulnerabilities

### V1 — Copy Assignment Operator Returns by Value (Primary, Exploitable)

**Root Cause:** The `Data::operator=` returns a `Data` object **by value** instead of by reference (`Data&`). This creates a temporary copy that is immediately destructed, calling `delete[] key` on a **newly allocated** key pointer — effectively causing a **use-after-free/double-free** scenario.

```cpp
// BUG: Returns Data by value, not Data&
Data operator=(const Data &rhs)
{
    key = new char[strlen(rhs.key)+1];  // allocates new key
    strcpy(key, rhs.key);
    value = rhs.value;
    // ... copies all fields
}   // <-- returned by value: temp copy created, then ~Data() called on temp
```

In the `edit()` function:

```cpp
void edit() {
    Data old;                // default-constructed, key=NULL
    old = *D;                // operator= returns by value → creates temp
                             // temp.~Data() frees temp.key (same ptr as old.key)
    D->edit_data();
    old.info();              // old.key is dangling (freed by temp's destructor)
    D->info();
}   // old.~Data() double-frees old.key
```

**Impact:** Every call to `edit()` produces a **double free** of the old key buffer.

### V2 — Stack-Reuse / Uninitialized Destructor via `set_name` (Primary, Exploitable)

**Root Cause:** `set_name()` and `edit()` share overlapping stack frames. The `set_name()` function writes up to 150 bytes to a stack buffer at `[rbp-0xb0]`. Then `edit()` creates a `Data old` object at the same stack location. The uninitialized `old.key` field inherits whatever `set_name` left on the stack. When `old.~Data()` runs, it calls `delete[]` on this controlled, stale pointer → **arbitrary free**.

```cpp
void set_name() {
    char tmp[160] = {};           // [rbp-0xb0] on stack
    // ... reads up to 150 bytes into tmp
    memcpy(name, tmp, cnt);       // copies to BSS
}

void edit() {
    Data old;                     // overlaps set_name's stack frame
    // old.key is uninitialized → contains whatever set_name wrote at [rbp-0x50]
    old = *D;                     // operator= allocates new key, writes to old
    // ...
}   // ~Data() calls delete[] old.key
    //   BUT old.key was set by the previous assignment's return-by-value temp
    //   AND the stack residue from set_name controls the INITIAL old.key
```

Specifically, `old.key` at stack offset `[rbp-0x50]` corresponds to `tmp[0x60]` in `set_name`. By placing a pointer at `name[0x60]` (byte offset 96 in the 150-byte name input), the attacker controls what address gets freed.

**Impact:** Arbitrary `free()` of any address the attacker places at offset 0x60 in the name buffer.

### V3 — Key Reuse When Shrinking (Enabler)

```cpp
void edit_data() {
    int old_len = strlen(key);
    unsigned int new_len = 0;
    // ...
    if (new_len > old_len) key = new char[new_len+1];  // only reallocates if LARGER
    set_data(new_len);  // writes new_len+1 bytes into OLD key buffer
}
```

When `new_len <= old_len`, the old key buffer is reused without reallocation. This is important because it means the key pointer survives edits, allowing the attacker to maintain control over where `D->key` points after freeing fake chunks into its location.

## Key Data Structures

### Data Class (0x40 bytes on heap)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `key` | `char *` (heap-allocated) |
| `0x08` | `value` | `long` |
| `0x10` | `change_count` | `long` |
| `0x18` | `year` | `int` |
| `0x1c` | `month` | `int` |
| `0x20` | `day` | `int` |
| `0x24` | `hour` | `int` |
| `0x28` | `min` | `int` |
| `0x2c` | `sec` | `int` |

### Global BSS Layout

| Address | Symbol | Size |
|---------|--------|------|
| `0x6032A0` | `D` (global Data pointer) | 8 bytes |
| `0x6032C0` | `name` (global name buffer) | 160 bytes |
| `0x603280` | `stderr` (FILE pointer) | 8 bytes |
| `0x603288` | `stdout` (FILE pointer) | 8 bytes |

The `0x7f` byte at `0x60328d` (from `stderr`/`stdout` pointers in BSS) serves as a fake fastbin size header for many exploits.

## Exploit Paths

All solutions exploit V1+V2 (the copy assignment operator bug + stack reuse) to achieve arbitrary free, then diverge on how they convert that into code execution.

---

### Path A — Arbitrary Free → House of Spirit → Fastbin Poisoning → Overwrite `D` → Leak libc → `__malloc_hook` Overwrite

**Used by:** Solutions 81, 194, 331, 1316, 1351, 3480, 3851, 5586, 6748, 8153, 32305, 34817, 36134, exp.py

**Steps:**

1. **Arbitrary Free via Stack Reuse (V2):** Forge a fake fastbin chunk in the BSS `name` buffer (at `name+0x10` = `0x6032D0`). Set `name[0x60]` to point to this fake chunk. Call `edit()` → `set_name` plants the pointer → `~Data()` frees the fake chunk into the fastbin.

2. **Fastbin Poisoning:** The freed fake chunk's `fd` is now writable via the `name` buffer. Set `fd` to `0x603285` (where the `0x7f` byte from `stderr` pointer creates a valid-looking size for a 0x70 fastbin chunk). Trigger two allocations of the same size to get the second allocation landing at `0x603295`, which overlaps the `D` pointer at `0x6032A0`.

3. **Overwrite `D`:** Write through the allocated chunk at `0x603295` to overwrite `D` (at `0x6032A0`) to point to `name` buffer. Now `D->key` is controlled via `name[0x00]`.

4. **Leak libc:** Set `D->key` to a GOT entry (e.g., `strlen@GOT`, `read@GOT`) or `stderr`/`stdout` BSS pointer. Call `show()` or wait for the `info()` output after edit — the key is printed via `cout << key`, leaking the libc address.

5. **Second Fastbin Attack:** Repeat the House of Spirit + fastbin poisoning, this time setting `fd` to `__malloc_hook - 0x23` (where a `0x7f` byte exists in libc as a fake size). Allocate twice to land a chunk overlapping `__malloc_hook`.

6. **Write One-Gadget:** Overwrite `__malloc_hook` with a one-gadget address. The next `malloc` (triggered by any key allocation) executes `execve("/bin/sh")`.

**Key Addresses (No PIE):**
- Fake chunk in name: `0x6032D0`
- `stderr` 0x7f fake size: `0x603285`
- `D` pointer: `0x6032A0`
- `name` buffer: `0x6032C0`

---

### Path B — Arbitrary Free → Free Data Object → Overlap Key with Data → Arbitrary R/W → `__malloc_hook`

**Used by:** Solutions 821, 1220, 13019

**Steps:**

1. **Heap Leak:** Free a fake chunk from BSS, arrange fastbin so that a heap address is written into the `name` buffer (as freed chunk's fd). Read it back via `show()`.

2. **Free the Data Object:** Use the heap leak to compute the address of the `Data` object. Free it via arbitrary free.

3. **Allocate Key Over Data:** Allocate a key with size matching the Data object's chunk. The key now overlaps the Data object, allowing direct control of `D->key`, `D->value`, `D->change_count`.

4. **Arbitrary Read:** Set `D->key` to any address → `show()` prints the content at that address. Leak libc via GOT entries.

5. **Arbitrary Write:** Set `D->key` to target address → `edit()` writes new key content to that address. Write one-gadget to `__malloc_hook`.

---

### Path C — Arbitrary Free → Unsorted Bin → libc Leak → `__malloc_hook`

**Used by:** Solutions 375, 3851

**Steps:**

1. **Create Larger Fake Chunk:** Forge a fake chunk in BSS with size `0xC1` or larger (past fastbin range), along with proper next-chunk headers.

2. **Free to Unsorted Bin:** Arbitrary-free the fake large chunk → libc main_arena pointers (fd/bk) are written into the BSS name buffer.

3. **Leak libc:** Read the unsorted bin pointers from the name buffer via `show()`.

4. **Fastbin Attack:** Proceed with fastbin poisoning to overwrite `__malloc_hook` with one-gadget.

---

### Path D — FSOP / Vtable Hijack on stdout/stderr

**Used by:** Solutions 331, 1316, 11954, exp.py

**Steps:**

1. **Leak libc** via Path A or B.

2. **Overwrite `_IO_2_1_stdout_` or `_IO_2_1_stderr_`:** Use arbitrary write to corrupt the FILE structure's vtable pointer to point to a fake vtable in the BSS `name` buffer.

3. **Populate Fake Vtable:** Fill the fake vtable with `system` address. Set the FILE's flags/name field to `"/bin/sh"`.

4. **Trigger:** Any I/O operation (e.g., `cout <<`) calls through the corrupted vtable → `system("/bin/sh")`.

This path is more complex but works around cases where one-gadget constraints aren't met.

---

### Path E — Stack Leak via `__environ` → Return Address Overwrite

**Used by:** Solution 821

**Steps:**

1. **Leak libc** via Path A or B.

2. **Leak Stack:** Set `D->key` to `__environ` in libc → `show()` prints the stack address.

3. **Overwrite Return Address:** Compute the return address location on the stack. Set `D->key` to that address and write a one-gadget or ROP chain.

4. **Trigger:** Choose "Exit" from menu → `main()` returns → one-gadget executes.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Arbitrary free | V1+V2: operator= return-by-value + stack reuse | Deterministic |
| Fastbin poisoning | Fake chunk in BSS + `0x7f` from stderr | Deterministic |
| Overwrite global `D` pointer | Fastbin allocation at `0x603295` | Deterministic |
| Arbitrary read (via key) | `D->key` controlled → `cout << key` | Deterministic |
| Arbitrary write (via key edit) | `D->key` controlled → `cin.getline(key, n)` | Deterministic |
| `__malloc_hook` overwrite | Fastbin attack near `__malloc_hook - 0x23` | Deterministic |
| Code execution | One-gadget via `__malloc_hook` or FSOP | Deterministic |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
# libc offsets
_IO_2_1_stderr_ = 0x3C4540
_IO_2_1_stdout_ = 0x3C4620
__malloc_hook    = 0x3C3B10
__free_hook      = 0x3C57A8
system           = 0x45390
stdin_fileno     = 0x3C38E0

# one_gadgets
one_gadgets = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

# BSS addresses (no PIE)
D_ptr       = 0x6032A0
name_buf    = 0x6032C0
stderr_ptr  = 0x603280
stdout_ptr  = 0x603288
fake_size   = 0x603285  # 0x7f byte from stderr pointer
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `81.md` | A | House of Spirit + fastbin poison → one_gadget via time leak | Uses date fields to leak libc |
| `194.md` | B | Arbitrary free → free Data obj → GOT leak → `__malloc_hook` | Clean structured approach |
| `331.md` | A+D | Fastbin poison → `D` overwrite → stdout vtable hijack | FSOP finish |
| `375.md` | A | Fastbin poison → `D` overwrite → leak stderr → fastbin `__malloc_hook` | Multiple fastbin rounds |
| `821.md` | A+E | Fastbin → `D` overwrite → environ leak → stack ROP | Overwrites return address |
| `1220.md` | B | Free Data obj → overlap key → GOT leak → `__malloc_hook` via fastbin | Heap address calculation |
| `1316.md` | A+D | Fastbin → stderr leak → overwrite stderr vtable → `system` | FSOP via stderr |
| `1351.md` | A | Fastbin → read GOT leak → `__malloc_hook` + one_gadget | Direct and clean |
| `1763.md` | A | Fastbin poison → `__malloc_hook` leak + overwrite | Uses malloc_hook+0x48 |
| `3480.md` | A | Fastbin + large key alloc → GOT leak → `__malloc_hook` | Uses 0x40-size fake chunks |
| `3851.md` | A+C | Multiple fastbin rounds + unsorted bin → libc leak | Complex heap layout |
| `5586.md` | A | Compact fastbin chain → stderr leak → `__malloc_hook` | Minimal operations |
| `6748.md` | A | Fastbin → exit GOT leak → `__malloc_hook` | Chinese writeup with analysis |
| `8153.md` | A | Fastbin → stderr leak → `__malloc_hook` | Clean exploit |
| `11954.md` | A+D | Fastbin → GOT leak → stdout vtable + one_gadget | FSOP fallback |
| `13019.md` | B+E | Free Data → GOT leak → environ → stack return overwrite | Heap + stack approach |
| `32305.md` | A | House of Spirit → fastbin → stderr leak → `__malloc_hook` | Detailed heap layout |
| `34817.md` | B+C | Free Data → unsorted bin → libc leak → `__malloc_hook` | Heap-heavy approach |
| `36134.md` | A | House of Spirit → fastbin poison → `__malloc_hook` | Well-documented steps |

## Files

| File | Description |
|------|-------------|
| `artifacts/caov.cpp` | Challenge source code (provided by author) |
| `artifacts/caov` | Challenge binary (x86-64, Full RELRO, No PIE) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `exp.py` | Working exploit script |
| `desc.txt` | Challenge description |
| `solution/*.md` | Community write-ups (52 solutions) |
