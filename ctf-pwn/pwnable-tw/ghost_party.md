---
tags:
  - type-confusion
  - use-after-free
  - vtable-hijack
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
description: "Reallocating mismatched C++ derived class objects into freed slots leads to type confusion, enabling vtable redirection to system."
proof-of-concept: no
---

# Ghost Party — pwnable.tw (400 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10401`
>
> Flag: `FLAG{D0n7_f0g07_7H3_c0pY_c0Ns7Ruc70R}`

## Challenge Overview

A C++ ghost management program (x86-64, PIE, Full RELRO, NX, Stack Canary) built against glibc 2.23. Source code (`ghostparty.cpp`) is provided. The player manages a `vector<Ghost*> ghostlist` of polymorphic ghost objects — 10 ghost subclasses (Werewolf, Devil, Zombie, Skull, Mummy, Dullahan, Vampire, Yuki-onna, Kasa-obake, Alan). Each has a vtable, virtual methods (`speak`, `changemsg`, `ghostinfo`, destructor), and class-specific fields (some raw `char*` pointers, some `std::string`).

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## Vulnerabilities

### V1 — Vampire Missing Copy Constructor (Primary, Use-After-Free / Double-Free)

**Root Cause:** The `Vampire` class has a raw `char *blood` member allocated with `new char[]`, but **no user-defined copy constructor**. The compiler generates a default copy constructor that performs a **shallow copy** of `blood` (copies the pointer, not the data). Meanwhile, `~Vampire()` calls `delete[] blood`.

```cpp
class Vampire : public Ghost {
    // NO copy constructor defined!
    // Compiler generates: Vampire(const Vampire &v) { blood = v.blood; ... }
    ~Vampire() { delete[] blood; }  // frees the shared pointer
private:
    char *blood;
};
```

The `smalllist<T>()` function's option 3 ("Join and hear what the ghost say") calls `speaking(*ghost)` which passes the ghost **by value**:

```cpp
template <class T>
void speaking(T ghost) {   // pass-by-value → copy constructor called
    ghost.speak();
};                          // temporary destroyed → ~Vampire() → delete[] blood

// In smalllist(), option 3:
case 3:
    ghostlist.push_back(ghost);   // ghost added to list (original pointer)
    speaking(*ghost);             // *ghost copied → shallow copy of blood
    // ~Vampire temporary dies → delete[] blood → UAF on original's blood!
```

**Impact:** After `smalllist(vampire, 3)`, the Vampire's `blood` pointer is a **dangling pointer** to freed heap memory. Reading `blood` via `ghostinfo()` leaks heap/libc data. The original Vampire's `~Vampire()` later double-frees the chunk.

### V2 — Alan Missing Destructor for `lightsaber` (Use-After-Free)

**Root Cause:** The `Alan` class stores `lightsaber` as `char*` assigned from a temporary `std::string::c_str()`. The `std::string` is destroyed when `addlightsaber()` returns, leaving `lightsaber` as a dangling pointer.

```cpp
class Alan : public Ghost {
    void addlightsaber(string str) {
        lightsaber = (char*)str.c_str();  // points to temporary string's buffer
    }                                     // str destroyed → lightsaber dangles
    ~Alan() {};                           // no delete → no double-free, but UAF on read
private:
    char *lightsaber;
};
```

**Impact:** After construction, the Alan's `lightsaber` pointer points to freed heap memory. Reading it via `ghostinfo()` leaks whatever data now occupies that chunk — commonly `stdout` (`_IO_2_1_stdout_`) address or heap metadata (fd/bk pointers), yielding **libc or heap leaks**.

### V3 — Devil/Zombie/Werewolf Proper Copy Constructors (Not Vulnerable)

These classes define explicit copy constructors that deep-copy their raw pointers. They serve as contrast to Vampire's missing copy constructor.

```cpp
class Devil : public Ghost {
    Devil(const Devil &copyghost) {
        // ...
        power = new char[strlen(copyghost.power)+1];  // deep copy
        strcpy(power, copyghost.power);
    };
};
```

## Key Data Structures

### Ghost Object Layout (base class, ~0x68 bytes)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `vtable` | `void**` (compiler-generated) |
| `0x08` | `age` | `int` |
| `0x10` | `name` | `char*` (heap-allocated) |
| `0x18` | `type` | `std::string` (SSO inline or heap) |
| `0x38` | `msg` | `std::string` (SSO inline or heap) |

### Vampire Object (extends Ghost, ~0x70 chunk = 0x60 usable)

| Offset | Field | Type |
|--------|-------|------|
| `0x00`–`0x57` | Ghost base fields | (vtable, age, name, type, msg) |
| `0x58` | `blood` | `char*` ← the vulnerable field |

### Werewolf Object (~0x70 chunk)

| Offset | Field | Type |
|--------|-------|------|
| `0x00`–`0x57` | Ghost base fields | |
| `0x58` | `trans` | `int` (full moon flag) |

### Alan Object (~0x70 chunk)

| Offset | Field | Type |
|--------|-------|------|
| `0x00`–`0x57` | Ghost base fields | |
| `0x58` | `lightsaber` | `char*` ← dangling after construction |

## Exploit Paths

All solutions exploit V1 (Vampire shallow copy) and/or V2 (Alan dangling lightsaber) for the initial leak, then diverge on the code execution strategy.

---

### Path A — Vampire UAF → Leak + Fastbin Dup → `__malloc_hook` Overwrite

**Used by:** Solutions 185, 821, 1912, 2972, 34817, and many others

**Steps:**

1. **Leak libc** via Vampire's dangling `blood`:
   - Create a Vampire with a large `blood` (e.g., `0x100` bytes → unsorted bin size). Use option 3 → `blood` freed.
   - The freed chunk's fd/bk contain main_arena pointers. `showinfo(vampire)` prints `Blood:` = libc leak.

2. **Fastbin duplication** via Vampire double-free:
   - Create Vampire with `blood` of size 0x60 (→ 0x70 chunk, fastbin). Use option 3 → blood freed (first free).
   - `rmghost(vampire)` → `~Vampire` calls `delete[] blood` again → **double-free** of the same 0x70 chunk.

3. **Fastbin poisoning** → allocate at `__malloc_hook - 0x23`:
   - Allocate a new object whose 0x70-sized allocation reads from the corrupted fastbin, writing `__malloc_hook - 0x23` as the next fd pointer.
   - Two more 0x70 allocations → the third lands at `__malloc_hook - 0x23`.
   - Write `one_gadget` at offset +0x13 (= `__malloc_hook`).

4. **Trigger `malloc`** → `one_gadget` → shell.

**Reliability:** Deterministic. Full RELRO means GOT is read-only, so `__malloc_hook`/`__realloc_hook` are the standard targets for glibc 2.23.

---

### Path B — Vampire UAF → Vtable Hijack via Chunk Overlap

**Used by:** Solutions 59, 568, 786, 6247, 9251, 31599, 32858

**Steps:**

1. **Leak PIE base** via Vampire UAF + Werewolf:
   - Create Vampire (option 3) with `blood` of size 0x60 → blood freed.
   - Create Werewolf (same 0x60 size) → reuses the freed blood chunk.
   - `showinfo(vampire)` prints `Blood:` = Werewolf's vtable pointer → **PIE base**.

2. **Leak heap/libc** via arbitrary read:
   - `rmghost(vampire)` → `~Vampire` deletes blood = **frees the Werewolf object** while `ghostlist[0]` still points to it (dangling `Ghost*`).
   - Create a Mummy/Kasa/Dullahan whose `std::string` data overlaps the freed Werewolf chunk → **fake Ghost object** at `ghostlist[0]`.
   - Set `fake.name = target_address`. `listghost()` calls `getname()` (non-virtual) → reads string at target → **arbitrary read**.
   - Read `GOT[__libc_start_main]` → libc base. Read `ghostlist` global → heap base.

3. **Hijack vtable** for code execution:
   - Build a final fake Ghost object with `vtable` pointing to a fake vtable on the heap.
   - Fake vtable's `ghostinfo` slot (vtable+0x10) = `one_gadget`.
   - `showinfo(0)` calls `ghostlist[0]->ghostinfo()` → one_gadget → shell.

**Reliability:** Deterministic once addresses are leaked. More complex than Path A but doesn't require fastbin manipulation.

---

### Path C — Alan UAF → Libc Leak + Vampire Double-Free → `__malloc_hook`

**Used by:** Solutions 331, 821, 1351, 6247

**Steps:**

1. **Leak libc** via Alan's dangling `lightsaber`:
   - Create Alan → `lightsaber` points to freed `std::string` buffer on heap.
   - The freed chunk gets reused by libc internal allocations. `showinfo(alan)` prints `Lightsaber:` = whatever pointer occupies the freed chunk → often a libc address (`stdout`, main_arena).
   - Alternatively, create a second Alan with a large lightsaber string to get unsorted bin placement.

2. **Double-free + fastbin poisoning** via Vampire (same as Path A steps 2-4).

3. **Overwrite `__malloc_hook`** with one_gadget → trigger → shell.

---

### Path D — FILE Structure Attack (`_IO_list_all` / stdout vtable)

**Used by:** Solutions 278, 331, 1351, 38838

**Steps:**

1. **Leak libc + heap** via V1 or V2.

2. **Fastbin poisoning** to allocate a chunk overlapping `stdout` or `_IO_list_all`:
   - Use the 0x7f byte near `_IO_list_all` or `stdout` as a fake fastbin chunk size.
   - Overwrite `stdout`'s vtable pointer → point to a fake vtable on the heap.

3. **Fake vtable** with `__overflow` or `xsputn` = `system` or `one_gadget`.
   - When `cout <<` triggers `stdout` vtable dispatch → shell.

**Reliability:** More fragile; requires careful FILE structure crafting.

---

### Path E — Devil UAF → Leak + Vtable Overlap

**Used by:** Solutions 59, 32858

Similar to Path B but uses Devil's `power` (also a raw `char*`) for UAF-based overlap. Devil has a proper copy constructor, but the by-value pass in `speaking()` still creates opportunities for heap layout manipulation after removal.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Dangling `blood` pointer (UAF read) | V1: Vampire shallow copy | Deterministic |
| Double-free of `blood` chunk | V1: Vampire dtor + shallow copy dtor | Deterministic |
| Dangling `lightsaber` pointer (UAF read) | V2: Alan c_str() on temporary | Deterministic |
| Libc leak (unsorted bin fd/bk) | Read via dangling pointer after free | Deterministic |
| PIE leak (vtable pointer) | Vampire blood overlaps Werewolf vtable | Deterministic |
| Heap leak | Read fd pointer from fastbin chunk | Deterministic |
| Arbitrary read | Fake Ghost object with controlled `name` | After PIE+heap leak |
| `__malloc_hook` overwrite | Fastbin dup + poisoning (glibc 2.23) | Deterministic |
| Vtable hijack | Fake vtable on heap → one_gadget | Deterministic |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
# libc offsets
main_arena_88   = 0x3c3b78
__malloc_hook   = 0x3c3b10
__free_hook     = 0x3c57a8
system          = 0x45390
__libc_start_main = 0x20740
stdout          = 0x3c4620
_IO_list_all    = 0x3c5520
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

# binary offsets (PIE-relative)
Werewolf_vtable = 0x210b98
ghostlist_vector = 0x211030
GOT_libc_start_main = 0x210e90
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | B | Vampire UAF → vtable overlap chain | Chains 3 vampires; overlaps vtable via fastbin |
| `185.md` | A | Vampire UAF → fastbin dup → `__malloc_hook` | Clean fastbin dup approach |
| `278.md` | D | Vampire + fastbin → stdout vtable hijack | Ruby; overwrites stdout vtable |
| `331.md` | D | Alan + Vampire → FILE struct → system | Overwrites stdout FILE struct with `system` |
| `568.md` | B | Alan UAF → libc leak → vtable hijack | Ruby; uses Alan for leak, Vampire for hijack |
| `786.md` | B | Vampire + Alan → vtable hijack | Uses dangling blood → vtable dispatch |
| `821.md` | A+C | Alan UAF → libc, Vampire dup → `__malloc_hook` | Alan lightsaber leak + fastbin dup |
| `1172.md` | B | Vampire UAF → PIE → arb read → vtable | Full fake Ghost chain via Mummy |
| `1351.md` | D | Alan + Vampire → `_IO_list_all` | FILE structure attack |
| `1912.md` | A | Vampire + Alan → fastbin → `__malloc_hook` | Heap + libc double leak |
| `2972.md` | A | Alan → heap+libc → Vampire dup → `__malloc_hook` | Alan for leaks, Vampire for corruption |
| `6247.md` | A+C | Alan → libc, Vampire dup → `__malloc_hook` | Concise approach |
| `8153.md` | A | Vampire → libc, double-free → `__malloc_hook` | Clean; uses `__realloc_hook` variant |
| `9251.md` | B | Alan → libc+PIE, Vampire → vtable hijack | Full leak chain, fake vtable dispatch |
| `24887.md` | B+E | Devil UAF → PIE → Vampire vtable spray | C++ exploit (!); uses pwntools C++ bindings |
| `31599.md` | B | Vampire → PIE, Kasa msg → fake Ghost → arb read | Uses Kasa-obake for fake objects |
| `32858.md` | B+E | Devil UAF → heap+libc, Vampire → vtable | Spray one_gadget into blood chunks |
| `34817.md` | A | Vampire → unsorted bin libc → fastbin dup | Minimal approach; "violates rule of three" |
| `38838.md` | D | Alan → libc, Vampire → `_IO_list_all` fastbin | FileStructure attack via `_IO_list_all` |

## Files

| File | Description |
|------|-------------|
| `artifacts/ghostparty.cpp` | Challenge source code (provided by challenge author) |
| `artifacts/ghostparty` | Challenge binary (x86-64, PIE, Full RELRO) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `exp.py` | Working exploit script (Path B: vtable hijack via fake Ghost) |
| `desc.txt` | Challenge description |
| `solution/*.md` | Community write-ups (51 solutions) |
