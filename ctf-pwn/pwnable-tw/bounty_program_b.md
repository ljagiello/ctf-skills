---
tags:
  - heap-buffer-overflow
  - unsorted-bin-attack
  - tcache-poisoning
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A one-byte heap overflow enables overlapping heap chunks to forge tcache entries under FORTIFY_SOURCE constraints and hijack __free_hook."
proof-of-concept: no
---

# Bounty Program β — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10410`
>
> Flag: `FLAG{STRt0k_1s_v3ry_d4ng3rouS_And_d0nt_f0rg3t_ch3ck_NuLl_p7r}`

## Challenge Overview

A bug bounty platform binary (x86-64, Full RELRO, PIE, NX, Canary, FORTIFY) built against glibc 2.27. Users register/login, create products, submit vulnerability reports with descriptions, manage vulnerability types, and evaluate bugs. A `wrapper` binary sets one environment variable before executing the main program. This is the patched successor to "Bounty Program α" — `malloc` replaced with `calloc`, `strlen`-based password leak removed, `urandom`-based description initialization removed — but the core `strtok` UAF bug remains.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## Key Data Structures

### User (0x58 bytes)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `password` | `char[16]` |
| `0x10` | `username` | `char[32]` |
| `0x30` | `bounty` | `void *` |
| `0x38` | **`contact`** | `char *` (write primitive target) |
| `0x40` | `uid` | `uint64_t` |
| `0x48` | `ref_cnt` | `uint64_t` |
| `0x50` | `next` | `struct User *` |

### Vulnerability Report (0x140 bytes)

| Offset | Field | Type |
|--------|-------|------|
| `0x000` | `title` | `char[256]` |
| `0x100` | `user_ptr` | `struct User *` |
| `0x108` | `descrip_size` | `uint64_t` |
| `0x110` | `ID` | `uint32_t` |
| `0x118` | **`descrip_ptr`** | `char *` |
| `0x120` | `type_ptr` | `struct Type *` |
| `0x128` | `next` | `struct Report *` |
| `0x130` | `prev` | `struct Report *` |
| `0x138` | `evaluated` | `uint8_t` |

### Vulnerability Type (0x10 bytes)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `name_ptr` | `char *` |
| `0x08` | `price` | `int` |
| `0x0c` | `ref_cnt` | `int` |

## Vulnerabilities

### V1 — `strtok` UAF via `calloc(NULL)` (Primary, Exploitable)

**Root Cause:** In `add_type()`, user-controlled `size` is passed to `calloc(1, size)`. Passing `-1` (or `0xffffffff` / `0xffffffffffffffff`) causes `calloc` to fail and return `NULL`. The code does **not** check the return value. Subsequently, `strtok(NULL, ",")` is called — since the first argument is `NULL`, `strtok` reuses its internal `olds` pointer from a previous `strtok` call, operating on **already-freed memory**.

```c
// add_type (simplified)
char *buf = calloc(1, user_size);  // returns NULL on huge size
// NO NULL CHECK
strtok(buf, ",");  // if buf==NULL, reuses olds from prior strtok
// iterates: strtok(NULL, ",") reads/writes through freed chunk
```

**Impact:**
- **Read primitive:** The `olds` pointer points into a freed chunk. If that chunk is in a free list (unsorted bin, smallbin, fastbin, tcache), its `fd`/`bk` metadata is read as "type names" and printed back → leaks **heap** and **libc** addresses.
- **Write primitive:** `strtok` scans for the delimiter `,` (byte `0x2c`). If the freed chunk's metadata contains `0x2c` as part of a pointer (e.g., `0x????2c??`), `strtok` **NUL-overwrites** that byte, changing the pointer. This corrupts heap metadata or struct field pointers.

### V2 — Heap Pointer Corruption via `strtok` NUL-Write

**Root Cause:** `strtok` replaces the delimiter byte with `\x00`. When `olds` points at a heap pointer containing `0x2c` (which is common — e.g., address `0x5555????2c10`), the `0x2c` byte is zeroed → `0x5555????0010`. This effectively changes the pointer to a different heap location.

**Impact:** Combined with heap grooming, this provides:
- Corruption of a report's `descrip_ptr` to overlap with another struct
- Corruption of tcache/fastbin `fd` pointers for arbitrary allocation
- Corruption of a user's `contact` pointer for arbitrary write via `change_contact()`

### V3 — Description Pointer Overlap via Modify Report

**Root Cause:** `modify_report()` allows changing the description size to a larger value, calling `realloc()`. If the new description overlaps with a previously freed report or type chunk, the overlapping memory can be read/written through the description.

## Exploit Paths

All solutions exploit V1 (the `strtok` UAF) for leaks. They diverge on the write primitive and final hijack.

---

### Path A — `strtok` UAF → Leak libc/heap → `__free_hook` + `setcontext` → ORW ROP

**Used by:** Solutions 370, 821, 3148, 5586, 6247, 8153, 22319, 31599, 36134, 36997

**Steps:**

1. **Leak libc:** Call `add_type(large_size, ...)` to get a chunk into the unsorted bin. Then `add_type(-1, ...)` triggers the `strtok` UAF — `olds` points at freed chunk metadata → reads back `main_arena` pointer → compute libc base.

2. **Leak heap:** Free a smaller chunk into fastbin/tcache, then trigger another `strtok` UAF → reads back heap `fd` pointer → compute heap base.

3. **Heap grooming:** Carefully arrange allocations so a report's description is at address `0x????2cXX`. Use the `strtok` NUL-write (V2) to corrupt the `fd` pointer of a freed chunk, redirecting it to overlap with a report struct or user struct.

4. **Write primitive:** Either:
   - Overwrite a user's `contact` pointer to `__free_hook` via corrupted fastbin/tcache allocation, then use `change_contact()` to write `setcontext+53` to `__free_hook`.
   - Corrupt a report's `descrip_ptr` to point at `__free_hook` and write through `modify_report()`.
   - Directly poison tcache fd to allocate at `__malloc_hook`.

5. **Trigger:** Call `free()` on a chunk whose first 8 bytes point to a `SigreturnFrame` or ROP chain. `setcontext+53` pivots the stack. The ROP chain performs `open("/home/bounty_program/flag") → read → write(1, ...)`.

**Reliability:** ~50-100% depending on heap base alignment (some solutions require `heap_base & 0xf000 == 0xf000` for the `0x2c` trick, giving 1/16 brute force).

---

### Path B — `strtok` UAF → tcache poisoning → `__malloc_hook` + Stack Pivot → ORW

**Used by:** Solutions 25916, 34817, 37983

**Steps:**

1. **Leak libc + heap:** Same as Path A using repeated `add_type(-1)`.

2. **Heap padding:** Allocate large descriptions to align the next allocation at `0x????2cXX` so the `strtok` NUL-write corrupts a tcache chunk's `fd` to point to a controlled location (e.g., near `__malloc_hook`).

3. **Tcache poisoning:** The corrupted `fd` chain now includes a fake entry near `__malloc_hook - 0x14`. Allocate through the tcache chain until landing on `__malloc_hook`, then overwrite with `add_rsp_0x48` or `leave; ret` gadget.

4. **Trigger:** The next `calloc` (via `remove_type` with a crafted size as the `rbp` value) triggers `__malloc_hook`. The stack pivot lands in a pre-placed ROP chain that does ORW.

**Reliability:** Higher than Path A in some configurations since it avoids the user-struct corruption complexity.

---

### Path C — `strtok` UAF → Report Overlap → Fake Report → `__malloc_hook` + `leave; ret`

**Used by:** Solutions 370 (exp.py), 9251, 32010

**Steps:**

1. **Leaks:** Same strtok UAF for libc and heap.

2. **Heap layout:** Arrange a report's description at a NUL-writable address. Use the strtok NUL-write to make the description pointer overlap with another report's struct memory.

3. **Fake report:** Write through the overlapping description to forge a fake report with `descrip_ptr = __malloc_hook`. Use `modify_report()` on the fake report to write `leave; ret` to `__malloc_hook`.

4. **ROP chain placement:** Place the ROP chain in a known heap address via a bug report's title/description.

5. **Trigger:** `remove_type(heap_rop_address, ...)` → `calloc(1, heap_rop_address)` → `__malloc_hook(heap_rop_address)` → `leave; ret` pivots to ROP chain → ORW shellcode.

---

### Path D — `GLIBC_TUNABLES` + tcache disable → Fastbin UAF → `__free_hook`

**Used by:** Solutions 2972, 3498, 6923

**Steps:**

1. **Disable tcache:** Use the wrapper to set `GLIBC_TUNABLES=glibc.malloc.tcache_count=0` (or `tcache_max=32`). This forces all allocations through fastbin/smallbin/unsorted bin, simplifying heap grooming.

2. **Leaks + overlap:** Same strtok UAF, but without tcache the free list behavior is more predictable. Freed user structs go directly to fastbin.

3. **Free root user:** Allocate a report overlapping a freed user struct. Modify the report to corrupt the user's `contact` field to `__free_hook`. Use `change_contact()` to write `setcontext+53`.

4. **Trigger via free:** Free a report whose title contains the SROP frame / ROP payload → `setcontext` pivots → ORW.

---

### Path E — `strtok` UAF → `tcache_perthread_struct` Control → Arbitrary Allocation

**Used by:** Solution 2972

**Steps:**

1. **Arrange tcache chunk** at address `0x????2cXX`, free it, then free another same-size chunk.

2. **strtok NUL-write** changes the first chunk's `fd` pointer to point to `tcache_perthread_struct` at the top of the heap.

3. **`strdup`** (called internally) consumes the poisoned tcache chain and allocates over `tcache_perthread_struct`, giving full control of all tcache bin heads.

4. **Write arbitrary tcache entries** to redirect future allocations to `__free_hook` or `__malloc_hook`.

## Differences from Bounty Program α

| Feature | Alpha | Beta |
|---------|-------|------|
| `malloc` vs `calloc` | `malloc` | `calloc` (zeroes memory) |
| Password hash leak via `strlen` | Present | Removed |
| Urandom in description | Present | Removed |
| `change_contact`/`change_password` | `strlen` checked | Fixed-size input |
| Core `strtok` bug | Present | **Still present** |
| `calloc(-1)` returns NULL | N/A | Exploitable (no NULL check) |

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc leak (main_arena) | V1: strtok UAF on unsorted bin chunk | Deterministic |
| Heap leak | V1: strtok UAF on fastbin/tcache chunk | Deterministic |
| NUL-byte write at 0x2c | V2: strtok delimiter overwrite | Requires `0x2c` in pointer (~1/16 heap ASLR) |
| Arbitrary write | Corrupted contact/description pointer | Deterministic after alignment |
| Code execution | `__free_hook`/`__malloc_hook` + setcontext/leave;ret | Deterministic after write |
| Flag read (no `execve`) | ORW ROP chain: open→read→write | Required (seccomp or sandbox) |

## Offsets (pwnable.tw `libc-2.27.so`)

```python
main_arena       = 0x3ebc40
unsorted_bin     = 0x3ebca0   # main_arena + 0x60
__malloc_hook    = 0x3ebc30
__free_hook      = 0x3c57a8   # (some solutions use 0x3ed8e8)
setcontext       = 0x520a5    # +53 offset for the usable gadget
leave_ret        = 0x54803
pop_rdi          = 0x2155f
pop_rsi          = 0x23e6a
pop_rdx          = 0x1b96
pop_rax          = 0x439c8
syscall_ret      = 0xd2975
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | A | strtok UAF → tcache drain → `__free_hook` + setcontext | Two approaches; uses `evaluate` for user struct manipulation |
| `821.md` | A | strtok UAF → description overlap → `__malloc_hook` + setcontext | Detailed struct analysis; `GLIBC_TUNABLES` for tcache_count=0 |
| `2972.md` | E | strtok → tcache_perthread_struct control | 4-bit brute force; `strdup` to allocate from poisoned tcache |
| `3148.md` | D | strtok UAF → fake unlink → `__free_hook` | No GLIBC_TUNABLES needed; detailed heap grooming |
| `3498.md` | D | Same exploit for α and β; no env vars | `REMOTE`/`BETA` flag switch |
| `5586.md` | A | `GLIBC_TUNABLES=tcache_max=32` → fastbin UAF | Disables tcache for simpler fastbins |
| `6247.md` | D | `GLIBC_TUNABLES=tcache_max=216` → fastbin → contact overwrite | Uses register/delete for heap shaping |
| `6923.md` | C | strtok → `__malloc_hook` + calloc trigger | Precise heap alignment; `mprotect` + shellcode |
| `8153.md` | A | strtok + α/β compatible | Notes β only differs in calloc; same strtok bug |
| `9251.md` | C | Double free via strtok NUL-write → `__malloc_hook` + `leave;ret` | Detailed NPC/entity adjacency technique |
| `22319.md` | A | strtok → `__free_hook` + setcontext → mprotect + shellcode | Clean code; heap base brute force |
| `25916.md` | B | tcache poisoning → `__malloc_hook` near allocation | Heap padding for 0x2c alignment |
| `31599.md` | C | strtok → description overlap → `__malloc_hook` + `leave;ret` | ORW via syscall chain |
| `32010.md` | A | strtok → user contact → `__free_hook` + setcontext | Comprehensive heap walk; fopen for flag |
| `34817.md` | B | 1/16 brute force; tcache fd poisoning → `__free_hook` | Two scripts (fastbin version + tcache version) |
| `36134.md` | B | tcache poisoning via strtok NUL-write → `__malloc_hook` | `add_rsp_0x48` gadget + `pop rsp` pivot; clean solve |
| `36997.md` | A | strtok → `0x2c` overwrite → `__malloc_hook` + `leave;ret` | Detailed strtok source analysis; 1/16 |
| `37983.md` | A | Uses `rand ^ 0xDADADADA` type confusion for product overlap | Notes diff between α/β patches |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (heap offset brute force + ORW shellcode) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original challenge binary (bounty_program_beta.tar.gz) |
| `solution/*.md` | Community write-ups (22 solutions) |
