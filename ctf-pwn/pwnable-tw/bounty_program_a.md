---
tags:
  - heap-buffer-overflow
  - tcache-poisoning
  - arbitrary-write
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
description: "A heap buffer overflow in report comment parsing allows corrupting tcache next pointers to achieve arbitrary memory write and overwrite __free_hook."
proof-of-concept: no
---

# Bounty Program α — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10208`
>
> Flag: `FLAG{s0m3_3nv_Ar3_pow3rful_it_h3lp_you_lif3_mor3_e4sy}`

## Challenge Overview

A bug bounty platform binary (x86-64, PIE, Full RELRO, NX, Stack Canary) built against glibc 2.27. Users can register/login, manage products, submit/edit/evaluate bug reports, and manage vulnerability types. A `wrapper` binary prompts for an environment variable name/value pair before `execve`-ing the main binary — this is the key hint: `GLIBC_TUNABLES` can control malloc behavior.

The program features a user system (linked list), product/type/report management with complex heap interactions, and an evaluation flow that links reports to users. All string fields use `calloc`/`strdup`/`strtok` internally.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## Vulnerabilities

### V1 — `strtok` Continuation Leak in `add_type` (Primary)

**Root Cause:** The `add_type` function uses `strtok(buf, ",")` to parse comma-separated type names from a `calloc`'d buffer. When `size` is passed as `-1` (or `0xFFFFFFFF` unsigned → huge), the `calloc(1, size)` fails and returns NULL, but the code calls `strtok(NULL, ",")` which continues from the **previous** strtok state — reading whatever heap data lies beyond the last parsed token.

```c
// add_type (simplified)
buf = calloc(1, size);       // size = -1 → calloc fails → buf = NULL
read(0, buf, size);          // read to NULL = no-op or ignored
tok = strtok(buf, ",");      // strtok(NULL, ",") → continues from previous state!
printf("type: %s\n", tok);   // leaks heap/libc pointers from adjacent memory
```

**Impact:** By carefully positioning the strtok internal state pointer (via prior string operations), the continuation reads arbitrary heap data. This is used to:
- **Leak heap addresses** — strtok walks into freed chunk metadata or adjacent allocations
- **Leak libc addresses** — if strtok state points near an unsorted bin chunk's fd/bk pointers
- **Tcache poisoning** — the `strtok(NULL, ",")` call can write a NUL byte at a comma position in existing heap data, and the subsequent price parsing writes attacker-controlled values into tcache metadata

### V2 — Password Overflow into Contact Pointer

**Root Cause:** The user struct stores username (0x1e bytes), password (0xf bytes), a contact pointer, and other fields. The `change_password` function reads up to `0x3f` bytes into the password field, but the password buffer is only 0xf bytes — the overflow reaches the contact pointer at offset `+0x38`.

```c
// change_password
read(0, user->password, 0x3f);  // 0x3f bytes into a 0xf-byte field
// overflow overwrites: price(+0x30), uid(+0x34), contact_ptr(+0x38)
```

**Impact:** Overwriting `contact_ptr` gives:
- **Arbitrary read** — `change_contact` writes to the address in `contact_ptr`; `show_products` / `user_info` reads from pointed-to memory (via company pointer in product struct)
- **Arbitrary write** — `change_contact` writes attacker data to the overwritten pointer

### V3 — User Struct / Evaluate Fake User

**Root Cause:** The `evaluate` function iterates the user linked list and modifies user structs based on report data. By crafting heap layouts where freed user chunks overlap with type name data, an attacker can forge fake user structs with controlled `prev`/`next` pointers, username, and password — enabling login to a "fake" user that overlaps critical heap metadata.

### V4 — Heap Address Leak via Username Overflow

**Root Cause:** When registering with a 0x1e-byte username and logging in with a 0x1f-byte username (with a garbage byte appended), the `user_info` display prints the `name` field which, due to missing NUL termination at the boundary, leaks heap pointers from adjacent struct fields (the `next` pointer of the evaluated report list).

```c
// user_info display
printf("Name > %s\n", user->name);  // 0x1e bytes, no NUL → leaks next 6 bytes
```

### V5 — MD5 Contact Oracle

**Root Cause:** The `user_info` command displays the MD5 hash of the contact buffer (20 bytes). By pointing the contact pointer to a target address (via V2) and brute-forcing byte-by-byte against the MD5 hash, an attacker can read arbitrary memory one byte at a time.

## Key Data Structures

### User Struct (~0x60 bytes, heap-allocated)

| Offset | Field | Size |
|--------|-------|------|
| `0x00` | `username` | 0x1e bytes |
| `0x1e` | `password` | 0x0f bytes |
| `0x30` | `price` | uint32_t |
| `0x34` | `uid` | uint32_t |
| `0x38` | `contact_ptr` | char * |
| `0x40` | `report_head` | void * |
| `0x48` | `prev` | user * |
| `0x50` | `next` | user * |

### Global State

- **User linked list** — doubly-linked list of registered users
- **Product array** — up to 8 products, each with name/company/comment pointers and a report linked list
- **Type array** — up to 8 vulnerability types, each with a name (`strdup`'d) and a price
- **Reports** — linked to products, contain title, description (`calloc`), type ID, reporter

## Exploit Paths

### Path A — strtok Continuation + Password Overflow → Arbitrary R/W → `__free_hook` + `setcontext`

**Used by:** Solutions 821, 9251, 6748, 6923, 8153, 18331, 26957

1. **Set `GLIBC_TUNABLES`** — Use the wrapper to set `glibc.malloc.perturb=N` which fills freed chunks with a known byte, making heap layout more predictable.
2. **Heap leak** — Register a user with 0x1e-byte username. After evaluation, `user_info` leaks heap pointers past the username boundary. Alternatively, use strtok continuation (V1) with `size=-1` to leak a freed chunk's fd pointer.
3. **Libc leak** — Use V2 to overwrite the contact pointer to a product's company field. Change the company pointer to point at a heap location containing an unsorted bin fd/bk (libc main_arena pointer). Read it via `show_products`. Alternatively, use strtok continuation after positioning an unsorted bin chunk's metadata in the strtok path.
4. **Arbitrary R/W primitive** — Via V2: `change_password` overwrites `contact_ptr` to target address; `change_contact` writes to it. Chain to overwrite `product.company` for reads.
5. **Write `setcontext+53` to `__free_hook`** — When `free()` is called, `rdi` points to the freed chunk. `setcontext+53` reads register values from `[rdi+offset]`, enabling a full register-controlled context switch.
6. **Trigger** — Place a ROP chain / `mprotect` + shellcode payload in a heap allocation, then free it. `setcontext` pivots `rsp` to the payload → `mprotect(heap, 0x1000, RWX)` → `read(0, heap, 0x200)` → jump to shellcode → `open("/home/bounty_program/flag")` + `read` + `write`.

### Path B — MD5 Oracle Byte-by-Byte Leak → Stack Leak → Stack ROP

**Used by:** Solutions 1351, 25916

1. **Heap leak** — Same as Path A.
2. **Libc leak via MD5 oracle** — Use V2 to point `contact_ptr` near a libc pointer. Read `user_info` to get the MD5 of the 20-byte contact buffer. Brute-force each byte (256 attempts per byte, 6 bytes needed for a full pointer) by comparing computed MD5 hashes. Slow but reliable.
3. **Stack leak** — Point contact to `libc.sym['environ']`, read via MD5 oracle (or direct read once arbitrary read is established).
4. **Stack ROP** — Use V2 arbitrary write to write a ROP chain onto the stack (`pop rdi; /bin/sh; system` or `mprotect` + shellcode). Overwrite saved RIP to pivot.

### Path C — strtok Continuation Tcache Poisoning → `__malloc_hook`

**Used by:** Solutions 31599, 32010

1. **Leak heap + libc** via strtok continuation (V1) and heap feng shui.
2. **Tcache poisoning** — Arrange heap so that `strtok(NULL, ",")` walks into a tcache chunk's `fd` pointer. The NUL byte written by strtok at the comma position, combined with price writes, corrupts the fd to point to `__malloc_hook`.
3. **Allocate from poisoned tcache** — Next `strdup` / type allocation returns a chunk at `__malloc_hook`. Write `add_rsp_0x48` gadget (stack pivot) or `one_gadget`.
4. **Trigger** — Next `malloc` call jumps to the gadget → pivot to ROP chain on the heap → `open/read/write` flag.

### Path D — Heap Feng Shui + Fake User + Evaluate Exploitation

**Used by:** Solutions exp.py (main), 3148, 6247

1. **Complex heap feng shui** — Use large report descriptions and type allocations to create precise heap layouts where freed user chunks can be reused.
2. **Fake user creation** — Craft a type name that, when placed in a freed user slot, forms a valid user struct with controlled username, password, and pointers.
3. **Login as fake user** — The fake user's contact pointer or report head points to a target (e.g., an unsorted bin chunk for libc leak).
4. **Establish R/W** — Through the fake user's overlapping fields, gain read/write primitives.
5. **`__free_hook` + `setcontext`** — Same finish as Path A.

### Path E — Tcache `thread_per_struct` Overwrite → `environ` Leak → Stack ROP

**Used by:** Solution 32858

1. **Leak heap + libc** via strtok continuation.
2. **Overwrite `tcache_perthread_struct`** — Use a large report description to overwrite the tcache metadata structure, redirecting a specific bin's entry to `libc.sym['environ'] - offset`.
3. **Allocate from corrupted tcache** — `calloc` returns a chunk overlapping `environ`. Read the stack pointer from the bug report's description output.
4. **Stack ROP** — Use tcache poisoning to allocate at the stack return address. Write ROP chain directly.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Heap address leak | V4: username overflow / V1: strtok continuation | Deterministic / ~1/256 |
| Libc address leak | V1: strtok near unsorted bin / V2: arbitrary read | Deterministic |
| Stack address leak | V5: MD5 oracle on `environ` / V2: arb read | Deterministic |
| Arbitrary read | V2: password overflow → contact ptr → show | Deterministic |
| Arbitrary write | V2: password overflow → contact ptr → change contact | Deterministic |
| Tcache poisoning | V1: strtok NUL + price writes | Heap-layout dependent |
| Code execution | `__free_hook` = `setcontext+53` or `__malloc_hook` = gadget | Deterministic after arb W |

## Offsets (pwnable.tw `libc-2.27.so`)

```python
__free_hook      = 0x3ed8e8
__malloc_hook    = 0x3ebc30
setcontext_53    = 0x520a5
mprotect         = 0x11bae0
_IO_2_1_stderr_  = 0x3ec680
main_arena+96    = 0x3ebca0
environ          = 0x3ee098
pop_rdi          = 0x2155f
pop_rsi          = 0x23e6a
pop_rdx          = 0x1b96
pop_rax          = 0x439c8
leave_ret        = 0x54803
syscall_ret      = 0xd2975
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `exp.py` | D | strtok + feng shui + fake user + `__free_hook` → `setcontext` | Most complex; full heap manipulation |
| `821.md` | A | strtok leak + password overflow → `setcontext` + `mprotect` + shellcode | Clean `setcontext` usage |
| `1351.md` | B | MD5 oracle byte-by-byte → stack leak → `mprotect` + shellcode ROP | `GLIBC_TUNABLES` perturb=1 |
| `2972.md` | D | strtok + fake user via register → libc leak via `show_vuln` → `setcontext` | Minimal feng shui |
| `3148.md` | D | strtok + heap spray + fake user → `__free_hook` → `setcontext` | Detailed heap layout comments |
| `6247.md` | D | `tcache_max` tunable + unsorted bin consolidation → `__free_hook` | Uses `glibc.malloc.tcache_max` |
| `6748.md` | A | password overflow → arb read/write → tcache fd poison → `setcontext` | Well-structured OOP exploit |
| `6923.md` | A | strtok `-1` leak × 2 → password overflow → `__free_hook` → `setcontext` | Direct strtok libc leak |
| `8153.md` | A + B | password overflow → `__environ` → stack ROP | Stack-based finish |
| `9251.md` | A | password overflow → arb R/W → `leave; ret` + malloc_hook → ROP | `fopen` + `fgets` for flag read |
| `18331.md` | A | strtok `size=-1` → password overflow → arb R/W → stack return overwrite | No `setcontext`; direct stack smash |
| `25916.md` | B + E | MD5 oracle + `_dl_open_hook` chain → `setcontext` | Most complex; multi-stage via `_dl_open_hook` |
| `26957.md` | C | strtok tcache poison → `__malloc_hook` + `setcontext` | Direct tcache FD corruption |
| `31599.md` | C | strtok continuation → tcache poison → `__malloc_hook` = `add_rsp_0x48` → ROP | Cleanest tcache poison approach |
| `32010.md` | D | strtok leak + report/type overlap → `__malloc_hook` = `leave; ret` | `leave; ret` pivot |
| `32858.md` | E | tcache_perthread_struct overwrite → `environ` leak → stack ROP | Unique tcache struct approach |
| `34817.md` | D | strtok + `__free_hook` → `setcontext` → open/read/write ROP | Two script variants |
| `36134.md` | B | MD5 oracle + password overflow + heap feng shui → `leave; ret` → ROP | Byte-by-byte MD5 for all leaks |

## Notes

- **No `system("/bin/sh")`** — The flag is at `/home/bounty_program/flag` and seccomp or sandbox restrictions prevent direct shell. All solutions use `open/read/write` shellcode or ROP to read the flag file.
- **`GLIBC_TUNABLES`** — The wrapper's env var prompt is the intended hint. Setting `glibc.malloc.perturb=N` fills freed heap with byte N, making heap layout deterministic and leaks reliable. Some solutions also use `glibc.malloc.tcache_max` or `glibc.malloc.check`.
- **Full RELRO** — GOT is read-only, so all exploits target `__free_hook` or `__malloc_hook` instead.

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (feng shui + fake user approach) |
| `desc.txt` | Challenge description |
| `artifacts/bounty_program_alpha.tar.gz` | Original challenge binary + wrapper + libc |
| `solution/*.md` | Community write-ups (24 solutions) |
