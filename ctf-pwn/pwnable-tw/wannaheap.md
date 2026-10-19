---
tags:
  - off-by-null
  - heap-consolidation
  - arbitrary-write
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.24
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "An off-by-null byte in treap key insertion triggers backward heap consolidation across active tree nodes, achieving arbitrary write in glibc 2.24."
proof-of-concept: no
---

# WannaHeap — pwnable.tw (400 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10305`
>
> Flag: `FLAG{I_w4nt_2_pl4y_w1th_f1l3_str34m}`

## Challenge Overview

A treap (tree-heap) based key-value store binary (x86-64, Full RELRO, PIE, NX, Stack Canary) running on **Ubuntu 17.04 with glibc 2.24** — the first glibc version to introduce `_IO_vtable_check`, and notably **without tcache**. A **seccomp** sandbox blocks `execve` and restricts `read` to `count <= 0x1337`, `mmap` to non-executable pages. No `free` is implemented. The flag must be read via ORW (open/read/write).

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  seccomp:  ALLOW open/read(≤0x1337)/write/close/munmap/mmap(no EXEC)/rt_sigreturn/exit/exit_group
```

### Program Flow

1. **Create data heap**: Asks for `Size` → `calloc(size+1)` → reads `Content`. A second size is asked if the first exceeds `0x313370`.
2. **Menu**: `[A]llocate` (insert key+data into treap), `[R]ead` (find by key, print data, then **`close(1)`**), `[F]ree` (not implemented), `[E]xit`.
3. Seccomp is installed **after** the data heap creation (so the initial `read` is unrestricted).

## Key Data Structures

### Treap Node (0x28 bytes, randomly padded in custom allocator)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `left_child` | `node *` |
| `0x08` | `right_child` | `node *` |
| `0x10` | `key` | `uint64_t` |
| `0x18` | `data_ptr` | `char *` (via `strdup`) |
| `0x20` | `priority` | `uint32_t` (from `/dev/urandom`) |

The custom allocator calls `calloc(0x28 + rand()%535 + rand()%8560)` and places the node at a random offset within the chunk (padded with `0xda` before and `0x42` after), making heap layout unpredictable.

## Vulnerabilities

### V1 — Arbitrary Null-Byte Write Relative to Data Heap (Primary)

**Root Cause:** In the "Create data heap" function, the first `scanf`-ed size `S1` is remembered. If `S1 > 0x313370`, the program re-prompts until a valid `S2 ≤ 0x313370` is given. The buffer is allocated with `S2`, but the null terminator is written at offset `S1`:

```c
scanf("%lu", &size);
uVar1 = size;                        // remember S1
while (size > 0x313370) {
    scanf("%lu", &size);             // get S2
}
buf = calloc(1, size + 1);          // allocate with S2
read_n(buf, size);                   // read S2 bytes
*(char*)(buf + uVar1) = 0;          // NULL write at S1 offset!
```

**Impact:** Since `calloc` of a large size (e.g., `0x300000`) uses `mmap`, which lands at a **fixed offset below libc**, `S1` can target any byte in the libc writable segment. The critical target is `_IO_2_1_stdin_->_IO_buf_base` (at `stdin + 0x38`), whose LSB is cleared to `\x00`.

**Trigger:**
```python
S1 = mmap_gap + libc.sym['_IO_2_1_stdin_'] + 0x38 - 0x10
# Typical values: 0x6c28e8 or 0x6d58e8 depending on mmap_gap (0x301000 or 0x314000)
S2 = 0x300000  # or 0x313370
```

After the null write, `_IO_buf_base` changes from `stdin+0x83` → `stdin+0x00` (or `stdin+0x40` depending on alignment), so subsequent stdin reads write **directly into the FILE structure**, including `_IO_buf_end` — which can then be extended to cover `main_arena` and beyond.

### V2 — Uninitialized Stack Buffer Leak in `strdup`

**Root Cause:** When `Allocate` reads the data field, it uses `read_n` into a **stack buffer of 0x18 bytes that is never zeroed**. The result is passed to `strdup`, which copies until the first `\0`.

```c
char buf[0x18];  // uninitialized!
read_n(buf, 0x18);
node->data = strdup(buf);
```

**Impact:** At treap insertion depth 2, `buf+8` on the stack contains a residual pointer to `_IO_2_1_stdout_` (whose LSB is `\x00`). By sending exactly **9 bytes** of data, the 9th byte overwrites that `\x00`, causing `strdup` to copy the remaining 5 bytes of the stdout pointer. Reading it back via `[R]ead` leaks `stdout >> 8`, yielding `libc_base`.

```python
# Leak: send 9 bytes, read back, extract bytes [9:14]
stdout_partial = u64(b'\x00' + leaked_5_bytes + b'\x00\x00')
libc_base = stdout_partial - libc.sym['_IO_2_1_stdout_']
```

This leak is probabilistic (~50%) since the treap's random priorities determine which node is at depth 2. Solutions retry until successful.

## Exploit Paths

All solutions share V1 (null-byte write on `stdin->_IO_buf_base`) + V2 (libc leak via uninitialized stack). They diverge on the FSOP / code execution strategy.

---

### Path A — `_dl_open_hook` via Unsorted Bin Attack + `setcontext` → ORW ROP

**Used by:** Solutions 194, 821, 1155, 1763, 1922, 7905, 8153, 31599, exp.py

**Steps:**

1. **Null-byte write** `stdin->_IO_buf_base` LSB → stdin buffer now overlaps the FILE struct.
2. **Leak libc** via V2 (allocate two nodes, read back the second).
3. **Extend `_IO_buf_end`**: First stdin read after the null write overwrites `_IO_buf_end` (at `stdin+0x40`), extending it to cover `main_arena`.
4. **Overwrite everything in one shot**: A single large `send()` rewrites:
   - `stdin` FILE struct (fix `_lock`, `vtable = _IO_file_jumps` to pass vtable check, extend `_IO_buf_end`)
   - `_IO_wide_data_0` area (embed a **fake unsorted bin chunk** with `bk = _dl_open_hook - 0x10`)
   - `main_arena` (forge `bins[]` to point at fake chunk; set `top = gadget(mov rdi,rax; call [rax+0x20])`; embed `setcontext+53` and a ucontext frame for stack pivot)
5. **Trigger**: The payload byte at the right offset happens to be `'A'` → triggers `Allocate` → `calloc` → walks the forged unsorted bin → **unsorted bin attack** writes `&main_arena+0x58` into `_dl_open_hook`.
6. **Crash path**: `malloc` detects corruption → `malloc_printerr` → `__libc_message(do_abort)` → `__backtrace` → `__libc_dlopen_mode("libgcc_s.so.1")` → `_dl_open` sees `_dl_open_hook != NULL` → calls `(*_dl_open_hook->dlopen_mode)()`.
7. `rax = _dl_open_hook = main_arena+0x58`, which points to gadget `mov rdi, rax; call [rax+0x20]` → calls `setcontext+53` with controlled `rdi` → **stack pivot** to ORW ROP chain.
8. **ROP**: `open("/home/wannaheap/flag") → read(1, buf, 0x100) → write(0, buf, 0x100)`.

**Key detail:** `Read` calls `close(1)`, so `open` returns fd 1. Output must go to fd 0 (the socket), since fd 2 is `/dev/null` on the server.

---

### Path B — `_IO_str_overflow` vtable hijack + `setcontext` → ORW ROP

**Used by:** Solutions 369, 2972, 6247, 36997

glibc 2.24's `_IO_vtable_check` allows vtables within the `__libc_IO_vtables` section. `_IO_str_jumps` is in that range, so pointing a FILE's vtable to an offset within `_IO_str_jumps` passes the check. `_IO_str_overflow` calls `fp->_s._allocate_buffer(new_size)` — a function pointer at `fp+0xe0`.

**Steps:**

1-3. Same as Path A (null write, leak, extend `_IO_buf_end`).
4. **Forge stdout**: Overwrite `_IO_2_1_stdout_` with a crafted FILE:
   - `vtable = _IO_str_jumps - 0x20` (offset so `__xsputn` slot maps to `_IO_str_overflow`)
   - `_IO_buf_end = (target_rdi - 100) / 2` (controls the `new_size` argument)
   - `fp->_s._allocate_buffer = setcontext+53` (at `fp+0xe0`)
5. **Trigger**: The `'E'` byte in the payload triggers `Exit` → `puts("Goodbye")` → `__xsputn` on stdout → `_IO_str_overflow` → `call [fp+0xe0]` = `setcontext+53`.
6. `setcontext` pivots stack to ORW ROP chain.

---

### Path C — `_IO_wstr_finish` / `_IO_wfile_jumps` vtable hijack + Stack Pivot → ORW ROP

**Used by:** Solutions 8153, 36997 (variant)

Uses `_IO_wfile_jumps` (also in the valid vtable section). `_IO_wstr_finish` calls `fp->_wide_data->_wide_vtable->__doallocate(fp)` — a chain of indirect calls that can be pointed to a stack-pivot gadget.

**Steps:**

1-3. Same as Path A.
4. **Forge stdout**: Set `vtable = _IO_wfile_jumps + offset`, `_wide_data` pointing to a controlled region with a fake wide vtable containing `xchg rax, rsp; ret` or `call [rdi+0x18]` → `setcontext+53`.
5. **Trigger**: `puts` on stdout → wide vtable dispatch → stack pivot → ORW ROP.

---

### Path D — `__free_hook` + `setcontext` via stdin Manipulation (No Unsorted Bin Attack)

**Used by:** Solution 186

**Steps:**

1-3. Same as Path A.
4. Instead of unsorted bin attack, directly control `stdin->_IO_markers`, `_IO_save_base`, `_IO_save_end`, and `_IO_read_base` to trigger libc's internal `malloc()`, `free()`, and `memcpy()` calls during stdin buffer management.
5. Arrange heap so that `free()` is called on a controlled buffer, then overwrite `__free_hook` with `setcontext+53 - 7` (avoiding the `0x45 = 'E'` byte that triggers Exit).
6. Trigger `free()` with controlled `rdi` → `setcontext` → ORW ROP.

---

### Path E — Side-Channel Flag Leak (Byte-at-a-time)

**Used by:** Solution 369, 1351

After gaining ROP, instead of directly outputting the flag:
1. `open` + `read` the flag into memory.
2. Use comparison gadgets (`cmp byte ptr [rax], dl; ret`, `setbe al; ret`) to compare each flag byte against a guessed value.
3. Based on the comparison result, either `read` from the socket (hangs waiting for input = flag byte ≥ guess) or trigger EOF (flag byte < guess) → binary search.

This is slower but works even if direct `write` to the socket is unreliable.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Arbitrary null-byte write to libc | V1: size mismatch in data heap creation | Deterministic (mmap offset is fixed) |
| stdin FILE struct overwrite | V1 → `_IO_buf_base` LSB cleared | Deterministic |
| libc base leak | V2: uninitialized stack in `strdup` | ~50% per connection (treap depth) |
| `_IO_buf_end` extension | Overwrite via corrupted stdin buffer | Deterministic after V1 |
| `main_arena` overwrite | Extended stdin buffer reaches `main_arena` | Deterministic after extension |
| Code execution | FSOP (multiple paths: `_dl_open_hook`, `_IO_str_overflow`, `_IO_wstr_finish`, `__free_hook`) | Deterministic after libc leak |
| ORW flag read | ROP chain: `open→read→write(fd=0)` | Deterministic |

## Offsets (libc 2.24-9ubuntu2.2, sha1 4e5dfd83...)

```python
_IO_2_1_stdin_   = 0x3c18c0
_IO_2_1_stdout_  = 0x3c2600
_IO_file_jumps   = 0x3be400
_IO_str_jumps    = 0x3be4c0
_IO_wfile_jumps  = 0x3bdec0
_dl_open_hook    = 0x3c62e0
main_arena       = 0x3c1b00
__malloc_hook    = 0x3c1af0
__free_hook      = 0x3c3788
_IO_stdfile_0_lock = 0x3c3770
setcontext       = 0x48010     # +53 = 0x48045
open / read / write = 0xf8660 / 0xf8880 / 0xf88e0

# Gadgets
mov_rdi_rax_call = 0x6ebbb     # mov rdi, rax; call [rax+0x20]
pop_rdi = 0x1fd7a
pop_rsi = 0x1fcbd
pop_rdx = 0x1b92
pop_rax = 0x3a998
pop_rdx_rsi = 0x116d69
syscall_ret = 0xbc765
ret = 0x937

# Null write target (varies by mmap gap)
# mmap_gap = 0x301000 → S1 = 0x6c28e8
# mmap_gap = 0x314000 → S1 = 0x6d58e8
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `186.md` | D | stdin manipulation → `__free_hook` + `setcontext` | No unsorted bin attack; no FSOP vtable hijack |
| `194.md` | A | `_dl_open_hook` + `setcontext` → ORW | Clean step-by-step explanation |
| `369.md` | B + E | `_IO_str_overflow` + side-channel binary search | Byte-at-a-time flag leak |
| `408.md` | A | `_dl_open_hook` vtable check bypass | Compact exploit |
| `705.md` | B | vtable check bypass via `_dl_find_dso_for_object` + `leave; ret` | Unusual RBP-based pivot |
| `821.md` | A | `_dl_open_hook` + `setcontext` → ORW | Detailed struct layout comments |
| `1155.md` | A | `_dl_open_hook` → `setcontext+53` → ORW | Clean modular exploit |
| `1351.md` | B + E | `_IO_str_overflow` + side-channel | Binary search with `cmp`/`jb` gadgets |
| `1763.md` | A | `_dl_open_hook` + `setcontext` | Random offset handling |
| `1922.md` | A | `_dl_open_hook` + detailed heap layout | Bilingual (Chinese/English) writeup |
| `2972.md` | B | `_IO_str_overflow` + `setcontext` → ORW | Concise; direct flag output |
| `3498.md` | A | `_dl_open_hook` + `setcontext` | Sparse comments, working exploit |
| `6247.md` | A | `_dl_open_hook` + `setcontext` | Full struct reconstruction |
| `7905.md` | A | `_dl_open_hook` + `setcontext` | Detailed variable naming |
| `8153.md` | C | `_IO_wstr_finish` + `xchg rax,rsp` pivot | Alternative vtable path |
| `31599.md` | A | `_dl_open_hook` + detailed writeup (Chinese) | Most comprehensive analysis |
| `36997.md` | C | `_IO_wfile_jumps` + `call [rdi+0x18]` → `setcontext` | Modern FSOP approach |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (`_dl_open_hook` path) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original binary |
| `solution/*.md` | Community write-ups (39 solutions) |
