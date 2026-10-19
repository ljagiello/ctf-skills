---
tags:
  - type-confusion
  - use-after-free
  - arbitrary-write
platform: pwnable.tw
points: 600
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Polymorphic C++ object destruction without virtual destructors leads to dangling pointer reuse and type confusion, achieving arbitrary memory write."
proof-of-concept: no
---

# Critical Heap++ — pwnable.tw (600 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10500`
>
> Flag: `FLAG{Cr1t1c4l_h34p_is_very_cr4zyyyyyyyyyy}`
>
> Note: A decoy flag `FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}` can be read via the `localtime()`/TZ trick without a shell. The real flag requires shell → running the setuid `get_flag` binary with passphrase `"Crazy heap !!"`.

## Challenge Overview

A heap management program (x86-64, **Full RELRO**, Canary, NX, **no PIE** base `0x400000`) linked against glibc 2.23. It maintains up to 10 heap slots (in a BSS array at `0x604040`, each `0x48` bytes) with three types: Normal, Clock, and System. The binary contains **no explicit `free()` calls** — all heap frees happen indirectly through libc internals (`setenv`/`realloc`, `localtime`/`tzset`, `realpath`).

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
```

### Heap Types

| Type | Magic | Capabilities |
|------|-------|-------------|
| Normal (`1`) | `0x13371337` | Show/Change content (format-string-vulnerable `printf`), name buffer |
| Clock (`2`) | `0xdeadbeef` | Show/Update time (`localtime()` → triggers `tzset()` → frees old TZ) |
| System (`3`) | `0x48694869` | `setenv`/`unsetenv`/`realpath`/`getenv` — interacts with libc heap internals |

### Menu

`1.Create / 2.Show / 3.Rename / 4.Play / 5.Delete / 6.Exit`

## Vulnerabilities

### V1 — `realpath(buf, buf)` Heap Buffer Overflow (Primary, Exploitable)

**Root Cause:** When playing a System heap, option 3 ("Get real path") calls `realpath(path, path)` where `path` is the same heap buffer for both source and destination. When `path` is a short relative path like `"."`, `realpath` resolves it to the full absolute path (e.g., `"/home/critical_heap++/home"` — 26 bytes) and writes back into the same small buffer, **overflowing into the next heap chunk's metadata**.

```c
// Simplified from decompilation
char *path = entry->cwd;  // from get_current_dir_name(), can be "."
realpath(path, path);      // source == destination → overflow
```

**Trigger:** Set `PWD="."` via `unsetenv("PWD")` + `setenv("PWD", ".")`, then create a System heap (which calls `get_current_dir_name()` — returns `strdup(".")` when `PWD` matches `.`). Call `realpath` on it.

**Impact:** Overwrites the `size` field of the adjacent free chunk with `0x656d` (ASCII `"me"` from `/home/critical_heap++/ho**me**`). This creates a massively oversized free chunk that spans far beyond its actual allocation, enabling controlled overlapping allocations.

```c
// PoC demonstrating the overflow:
setenv("PWD", ".", 1);
char *c = get_current_dir_name();  // returns "." (malloc'd, tiny chunk)
// allocate victim right after
char *victim = malloc(1);          // victim chunk size = 0x21
realpath(c, c);                    // overflow! writes "/home/critical_heap++/home"
// victim chunk size is now 0x656d
```

### V2 — Format String Read via Normal Heap (Exploitable)

**Root Cause:** `Play → Normal → 1.Show content` calls `__printf_chk(1, content)` where content is user-controlled. Although FORTIFY blocks `%n` and positional `%N$`, sequential `%c`/`%p`/`%s` still work for reading.

```c
// User controls content via "Change content"
__printf_chk(1, content);  // format string vuln — arbitrary read
```

**Trigger:** Set content to `"%c"*11 + "%s" + p64(target_addr)`. The `%s` reads from the target address (placed on the stack via the `read()` → `strncpy()` path).

**Impact:** Arbitrary memory read. Used to leak:
- **libc base** (read GOT entries like `atoi@GOT` at fixed addresses since no PIE)
- **heap addresses** (read residual pointers from name/content buffers)
- **stack addresses** (read `environ` pointer from libc)

### V3 — `localtime()`/`tzset()` Controlled Free (Enabler)

**Root Cause:** When `TZ` environment variable changes, `tzset()` (called by `localtime()`) frees the old timezone data buffer and allocates a new one. By controlling `TZ`, we control the size of freed chunks.

```c
// Inside glibc tzset/localtime:
tz = getenv("TZ");
free(old_tz);                    // frees old TZ strdup
old_tz = tz ? __strdup(tz) : NULL;
```

**Impact:** Create fastbin chunks of specific sizes (notably 0x70) by:
1. `setenv("TZ", "A"*0x60)` — allocates 0x70 chunk for TZ data
2. Update Clock heap → `localtime()` → `tzset()` reads new TZ → frees the old 0x70 chunk

### V4 — `setenv`/`realloc(environ)` Controlled Alloc/Free (Enabler)

**Root Cause:** glibc's `setenv` uses `realloc` on the internal environ array. Adding/removing environment variables triggers `realloc` which frees old buffers and allocates new ones, creating unsorted bin chunks of controllable sizes.

**Impact:** Combined with V1, enables precise heap layout control — place free chunks where the `realpath` overflow can reach them.

### V5 — Name Buffer Leak on Show (Minor)

**Root Cause:** `Show` prints the heap name using `printf("%s", name)`. Since `strdup` may place the name chunk adjacent to other data, and the name isn't always NUL-terminated at the exact boundary, adjacent heap metadata (including libc pointers from free chunks) can leak.

## Exploit Paths

### Path A — `realpath` Overflow → Fastbin Attack → `__malloc_hook` (Most Common)

**Used by:** Solutions 11, 59, 370, 678, 755, 1351, 1912, 1980, 2972, 3851, 7905, 34817, 38838, exp.py

**Steps:**

1. **Leak libc** via V2 (format string read of GOT entry) or V5 (name buffer adjacency to freed chunks).

2. **Create a 0x70 fastbin chunk** via V3: set `TZ` to a 0x60-byte string, create a Clock heap, then change `TZ` to `":"` and update time → `localtime()` → `tzset()` frees the old 0x70 TZ chunk.

3. **Trigger V1 (`realpath` overflow):** Prepare `PWD="."`, create a System heap to get a tiny `cwd` buffer, call `realpath` → overflows into the adjacent free chunk, corrupting its `size` to `0x656d`.

4. **Allocate from the corrupted chunk:** The 0x656d-sized free chunk enters unsorted bin. Subsequent `malloc` calls carve pieces from it, eventually producing a chunk that **overlaps the 0x70 fastbin chunk**.

5. **Fastbin poisoning:** Use `Rename` to overwrite the overlapping 0x70 chunk's `fd` pointer to `__malloc_hook - 0x23` (where a `0x7f` byte exists as a fake chunk size).

6. **Allocate twice from fastbin:** First `malloc(0x60)` returns the real 0x70 chunk. Second returns the fake chunk at `__malloc_hook - 0x13`.

7. **Overwrite `__malloc_hook`:** `Rename` the fake chunk: `"\x00"*3 + p64(one_gadget)` writes `one_gadget` to `__malloc_hook`.

8. **Trigger:** Any subsequent `malloc` (e.g., `Create` a new heap → `strdup(name)`) calls `__malloc_hook` → one_gadget → shell.

```python
# Core fastbin attack payload
rename(name_chunk, 'X'*offset + p64(0) + p64(0x71) + p64(__malloc_hook - 0x23))
# ... two mallocs of 0x60 ...
rename(fake_chunk, '\x00'*3 + p64(one_gadget))
```

### Path B — `realpath` Overflow → Unsafe Unlink → BSS Overwrite → FSOP/`stdout` Hijack

**Used by:** Solutions 278, 550, 755

**Steps:**

1. **Leak libc + heap** via V2 (format string).

2. **Trigger V1** to corrupt an unsorted bin chunk's size.

3. **Allocate from the corrupted chunk** to overlap with an `environ` array buffer (from `setenv` → `realloc`). Forge fake chunk metadata (fd, bk, size) that pass unlink's `FD->bk == P && BK->fd == P` check, with `fd = 0x604088-0x18` and `bk = 0x604088-0x10` (pointing into the BSS heap slots array).

4. **Trigger unsafe unlink** by calling `setenv` which `realloc`s the environ array → consolidates with the fake chunk → unlink writes `&heap_slots[N].name - 0x18` into `heap_slots[N].name`.

5. **Use `Rename` on slot N** to overwrite other slots in the BSS heap array. Point one slot's name to `stdout` FILE pointer in BSS.

6. **Forge a fake `_IO_FILE_plus`** structure on the heap with `vtable.__xsputn = system` and flags containing `"/bin/sh"`.

7. **Overwrite `stdout`** to point to the fake FILE struct. Next `printf` call → `system("sh")`.

### Path C — `realpath` Overflow → Overlapping Chunks → Unsorted Bin Attack → BSS Allocation → Stack Pivot/ROP

**Used by:** Solutions 550, 755, 821

**Steps:**

1. **Leak libc + heap + stack** via V2.
2. **Trigger V1** overflow, create overlapping chunks.
3. **Corrupt a free chunk's `bk`** to point to a BSS address that has a valid fake size.
4. **Allocate from unsorted bin** — `malloc` returns the BSS address as a chunk. Use `Rename` to overwrite heap slot `name` pointers.
5. **Point a slot's name at the saved RBP** on the stack. `Rename` writes a stack pivot gadget or ROP chain (`pop rdi; ret; "/bin/sh"; system`).
6. When the function returns, control flow is hijacked.

### Path D — `realpath` Overflow → `_IO_list_all` Overwrite → FSOP via `malloc` Abort

**Used by:** exp.py, solution 38838

**Steps:**

1. **Leak libc + heap** via V2 or V5.
2. **Trigger V1** and create overlapping chunks to gain arbitrary write to BSS heap slots.
3. **Forge a fake `_IO_FILE_plus`** on the heap: `flags = "/bin/sh\0"`, `_IO_write_base < _IO_write_ptr` (to satisfy overflow check), `vtable` pointing to a fake vtable with `__overflow = system`.
4. **Overwrite `_IO_list_all`** to point to the fake FILE struct.
5. **Trigger `malloc` abort** (e.g., double-free or corruption) → `_IO_flush_all_lockp` → walks `_IO_list_all` → calls `__overflow` on the fake FILE → `system("/bin/sh")`.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Heap overflow (corrupt next chunk size to 0x656d) | V1: `realpath(buf, buf)` | Deterministic |
| Arbitrary memory read | V2: Format string in Normal heap | Deterministic |
| Controlled free (0x70 fastbin) | V3: `localtime()`/`tzset()` TZ change | Deterministic |
| Controlled alloc/free (unsorted bin) | V4: `setenv`/`realloc(environ)` | Deterministic |
| libc leak | V2 (GOT read) or V5 (heap adjacency) | Deterministic |
| Fastbin poisoning → `__malloc_hook` | Overlapping chunk + fd overwrite | Deterministic after layout |
| Code execution | `__malloc_hook` = one_gadget / FSOP | Deterministic |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
__malloc_hook  = 0x3c3b10
__free_hook    = 0x3c57a8
_IO_list_all   = 0x3c4520
system         = 0x45390
one_gadgets    = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# For fake fastbin chunk at __malloc_hook:
fake_fast_addr = __malloc_hook - 0x23   # or -0x13 (user data)
# BSS heap slots array
heap_slots     = 0x604040
```

## Post-Shell: Getting the Real Flag

The shell runs as `uid=1000`. The real flag is owned by `uid=1001` with mode `400`:
```
-r-------- 1 1001 1001   43 .You_found_the_fl4g
-r-sr-xr-x 1 1001 1001 9232 get_flag          # setuid 1001
```

Execute: `cd /home/critical_heap++ && ./get_flag` → enter `"Crazy heap !!"` → prints the real flag.

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `11.md` | A | fmt leak + fastbin via overlapping chunk | Ruby exploit |
| `59.md` | A | `%s` GOT leak + realpath overflow + fastbin attack | Clean Python2 |
| `278.md` | B | Unsafe unlink → BSS → `stdout` FSOP | Most complex approach; detailed explanation |
| `370.md` | A | `localtime` free + realpath overflow + fastbin | Two flags noted (decoy + real) |
| `550.md` | C | Two overlapping environ buffers → unsorted bin attack → BSS → stack pivot | Very detailed 8-step writeup |
| `560.md` | A | Node struct manipulation → BSS link → write-anywhere | Uses `tsearch` tree corruption |
| `678.md` | A | Delete+recreate leak + fastbin attack | Compact exploit |
| `755.md` | B+C | Unsafe unlink + tree fix + BSS overwrite → ROP | Detailed with tree node repair |
| `821.md` | A | Multiple realpath triggers + environ manipulation | Uses environ realloc for unsorted bins |
| `1351.md` | A | Various TZ sizes → fastbin sizes + realpath + fastbin attack | Methodical heap arrangement |
| `1912.md` | A | `localtime` free for fastbin + realpath overflow | Format string with `%s` + GOT leak |
| `1980.md` | A | Extensive env manipulation + realpath + FSOP via `__free_hook` | Uses `gets` gadget for `stdout` overwrite |
| `2972.md` | A | Standard fastbin attack | Clean Python3 |
| `3851.md` | A | Heap/libc leak via show + fastbin attack | Verbose with heap layout management |
| `7905.md` | A | Detailed Chinese writeup; documents decoy flag trap | Most thorough analysis; full format string + fastbin |
| `8153.md` | — | One-line note ("realpath overflow") | No exploit code |
| `34817.md` | A | `PWD=../critical_heap++` variant | Uses relative path variant for realpath trigger |
| `38838.md` | D | FSOP via `_IO_list_all` + fake vtable | Uses heap overlap → BSS → `_IO_list_all` overwrite |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (FSOP path via `_IO_list_all`) |
| `desc.txt` | Challenge description |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (24 solutions) |
