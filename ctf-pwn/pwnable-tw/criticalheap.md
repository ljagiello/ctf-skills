---
tags:
  - type-confusion
  - arbitrary-write
  - shellcode
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Type confusion between system and normal heap objects permits modifying structure pointers, granting arbitrary write into an RWX page to execute shellcode."
proof-of-concept: no
---

# criticalheap — pwnable.tw (200 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10500`
>
> Decoy flag: `FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}` (reads directly from file, NOT accepted)
>
> Real flag: `FLAG{Cr1t1c4l_h34p_is_very_cr4zyyyyyyyyyy}` (requires shell)

## Challenge Overview

A heap management program (x86-64, Full RELRO, Canary, NX, **No PIE**, FORTIFY) built against glibc 2.23. It maintains up to 10 entries in a global BSS array (`0x604040`), each 0x48 bytes, in three types: Normal (content + format string), Clock (`localtime()`), and System (`setenv`/`unsetenv`/`getenv`/`realpath`). Menu: `1.Create / 2.Show / 3.Rename / 4.Play / 5.Delete / 6.Exit`.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only at runtime
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
  FORTIFY:  Enabled              # __printf_chk blocks %n and %N$
```

**Key insight:** The challenge description says *"Try to capture `/home/critical_heap++/flag`"* — this file is a **decoy**. The real flag requires a shell to run a setuid `get_flag` binary.

## Data Structures

```c
// Global array at 0x604040, 10 slots of 0x48 bytes each
struct Heap {
    char *name;          // +0x00  strdup'd heap pointer
    uint64_t in_use;     // +0x08
    uint64_t type;       // +0x10  (1=Normal 0x13371337, 2=Clock 0xdeadbeef, 3=System 0x48694869)
    union {              // +0x18
        NormalData normal;
        ClockData  clock;
        SystemData system;
    };
};

struct NormalData {
    char content[0x28];  // +0x18  read() directly into BSS, no NUL termination
    uint64_t is_changed; // +0x40  prevents second change
};

struct SystemData {
    char *dirname;       // +0x18  get_current_dir_name() result
    uint64_t detail;     // +0x20  getenv() stores result pointer here
    // ...
};
```

## Vulnerabilities

### V1 — Format String via `__printf_chk` (Primary, Arbitrary Read)

**Root Cause:** `Play → Normal → 1.Show content` calls `__printf_chk(1, content)` where `content` is user-controlled (stored at slot+0x18 in BSS).

```c
// Pseudocode for play_normal_show
__printf_chk(1, &slot[idx].content);  // content is user-supplied format string
```

**Constraints:** FORTIFY mode blocks `%n` (write) and `%N$` (positional arguments). However, `%c`, `%p`, `%s`, `%x` still work for reading.

**Exploitation:** `Play → Normal → 2.Change content` reads input into a stack buffer (`local_38`) then copies to BSS content. The `p64(target_addr)` placed after format specifiers lands on the stack as the 12th-13th argument:

```python
payload = b'%c' * 11 + b'%s' + p64(target_addr)   # %s reads string at target_addr
```

**Impact:** Arbitrary memory read. Combined with No PIE, this can leak heap pointers, libc addresses (from GOT), and flag data.

### V2 — `read()` Without NUL Termination (Heap/Info Leak)

**Root Cause:** Normal heap content is read via `read(0, &slot.content, 0x28)` with no NUL byte appended. The content field is 0x28 bytes, and `Show heap` (option 2) prints it with `printf("%s", content)`.

```c
read(0, slot + 0x18, 0x28);  // No NUL terminator
// Later: printf("%s", slot + 0x18);  // reads past content into adjacent data
```

**Impact:** If content fills all 0x28 bytes, `printf("%s")` leaks data beyond the content boundary — typically a heap pointer left from a previous System heap's `getenv()` result stored at +0x20.

### V3 — Delete Does Not Clear Data (UAF / Type Confusion)

**Root Cause:** `Delete` only sets `slot.in_use = 0`. It does **not** free the `name` pointer, zero the content, or reset the type. A subsequent `Create` at the same index reuses the BSS slot with stale data from the previous entry.

```c
// delete_heap
slot[idx].in_use = 0;   // that's it — no free(), no memset()
```

**Impact:** Creating a Normal heap in a slot previously occupied by a System heap leaves the System heap's data (including heap pointers from `getenv()`) at offsets that overlap with Normal content. Reading the Normal content leaks heap addresses.

### V4 — `localtime()` / TZ Environment Variable File Read (The "Secret")

**Root Cause:** Creating a Clock heap calls `localtime()`, which internally calls `tzset_internal()` → `__tzfile_read()`. When the `TZ` environment variable is set to a file path, glibc opens and reads that file as timezone data, storing its contents on the heap.

```c
// glibc tzset.c (simplified)
tz = getenv("TZ");
__tzfile_read(tz, 0, NULL);  // opens TZ as a file path, reads into heap

// tzfile.c
f = fopen(file, "rce");      // opens the flag file!
fread(...);                   // reads contents into malloc'd buffer
```

**Impact:** Setting `TZ=/home/critical_heap++/flag` (or using `TZDIR=/home/critical_heap++` + `TZ=flag`) and triggering `localtime()` loads the flag file's contents into heap memory. Combined with V1 (format string read), this leaks the flag without needing a shell.

### V5 — `realpath()` Heap Overflow (Shell Path Only)

**Root Cause:** `Play → System → 3.Get real path` calls `realpath(buf, buf)` with the **same buffer** as both source and destination. When `buf` contains a short relative path like `"."`, the resolved absolute path overwrites and extends past the original buffer's allocation.

**Prerequisites:** Set `PWD="."` via `setenv` (after `unsetenv("PWD")` since the remote `PWD=/`). The System heap's `dirname` field (from `get_current_dir_name()`) returns `"."` when `PWD="."`.

**Impact:** Overwrites adjacent heap chunk metadata (size field), enabling fastbin corruption for arbitrary write. This is the critical primitive needed for the **shell path** (see Path B below).

## Exploit Paths

### Path A — TZ File Read + Format String Leak (Flag Only, No Shell)

**Used by:** ~90% of solutions (59, 194, 278, 550, 821, 1351, 2315, 2797, 3480, 3851, 8410, 8942, 11540, 18331, 21490, 24887, 29544, 31599, 34817, 36997)

**Steps:**

1. **Leak heap address (V2 + V3):**
   - Create a System heap at slot 0. Use `setenv`/`getenv` to store a heap pointer at +0x20.
   - Delete slot 0 (data remains). Recreate slot 0 as Normal with 8 bytes of content.
   - `Show heap` on slot 0: content (8 bytes) + stale pointer at +0x20 = heap leak.
   - `heap_base = leaked_ptr - offset` (offset varies: 0x30, 0x50, 0x62, 0x142, 0x145 depending on allocation order).

2. **Set TZ to flag path (V4):**
   - Create a System heap. Use `setenv("TZ", "/home/critical_heap++/flag")`.
   - Some solutions also set `TZDIR=/home/critical_heap++` and `TZ=flag` or `TZ=:./flag`.

3. **Trigger `localtime()` to read flag into heap:**
   - Create a Clock heap → `localtime()` reads the flag file into a heap buffer.

4. **Leak flag with format string (V1):**
   - Create/reuse a Normal heap. Change content to a format string payload:
     ```python
     payload = b'%c' * 11 + b'%s' + p64(heap_base + flag_offset)
     ```
   - `Play → Normal → Show` triggers `__printf_chk(1, payload)` → `%s` dereferences the flag address → flag printed.
   - Flag offset from heap base varies (~0x320 to 0x5e0 depending on environment).

**Result:** Prints `FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}` — this is the **decoy flag**. Submitting it gets accepted on the platform for this challenge (criticalheap, 200 pts), but the real challenge (criticalheap++, 600 pts) shares the same binary and requires a shell.

**Reliability:** Some solutions brute-force the flag offset in 0x10 increments since the exact heap layout depends on the number of environment variables at process start.

---

### Path B — Format String + realpath Overflow → Fastbin Attack → Shell

**Used by:** Solution 1162 (detailed), 7905 (partial reference)

This is the **criticalheap++ (600 pts)** path that obtains a real shell:

1. **Leak libc via GOT (V1):** Use format string `%c*11 + %s + p64(puts@GOT)` to read `puts` address from the fixed GOT (No PIE) → `libc_base`.

2. **Leak heap address (V2):** Same as Path A step 1.

3. **Manufacture a freed 0x70 fastbin chunk:**
   - First `localtime()` reads `/etc/localtime` (Etc/UTC), allocating a timezone data chunk.
   - `setenv("TZ", "z"*0x40)` changes TZ; next `localtime()` call (`Update time`) frees the old timezone chunk → enters `fastbin[5]` (size 0x70).

4. **`realpath()` overflow (V5):** Corrupt the freed chunk's size to create an overlapping region.

5. **Fastbin attack → `__malloc_hook`:**
   - Rename a heap whose name chunk overlaps the freed 0x70 chunk → overwrite `fd` to `__malloc_hook - 0x23` (fake chunk with size byte `0x7f`).
   - Two allocations: first returns the real chunk, second returns the fake chunk at `__malloc_hook - 0x13`.
   - Write `one_gadget` to `__malloc_hook` via rename.

6. **Trigger `__malloc_hook`:** Any `malloc` call (e.g., `strdup` during Create) fires the one_gadget → shell.

7. **Get real flag:**
   ```bash
   cd /home/critical_heap++ && echo 'Crazy heap !!' | ./get_flag
   # FLAG{Cr1t1c4l_h34p_is_very_cr4zyyyyyyyyyy}
   ```

**Reliability:** Requires matching heap layout between local and remote. Environment variables affect layout significantly; solution 1162 dynamically calculates offsets using format string reads.

---

### Path C — Stack Leak + Format String (No Heap Leak Needed)

**Used by:** Solution 34817

1. **Leak stack address (V2):** Show a Normal heap with a long name (0x28 bytes). The `printf("%s")` in `Show heap` leaks past the name into stack frame data, revealing a stack pointer.

2. **Set TZ and trigger `localtime()`:** Same as Path A steps 2-3. The flag file content is read to the stack frame of `__tzfile_read`.

3. **Format string read from stack:** Calculate `flag_stack_addr = leaked_stack - known_offset`. Use the format string to read from this stack address.

**Limitation:** The stack offset between the leak and the flag data varies between local and remote environments, making this approach fragile.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Heap address leak | V2 + V3: content overflow + stale data | Deterministic |
| Arbitrary memory read | V1: `__printf_chk` format string with `%s` | Deterministic |
| Flag file → heap | V4: TZ env + `localtime()` tzfile read | Deterministic |
| libc leak | V1: format string read on GOT (No PIE) | Deterministic |
| Heap overflow | V5: `realpath(buf, buf)` | Deterministic (requires PWD=".") |
| Arbitrary write | V5 → fastbin corruption → `__malloc_hook` | Environment-dependent |

## Key Offsets

```python
# Fixed addresses (No PIE)
heap_array    = 0x604040       # global BSS array of 10 Heap structs
puts_got      = 0x603f40       # for libc leak

# glibc 2.23 (pwnable.tw remote libc)
system        = 0x45390        # or 0x46390 depending on exact build
one_gadgets   = [0x45216, 0xef6c4, 0xf0567]
__malloc_hook = libc_base + 0x3c3b10
__free_hook   = libc_base + 0x3c57a8

# Heap offsets (vary with environment variable count)
flag_offset   = 0x320 ~ 0x5e0  # from heap_base to flag data after localtime()
```

## The Decoy Trap

The flag file at `/home/critical_heap++/flag` contains `FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}` — note the self-referential name *"Oh you find the secret in localtime"*. This is intentionally planted as a decoy. The platform accepts it for the **criticalheap (200 pts)** problem, but the companion **criticalheap++ (600 pts)** requires obtaining a shell and running the setuid `get_flag` binary with the passphrase `"Crazy heap !!"` to get the real flag.

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | A | TZ + fmt string | Brief; notes decoy awareness |
| `194.md` | A | TZ + fmt string, brute flag offset | Scans heap range 0x400-0x600 |
| `278.md` | A | TZDIR + TZ, Ruby exploit | Includes PoC of TZ file read with strace |
| `550.md` | A | TZ + fmt string, GOT libc leak | Detailed struct layout; sets TZDIR |
| `821.md` | A | TZ + fmt string | Uses `%s` with GOT leak for heap pivot |
| `1162.md` | B | realpath overflow → fastbin → shell | Full shell exploit; `_IO_list_all` hijack |
| `1351.md` | A | TZ via `/proc/self/cwd/flag` | Compact solution |
| `2315.md` | A | TZ + fmt string, detailed vuln analysis | Best writeup; struct layouts + glibc source refs |
| `2797.md` | A | TZDIR + TZ + fmt string | Uses `%c`*12 + `%s` |
| `3480.md` | A | TZ + fmt string | Also leaks libc via GOT |
| `3851.md` | A | TZ + fmt string, getenv leak | Detailed; two leak phases |
| `4082.md` | A | TZ + fmt string (Chinese) | Thorough struct analysis with screenshots |
| `7905.md` | B (partial) | Notes decoy; references criticalheap++ | Detailed analysis of real vs decoy flag |
| `8153.md` | A | TZ + fmt string | Sets TZDIR separately |
| `8410.md` | A | TZ + fmt string, `%p`*5 heap leak | Compact |
| `8942.md` | A | TZ + fmt string, EMT padding | Brute-forces heap offset range |
| `11540.md` | A | TZ + fmt string, `%p`*12 `%s` | Clean remote exploit |
| `18331.md` | A | TZ + fmt string, content overflow leak | Standard approach |
| `21490.md` | A | TZ + fmt string (Chinese) | Good analysis of localtime internals |
| `24887.md` | A | TZ + fmt string, auto-increment offset | Retries with offset += 8 |
| `29544.md` | A | TZ + fmt string, content overflow | Standard approach |
| `31599.md` | A | TZ + fmt string, `%p`*12 + `%s` | Leak via content overflow |
| `34817.md` | C | Stack leak + fmt string | No heap leak; reads flag from stack |
| `36997.md` | A | TZ + fmt string, brute offset | Retries with offset += 0x10 |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (Path A) |
| `desc.txt` | Challenge description |
| `artifacts/critical_heap.tar.gz` | Original challenge binary + Docker env |
| `solution/*.md` | Community write-ups (36 solutions) |
