---
tags:
  - logic-flaw
  - file-descriptor-leak
  - command-injection
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "Exploiting leaked file descriptors and internal bash builtins enables escaping restricted execution mode to execute privileged binaries."
proof-of-concept: no
---

# Bash Revenge — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> There is an old version bash with some vulnerabilities, such as CVE-2016-9401.
> Can you develop a 1-day exploit for this challenge? :p
>
> `nc chall.pwnable.tw 10407`
>
> Flag: `FLAG{us3_4ft3r_fr33_1n_bash_1s_p0w3rful}`

## Challenge Overview

You connect to a `chroot`-jailed bash 4.3.0(2) shell on x86-64. The jail contains **only bash and its libraries** — no `cat`, `ls`, `id`, or any other binary. The flag is at `/flag`, root-owned and outside the chroot. A separate root xinetd service on `127.0.0.1:1337` serves the flag via `/bin/cat /flag`. Bash is built **without `/dev/tcp` support**, so the only way to get the flag is to gain **arbitrary code execution** inside bash and use raw `socket()`/`connect()` syscalls to reach the loopback flag service.

```
bin/bash:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)    # Fixed addresses in .text/.bss/.got
  NOT stripped
  Uses bash's OWN internal allocator (lib/malloc/malloc.c), NOT glibc malloc

libc: Ubuntu 16.04 glibc 2.23-0ubuntu10
```

## Key Data Structures

### Bash Internal Malloc Chunk Header

Bash uses its own `malloc` implementation with a custom chunk format:

```c
union mhead {
  bits64_t mh_align;              // 8 bytes total
  struct {
    char     mi_alloc;            // 0xf7 = ISALLOC, 0x54 = ISFREE
    char     mi_index;            // bucket index in nextf[]
    u_bits16_t mi_magic2;         // must be 0x5555
    u_bits32_t mi_nbytes;         // size of user data
  } minfo;
};
// Trailing guard: u_bits32_t == mi_nbytes (size footer)
```

A valid allocated chunk header for a 0x30-byte allocation in bucket 3 is the single qword **`0x30555503f7`**.

### SHELL_VAR Structure

```c
typedef struct variable {
  char *name;                        // +0x00
  char *value;                       // +0x08  → arbitrary read target
  char *exportstr;                   // +0x10
  sh_var_value_func_t *dynamic_value;// +0x18  → called on $VAR expansion
  sh_var_assign_func_t *assign_func; // +0x20  → called on VAR=value
  int attributes;                    // +0x28
  int context;                       // +0x2c
} SHELL_VAR;                         // sizeof = 0x30
```

## Vulnerabilities

### V1 — CVE-2016-9401: `popd` OOB Free (Primary, Exploitable)

**Root Cause:** In `builtins/pushd.def`, `popd_builtin` accepts `popd +-N` where N is parsed by `legal_number` which allows **negative values**. The bounds check only rejects `which > offset`, so negative `which` passes:

```c
// pushd.def:popd_builtin
i = (direction == '+') ? directory_list_offset - which : which;
free(pushd_directory_list[i]);   // line 384 — OOB index
```

If `pushd` was never called, `pushd_directory_list == NULL`, so:

```
popd +-N  →  free( *(void**)(8 * N) )
```

This is **`free()` on a pointer stored at an arbitrary, attacker-chosen, fixed address**. Since bash is non-PIE, the target can be any fixed `.bss`/`.data` address.

**Impact:** Arbitrary free of any pointer reachable via a fixed address. This is the sole entry point for the entire exploit — every solution builds on this primitive.

### V2 — NUL-Byte Injection via `localbuf` (Enabler)

**Root Cause:** Bash reads raw command input into the global `char localbuf[128]` at fixed address `0x6b7c40`. This buffer stores the raw bytes from `read()`, **including NUL bytes**, which are later ignored by the command parser.

**Impact:** An attacker can craft a command whose raw bytes contain a **forged malloc chunk** (with NUL-byte metadata) at a known address. This is critical because bash's string operations normally can't produce NUL bytes, and the allocator requires specific magic bytes in the header.

### V3 — NUL-Byte Injection via `printf`/`echo -ne` (Enabler)

**Root Cause:** `printf` and `echo -ne` interpret `\x00` escape sequences and write NUL bytes to stdout. Stdout is **buffered**, so the output accumulates in a heap buffer at a predictable offset from the heap base.

**Impact:** Arbitrary binary data (including NUL bytes) can be written to the stdout buffer on the heap, enabling fake chunk construction without `localbuf`.

### V4 — Heap Leak via Freed BSS Pointers (Enabler)

**Root Cause:** Several global BSS pointers (`ps1_prompt`, `ps2_prompt`, `the_current_wd`, `dollar_vars[1]`, etc.) point to heap-allocated strings. Freeing them via V1 replaces the string data with a free-list `next` pointer. Reading the variable back (e.g., `echo $PS2`, `echo $1`, `pwd`) leaks the heap address.

### V5 — `/proc/self/maps` Leak (Alternative, "Bash Revenge" only)

**Root Cause:** In the "Bash Revenge" variant (port 10407), `/proc` is accessible. `cat /proc/$$/maps` directly leaks heap base and libc base.

## Exploit Paths

All solutions share the same core flow: **V1 (arbitrary free) → fake chunk → reclaim as controlled structure → arb read + RIP hijack → ROP → shellcode → socket to flag service**. They differ in how they plant the fake chunk, what structure they reclaim, and how they achieve code execution.

---

### Path A — `localbuf` Fake Chunk → SHELL_VAR Reclaim → `setcontext` ROP

**Used by:** Solutions 370 (exp.py), 1428, 2311, 2972, 3498, 7905, 8153, 15989, 36714

**Steps:**

1. **Plant fake chunk in `localbuf`:** Send a raw command whose bytes at offset `+0x30` or `+0x40` form a valid bash-malloc chunk header (`0x30555503f7`) + body + size footer. The chunk sits at a known fixed address.

2. **Free the fake chunk via V1:** `popd +-(localbuf_offset/8)` dereferences a pointer stored in `localbuf` (planted in step 1) and frees it, inserting the fake chunk into bash's free list.

3. **Reclaim with SHELL_VAR:** Trigger a variable assignment (e.g., `A=B C=D`) which allocates a `SHELL_VAR` struct via `new_shell_variable()`. The allocation reuses the freed fake chunk, placing the struct inside `localbuf`.

4. **Arbitrary read (libc leak):** Overwrite the SHELL_VAR's `value` pointer (at `+0x08`) with a GOT entry (e.g., `read@got = 0x6b2288`). Running `echo $C` prints the GOT value → libc base.

5. **RIP hijack via `dynamic_value`:** Set the SHELL_VAR's `dynamic_value` pointer (at `+0x18`) to `gets` or `setcontext+53`. Expanding `$VAR` calls `dynamic_value(var_ptr)`, giving control of RIP with `rdi` pointing to the struct.
   - **`gets` stage:** `dynamic_value = gets` → reads a `setcontext` ucontext frame + ROP chain into `localbuf`.
   - **`setcontext+53` stage:** Stack-pivots via the ucontext frame into the ROP chain.

6. **ROP → shellcode:** `read(0, bss, N)` then `mprotect(bss, 0x1000, RWX)` then jump to shellcode.

7. **Shellcode:** Raw syscalls: `socket(AF_INET, SOCK_STREAM, 0)` → `connect(fd, {127.0.0.1:1337}, 16)` → `read(fd, buf, 0x100)` → `write(1, buf, 0x100)`.

---

### Path B — `printf` Stdout Buffer Fake Chunk → SHELL_VAR

**Used by:** Solutions 821, 1351, 2311 (bash variant), 9251, 22319, 26957, 28605, 28652, 31599, 33090

**Steps:**

1. **Leak heap:** Free a BSS pointer (e.g., `ps1_prompt`, `ps2_prompt`, `the_current_wd`, `$1`) via V1, then read back the freed value to get a heap pointer.

2. **Plant fake chunk on heap:** Use `printf "\x00...\xf7\x03\x55\x55..."` or `echo -ne` to write a forged chunk into the stdout buffer at `heap_base + 0x2808` (predictable offset).

3. **Free the fake chunk:** Calculate the fake chunk's address on the heap, plant a pointer to it in a known location, and free via V1.

4. **Reclaim and exploit SHELL_VAR:** Same as Path A steps 3-7, but the controlled memory is on the heap instead of in `localbuf`.

Some solutions use `printf`-based overwrite in a loop: after reclaim, `printf` overwrites the SHELL_VAR fields directly since the struct lives inside the stdout buffer.

---

### Path C — Array Element / JOB Struct Hijack

**Used by:** Solutions 1351, 22319, 35463, 36714

**Variant approach:** Instead of (or in addition to) SHELL_VAR, reclaim the fake chunk with:

- **Array elements:** Bash arrays store `{int64_t index; char *value; ...}`. Confusing an array element with a struct that has a `char *name` at offset 0 gives arbitrary read via the array index. Solutions 1351 and 22319 use `arr[N]=value` with a crafted index to trigger `assign_func` or `bind_array_var_internal`.

- **JOB structs:** Background jobs (`cmd &`) allocate JOB structs with function pointers (`j_cleanup`). Freeing a fake chunk and having a JOB struct reclaim it gives RIP control when the job is cleaned up. Solutions 22319 and 35463 use `jobs` builtin to leak via the command string pointer, then trigger cleanup.

---

### Path D — `tilde_expansion_preexpansion_hook` / `longjmp` Hijack

**Used by:** Solutions 2972, 36714

**Alternative RIP hijack methods:**

- **`tilde_expansion_preexpansion_hook`:** A function pointer in BSS that's called when `~` is expanded. Overwrite it via the fake-chunk-in-printf-buffer technique, then trigger with `~AAAA...` (long tilde expansion). RDI/RSI/RDX are partially controlled by input length.

- **`top_level` longjmp buffer:** Read the `top_level` jmp_buf at `0x6B90E0`, extract the XOR key used by glibc's pointer guard (`PTR_MANGLE`), encrypt a new RBP/RSP/RIP, overwrite the buffer, and trigger `exit 0` → `longjmp(top_level)` → stack pivot into ROP.

---

### Path E — GOT Overwrite via `printf -v` / Free-List Manipulation

**Used by:** Solution 1428

**Steps:**

1. Free chunks to get them onto the free list.
2. Use `printf -v varname` to allocate and write controlled data into free-list next pointers.
3. Chain allocations to eventually place a controlled value at a GOT entry (e.g., `dcgettext@got → add_ret_gadget`).
4. When bash calls the GOT function, it hits the gadget, which calls `gets` to read a full ROP chain.

---

### Path F — `/proc/self/maps` Direct Leak (Bash Revenge Only)

**Used by:** Solution 1351 (bash revenge variant)

On port 10407, `/proc` is mounted:

```bash
cat /proc/$$/maps
```

This directly leaks heap base and libc base, skipping the heap-leak step entirely. The rest of the exploit follows Path B.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Arbitrary free at fixed address | V1: CVE-2016-9401 `popd +-N` | Deterministic |
| Fake chunk at known address | V2: `localbuf` or V3: `printf` stdout buf | Deterministic |
| Heap address leak | V4: Free BSS pointer, read back | Deterministic |
| libc leak | GOT read via SHELL_VAR `value` ptr | Deterministic |
| Stack leak (optional) | Read `shell_environment` or `__environ` | Deterministic |
| RIP control | SHELL_VAR `dynamic_value`/`assign_func` | Deterministic |
| Code execution | `setcontext+53` → ROP → `mprotect` → shellcode | Deterministic |
| Flag exfil | Shellcode: `socket`→`connect`→`read`→`write` | Deterministic |

## Offsets (libc 2.23-0ubuntu10, amd64)

```python
# bash binary (non-PIE)
localbuf       = 0x6b7c40
read_got       = 0x6b2288
snprintf_got   = 0x6b2030
stdin_bss      = 0x6b5110
ps1_prompt     = 0x6b86d8   # (varies by solution)
the_current_wd = 0x6b7ec0
dollar_vars    = 0x6b8920

# libc offsets
read           = 0xf7250
gets           = 0x6ed80
setcontext     = 0x47b75    # +53 for the register-loading gadget
mprotect       = 0x101770
pop_rdi        = 0x21102
pop_rsi        = 0x202e8
pop_rdx        = 0x1b92
pop_rax        = 0x33544
syscall_ret    = 0xbc375
```

## Solution Write-ups

| File | Primary Path | Heap Leak Method | RIP Hijack | Notes |
|------|-------------|------------------|------------|-------|
| `370.md` | A | `the_current_wd` free | `setcontext` + ROP | Two scripts; connect-back shellcode |
| `821.md` | B | `$1` free + `printf` | `setcontext` + ROP | Disabled history for heap stability |
| `1351.md` | B + F | `/proc/self/maps` (revenge) / brute heap (bash) | `setcontext` via array assign | Two variants for both ports |
| `1428.md` | A | `localbuf` | `setcontext` via `dynamic_value` | Clean write-up; explains NUL-byte trick |
| `2311.md` | A + E | `localbuf` | `gets` → `setcontext` | Detailed format; also describes Bash (200pt) |
| `2972.md` | D | stack/heap leak via `printf -v` | `tilde_expansion_hook` | Uses nested functions for stack depth |
| `3148.md` | B | `ps1_prompt` free | `setcontext` + ROP | Concise; `echo -ne` for NUL bytes |
| `3498.md` | A | `the_current_wd` free | stack pivot via `xchg edi,esp` | Detailed chunk metadata documentation |
| `6748.md` | B | array element spray | `setcontext` + ROP | Uses `printf` buffer spray + array free |
| `7905.md` | A | `dollar_vars` free | `setcontext` + mmap + shellcode | Extensive BashInterface class |
| `8153.md` | A | `localbuf` + GOT leak | `gets` → `setcontext` | Detailed writeup with Docker repro |
| `9251.md` | B | `$0` free + `echo -ne` | `setcontext` via JOB cleanup | Also tried array type confusion |
| `15989.md` | B | `current_host_name` free | `setcontext` via JOB struct | Uses `echo -ne` for heap writes |
| `22319.md` | C | `export` spray + free | `gets` via JOB `j_cleanup` | Leaks via coproc + `jobs` |
| `26957.md` | B | `popd` heap leak | `setcontext` via HIST struct | Uses history objects for reclaim |
| `28605.md` | B | `PS2` free | `xchg edi,esp` stack pivot | 14-chunk heap spray |
| `28652.md` | B | `the_current_wd` | `setcontext` via SHELL_VAR | Uses `read -e -N 128` for `lbuf` NULs |
| `31599.md` | B | `export` leak | `setcontext` via SHELL_VAR | Array-based free for heap chunk |
| `33090.md` | B | `printf` heap write | `setcontext` + `$leak1` | Uses `printf -v` trick for NUL data |
| `35463.md` | C | `C_ENV` spray + free | `gets` via JOB | Extensive automation with coproc |
| `36714.md` | D | `pushd` + var alloc | `longjmp` buffer overwrite | Unique approach: encrypt new jmp_buf |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (localbuf fake chunk approach) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original challenge tarball (`bash_revenge.tgz`) |
| `solution/*.md` | Community write-ups (21 solutions) |
