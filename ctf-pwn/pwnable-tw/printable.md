---
tags:
  - format-string
  - fini-array-overwrite
  - stack-pivoting
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.23
relro: full
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A single printf call with closed stdout is exploited via 1-byte format string overwrite on stderr, looping execution through stack pivoting."
proof-of-concept: no
---

# Printable — pwnable.tw (400 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> Everything is printable
>
> `nc chall.pwnable.tw 10307`
>
> Flag: `FLAG{FILE_str34m_1s_pr1nt4bl3}`

## Challenge Overview

A minimal x86-64 No-PIE binary with Full RELRO, NX, and no stack canary check. The program reads 0x80 bytes, then `printf`s the buffer as a format string — but `close(1)` is called *before* the format string executes, making the output blind. After `printf`, `exit(0)` is called — the main function never returns.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO          # GOT is read-only
  Stack:    No canary found     # canary exists but exit() is called, never checked
  NX:       NX enabled
  PIE:      No PIE (0x400000)
  libc:     glibc 2.23 (Ubuntu GLIBC 2.23-0ubuntu5)
```

Decompiled `main`:

```c
void main() {
    char buf[0x80];             // rbp-0x90
    init_proc();                // setvbuf(stdin/out/err, ...); alarm(60)
    memset(buf, 0, 0x80);
    printf("Input :");          // flushed to fd1 BEFORE close
    close(1);                   // stdout closed — printf output goes nowhere
    read(0, buf, 0x80);         // 0x80 bytes, no overflow
    printf(buf);                // FORMAT STRING BUG (blind — fd1 is closed)
    exit(0);                    // never returns through main
}
```

Key constraints:
- **Blind format string**: `close(1)` means `printf` output fails to flush. Additionally, `vfprintf` uses a `buffered_vfprintf` helper with a 0x2000-byte stack buffer — once it fills, the failed write to fd1 causes `printf` to bail, capping `%n` writes to ~8192 characters.
- **No return**: `exit(0)` is called, so there's no return address on the main stack to overwrite directly.
- **Full RELRO**: GOT is read-only, `ret2dlresolve` is dead.
- **No PIE**: `.text` and `.bss` addresses are fixed (0x400000, 0x601000).

The binary's `.bss` contains copy-relocated libc FILE pointers:

```
0x601020 : FILE *stdout   → &_IO_2_1_stdout_
0x601030 : FILE *stdin    → &_IO_2_1_stdin_
0x601040 : FILE *stderr   → &_IO_2_1_stderr_
```

## Vulnerability

### V1 — Blind Format String (Primary, Exploitable)

```c
read(0, buf, 0x80);
printf(buf);                // attacker-controlled format string
```

The buffer is at `rsp` when `printf` is called, so user input starts at `%6$`. The 0x80-byte input provides room for format specifiers plus up to 4 embedded pointers (at offsets 0x50–0x78).

**Critical stack arguments:**
- `%23$` — On the second invocation (after gaining a loop), a stack pointer that happens to point at printf's own return address.
- `%25$` / `%60$` — `__libc_start_main` return address → libc leak anchor.
- `%42$` — Pointer into `_dl_fini`'s state (specifically, the `link_map->l_addr` used to compute `fini_array` location). Writable.
- `%53$` — A stack pointer that can be retargeted to point at printf's return address.

## Exploit Paths

The fundamental challenge is the same for all solutions: **gain a printf loop** (since the single-shot format string is blind and exits), then **restore output** (since fd1 is closed), then **leak libc** and **get code execution**.

---

### Path A — `_dl_fini` Hijack → Loop via Fake `fini_array` → stdout→stderr Swap → Leak + ROP

**Used by:** Solutions 8153 (exp.py), 31599, 36233, 36997, 38641, 35917, 11177

**Concept:** `exit()` calls `_dl_fini()` which computes `fini_array = link_map->l_addr + DT_FINI_ARRAY->d_un.d_ptr`. The `link_map` pointer is on the stack at `%42$`. By overwriting `l_addr` (or the fini_array offset), the computed array pointer shifts into writable `.bss`, where we place a function pointer back to `main` (at `0x400925` = after the `close(1)`).

**Steps:**

1. **Redirect `fini_array` into `.bss`:** Write to `%42$` to change `l_addr` so `fini_array + l_addr` points to a `.bss` address (e.g., `0x601000`). Simultaneously write the address of `0x400925` (the `read`+`printf` sequence) at that `.bss` location.

2. **Swap `stdout` → `stderr`:** Partial-overwrite `stdout` pointer at `0x601020` so it points to `_IO_2_1_stderr_` instead of `_IO_2_1_stdout_`. Since they're in the same libc page, only 1-2 low bytes differ. This requires guessing one nibble of libc ASLR → **1/16 probability**.

3. **When `exit()` runs**, `_dl_fini` calls the fake fini_array entry → jumps back to `read(0,buf,0x80); printf(buf)` — now we have a **printf loop** and output goes to `stderr` (fd2 = the socket).

4. **Leak:** Use `%23$p` (or `%57$p`, `%60$p`) to leak a stack address and a libc address.

5. **Shell:** Multiple sub-approaches:
   - **`add rsp, 0x80; ret` gadget**: Overwrite printf's return address with this libc gadget. Place `pop rdi; ret | "/bin/sh" | system` in the buffer at the right offset.
   - **One-gadget**: Overwrite printf's return address with a one-gadget address directly.
   - **Stack pivot to BSS + ROP**: Build a ROP chain in `.bss` via repeated format string writes, then pivot `rsp` there.

**Probability:** ~1/16 per connection (libc nibble guess for `stdout→stderr` swap). Some variants add stack entropy guessing → 1/256 or 1/4096.

---

### Path B — Sequential (Non-Positional) Format String → Retarget Stack Pointer → Loop

**Used by:** Solutions 821, 2311 (brute force version), 3498, 7905, 22319, 15724

**Concept:** glibc's `vfprintf` processes **non-positional** `%` specifiers lazily (one argument at a time), but switches to `printf_positional` (which caches all arguments up front) the moment it sees a positional `%N$` specifier. By carefully placing non-positional writes *before* the first positional write, we can **retarget a stack pointer and then write through it in the same printf call**.

**Steps:**

1. **First payload (sequential trick):** Use 25 `%c` specifiers to advance the argument pointer to arg 26 (which is `argv`, a stack-to-stack pointer). Then `%hn` writes the low 16 bits of `printf`'s return address slot into that pointer, retargeting it. Then use a positional `%53$hhn` to write through the retargeted pointer, changing printf's return address low byte from `0x52` to `0x25` → redirecting to `0x400925` (the `read`+`printf` loop).

2. **Constraint:** The `%hn` value equals `printf_ret & 0xffff`, which must be < 0x2000 (the stdio buffer cap). This means the stack page nibble must be 0 → **1/16**. The low 12 bits of the stack are also randomized → **1/256** additional guess (since return address is 16-byte aligned, low nibble is fixed → 8 bits of entropy).

3. **Subsequent payloads:** Now looping, use positional `%53$hhn` to keep overwriting the return address each iteration. Swap `stdout→stderr` (1/16 if not already done), leak libc/stack, and write a ROP chain or one-gadget to the return address.

**Probability:** 1/4096 to 1/65536 per connection depending on variant.

---

### Path C — `_dl_fini` Hijack → BSS ROP Chain (No Leak Needed)

**Used by:** Solutions 2311 (no-brute version), 2972, 8153

**Concept:** Instead of leaking libc, build a multi-stage ROP chain entirely from the No-PIE binary's gadgets (`__libc_csu_init` pop/call gadgets) to achieve `execve("/bin/sh", 0, 0)`.

**Steps:**

1. **Gain printf loop** via Path A's `fini_array` hijack.

2. **Write ROP chain byte-by-byte into `.bss`** using repeated format string iterations. Each iteration writes one non-zero byte via `%hhn` to a specific `.bss` address.

3. **Pivot:** Overwrite printf's return address with `pop rsp; pop r13; pop r14; pop r15; ret` (`0x4009bd`), targeting `.bss`.

4. **ROP chain uses `__libc_csu_init` gadgets** to call `read(0, bss, large)` for a second-stage payload, then partial-overwrite a libc address in the GOT/stack to create a `syscall` gadget, and finally `execve("/bin/sh", 0, 0)`.

**Probability:** Deterministic after the 1/16 `fini_array` shift alignment, or fully deterministic if `l_addr` manipulation is precise.

---

### Path D — One-Shot: Partial Overwrite `stdin@bss` to One-Gadget via Atexit

**Used by:** Solutions 11177, 6748

**Concept:** The `exit()` path goes through `__run_exit_handlers` which uses an `atexit` function list. A pointer on the stack (accessible via `%42$`) influences the atexit array offset. By overwriting this offset to point at `stdout@bss`, and then partial-overwriting the libc pointer at `stdout@bss` to a one-gadget, `exit()` jumps directly to the one-gadget.

**Steps:**

1. Overwrite the atexit offset (via `%42$`) to redirect the exit handler to `stdout@bss` (`0x601020`).
2. Partial-overwrite `stdout` pointer's low 3 bytes to a one-gadget address.
3. Brute-force the remaining 12 bits of libc entropy → **1/4096**.

**Probability:** 1/4096 per connection. Simpler payload, single-shot.

---

### Path E — Fake FILE Struct → Vtable Hijack → One-Gadget

**Used by:** Solution 3498

**Concept:** After gaining a printf loop (via Path A or B), construct a fake `FILE` struct in `.bss` with a crafted vtable. Redirect `stdout@bss` to the fake struct. The vtable's `xsputn` entry points to a `add byte ptr [rax], al` gadget that is repeatedly invoked by `printf`'s `buffered_vfprintf` path, incrementally transforming `stdin@bss` into a one-gadget address.

**Steps:**

1. Gain printf loop.
2. Build fake FILE struct in `.bss` with `flags = 0x8002`, vtable pointing to gadgets.
3. Swap `stdout` to the fake struct.
4. Invoke the `add [rax], al` gadget ~58 times, each time it adds `al` to `[rax]` where `rax = stdin@bss`, slowly morphing the libc pointer into a one-gadget.
5. When the pointer matches, the next `printf` triggers the one-gadget.

**Probability:** Depends on initial libc layout; additional nibble guessing may be needed.

## Key Addresses (No-PIE Binary)

```python
# Binary
main_read_printf = 0x400925    # read(0,buf,0x80); printf(buf) — loop target
fini_array       = 0x600db8    # .fini_array (read-only segment)
bss_start        = 0x601000    # writable .bss
stdout_bss       = 0x601020    # copy-relocated stdout
stdin_bss        = 0x601030    # copy-relocated stdin
stderr_bss       = 0x601040    # copy-relocated stderr

# Gadgets
pop_rdi          = 0x4009c3    # pop rdi; ret
pop_rsi_r15      = 0x4009c1    # pop rsi; pop r15; ret
pop_rsp_3        = 0x4009bd    # pop rsp; pop r13; pop r14; pop r15; ret (stack pivot)
csu_pop6         = 0x4009ba    # pop rbx; rbp; r12; r13; r14; r15; ret
csu_call         = 0x4009a0    # call [r12+rbx*8](r15, r14, r13)
ret              = 0x4009c4    # ret
```

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
_IO_2_1_stderr_      = 0x3c4540
_IO_2_1_stdout_      = 0x3c4620
__libc_start_main_ret = 0x20830
system               = 0x45390
bin_sh               = 0x18c177
one_gadgets          = [0x4526a, 0xef6c4, 0xf0567]
```

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Format string (blind) | `printf(buf)` after `close(1)` | Deterministic |
| Printf loop | `fini_array` hijack or stack retarget | 1/16 (fini) or 1/4096 (stack) |
| Restore output | `stdout@bss` → `_IO_2_1_stderr_` partial overwrite | 1/16 (libc nibble) |
| libc leak | `%25$p` or `%60$p` (once output restored) | Deterministic |
| Stack leak | `%23$p` or `%11$p` | Deterministic |
| Code execution | ROP chain / one-gadget on printf return address | Deterministic after leaks |

## Solution Write-ups

| File | Primary Path | Key Technique | Probability | Notes |
|------|-------------|---------------|-------------|-------|
| `821.md` | B | Sequential fmt → stack retarget → one-gadget | 1/4096 | Brute force stack guess |
| `1351.md` | A | `l_addr` hijack → stdout→stderr → leak → one-gadget | 1/16 | Uses link_map pointer |
| `2311.md` | B + C | Sequential fmt → BSS ROP (no leak) + deterministic variant | 1/4096 or det. | Two scripts: brute + no-brute |
| `2972.md` | A + C | `fini_array` → BSS ROP via `__libc_csu_init` | ~1/16 | `mprotect` + shellcode |
| `3148.md` | A | `fini_array` → leak → one-gadget on stack | 1/16 | Concise; direct one-gadget write |
| `3498.md` | E | Fake FILE vtable → `add [rax], al` × N → one-gadget | 1/4096 | Most creative approach |
| `3568.md` | A | stdout→stderr → leak → fmt write one-gadget | 1/16 | Chinese writeup |
| `6748.md` | D | Atexit → partial overwrite stdin to one-gadget | 1/4096 | Brute 12 bits libc |
| `7905.md` | B | Sequential trick → loop → ROP | 1/65536 | Most detailed analysis |
| `8153.md` | A | `l_addr` + stdout swap → leak + `add rsp` ROP | 1/16 | Clean multi-stage; detailed writeup |
| `11177.md` | D | Atexit offset → partial overwrite | 1/4096 | Size-optimized fmt writer |
| `15724.md` | B | Stack retarget → leak → one-gadget | 1/16 | Stack + libc leak in one shot |
| `22319.md` | B | Stack pivot → `__libc_csu_init` ROP → `syscall` | 1/4096 | No libc leak needed |
| `24887.md` | A | `fini_array` → leak → fmt write one-gadget | 1/16 | Uses formatstring library |
| `31599.md` | A | `fini_array` → leak → `add rsp` gadget + inline ROP | 1/16 | Exp.py approach |
| `35917.md` | A | `_dl_fini` analysis → `fini_array` shift | 1/16 | Detailed reverse engineering |
| `36233.md` | A | `fini_array` + stdout→stderr → leak → `add rsp, 0x80` ROP | 1/16 | Detailed Chinese writeup |
| `38641.md` | A | `fini_array` → stdout swap → leak → `add rsp` + ROP | 1/16 | Clean exploit |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (Path A: `fini_array` + stdout swap + ROP) |
| `desc.txt` | Challenge description |
| `solution/*.md` | Community write-ups (47 solutions) |
