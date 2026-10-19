---
tags:
  - arbitrary-write
  - seccomp-bypass
  - timing-side-channel
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
description: "A heap write primitive in seccomp rule management permits overwriting __free_hook to trigger a BPF filter oracle disclosing memory contents."
proof-of-concept: no
---

# SeccompTools — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10408`
>
> Flag: `FLAG{u_r_master_of_secooooooomp!}`

## Challenge Overview

A seccomp BPF rule editor/emulator (x86-64, PIE, Full RELRO, NX, Stack Canary) built against glibc 2.23. The program lets users create custom BPF (Berkeley Packet Filter) seccomp rules, disassemble them, emulate them, and install them into the kernel. It loads example rules from files via `fopen`/`fread` and validates that rules "allow ORW" before installing them. After loading an example, the `FILE *stream` pointer is stored in BSS and later `fclose`'d.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## Vulnerabilities

### V1 — BPF_LEN Emulator/Kernel Differential (Primary, Exploitable)

**Root Cause:** The program's BPF emulator does **not** implement the `BPF_LD | BPF_LEN` instruction (opcode `0x80`). In the emulator, `A` remains 0 after this instruction. In the real Linux kernel seccomp, `BPF_LEN` loads `sizeof(struct seccomp_data)` = **64** into `A`.

```
Emulator:  BPF_LEN → A = 0  (unimplemented, A unchanged)
Kernel:    BPF_LEN → A = 64 (sizeof(struct seccomp_data))
```

This creates a **parser differential**: a rule can be crafted that passes the emulator's ORW validation check but installs a completely different policy in the kernel.

```python
# Bypass the ORW check:
BPF_STMT(BPF_LD | BPF_LEN, 0)          # emulator: A=0, kernel: A=64
BPF_JUMP(BPF_JEQ, 64, bypass_to_real, 0)  # emulator: false→allow, kernel: true→real_filter
BPF_STMT(BPF_RET, SECCOMP_RET_ALLOW)    # emulator always reaches here
# ... actual malicious filter follows (kernel only) ...
```

**Impact:** Allows installing arbitrary seccomp filters that the ORW validation doesn't see.

### V2 — SECCOMP_RET_ERRNO Makes `open()` Return 0 (Exploitable)

**Root Cause:** When a seccomp filter returns `SECCOMP_RET_ERRNO(0)` for the `open` syscall, the kernel skips the syscall and returns 0 (no error). Since fd 0 = stdin, `fopen()` receives a `FILE *` backed by fd 0 (stdin). Subsequent `fread()` from this stream reads user input instead of a file.

```c
// In the binary, loading an example rule:
stream = fopen("allow_orw.bpf", "rb");   // open() → blocked by seccomp → returns 0 (stdin)
fread(filter_buf, 1, filter_size, stream); // reads from stdin!
// filter_size comes from the first 2 bytes of the "file" (user-controlled)
```

**Impact:** The user controls `filter_size` (up to 0xffff) via the first 2 bytes sent, while `filter_buf` is at a fixed BSS offset (`0x203080`). Sending size `0x1008` overflows past the 0x1000-byte `filter_buf` and overwrites the adjacent `stream` pointer at `filter_buf + 0x1000`.

### V3 — BSS `stream` Pointer Overwrite → FSOP (Exploitable)

**Root Cause:** The `FILE *stream` pointer lives 0x1000 bytes after `filter_buf` in BSS. By overflowing via V2, the attacker replaces `stream` with a pointer to a forged `_IO_FILE_plus` structure in the same buffer. When the program calls `fclose(stream)`, it follows the fake vtable to attacker-controlled code.

```c
// After fread overflow:
// filter_buf[0x1000] now contains &fake_FILE (points back into filter_buf)
fclose(stream);  // → calls fake_vtable->__finish(fake_FILE)
```

**Impact:** Full control of RIP when `fclose` dispatches through the fake vtable.

### V4 — Seccomp Side-Channel Oracle for Address Leak (Exploitable)

**Root Cause:** BPF filters can inspect `seccomp_data` fields including `instruction_pointer` (libc code address of the syscall instruction) and syscall arguments (`args[0]`–`args[5]`, which include buffer addresses). By returning `SECCOMP_RET_ERRNO` when a specific bit is set and `SECCOMP_RET_ALLOW` otherwise, the attacker creates a side-channel oracle.

```
struct seccomp_data {
    int   nr;                  // offset 0x00: syscall number
    __u32 arch;                // offset 0x04
    __u64 instruction_pointer; // offset 0x08: libc address!
    __u64 args[6];             // offset 0x10: includes buffer addresses (PIE leak)
};
```

The oracle works by observing whether `fread` (which calls `read` internally) succeeds or blocks:
- If the filter returns `ERRNO` for a `read`, `fread` retries in a loop → the program appears to hang (no output).
- If the filter returns `ALLOW`, the `read` succeeds → the program prints "Done!".

**Impact:** Leaks PIE base (from `args[0]` = buffer address in `read`) and libc base (from `instruction_pointer` = address of `read` syscall) bit-by-bit or byte-by-byte.

## Exploit Flow (Universal Across All Solutions)

All 16 solutions follow the same three-phase structure:

### Phase 1 — Leak Addresses via Seccomp Oracle

Install a BPF filter (bypassing the ORW check via V1) that uses the side-channel oracle (V4) to leak:
- **PIE base**: from `seccomp_data.args[0]` (the buffer address passed to `read`) or `seccomp_data.args[1]`
- **libc base**: from `seccomp_data.instruction_pointer` (the libc address where `read` syscall is executed)

### Phase 2 — Overflow BSS via Forced stdin Read

Install a new filter that makes `open()` return `ERRNO(0)` (V2) for the specific example file. Trigger the "load example" code path → `fopen` returns a `FILE *` backed by stdin → `fread` reads attacker-controlled data → overflow `filter_buf` (0x1000 bytes) + overwrite `stream` pointer (V3).

### Phase 3 — FSOP via Fake FILE Structure

The overflowed buffer contains a forged `_IO_FILE_plus` structure with a fake vtable. When `fclose(stream)` is called, it dispatches through the fake vtable, giving RIP control.

## Exploit Path Variants (Phase 3 Finish)

### Path A — `system("/bin/sh")` or `system(";sh;")` via vtable hijack (~50%)

**Used by:** Solutions 370, 821, 14, 2972, 3972, 38838, 408

Place `"/bin/sh"` or `";sh;"` in the `_flags` field of the fake FILE. Point the vtable's `__finish` or `__close` entry at `system`. When `fclose` calls `vtable->__finish(fp)`, it executes `system(fp)` where `fp` starts with the shell command string.

Some solutions use `_IO_str_overflow` or `_vtable_offset` tricks to call `system` through `_IO_str_jumps` instead of directly forging the entire vtable.

### Path B — `setcontext` + ORW ROP Chain (~40%)

**Used by:** Solutions exp.py (main), 8153, 9251, 22319, 31599, 34817, 35282

Point the vtable's `__finish` at `setcontext+53` (glibc 2.23). The `setcontext` gadget loads registers from the `_IO_FILE` structure fields (treating `rdi` as the struct pointer), then pivots the stack to an attacker-controlled ROP chain. The ROP chain performs:

```python
open("/home/seccomp-tools/flag", O_RDONLY)
read(fd, buffer, 0x100)
write(1, buffer, 0x100)
```

This approach is preferred because `execve` may be blocked by previously installed seccomp filters.

### Path C — `mprotect` + Shellcode (~10%)

**Used by:** Solutions 5586, 8153

After gaining RIP control via FSOP, use a ROP chain to call `mprotect(bss_page, 0x1000, RWX)` followed by jumping to shellcode embedded in the BSS buffer. The shellcode performs ORW to read the flag.

### Path D — Format String via FSOP → Two-Stage Leak + Shell

**Used by:** Solution 6748

Instead of directly calling `system`, forge the FILE struct to trigger `printf` with a format string (`%21$p`) to leak a stack/libc address. Then perform a second FSOP round to call `system` with the fully resolved address.

## Oracle Technique Variants

| Technique | Speed | Used By |
|-----------|-------|---------|
| Bit-by-bit probing (36-48 iterations per address) | ~30-60s | 370, 1980, 5586, 8153, 9251, 35282, 38838 |
| Binary search on 16-bit chunks (log₂ probes per chunk) | ~15-30s | 31599, 34817, 408 |
| Byte-by-byte with `fread` size encoding | ~40-50s | exp.py (main), 821 |
| Nibble-by-nibble via `write` size side-channel | ~60-90s | 3972 |
| 256-value brute per byte (linear scan) | ~120s+ | 370, 2972 |

## Key Offsets (pwnable.tw remote, glibc 2.23)

```python
# Binary
filter_buf_bss    = 0x203080   # BSS offset of the BPF filter buffer
stream_bss        = 0x204088   # BSS offset of FILE *stream (filter_buf + 0x1008)
allow_orw_bpf_str = 0x277c     # ".rodata" offset of "allow_orw.bpf" string
puts_plt          = 0xa70

# libc
system            = 0x45390
setcontext_53     = 0x47b75    # setcontext+53 (register load gadget)
__open_nocancel_7 = 0xf6460    # common instruction_pointer leak offset
main_arena        = 0x3c3b20
_IO_2_1_stderr_   = 0x3c4680
_IO_stdfile_1_lock = 0x3c5770

# ROP gadgets (libc)
pop_rdi           = 0x21102
pop_rsi           = 0x202e8
pop_rdx           = 0x1b92
pop_rax           = 0x33544
syscall_ret       = 0xbb7c5    # or 0x35426, 0x106c05
mprotect          = 0x100b80

# one_gadgets
one_gadgets       = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

## `seccomp_data` Layout (for BPF Oracle)

```
struct seccomp_data {
    0x00: int   nr;                   // syscall number
    0x04: __u32 arch;                 // AUDIT_ARCH_X86_64 = 0xC000003E
    0x08: __u64 instruction_pointer;  // → libc address (where syscall insn lives)
    0x10: __u64 args[0];              // → filename ptr for open, buf ptr for read
    0x18: __u64 args[1];              // → buf ptr (PIE leak via fread→read)
    0x20: __u64 args[2];              // → size (controllable via fread loop)
    0x28: __u64 args[3];
    0x30: __u64 args[4];
    0x38: __u64 args[5];
};
// sizeof(seccomp_data) = 64 = 0x40
// BPF accesses 32-bit words: data[0x08]=ip_low, data[0x0c]=ip_high, etc.
```

## Solution Write-ups

| File | Leak Technique | Finish | Notes |
|------|---------------|--------|-------|
| `370.md` | Byte scan via fread size encoding | `system(";sh;")` via vtable | Two scripts; detailed BPF rule construction |
| `821.md` | Byte-by-byte fread size oracle | `_IO_str_overflow` → `system` | Detailed 3-step explanation; seccomp filter tree priority |
| `14.md` | Bit-by-bit probing (48 iterations) | `setcontext` + mprotect + shellcode | Uses `seccomp-tools asm` for rule compilation |
| `1980.md` | Bit-by-bit probing | Fake FILE vtable → `system` | Heap leak approach with `args[1]` |
| `2972.md` | Binary search on open args[0] | FSOP vtable `system(";sh;")` | Uses `seccomp-tools asm` for compilation |
| `3972.md` | Nibble-by-nibble via write() args | Format string leak → `system` | Most creative: uses various write() triggers |
| `5586.md` | Byte-by-byte via fread internal reads | `setcontext` → mprotect + ORW shellcode | Detailed BPF oracle using read size encoding |
| `6748.md` | Binary search on 16-bit chunks | `setcontext` → mprotect + shellcode | Elegant exploit with minimal filter count |
| `8153.md` | Bit probing via `fopen` success/fail | `setcontext` + ORW ROP | Uses `mprotect` + shellcode as final stage |
| `9251.md` | Binary search open args + seccomp tree | `setcontext` → stack pivot → ORW ROP | Detailed seccomp filter tree priority explanation |
| `22319.md` | Bit-by-bit with multiple read sizes | Fake FILE `_IO_finish` → `setcontext` | Uses `FileStructure` from pwntools |
| `31599.md` | Binary search on `instruction_pointer` | `setcontext` + ORW ROP chain | Clean binary search; separate PIE + libc leaks |
| `34817.md` | Binary search via BPF `jge` | `setcontext` + `openat` ORW ROP | Uses `SECCOMP_ASSEMBLER.py` helper |
| `35282.md` | Bit-by-bit via fread size + offset | Fake FILE vtable → `one_gadget` / `system` | Heap address + libc leak |
| `38838.md` | Binary search on 16-bit halves | `setcontext` + ORW ROP | Uses `FileStructure`; clean 2-stage leak |
| `408.md` | Bit-by-bit with read size/offset encoding | Fake FILE → `execve` | Simplest vtable hijack |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit: BPF oracle + House of Spirit + FSOP → ORW ROP |
| `IO_FILE.py` | Helper: `_IO_FILE_plus` and `_IO_jump_t` struct constructors |
| `SECCOMP_ASSEMBLER.py` | Helper: BPF assembly → bytecode compiler |
| `desc.txt` | Challenge description |
| `artifacts/` | Original challenge binary and libc |
| `solution/*.md` | Community write-ups (16 solutions) |
