---
name: ctf-pwn
description: Binary exploitation (pwn) techniques for CTF challenges. Use when exploiting buffer overflows, format strings, heap vulnerabilities, race conditions, or kernel bugs.
license: MIT
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Binary Exploitation (Pwn)

Quick reference for binary exploitation (pwn) CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [overflow-basics.md](overflow-basics.md) - Stack/global buffer overflow, ret2win, canary bypass, struct pointer overwrite, signed integer bypass, hidden gadgets
- [rop-and-shellcode.md](rop-and-shellcode.md) - ROP chains (ret2libc, syscall ROP), shellcode with input reversal, seccomp bypass, .fini_array hijack, pwntools template
- [format-string.md](format-string.md) - Format string exploitation (leaks, GOT overwrite, blind pwn, filter bypass, canary leak, __free_hook)
- [advanced.md](advanced.md) - Heap, JIT, esoteric GOT, custom allocators, DNS overflow, MD5 preimage, ASAN, rdx control, canary-aware overflow, CSV injection
- [sandbox-escape.md](sandbox-escape.md) - Python sandbox escape, custom VM exploitation, FUSE/CUSE devices, busybox/restricted shell, shell tricks

---

## Source Code Red Flags

- Threading/`pthread` -> race conditions
- `usleep()`/`sleep()` -> timing windows
- Global variables in multiple threads -> TOCTOU

## Race Condition Exploitation

```bash
bash -c '{ echo "cmd1"; echo "cmd2"; sleep 1; } | nc host port'
```

## Common Vulnerabilities

- Buffer overflow: `gets()`, `scanf("%s")`, `strcpy()`
- Format string: `printf(user_input)`
- Integer overflow, UAF, race conditions

## Protection Implications for Exploit Strategy

| Protection | Status | Implication |
|-----------|--------|-------------|
| PIE | Disabled | All addresses (GOT, PLT, functions) are fixed - direct overwrites work |
| RELRO | Partial | GOT is writable - GOT overwrite attacks possible |
| RELRO | Full | GOT is read-only - need alternative targets (hooks, vtables, return addr) |
| NX | Enabled | Can't execute shellcode on stack/heap - use ROP or ret2win |
| Canary | Present | Stack smash detected - need leak or avoid stack overflow (use heap) |

**Quick decision tree:**
- Partial RELRO + No PIE -> GOT overwrite (easiest, use fixed addresses)
- Full RELRO -> target `__free_hook`, `__malloc_hook` (glibc < 2.34), or return addresses
- Stack canary present -> prefer heap-based attacks or leak canary first

## Stack Buffer Overflow

1. Find offset: `cyclic 200` then `cyclic -l <value>`
2. Check protections: `checksec --file=binary`
3. No PIE + No canary = direct ROP
4. Canary leak via format string or partial overwrite

**ret2win with magic value:** Overflow -> `ret` (alignment) -> `pop rdi; ret` -> magic -> win(). See [overflow-basics.md](overflow-basics.md) for full exploit code.

**Stack alignment:** Modern glibc needs 16-byte alignment; SIGSEGV in `movaps` = add extra `ret` gadget. See [overflow-basics.md](overflow-basics.md).

**Offset calculation:** Buffer at `rbp - N`, return at `rbp + 8`, total = N + 8. See [overflow-basics.md](overflow-basics.md).

**Input filtering:** `memmem()` checks block certain byte sequences; assert payload doesn't contain banned strings. See [overflow-basics.md](overflow-basics.md).

**Finding gadgets:** `ROPgadget --binary binary | grep "pop rdi"`, or use pwntools `ROP()` which also finds hidden gadgets in CMP immediates. See [overflow-basics.md](overflow-basics.md).

## Struct Pointer Overwrite (Heap Menu Challenges)

**Pattern:** Menu create/modify/delete on structs with data buffer + pointer. Overflow name into pointer field with GOT address, then write win address via modify. See [overflow-basics.md](overflow-basics.md) for full exploit and GOT target selection table.

## Signed Integer Bypass

**Pattern:** `scanf("%d")` without sign check; negative quantity * price = negative total, bypasses balance check. See [overflow-basics.md](overflow-basics.md).

## Canary-Aware Partial Overflow

**Pattern:** Overflow `valid` flag between buffer and canary. Use `./` as no-op path padding for precise length. See [overflow-basics.md](overflow-basics.md) and [advanced.md](advanced.md) for full exploit chain.

## Global Buffer Overflow (CSV Injection)

**Pattern:** Adjacent global variables; overflow via extra CSV delimiters changes filename pointer. See [overflow-basics.md](overflow-basics.md) and [advanced.md](advanced.md) for full exploit.

## ROP Chain Building

Leak libc via `puts@PLT(puts@GOT)`, return to vuln, stage 2 with `system("/bin/sh")`. See [rop-and-shellcode.md](rop-and-shellcode.md) for full two-stage ret2libc pattern, leak parsing, and return target selection.

**Raw syscall ROP:** When `system()`/`execve()` crash (CET/IBT), use `pop rax; ret` + `syscall; ret` from libc. See [rop-and-shellcode.md](rop-and-shellcode.md).

**rdx control:** After `puts()`, rdx is clobbered to 1. Use `pop rdx; pop rbx; ret` from libc, or re-enter binary's read setup + stack pivot. See [rop-and-shellcode.md](rop-and-shellcode.md) and [advanced.md](advanced.md).

**Shell interaction:** After `execve`, `sleep(1)` then `sendline(b'cat /flag*')`. See [rop-and-shellcode.md](rop-and-shellcode.md).

## Use-After-Free (UAF) Exploitation

**Pattern:** Menu create/delete/view where `free()` doesn't NULL pointer.

**Classic UAF flow:**
1. Create object A (allocates chunk with function pointer)
2. Leak address via inspect/view (bypass PIE)
3. Free object A (creates dangling pointer)
4. Allocate object B of **same size** (reuses freed chunk via tcache)
5. Object B data overwrites A's function pointer with `win()` address
6. Trigger A's callback -> jumps to `win()`

**Key insight:** Both structs must be the same size for tcache to reuse the chunk.

```python
create_report("sighting-0")  # 64-byte struct with callback ptr at +56
leak = inspect_report(0)      # Leak callback address for PIE bypass
pie_base = leak - redaction_offset
win_addr = pie_base + win_offset

delete_report(0)              # Free chunk, dangling pointer remains
create_signal(b"A"*56 + p64(win_addr))  # Same-size struct overwrites callback
analyze_report(0)             # Calls dangling pointer -> win()
```

## Seccomp Bypass

Alternative syscalls when seccomp blocks `open()`/`read()`: `openat()` (257), `openat2()` (437, often missed!), `sendfile()` (40), `readv()`/`writev()`.

**Check rules:** `seccomp-tools dump ./binary`

See [rop-and-shellcode.md](rop-and-shellcode.md) for quick reference and [advanced.md](advanced.md) for conditional buffer address restrictions, shellcode without relocations, `scmp_arg_cmp` struct layout.

## Stack Shellcode with Input Reversal

**Pattern:** Binary reverses input buffer. Pre-reverse shellcode, use partial 6-byte RIP overwrite, trampoline `jmp short` to NOP sled. See [rop-and-shellcode.md](rop-and-shellcode.md).

## .fini_array Hijack

Writable `.fini_array` + arbitrary write -> overwrite with win/shellcode address. Works even with Full RELRO. See [rop-and-shellcode.md](rop-and-shellcode.md) for implementation.

## Path Traversal Sanitizer Bypass

**Pattern (Galactic Archives):** Sanitizer skips character after finding banned char.

```python
# Sanitizer removes '.' and '/' but skips next char after match
# ../../etc/passwd -> bypass with doubled chars:
"....//....//etc//passwd"
# Each '..' becomes '....' (first '.' caught, second skipped, third caught, fourth survives)
```

**Flag via `/proc/self/fd/N`:**
- If binary opens flag file but doesn't close fd, read via `/proc/self/fd/3`
- fd 0=stdin, 1=stdout, 2=stderr, 3=first opened file

## Kernel Exploitation

- Look for vulnerable `lseek` handlers allowing OOB read/write
- Heap grooming with forked processes
- SUID binary exploitation via kernel-to-userland buffer overflow
- Check kernel config for disabled protections:
  - `CONFIG_SLAB_FREELIST_RANDOM=n` -> sequential heap chunks
  - `CONFIG_SLAB_MERGE_DEFAULT=n` -> predictable allocations

## Format String Quick Reference

- Leak stack: `%p.%p.%p.%p.%p.%p` | Leak specific: `%7$p`
- Write: `%n` (4-byte), `%hn` (2-byte), `%hhn` (1-byte), `%lln` (8-byte full 64-bit)
- GOT overwrite for code execution (Partial RELRO required)

See [format-string.md](format-string.md) for GOT overwrite patterns, blind pwn, filter bypass, canary+PIE leak, `__free_hook` overwrite, and argument retargeting.

## .rela.plt / .dynsym Patching (Format String)

**When to use:** GOT addresses contain bad bytes (e.g., 0x0a with fgets), making direct GOT overwrite impossible. Requires `.rela.plt` and `.dynsym` in writable memory.

**Technique:** Patch `.rela.plt` relocation entry symbol index to point to different symbol, then patch `.dynsym` symbol's `st_value` with `win()` address. When the original function is called, dynamic linker reads patched relocation and jumps to `win()`.

```python
# Key addresses (from readelf -S)
REL_SYM_BYTE = 0x4006ec   # .rela.plt[exit].r_info byte containing symbol index
STDOUT_STVAL_LO = 0x4004e8  # .dynsym[11].st_value low halfword
STDOUT_STVAL_HI = 0x4004ea  # .dynsym[11].st_value high halfword

# Format string writes via %hhn (8-bit) and %hn (16-bit)
# 1. Write symbol index 0x0b to r_info byte
# 2. Write win() address low halfword to st_value
# 3. Write win() address high halfword to st_value+2
```

**When GOT has bad bytes but .rela.plt/.dynsym don't:** This technique bypasses all GOT byte restrictions since you never write to GOT directly.

## Heap Exploitation

- tcache poisoning (glibc 2.26+), fastbin dup / double free
- House of Force (old glibc), unsorted bin attack
- Check glibc version: `strings libc.so.6 | grep GLIBC`
- Freed chunks contain libc pointers (fd/bk) -> leak via error messages or missing null-termination
- Heap feng shui: control alloc order/sizes, create holes, place targets adjacent to overflow source

See [advanced.md](advanced.md) for custom allocator exploitation (nginx pools), heap overlap via base conversion, tree data structure stack underallocation.

## JIT Compilation Exploits

**Pattern:** Off-by-one in instruction encoding -> misaligned machine code. Embed shellcode as operand bytes of subtraction operations, chain with 2-byte `jmp` instructions. See [advanced.md](advanced.md).

## Esoteric Language GOT Overwrite

**Pattern:** Brainfuck/Pikalang interpreter with unbounded tape = arbitrary read/write relative to buffer base. Move pointer to GOT, overwrite byte-by-byte with `system()`. See [advanced.md](advanced.md).

## DNS Record Buffer Overflow

**Pattern:** Many AAAA records overflow stack buffer in DNS response parser. Set up DNS server with excessive records, overwrite return address. See [advanced.md](advanced.md).

## ASAN Shadow Memory Exploitation

**Pattern:** Binary with AddressSanitizer has format string + OOB write. ASAN may use "fake stack" (50% chance). Leak PIE, detect real vs fake stack, calculate OOB write offset to overwrite return address. See [advanced.md](advanced.md).

## Format String with RWX .fini_array Hijack

**Pattern (Encodinator):** Base85-encoded input in RWX memory passed to `printf()`. Write shellcode to RWX region, overwrite `.fini_array[0]` via format string `%hn` writes. Use convergence loop for base85 argument numbering. See [advanced.md](advanced.md).

## Custom Canary Preservation

**Pattern:** Buffer overflow must preserve known canary value. Write exact canary bytes at correct offset: `b'A' * 64 + b'BIRD' + b'X'`. See [advanced.md](advanced.md).

## MD5 Preimage Gadget Construction

**Pattern (Hashchain):** Brute-force MD5 preimages with `eb 0c` prefix (jmp +12) to skip middle bytes; bytes 14-15 become 2-byte i386 instructions. Build syscall chains from gadgets like `31c0` (xor eax), `cd80` (int 0x80). See [advanced.md](advanced.md) for C code and v2 technique.

## Python Sandbox Escape

AST bypass via f-strings, audit hook bypass with `b'flag.txt'` (bytes vs str), MRO-based `__builtins__` recovery. See [sandbox-escape.md](sandbox-escape.md).

## VM Exploitation (Custom Bytecode)

**Pattern:** Custom VM with OOB read/write in syscalls. Leak PIE via XOR-encoded function pointer, overflow to rewrite pointer with `win() ^ KEY`. See [sandbox-escape.md](sandbox-escape.md).

## FUSE/CUSE Character Device Exploitation

Look for `cuse_lowlevel_main()` / `fuse_main()`, backdoor write handlers with command parsing. Exploit to `chmod /etc/passwd` then modify for root access. See [sandbox-escape.md](sandbox-escape.md).

## Busybox/Restricted Shell Escalation

Find writable paths via character devices, target `/etc/passwd` or `/etc/sudoers`, modify permissions then content. See [sandbox-escape.md](sandbox-escape.md).

## Shell Tricks

`exec<&3;sh>&3` for fd redirection, `$0` instead of `sh`, `ls -la /proc/self/fd` to find correct fd. See [sandbox-escape.md](sandbox-escape.md).

## Useful Commands

```bash
checksec --file=binary          # Check binary protections
one_gadget libc.so.6            # Find one-shot gadgets
ropper -f binary                # Find ROP gadgets
ROPgadget --binary binary       # Alternative gadget finder
seccomp-tools dump ./binary     # Check seccomp rules
strings libc.so.6 | grep GLIBC # Check glibc version
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

See [rop-and-shellcode.md](rop-and-shellcode.md) for the full template.
