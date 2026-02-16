---
name: ctf-pwn
description: Binary exploitation (pwn) techniques for CTF challenges. Use when exploiting buffer overflows, format strings, heap vulnerabilities, race conditions, kernel bugs, ROP chains, ret2libc, shellcode, GOT overwrite, use-after-free, seccomp bypass, or sandbox escape.
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
- [format-string.md](format-string.md) - Format string exploitation (leaks, GOT overwrite, blind pwn, filter bypass, canary leak, __free_hook, .rela.plt patching)
- [advanced.md](advanced.md) - Heap, UAF, JIT, esoteric GOT, custom allocators, DNS overflow, MD5 preimage, ASAN, rdx control, canary-aware overflow, CSV injection, path traversal, kernel
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

**rdx control:** After `puts()`, rdx is clobbered to 1. Use `pop rdx; pop rbx; ret` from libc, or re-enter binary's read setup + stack pivot. See [rop-and-shellcode.md](rop-and-shellcode.md).

**Shell interaction:** After `execve`, `sleep(1)` then `sendline(b'cat /flag*')`. See [rop-and-shellcode.md](rop-and-shellcode.md).

## Use-After-Free (UAF) Exploitation

**Pattern:** Menu create/delete/view where `free()` doesn't NULL pointer. Create -> leak -> free -> allocate same-size object to overwrite function pointer -> trigger callback. Key: both structs must be same size for tcache reuse. See [advanced.md](advanced.md) for full exploit code.

## Seccomp Bypass

Alternative syscalls when seccomp blocks `open()`/`read()`: `openat()` (257), `openat2()` (437, often missed!), `sendfile()` (40), `readv()`/`writev()`.

**Check rules:** `seccomp-tools dump ./binary`

See [rop-and-shellcode.md](rop-and-shellcode.md) for quick reference and [advanced.md](advanced.md) for conditional buffer address restrictions, shellcode without relocations, `scmp_arg_cmp` struct layout.

## Stack Shellcode with Input Reversal

**Pattern:** Binary reverses input buffer. Pre-reverse shellcode, use partial 6-byte RIP overwrite, trampoline `jmp short` to NOP sled. See [rop-and-shellcode.md](rop-and-shellcode.md).

## .fini_array Hijack

Writable `.fini_array` + arbitrary write -> overwrite with win/shellcode address. Works even with Full RELRO. See [rop-and-shellcode.md](rop-and-shellcode.md) for implementation.

## Path Traversal Sanitizer Bypass

**Pattern:** Sanitizer skips char after banned char match; double chars to bypass (e.g., `....//....//etc//passwd`). Also try `/proc/self/fd/3` if binary has flag fd open. See [advanced.md](advanced.md).

## Kernel Exploitation

OOB via vulnerable `lseek`, heap grooming with `fork()`, SUID exploits. Check `CONFIG_SLAB_FREELIST_RANDOM` and `CONFIG_SLAB_MERGE_DEFAULT`. See [advanced.md](advanced.md).

## Format String Quick Reference

- Leak stack: `%p.%p.%p.%p.%p.%p` | Leak specific: `%7$p`
- Write: `%n` (4-byte), `%hn` (2-byte), `%hhn` (1-byte), `%lln` (8-byte full 64-bit)
- GOT overwrite for code execution (Partial RELRO required)

See [format-string.md](format-string.md) for GOT overwrite patterns, blind pwn, filter bypass, canary+PIE leak, `__free_hook` overwrite, and argument retargeting.

## .rela.plt / .dynsym Patching (Format String)

**When to use:** GOT addresses contain bad bytes (e.g., 0x0a). Patch `.rela.plt` symbol index + `.dynsym` st_value to redirect function resolution to `win()`. Bypasses all GOT byte restrictions. See [format-string.md](format-string.md) for full technique and code.

## Heap Exploitation

- tcache poisoning (glibc 2.26+), fastbin dup / double free
- House of Force (old glibc), unsorted bin attack
- **House of Apple 2** (glibc 2.34+): FSOP via `_IO_wfile_jumps` when `__free_hook`/`__malloc_hook` removed. Fake FILE with `_flags = " sh"`, vtable chain → `system(fp)`.
- **House of Einherjar**: Off-by-one null clears PREV_INUSE, backward consolidation with self-pointing unlink.
- **Safe-linking** (glibc 2.32+): tcache fd mangled as `ptr ^ (chunk_addr >> 12)`.
- Check glibc version: `strings libc.so.6 | grep GLIBC`
- Freed chunks contain libc pointers (fd/bk) -> leak via error messages or missing null-termination
- Heap feng shui: control alloc order/sizes, create holes, place targets adjacent to overflow source

See [advanced.md](advanced.md) for House of Apple 2 FSOP chain, custom allocator exploitation (nginx pools), heap overlap via base conversion, tree data structure stack underallocation.

## JIT Compilation Exploits

**Pattern:** Off-by-one in instruction encoding -> misaligned machine code. Embed shellcode as operand bytes of subtraction operations, chain with 2-byte `jmp` instructions. See [advanced.md](advanced.md).

**BF JIT unbalanced bracket:** Unbalanced `]` pops tape address (RWX) from stack → write shellcode to tape with `+`/`-`, trigger `]` to jump to it. See [advanced.md](advanced.md).

## Type Confusion in Interpreters

**Pattern:** Interpreter sets wrong type tag → struct fields reinterpreted. Unused padding bytes in one variant become active pointers/data in another. Flag bytes as type value trigger UNKNOWN_DATA dump. See [advanced.md](advanced.md).

## Off-by-One Index / Size Corruption

**Pattern:** Array index 0 maps to `entries[-1]`, overlapping struct metadata (size field). Corrupted size → OOB read leaks canary/libc, then OOB write places ROP chain. See [advanced.md](advanced.md).

## Double win() Call

**Pattern:** `win()` checks `if (attempts++ > 0)` — needs two calls. Stack two return addresses: `p64(win) + p64(win)`. See [advanced.md](advanced.md).

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

`checksec`, `one_gadget`, `ropper`, `ROPgadget`, `seccomp-tools dump`, `strings libc | grep GLIBC`. See [rop-and-shellcode.md](rop-and-shellcode.md) for full command list and pwntools template.
