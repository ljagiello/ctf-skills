---
name: ctf-pwn
description: Provides binary exploitation (pwn) techniques for CTF challenges. Use when exploiting buffer overflows, format strings, heap vulnerabilities (House of Orange, Spirit, Lore, Apple 2, Einherjar, tcache stashing unlink), race conditions, kernel bugs, ROP chains, ret2libc, ret2dlresolve, shellcode, GOT overwrite, use-after-free, seccomp bypass, FSOP, stack pivot, sandbox escape, Windows SEH overwrite, VirtualAlloc ROP, SeDebugPrivilege escalation, or Linux kernel exploitation (modprobe_path, tty_struct, userfaultfd, KASLR bypass, SLUB heap spray).
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Binary Exploitation (Pwn)

Quick reference for binary exploitation (pwn) CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [overflow-basics.md](overflow-basics.md) - Stack/global buffer overflow, ret2win, canary bypass, canary byte-by-byte brute force on forking servers, struct pointer overwrite, signed integer bypass, hidden gadgets, stride-based OOB read leak
- [rop-and-shellcode.md](rop-and-shellcode.md) - Core ROP chains (ret2libc, syscall ROP, rdx control, shell interaction), ret2csu, bad character XOR bypass, exotic x86 gadgets (BEXTR/XLAT/STOSB/PEXT), stack pivot via xchg rax,esp, sprintf() gadget chaining for bad character bypass
- [rop-advanced.md](rop-advanced.md) - Advanced ROP techniques: double stack pivot to BSS via leave;ret, SROP (Sigreturn-Oriented Programming) with UTF-8 constraints, seccomp bypass, RETF architecture switch (x64→x32) for seccomp bypass, shellcode with input reversal, .fini_array hijack, ret2vdso, pwntools template
- [format-string.md](format-string.md) - Format string exploitation (leaks, GOT overwrite, blind pwn, filter bypass, canary leak, __free_hook, .rela.plt patching, saved EBP overwrite for .bss pivot, argv[0] overwrite for stack smash info leak, .fini_array loop for multi-stage exploitation)
- [advanced.md](advanced.md) - Heap, UAF, JIT, esoteric GOT, custom allocators (nginx, talloc), DNS overflow, MD5 preimage, ASAN, rdx control, canary-aware overflow, CSV injection, path traversal, GC null-ref cascading corruption, io_uring UAF with SQE injection, integer truncation int32→int16 bypass, musl libc heap exploitation (meta pointer + atexit hijack), House of Orange/Spirit/Lore, ret2dlresolve, tcache stashing unlink attack
- [advanced-exploits.md](advanced-exploits.md) - Advanced exploit techniques (part 1): VM signed comparison, BF JIT shellcode, type confusion, off-by-one index corruption, DNS overflow, ASAN shadow memory, format string with encoding constraints, custom canary preservation, signed integer bypass, canary-aware partial overflow, CSV injection, MD5 preimage gadgets, VM GC UAF slab reuse, path traversal sanitizer bypass, FSOP + seccomp bypass via openat/mmap/write
- [advanced-exploits-2.md](advanced-exploits-2.md) - Advanced exploit techniques (part 2): bytecode validator bypass via self-modification, io_uring UAF with SQE injection, integer truncation int32->int16, GC null-reference cascading corruption, leakless libc via multi-fgets stdout FILE overwrite, signed/unsigned char underflow heap overflow, XOR keystream brute-force write primitive, tcache pointer decryption heap leak, unsorted bin promotion via forged chunk size, FSOP stdout TLS leak, TLS destructor hijack via `__call_tls_dtors`, custom shadow stack pointer overflow bypass, signed int overflow negative OOB heap write, XSS-to-binary pwn bridge
- [advanced-exploits-4.md](advanced-exploits-4.md) - Advanced exploit techniques (part 4): Windows SEH overwrite + pushad VirtualAlloc ROP, IAT-relative resolution, detached process shell stability, SeDebugPrivilege SYSTEM escalation, ARM buffer overflow with Thumb shellcode, Forth interpreter system word exploitation, GF(2) Gaussian elimination for multi-pass tcache poisoning
- [advanced-exploits-3.md](advanced-exploits-3.md) - Advanced exploit techniques (part 3): stack variable overlap / carry corruption OOB, 1-byte overflow via 8-bit loop counter, game AI arithmetic mean OOB read, arbitrary read/write GOT overwrite to shell, stack leak via __environ + memcpy overflow, JIT sandbox escape via uint16 jump truncation, DNS compression pointer stack overflow with multi-question ROP, ELF code signing bypass via program header manipulation, game level format signed/unsigned coordinate mismatch, file descriptor inheritance via missing O_CLOEXEC, sign extension integer underflow in metadata parsing, ROP chain construction with read-only primitive
- [sandbox-escape.md](sandbox-escape.md) - Custom VM exploitation, FUSE/CUSE devices, busybox/restricted shell, shell tricks, process_vm_readv sandbox bypass, named pipe file size bypass (cross-references ctf-misc/pyjails.md for Python jail techniques)
- [kernel.md](kernel.md) - Linux kernel exploitation fundamentals: environment setup, QEMU debug, heap spray structures (tty_struct, poll_list, user_key_payload, seq_operations), kernel stack overflow, canary leak, privilege escalation (ret2usr, kernel ROP), modprobe_path overwrite, core_pattern overwrite, kmalloc size mismatch heap overflow + struct file f_op corruption
- [kernel-techniques.md](kernel-techniques.md) - Kernel exploitation techniques: tty_struct kROP (fake vtable + stack pivot), AAW via ioctl register control, userfaultfd race stabilization, SLUB allocator internals (freelist hardening/obfuscation), leak via kernel panic, MADV_DONTNEED race window extension (DiceCTF 2026), cross-cache CPU-split attack (DiceCTF 2026), PTE overlap file write (DiceCTF 2026)
- [kernel-bypass.md](kernel-bypass.md) - Kernel protection bypass: KASLR/FGKASLR bypass (__ksymtab), KPTI bypass (swapgs trampoline, signal handler, modprobe_path/core_pattern via ROP), SMEP/SMAP bypass, GDB kernel module debugging, initramfs/virtio-9p workflow, exploit templates, exploit delivery

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
5. Canary brute-force byte-by-byte on forking servers (7*256 attempts max)

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

**ret2csu:** `__libc_csu_init` gadgets control `rdx`, `rsi`, `edi` and call any GOT function — universal 3-argument call without libc gadgets. See [rop-and-shellcode.md](rop-and-shellcode.md#ret2csu--__libc_csu_init-gadgets-crypto-cat).

**Bad char XOR bypass:** XOR payload data with key before writing to `.data`, then XOR back in place with ROP gadgets. Avoids null bytes, newlines, and other filtered characters. See [rop-and-shellcode.md](rop-and-shellcode.md#bad-character-bypass-via-xor-encoding-in-rop-crypto-cat).

**Exotic gadgets (BEXTR/XLAT/STOSB/PEXT):** When standard `mov` write gadgets are unavailable, chain obscure x86 instructions for byte-by-byte memory writes. See [rop-and-shellcode.md](rop-and-shellcode.md#exotic-x86-gadgets--bextrxlatstosbpext-crypto-cat).

**Stack pivot (xchg rax,esp):** Swap stack pointer to attacker-controlled heap/buffer when overflow is too small for full ROP chain. Requires `pop rax; ret` to load pivot address first. See [rop-and-shellcode.md](rop-and-shellcode.md#stack-pivot-via-xchg-raxesp-crypto-cat).

**rdx control:** After `puts()`, rdx is clobbered to 1. Use `pop rdx; pop rbx; ret` from libc, or re-enter binary's read setup + stack pivot. See [rop-and-shellcode.md](rop-and-shellcode.md).

**Shell interaction:** After `execve`, `sleep(1)` then `sendline(b'cat /flag*')`. See [rop-and-shellcode.md](rop-and-shellcode.md).

## ret2vdso — No-Gadget Binary Exploitation

**Pattern:** Statically-linked binary with minimal functions and no useful ROP gadgets. The Linux kernel maps a vDSO into every process, containing usable gadgets. Leak vDSO base from `AT_SYSINFO_EHDR` (auxv type `0x21`) on the stack, dump the vDSO, extract gadgets for `execve`. vDSO is kernel-specific — always dump the remote copy. See [rop-advanced.md](rop-advanced.md#ret2vdso--using-kernel-vdso-gadgets-htb-nowhere-to-go).

## Use-After-Free (UAF) Exploitation

**Pattern:** Menu create/delete/view where `free()` doesn't NULL pointer. Create -> leak -> free -> allocate same-size object to overwrite function pointer -> trigger callback. Key: both structs must be same size for tcache reuse. See [advanced.md](advanced.md) for full exploit code.

## Seccomp Bypass

Alternative syscalls when seccomp blocks `open()`/`read()`: `openat()` (257), `openat2()` (437, often missed!), `sendfile()` (40), `readv()`/`writev()`, `mmap()` (9, map flag file into memory instead of read), `pread64()` (17).

**Check rules:** `seccomp-tools dump ./binary`

See [rop-advanced.md](rop-advanced.md) for quick reference and [advanced.md](advanced.md) for conditional buffer address restrictions, shellcode without relocations, `scmp_arg_cmp` struct layout.

## Stack Shellcode with Input Reversal

**Pattern:** Binary reverses input buffer. Pre-reverse shellcode, use partial 6-byte RIP overwrite, trampoline `jmp short` to NOP sled. See [rop-advanced.md](rop-advanced.md).

## .fini_array Hijack

Writable `.fini_array` + arbitrary write -> overwrite with win/shellcode address. Works even with Full RELRO. See [rop-advanced.md](rop-advanced.md) for implementation.

## Path Traversal Sanitizer Bypass

**Pattern:** Sanitizer skips char after banned char match; double chars to bypass (e.g., `....//....//etc//passwd`). Also try `/proc/self/fd/3` if binary has flag fd open. See [advanced.md](advanced.md).

## Kernel Exploitation

**modprobe_path overwrite (smallkirby/kernelpwn):** Overwrite `modprobe_path` with evil script path, then `execve` a binary with non-printable first 4 bytes. Kernel runs the script as root. Requires AAW; blocked by `CONFIG_STATIC_USERMODEHELPER`. See [kernel.md](kernel.md).

**tty_struct kROP (smallkirby/kernelpwn):** `open("/dev/ptmx")` allocates `tty_struct` in kmalloc-1024. Overwrite `ops` with fake vtable → `ioctl()` hijacks RIP. Build two-phase kROP within `tty_struct` itself via `leave` gadget stack pivot. See [kernel.md](kernel.md).

**userfaultfd race stabilization (smallkirby/kernelpwn):** Register mmap'd region with uffd. Kernel page fault blocks the thread → deterministic race window for heap manipulation. See [kernel.md](kernel.md).

**Heap spray structures:** `tty_struct` (kmalloc-1024, kbase leak), `tty_file_private` (kmalloc-32, kheap leak), `poll_list` (variable, arbitrary free via linked list), `user_key_payload` (variable, `add_key()` controlled data), `seq_operations` (kmalloc-32, kbase leak). See [kernel.md](kernel.md).

**ret2usr (hxp CTF 2020):** When SMEP/SMAP are disabled, call `prepare_kernel_cred(0)` → `commit_creds()` directly from userland function, then `swapgs; iretq` to return as root. See [kernel.md](kernel.md).

**Kernel ROP chain (hxp CTF 2020):** With SMEP, build ROP: `pop rdi; ret` → 0 → `prepare_kernel_cred` → `mov rdi, rax` → `commit_creds` → `swapgs` → `iretq` → userland. See [kernel.md](kernel.md).

**KPTI bypass methods (hxp CTF 2020):** Four approaches: `swapgs_restore_regs_and_return_to_usermode + 22` trampoline, SIGSEGV signal handler, modprobe_path overwrite via ROP, core_pattern pipe via ROP. See [kernel.md](kernel.md).

**FGKASLR bypass (hxp CTF 2020):** Early `.text` section gadgets are unaffected. Resolve randomized functions via `__ksymtab` relative offsets in multi-stage exploit. See [kernel.md](kernel.md).

**Config recon:** Check QEMU script for SMEP/SMAP/KASLR/KPTI. Detect FGKASLR via `readelf -S vmlinux` section count (30 vs 36000+). Check `CONFIG_KALLSYMS_ALL` via `grep modprobe_path /proc/kallsyms`. See [kernel.md](kernel.md).

OOB via vulnerable `lseek`, heap grooming with `fork()`, SUID exploits. Check `CONFIG_SLAB_FREELIST_RANDOM` and `CONFIG_SLAB_MERGE_DEFAULT`. See [advanced.md](advanced.md).

**Race window extension (DiceCTF 2026):** `MADV_DONTNEED` + `mprotect()` loop forces repeated page faults during kernel operations touching userland memory, extending race windows from sub-ms to tens of seconds. See [kernel-techniques.md](kernel-techniques.md#race-window-extension-via-madv_dontneed--mprotect-dicectf-2026).

**Cross-cache via CPU split (DiceCTF 2026):** Allocate on CPU 0, free from CPU 1 — objects escape dedicated SLUB caches via partial list overflow → buddy allocator. See [kernel-techniques.md](kernel-techniques.md#cross-cache-attack-via-cpu-split-strategy-dicectf-2026).

**PTE overlap file write (DiceCTF 2026):** Reclaim freed page as PTE page, overlap anonymous + file-backed mappings → write through anonymous side modifies file content at physical page level. See [kernel-techniques.md](kernel-techniques.md#pte-overlap-primitive-for-file-write-dicectf-2026).

## io_uring UAF with SQE Injection

**Pattern:** Custom slab allocator + io_uring worker thread. FLUSH frees objects (UAF), type confusion via slab fallback, craft `IORING_OP_OPENAT` SQE in reused memory. io_uring trusts SQE contents from userland shared memory. See [advanced-exploits-2.md](advanced-exploits-2.md#io_uring-uaf-with-sqe-injection-apoorvctf-2026).

## Integer Truncation Bypass (int32→int16)

**Pattern:** Input validated as int32 (>= 0), cast to int16_t for bounds check. Value 65534 passes int32 check, becomes -2 as int16_t → OOB array access. Use `xchg rdi, rax; cld; ret` gadget for dynamic fd capture in containerized ORW chains. See [advanced-exploits-2.md](advanced-exploits-2.md#integer-truncation-bypass-int32int16-apoorvctf-2026).

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
- **House of Apple 2** (glibc 2.34+): FSOP (File Stream Oriented Programming) via `_IO_wfile_jumps` when `__free_hook`/`__malloc_hook` removed. Fake FILE with `_flags = " sh"`, vtable chain → `system(fp)`. For SUID binaries: use `setcontext()` variant to stack pivot → `setuid(0)` → `system()` (dash drops privs when uid != euid). See [advanced.md](advanced.md#setcontext-variant-for-suid-binaries-midnight-flag-2026).
- **Classic unlink**: Corrupt adjacent chunk metadata, trigger backward consolidation for write-what-where primitive. Pre-2.26 glibc only. See [advanced.md](advanced.md#classic-heap-unlink-attack-crypto-cat).
- **House of Einherjar**: Off-by-one null clears PREV_INUSE, backward consolidation with self-pointing unlink.
- **Safe-linking** (glibc 2.32+): tcache fd mangled as `ptr ^ (chunk_addr >> 12)`.
- Check glibc version: `strings libc.so.6 | grep GLIBC`
- Freed chunks contain libc pointers (fd/bk) -> leak via error messages or missing null-termination
- Heap feng shui: control alloc order/sizes, create holes, place targets adjacent to overflow source

**House of Orange:** Corrupt top chunk size → large malloc forces sysmalloc → old top freed without calling `free()`. Chain with FSOP. See [advanced.md](advanced.md#house-of-orange).

**House of Spirit:** Forge fake chunk in target area, `free()` it, reallocate to get write access. Requires valid size + next chunk size. See [advanced.md](advanced.md#house-of-spirit).

**House of Lore:** Corrupt smallbin `bk` → link fake chunk → second malloc returns attacker-controlled address. See [advanced.md](advanced.md#house-of-lore).

**ret2dlresolve:** Forge Elf64_Sym/Rela to resolve arbitrary libc function without leak. `Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])`. Requires Partial RELRO. See [advanced.md](advanced.md#ret2dlresolve).

**tcache stashing unlink (glibc 2.29+):** Corrupt smallbin chunk's `bk` during tcache stashing → arbitrary address linked into tcache → write primitive. See [advanced.md](advanced.md#tcache-stashing-unlink-attack).

See [advanced.md](advanced.md) for House of Apple 2 FSOP chain (+ setcontext SUID variant), House of Orange/Spirit/Lore, ret2dlresolve, tcache stashing unlink, custom allocator exploitation (nginx pools), heap overlap via base conversion, tree data structure stack underallocation, FSOP + seccomp bypass via openat/mmap/write with `mov rsp, rdx` stack pivot.

**GF(2) Gaussian elimination for tcache poisoning:** When a deterministic XOR cipher corrupts heap metadata as a side effect, model the corruption as linear algebra over GF(2). Find a subset of cipher seeds whose combined XOR transforms tcache `fd` from current value to target address. See [advanced-exploits-4.md](advanced-exploits-4.md#gf2-gaussian-elimination-for-multi-pass-tcache-poisoning-midnight-flag-2026).

## talloc Pool Header Forgery (Boston Key Party 2016)

**Pattern:** talloc (hierarchical allocator in Samba/CUPS) pool header forgery. Forge fake pool header with controlled `end`/`object_count` fields to redirect next `talloc()` to arbitrary address. Leak GOT for libc, write `__free_hook` with `system()`. See [advanced.md](advanced.md#talloc-pool-header-forgery-for-arbitrary-readwrite-boston-key-party-2016).

## JIT Compilation Exploits

**Pattern:** Off-by-one in instruction encoding -> misaligned machine code. Embed shellcode as operand bytes of subtraction operations, chain with 2-byte `jmp` instructions. See [advanced.md](advanced.md).

**BF JIT unbalanced bracket:** Unbalanced `]` pops tape address (RWX) from stack → write shellcode to tape with `+`/`-`, trigger `]` to jump to it. See [advanced.md](advanced.md).

## Type Confusion in Interpreters

**Pattern:** Interpreter sets wrong type tag → struct fields reinterpreted. Unused padding bytes in one variant become active pointers/data in another. Flag bytes as type value trigger UNKNOWN_DATA dump. See [advanced.md](advanced.md).

## Off-by-One Index / Size Corruption

**Pattern:** Array index 0 maps to `entries[-1]`, overlapping struct metadata (size field). Corrupted size → OOB read leaks canary/libc, then OOB write places ROP chain. See [advanced.md](advanced.md).

## Double win() Call

**Pattern:** `win()` checks `if (attempts++ > 0)` — needs two calls. Stack two return addresses: `p64(win) + p64(win)`. See [advanced.md](advanced.md).

## Arbitrary Read/Write to Shell via GOT Overwrite (BSidesSF 2026)

**Pattern:** Binary provides explicit read/write primitives. Leak libc via GOT read, overwrite `strtoll@GOT` with `system`, next call becomes `system(user_input)`. Choose GOT targets where the function takes a user-controlled string as first arg. See [advanced-exploits-3.md](advanced-exploits-3.md#arbitrary-readwrite-to-shell-via-got-overwrite-bsidessf-2026).

## Stack Leak via __environ and memcpy Overflow (BSidesSF 2026)

**Pattern:** Binary with read-only primitive and `memcpy(stack_buf, user_addr, user_len)`. Leak libc via GOT, leak stack via `__environ`, plant ROP addresses in input buffer, overflow memcpy to copy them over return address, send EOF to trigger return. See [advanced-exploits-3.md](advanced-exploits-3.md#stack-leak-via-__environ-and-memcpy-overflow-bsidessf-2026).

## JIT Sandbox Escape via uint16 Jump Truncation (BSidesSF 2026)

**Pattern:** JIT compiler truncates conditional jump offset to uint16, causing misalignment when code exceeds 64KB. Embed 2-byte shellcode fragments in `add` immediates, thread with `jmp $+3` to chain execution. See [advanced-exploits-3.md](advanced-exploits-3.md#jit-sandbox-escape-via-conditional-jump-uint16-truncation-bsidessf-2026).

## DNS Compression Pointer Stack Overflow (BSidesSF 2026)

**Pattern:** Custom DNS server doesn't track decompressed name length. Compression pointer chains revisit data, overflowing stack buffer. Split ROP chain across multiple DNS question entries. See [advanced-exploits-3.md](advanced-exploits-3.md#dns-compression-pointer-stack-overflow-with-multi-question-rop-bsidessf-2026).

## ELF Code Signing Bypass via Program Headers (BSidesSF 2026)

**Pattern:** Signing scheme hashes section headers/content but not program headers. Append shellcode, modify LOAD segment's `p_offset` to point to appended data — signature still valid, loader executes attacker code. See [advanced-exploits-3.md](advanced-exploits-3.md#elf-code-signing-bypass-via-program-header-manipulation-bsidessf-2026).

## Game Level Format Signed/Unsigned Coordinate Mismatch (BSidesSF 2026)

**Pattern:** Level editor parses signed integer coordinates but bounds-checks via unsigned comparison — negative coordinates pass the check and write block IDs (arbitrary bytes) before the level array, enabling stack return address overwrite. Leak stack address via hidden developer mode, encode shellcode as block IDs. See [advanced-exploits-3.md](advanced-exploits-3.md#game-level-format-signedunsigned-coordinate-mismatch-bsidessf-2026).

## File Descriptor Inheritance via Missing O_CLOEXEC (BSidesSF 2026)

**Pattern:** Service reads secret into `memfd_create()` FD without `MFD_CLOEXEC`, then calls `system()` for user commands — child inherits the FD. Bypass `strstr()` keyword filters with shell quote splitting (`p'r'oc` instead of `proc`) to read `/proc/self/fd/N`. See [advanced-exploits-3.md](advanced-exploits-3.md#file-descriptor-inheritance-via-missing-o_cloexec-bsidessf-2026).

## Sign Extension Integer Underflow in Metadata Parsing (BSidesSF 2026)

**Pattern:** Metadata parser's `to_int32` converts unsigned values >= 0x80000000 to negative signed integers. Used as array index/offset, this causes OOB memory access. Iterate byte-by-byte to leak flag from memory. See [advanced-exploits-3.md](advanced-exploits-3.md#sign-extension-integer-underflow-in-metadata-parsing-bsidessf-2026).

## ROP Chain Construction with Read-Only Primitive (BSidesSF 2026)

**Pattern:** Binary with only `read()` primitive — no write, no win function. Leak libc via GOT, then "import" arbitrary byte values onto the stack by reading from libc offsets whose content matches desired ROP gadget addresses. Read primitive doubles as write primitive. See [advanced-exploits-3.md](advanced-exploits-3.md#rop-chain-construction-with-read-only-primitive-bsidessf-2026).

## Esoteric Language GOT Overwrite

**Pattern:** Brainfuck/Pikalang interpreter with unbounded tape = arbitrary read/write relative to buffer base. Move pointer to GOT, overwrite byte-by-byte with `system()`. See [advanced.md](advanced.md).

## DNS Record Buffer Overflow

**Pattern:** Many AAAA records overflow stack buffer in DNS response parser. Set up DNS server with excessive records, overwrite return address. See [advanced.md](advanced.md).

## ASAN Shadow Memory Exploitation

**Pattern:** Binary with AddressSanitizer has format string + OOB write. ASAN may use "fake stack" (50% chance). Leak PIE, detect real vs fake stack, calculate OOB write offset to overwrite return address. See [advanced.md](advanced.md).

## Format String .fini_array Loop for Multi-Stage Exploitation (Codegate 2016)

**Pattern:** No GOT function called after `printf()`. Overwrite `.fini_array[0]` with `main()` for re-execution loop. Stage 1: leak libc/stack. Stage 2: `printf@GOT` to `system()`, `__stack_chk_fail@GOT` to `main()`. Stage 3: corrupt canary to trigger `__stack_chk_fail` re-entry, now `printf(input)` is `system(input)`. See [format-string.md](format-string.md#format-string-fini_array-loop-for-multi-stage-exploitation-codegate-2016).

## Format String with RWX .fini_array Hijack

**Pattern (Encodinator):** Base85-encoded input in RWX memory passed to `printf()`. Write shellcode to RWX region, overwrite `.fini_array[0]` via format string `%hn` writes. Use convergence loop for base85 argument numbering. See [advanced.md](advanced.md).

## Custom Canary Preservation

**Pattern:** Buffer overflow must preserve known canary value. Write exact canary bytes at correct offset: `b'A' * 64 + b'BIRD' + b'X'`. See [advanced.md](advanced.md).

## MD5 Preimage Gadget Construction

**Pattern (Hashchain):** Brute-force MD5 preimages with `eb 0c` prefix (jmp +12) to skip middle bytes; bytes 14-15 become 2-byte i386 instructions. Build syscall chains from gadgets like `31c0` (xor eax), `cd80` (int 0x80). See [advanced.md](advanced.md) for C code and v2 technique.

## Python Sandbox Escape

AST bypass via f-strings, audit hook bypass with `b'flag.txt'` (bytes vs str), MRO-based `__builtins__` recovery. See [sandbox-escape.md](sandbox-escape.md).

## VM GC-Triggered UAF (Slab Reuse)

**Pattern:** Custom VM with NEWBUF/SLICE/GC opcodes. Slicing creates shared slab reference; dropping+GC'ing slice frees slab while parent still holds it. Allocate function object to reuse slab, leak code pointer via UAF read, overwrite with win() address. See [advanced.md](advanced.md).

## GC Null-Reference Cascading Corruption

**Pattern:** Mark-compact GC follows null references to heap address 0, creating fake object. During compaction, memmove cascades corruption through adjacent object headers → OOB access → libc leak → FSOP. See [advanced.md](advanced.md).

## OOB Read via Stride/Rate Leak

**Pattern:** String processing function with user-controlled stride skips past null terminator, leaking stack canary and return address one byte at a time. Then overflow with leaked values. See [overflow-basics.md](overflow-basics.md).

## SROP with UTF-8 Constraints

**Pattern:** When payload must be valid UTF-8 (Rust binaries, JSON parsers), use SROP — only 3 gadgets needed. Multi-byte UTF-8 sequences spanning register field boundaries "fix" high bytes. See [rop-advanced.md](rop-advanced.md).

## VM Exploitation (Custom Bytecode)

**Pattern:** Custom VM with OOB read/write in syscalls. Leak PIE via XOR-encoded function pointer, overflow to rewrite pointer with `win() ^ KEY`. See [sandbox-escape.md](sandbox-escape.md).

## FUSE/CUSE Character Device Exploitation

Look for `cuse_lowlevel_main()` / `fuse_main()`, backdoor write handlers with command parsing. Exploit to `chmod /etc/passwd` then modify for root access. See [sandbox-escape.md](sandbox-escape.md).

## Busybox/Restricted Shell Escalation

Find writable paths via character devices, target `/etc/passwd` or `/etc/sudoers`, modify permissions then content. See [sandbox-escape.md](sandbox-escape.md).

## process_vm_readv Sandbox Bypass (0CTF 2016)

**Pattern:** Sandbox validates file paths via `process_vm_readv()` + `realpath()`. Map memory with `PROT_READ` only at fixed address via `mmap(MAP_FIXED)` -- sandbox's `process_vm_readv` fails silently, bypassing path validation entirely. See [sandbox-escape.md](sandbox-escape.md#process_vm_readv-failure-as-sandbox-escape-0ctf-2016).

## Named Pipe (mkfifo) File Size Bypass (Nuit du Hack 2016)

**Pattern:** Binary checks `stat()` file size before reading. Named pipes report `st_size = 0` but deliver arbitrary data via `read()`. `mkfifo /tmp/pipe && cat payload > /tmp/pipe &` then pass pipe to binary. Combine with `ln -s /flag arena.c` for string reuse in ROP. See [sandbox-escape.md](sandbox-escape.md#named-pipe-mkfifo-for-file-size-check-bypass-nuit-du-hack-2016).

## Shell Tricks

`exec<&3;sh>&3` for fd redirection, `$0` instead of `sh`, `ls -la /proc/self/fd` to find correct fd. See [sandbox-escape.md](sandbox-escape.md).

## Double Stack Pivot to BSS via leave;ret (Midnightflag 2026)

**Pattern:** Small overflow (only RBP + RIP). Overwrite RBP → BSS address, RIP → `leave; ret` gadget. `leave` sets RSP = RBP (BSS). Second stage at BSS calls `fgets(BSS+offset, large_size, stdin)` to load full ROP chain. See [rop-advanced.md](rop-advanced.md#double-stack-pivot-to-bss-via-leaveret-midnightflag-2026).

## RETF Architecture Switch for Seccomp Bypass (Midnightflag 2026)

**Pattern:** Seccomp blocks 64-bit syscalls (`open`, `execve`). Use `retf` gadget to load CS=0x23 (IA-32e compatibility mode). In 32-bit mode, `int 0x80` uses different syscall numbers (open=5, read=3, write=4) not covered by the filter. Requires `mprotect` to make BSS executable for 32-bit shellcode. See [rop-advanced.md](rop-advanced.md#retf-architecture-switch-for-seccomp-bypass-midnightflag-2026).

## Leakless Libc via Multi-fgets stdout FILE Overwrite (Midnightflag 2026)

**Pattern:** No libc leak available. Chain multiple `fgets(addr, 7, stdin)` calls via ROP to construct fake stdout FILE struct on BSS. Set `_IO_write_base` to GOT entry, call `fflush(stdout)` → leaks GOT content → libc base. The 7-byte writes avoid null byte corruption since libc pointer MSBs are already `\x00`. See [advanced-exploits-2.md](advanced-exploits-2.md#leakless-libc-via-multi-fgets-stdout-file-overwrite-midnightflag-2026).

## Signed/Unsigned Char Underflow → Heap Overflow (Midnightflag 2026)

**Pattern:** Size field stored as `signed char`, cast to `unsigned char` for use. `size = -112` → `(unsigned char)(-112) = 144`, overflowing a 127-byte buffer by 17 bytes. Combine with XOR keystream brute-force for byte-precise writes, forge chunk sizes for unsorted bin promotion (libc leak), FSOP stdout for TLS leak, and TLS destructor (`__call_tls_dtors`) overwrite for RCE. See [advanced-exploits-2.md](advanced-exploits-2.md#signedunsigned-char-underflow--heap-overflow--tls-destructor-hijack-midnightflag-2026).

## TLS Destructor Hijack via `__call_tls_dtors`

**Pattern:** Alternative to House of Apple 2 on glibc 2.34+. Forge `__tls_dtor_list` entries with pointer-guard-mangled function pointers: `encoded = rol(target ^ pointer_guard, 0x11)`. Requires leaking pointer guard from TLS segment (via FSOP stdout redirection). Each node calls `PTR_DEMANGLE(func)(obj)` on exit. See [advanced-exploits-2.md](advanced-exploits-2.md#tls-destructor-overwrite-for-rce-via-__call_tls_dtors).

## Signed Int Overflow → Negative OOB Heap Write (Midnight 2026)

**Pattern (Canvas of Fear):** Index formula `y * width + x` in signed 32-bit int overflows to negative value, passing bounds check and writing backward into heap metadata. Use to corrupt adjacent chunk sizes/pointers, leak libc via unsorted bin, redirect a data pointer to `environ` for stack leak, then write ROP chain to main's return address. When binary is behind a web API, chain XSS → Fetch API → heap exploit, and inject `\n` in API parameters for command stacking via `sendline()`.

See [advanced-exploits-2.md](advanced-exploits-2.md#signed-int-overflow--negative-oob-heap-write--xss-to-binary-pwn-bridge-midnight-2026) for full exploit chain, XSS bridge pattern, and RGB pixel write primitive.

## Custom Shadow Stack Bypass via Pointer Overflow (Midnight 2026)

**Pattern (Revenant):** Userland shadow stack in `.bss` with unbounded pointer. Recurse to advance `shadow_stack_ptr` past the array into user-controlled memory (e.g., `username` buffer), write `win()` there, then overflow the hardware stack return address to match. Both checks pass.

```python
# Iterate (target_addr - shadow_stack_base) // 8 times to overflow pointer
for i in range(512):
    io.sendlineafter(b"Survivor name:\n", fit(exe.symbols["win"]))
    io.sendlineafter(b"[0] Flee", b"4")  # recurse
```

See [advanced-exploits-2.md](advanced-exploits-2.md#custom-shadow-stack-bypass-via-pointer-overflow-midnight-2026) for full exploit and `.bss` layout analysis.

## Windows SEH Overwrite + VirtualAlloc ROP (RainbowTwo HTB)

Format string leak defeats ASLR. SEH (Structured Exception Handler) overwrite with stack pivot to ROP chain. `pushad` builds VirtualAlloc call frame for DEP (Data Execution Prevention) bypass. Detached process launcher for shell stability on thread-based servers. See [advanced-exploits-4.md](advanced-exploits-4.md#windows-seh-overwrite--pushad-virtualalloc-rop-rainbowtwo-htb).

## SeDebugPrivilege → SYSTEM

`SeDebugPrivilege` + Meterpreter `migrate -N winlogon.exe` -> SYSTEM. See [advanced-exploits-4.md](advanced-exploits-4.md#sedebugprivilege-to-system-rainbowtwo-htb).

## Useful Commands

`checksec`, `one_gadget`, `ropper`, `ROPgadget`, `seccomp-tools dump`, `strings libc | grep GLIBC`. See [rop-advanced.md](rop-advanced.md) for full command list and pwntools template.
