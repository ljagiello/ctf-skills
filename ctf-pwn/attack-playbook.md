# Linux Userland Attack Playbook

Use this as the workflow view for a Linux/glibc target. It answers *what to look for* and *which primitive to pursue*; use the linked technique notes for full payloads, version-specific bypasses, and CTF writeups.

## Recon

Enumerate input and privilege boundaries before choosing an exploit path:

- Arguments and environment: `argv`, `getopt()`, `getenv()`, `LD_PRELOAD`, `PATH`.
- Files: attacker-selected `fopen()`/`read()` paths and configuration files such as `/etc/program.conf` or `~/.config/...`.
- Standard input: `read()` and `fgets()` loops.
- Network sockets: `accept()`, `recv()`, and `recvfrom()`.
- IPC: D-Bus, Unix-domain sockets, and shared memory.
- Privilege boundary: SUID/SGID state and whether the process changes UID/EUID.
- Event paths: signal handlers (`SIGUSR*`, `SIGALRM`, ...) and any signal-unsafe code.
- Pseudo-filesystem interfaces: values read from `/proc` or `/sys`.

Record which entry point reaches dangerous allocations, copies, format sinks, dereferences, or privileged operations. A bug that is hard to reach is usually worse than a stronger primitive that is unreachable.

Static signals from ELF metadata, libc build, and protection tooling can rank candidate primitives, but they do not prove exploitability by themselves. When the request asks for exploitability or security impact, read [static-signals.md](static-signals.md) before choosing a route.

## Leak Selection

Identify the smallest leak that defeats the mitigations actually enabled by the target:

| Secret | Useful sources |
| --- | --- |
| libc | unsorted/small/large-bin `fd`/`bk`, stack return paths, writable function pointers, heap/stack residue, FILE structures |
| heap | tcache/fastbin/largebin metadata, stack residue, TLS |
| stack | uninitialized stack, saved frames, libc `__environ` |
| canary | uninitialized/overread stack, TLS |
| binary | stack residue and function/data pointers with binary offsets |
| memory map | file-read primitive against `/proc/self/maps` |

Common ways to obtain a leak:

- Read an uninitialized heap or stack allocation.
- Use a format-string bug.
- Turn FILE corruption into an arbitrary read.
- Turn an overflow or arbitrary allocation into an overread.
- Combine a write primitive with an object that later prints or copies from it.

For libc identification, use the database linked from [format-string.md](format-string.md#format-string-basics). For full format-string mechanics, see [format-string.md](format-string.md).

## Control-Flow and Write Targets

Choose the target after checking binary protections, libc version, and the strength of the write primitive:

| Write target | Typical condition |
| --- | --- |
| return address | controllable stack write or overflow |
| binary GOT | Partial RELRO |
| libc GOT | version-dependent; verify against the target libc |
| malloc/free/realloc hooks | glibc < 2.34 |
| FILE vtable | older glibc; modern targets usually require a validated-vtable bypass |
| FILE wide vtable | viable on modern glibc |
| binary function pointer / `fini_array` | binary-specific writable target |
| `l_addr` plus a function pointer | binary-specific base/pointer combination |

Payload selection:

- **ROP** when gadget addresses and stack control are available.
- **SROP** when a sigreturn trigger can replace many gadget requirements.
- **One gadget** when its register/stack constraints can be met.
- **`system("/bin/sh")`** when `/bin/sh` can be placed in `rdi` and stack alignment is preserved.

Version-specific modern-libc chains: [nobodyisnobody/docs](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc) and [n132/Libc-GOT-Hijacking](https://github.com/n132/Libc-GOT-Hijacking).

## Route To A Technique

| Situation | Canonical deep dive |
| --- | --- |
| Input reaches `printf`/`sprintf`/`syslog` as a format | [format-string.md](format-string.md) |
| Corruption reaches `_IO_FILE`, especially on Full RELRO | [heap-fsop.md](heap-fsop.md) |
| Bug is tcache/fastbin/unsorted/largebin or allocator metadata | [heap-techniques.md](heap-techniques.md) |
| Need stack pivot, ret2libc, syscall ROP, or shellcode | [rop-and-shellcode.md](rop-and-shellcode.md) |
| Need SROP, modern ROP, vDSO, or seccomp evasion | [rop-advanced.md](rop-advanced.md) |
| Need exact stack/canary behavior or partial overflows | [overflow-basics.md](overflow-basics.md) |

## Payload Checklist

- **Stack pivot:** use controlled `rbp` plus `leave`, or `mov rsp, <reg>`; pivot to input, BSS, heap, or residual stack only after proving read/write/execute expectations.
- **ROP:** preserve 16-byte stack alignment; use `ret` as padding, `setcontext` for broad register control, and existing vtable/function pointers when useful.
- **Shellcode:** prefer existing RWX when present; otherwise `mprotect`/`mmap` through ROP. For filters, consider null-free, alphanumeric, staged, self-modifying, and carefully encoded ModR/M forms.
- **Partial overwrite:** overwrite only trailing bytes when the nearby code/data differs by known low bits; account for brute-force probability.
- **Seccomp:** enumerate allowed syscalls, look for equivalent calls, and use ORW when execution is blocked. See [advanced.md](advanced.md#seccomp-advanced-techniques).
- **TLS:** corruption can expose the canary, tcache state, stack guard, or destructor pointers; see the allocator notes in [heap-techniques.md](heap-techniques.md#heap-exploitation).
- **Environment variables:** check whether they alter libc/application behavior, disable or shape caching behavior, fill payloads, or make layout predictable.
- **Blind brute force:** use distinguishable crash/hang/output timing when no direct oracle exists; budget attempts before choosing another primitive.
