"""Mocked r2pipe script tests for ctf-reverse toolkit.

Validates the parsing and verification patterns behind the
ctf-reverse/radare2-r2pipe techniques: cmdj() vs cmdJ() key mangling,
empty-result handling, aflj realsz vs size, write-verification by byte
read, and the ESIL scratch-address invariant.
No real radare2, no r2pipe, no compiler, no network — every r2pipe
method is mocked with unittest.mock; the one integration test that
needs real binaries skips cleanly when r2 or cc is missing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from collections import namedtuple
from unittest.mock import MagicMock, patch

try:
    import pytest  # type: ignore[import]
except ImportError:  # pragma: no cover
    pytest = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Helpers — canned r2 JSON shapes + mocked r2pipe, mirror ctf-reverse style
# ---------------------------------------------------------------------------

# Verified against radare2 6.2.2 / r2pipe 1.9.8.
AEIM_MAP_START = 0x100000  # esil.stack.addr
AEIM_MAP_END = 0x1EFFFF  # esil.stack.addr + esil.stack.size (0xf0000) - 1
AEIM_RSP = 0x178000  # what aeim leaves in rsp
SCRATCH_OFFSET = 0x800
SCRATCH_ADDR = AEIM_RSP - SCRATCH_OFFSET  # 0x177800, the ESIL dst buffer

WRITE_REFUSAL = "ERROR: Cannot write. Use `omp`, `io.cache` or reopen the file in rw with `oo+`"
BYTES_AT_1169_BEFORE = "0f94c0"  # sete al, verified: r2 -q -c 'p8 3 @ 0x1169' on the check binary
SETZ_PATCH = "b00190"  # mov al, 1 ; nop

# Real aflj element key order, from r2 6.2.2 — `is-pure` lands at index 3.
_AFLJ_KEYS = (
    "addr",
    "name",
    "size",
    "is-pure",
    "realsz",
    "noreturn",
    "recursive",
    "stackframe",
    "calltype",
    "cost",
    "cc",
    "bits",
    "type",
    "nbbs",
    "tracecov",
    "is-lineal",
    "ninstrs",
    "edges",
    "ebbs",
    "signature",
    "minaddr",
    "maxaddr",
    "maxbbins",
    "midbbins",
    "ratbbins",
    "indegree",
    "outdegree",
    "nlocals",
    "nargs",
    "difftype",
)

_AFLJ_DEFAULTS = {
    "noreturn": False,
    "recursive": False,
    "stackframe": 0,
    "calltype": "amd64",
    "cost": 0,
    "cc": 0,
    "bits": 64,
    "type": "fcn",
    "nbbs": 1,
    "tracecov": 0,
    "is-lineal": True,
    "ninstrs": 2,
    "edges": 0,
    "ebbs": 1,
    "signature": "",
    "minaddr": 0,
    "maxaddr": 0,
    "maxbbins": 0,
    "midbbins": 0.0,
    "ratbbins": 1.0,
    "indegree": 0,
    "outdegree": 0,
    "nlocals": 0,
    "nargs": 0,
    "difftype": "new",
}


def _aflj_element(addr: int, name: str, size: int, realsz: int, **overrides) -> dict:
    """Real-shaped aflj element. `is-pure` is the STRING 'false', not a bool."""
    rec = {"addr": addr, "name": name, "size": size, "realsz": realsz, "is-pure": "false"}
    rec.update(_AFLJ_DEFAULTS)
    rec.update(overrides)
    return {key: rec[key] for key in _AFLJ_KEYS}


def _as_cmdJ(record: dict):
    """What r2pipe 1.9.8 cmdJ() returns: namedtuple('X', d.keys(), rename=True)."""
    fields = namedtuple("X", list(record.keys()), rename=True)
    return fields(*record.values())


def _bulk_functions(session) -> list:
    """Bulk-enumeration consumer: cmdj('aflj') -> list. Empty results are empty, never a raise."""
    fns = session.cmdj("aflj")
    if not isinstance(fns, list) or not fns:
        return []
    return list(fns)


def _render_afl(fns: list) -> list[str]:
    """One line per function; the size column afl prints is realsz, not size."""
    return [f"{f['addr']:#08x}  {f['realsz']:>4}  {f['name']}" for f in fns]


def _inside_aeim_map(addr: int) -> bool:
    """True when addr lies in the map aeim creates (0x100000-0x1effff, rw)."""
    return AEIM_MAP_START <= addr <= AEIM_MAP_END


def _patch_byte(session, addr: int, hexbytes: str) -> tuple[str, bool, str]:
    """Write with wx, then confirm by reading the bytes back.

    r2 exits 0 even when the write is refused, so the exit code proves
    nothing; only the read-back hex confirms the patch landed.
    Returns (r2 write output, patched?, observed hex).
    """
    write_out = session.cmd(f"wx {hexbytes} @ {addr:#x}")
    width = len(bytes.fromhex(hexbytes))
    call = session.cmd(f"p8 {width} @ {addr:#x}")
    observed = (call or "").strip().replace(" ", "")
    return write_out, observed == hexbytes.lower(), observed


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestR2pipeJson(unittest.TestCase):
    """Mocked r2pipe tests for ctf-reverse snippets — no r2, no compiler."""

    def test_cmdj_mangles_hyphenated_keys(self) -> None:
        """cmdJ() runs aflj dicts through namedtuple(..., rename=True): is-pure -> _3."""
        rec = _aflj_element(0x1119, "sym.check", 57, 34, ninstrs=12, cost=15)

        # cmdj() keeps a plain dict: the hyphenated key is reachable by key.
        self.assertIsInstance(rec, dict)
        self.assertEqual(rec["is-pure"], "false")
        self.assertIsInstance(rec["is-pure"], str)
        self.assertIs(rec["noreturn"], False)  # other booleans are real JSON bools

        # cmdJ(): hyphenated identifiers are renamed away.
        mangled = _as_cmdJ(rec)
        self.assertFalse(hasattr(mangled, "is-pure"), "is-pure must not be an attribute")
        with self.assertRaises(AttributeError):
            getattr(mangled, "is-pure")
        self.assertEqual(mangled._fields[3], "_3")
        self.assertEqual(mangled[3], "false")
        self.assertEqual(mangled._3, "false")
        self.assertEqual(mangled._3, rec["is-pure"])
        # non-hyphenated keys are untouched by rename=True
        self.assertEqual(mangled.name, "sym.check")
        self.assertIs(mangled.noreturn, False)

    def test_cmdj_returns_empty_dict_not_raise(self) -> None:
        """cmdj() gives {} for empty output; the consumer treats it as empty without raising."""
        mock_open = MagicMock()
        session = MagicMock()
        session.cmdj.return_value = {}
        mock_open.return_value = session

        with patch.dict("sys.modules", {"r2pipe": MagicMock(open=mock_open)}):
            import r2pipe  # patched module

            fns = _bulk_functions(r2pipe.open("t"))

        self.assertIsInstance(fns, list)
        self.assertEqual(fns, [])
        self.assertEqual(_render_afl(fns), [])
        mock_open.assert_called_once_with("t")
        session.cmdj.assert_called_once_with("aflj")

    def test_bulk_enumeration_empty(self) -> None:
        """aflj pre-analysis is [], aE is {}, garbage is None — all render as no functions."""
        for empty in ([], {}, None):
            session = MagicMock()
            session.cmdj.return_value = empty
            self.assertEqual(_bulk_functions(session), [], f"{empty!r} must mean zero functions")
            session.cmdj.assert_called_once_with("aflj")

        recs = [
            _aflj_element(0x10c0, "sym.deregister_tm_clones", 41, 34),
            _aflj_element(0x10f0, "sym.register_tm_clones", 51, 57),
        ]
        session = MagicMock()
        session.cmdj.return_value = recs
        self.assertEqual(_bulk_functions(session), recs)

    def test_aflj_realsz_vs_size(self) -> None:
        """afl's size column is realsz: 34/57 here, while aflj size says 41/51."""
        recs = [
            _aflj_element(0x10C0, "sym.deregister_tm_clones", 41, 34),
            _aflj_element(0x10F0, "sym.register_tm_clones", 51, 57),
        ]
        for rec in recs:
            self.assertNotEqual(rec["size"], rec["realsz"], "canned pair must differ")

        lines = _render_afl(recs)
        self.assertEqual(
            lines,
            [
                "0x0010c0    34  sym.deregister_tm_clones",
                "0x0010f0    57  sym.register_tm_clones",
            ],
        )

        by_size = [f"{r['addr']:#08x}  {r['size']:>4}  {r['name']}" for r in recs]
        self.assertNotEqual(lines, by_size, "rendering off size() is the bug")
        self.assertIn("41", by_size[0])
        self.assertIn("51", by_size[1])
        self.assertNotIn("41", lines[0])
        self.assertNotIn("51", lines[1])
        self.assertIn("34", lines[0])
        self.assertIn("57", lines[1])

    def test_patch_verify_reads_bytes_not_exit_code(self) -> None:
        """r2 exits 0 even when the write is refused; only the read-back hex proves the patch."""
        session = MagicMock(returncode=0)
        session.cmd.side_effect = [WRITE_REFUSAL, BYTES_AT_1169_BEFORE]
        write_out, patched, observed = _patch_byte(session, 0x1169, SETZ_PATCH)

        self.assertIn("Cannot write", write_out, "r2 reports the refusal on stdout")
        self.assertIn("reopen the file in rw with `oo+`", write_out)
        self.assertEqual(session.returncode, 0, "r2 really does exit 0 on a refused write")
        self.assertFalse(patched, "exit code 0 must not be read as 'patch applied'")
        self.assertEqual(observed, BYTES_AT_1169_BEFORE)

        # the byte read is the confirmation step
        self.assertEqual(session.cmd.call_count, 2)
        verify_call = session.cmd.call_args_list[1].args[0]
        self.assertIn("p8 3", verify_call)
        self.assertIn("0x1169", verify_call)
        self.assertNotIn("wx", verify_call)

        # success case: same exit code, different read-back bytes
        session = MagicMock(returncode=0)
        session.cmd.side_effect = ["", SETZ_PATCH]
        write_out, patched, observed = _patch_byte(session, 0x1169, SETZ_PATCH)
        self.assertEqual(write_out, "")
        self.assertTrue(patched)
        self.assertEqual(observed, SETZ_PATCH)

    def test_esil_scratch_address_is_inside_stack_map(self) -> None:
        """0x177800 == rsp - 0x800 and sits inside the aeim map (0x100000-0x1effff)."""
        self.assertEqual(AEIM_RSP, 0x178000)
        self.assertEqual(SCRATCH_ADDR, 0x177800)
        self.assertEqual(SCRATCH_ADDR, AEIM_RSP - SCRATCH_OFFSET)

        self.assertTrue(_inside_aeim_map(SCRATCH_ADDR))
        self.assertTrue(_inside_aeim_map(AEIM_RSP))
        self.assertLessEqual(AEIM_MAP_START, SCRATCH_ADDR)
        self.assertGreaterEqual(AEIM_MAP_END, SCRATCH_ADDR)
        # aeim takes no argument: aeim 0x1000 maps 0x1000-0xf0fff and drops the scratch
        self.assertFalse(0x1000 <= SCRATCH_ADDR <= 0xF0FFF)


_INTEGRATION_SRC = (
    "int check(char*s){int r=0;for(int i=0;s[i];i++)r+=s[i]^0x5a;return r==1234;}\n"
    "int main(int c,char**v){return check(v[1]);}\n"
)


def _run_r2_json(args: list) -> object:
    out = subprocess.run(
        ["r2", "-q", "-A", *args],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return json.loads(out.stdout)


@unittest.skipUnless(
    shutil.which("r2") and shutil.which("cc"),
    "integration test needs r2 and cc on PATH",
)
class TestReverseR2Integration(unittest.TestCase):
    """Real r2 + cc on the trivial check binary from ctf-reverse."""

    def test_check_binary_functions_and_xref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "t.c")
            exe = os.path.join(tmp, "t")
            with open(src, "w", encoding="utf-8") as fh:
                fh.write(_INTEGRATION_SRC)
            subprocess.run(
                ["cc", "-O0", "-o", exe, src],
                check=True,
                capture_output=True,
                timeout=300,
            )

            fns = _run_r2_json(["-c", "aflj", exe])
            self.assertIsInstance(fns, list)
            # The exact function count depends on the platform's C runtime:
            # glibc ELF appends ~7 startup stubs (entry0, __libc_csu_*,
            # *tm_clones, ...) while Mach-O adds none. Assert the source
            # functions are present rather than pinning a platform-specific
            # count.
            self.assertGreaterEqual(
                len(fns), 2, f"expected at least check+main, got {[f['name'] for f in fns]}"
            )
            names = {f["name"] for f in fns}
            # Symbol decoration differs by target: "sym.check" on ELF,
            # "sym._check" on Mach-O (leading underscore). Match either.
            check_name = next(
                (n for n in names if n == "check" or n.endswith("check")), None
            )
            self.assertIsNotNone(check_name, f"check fn not found among {sorted(names)}")
            self.assertIn("main", names)

            for f in fns:
                self.assertIsInstance(f["is-pure"], str, "r2 emits is-pure quoted")
                self.assertIsInstance(f["addr"], int)
                self.assertIsInstance(f["size"], int)
                self.assertIsInstance(f["realsz"], int)

            # axt means "who calls this": check has exactly one *caller* (main).
            # Some targets also report a data-reference xref (type "NULL"), so
            # filter to CALL xrefs. The call mnemonic is arch-specific ("call"
            # on x86, "bl" on arm64), so verify the caller and the referenced
            # name, not the opcode string.
            xrefs = _run_r2_json(["-c", f"axtj @ {check_name}", exe])
            self.assertIsInstance(xrefs, list)
            callers = [x for x in xrefs if x.get("type") == "CALL"]
            self.assertEqual(1, len(callers), f"expected one CALL xref, got {xrefs}")
            self.assertEqual("main", callers[0].get("fcn_name"))
            self.assertEqual("CALL", callers[0].get("type"))
            self.assertEqual(check_name, callers[0].get("refname"))


if __name__ == "__main__":
    unittest.main()
