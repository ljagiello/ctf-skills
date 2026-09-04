"""Known-answer vectors for misc technique snippets.

Validates pure-Python replacements for misc islands:
NFKC normalization bypass, single-byte XOR flag decode,
audit-hook family documentation, QR polyglot workflow,
and BASH_ENV vector documentation.

Each test is deterministic, uses canned small parameters, and
performs only local filesystem reads — no network.
"""

from __future__ import annotations

import base64
import pathlib
import unicodedata
import unittest

try:
    import pytest  # type: ignore[import]
except ImportError:  # pragma: no cover
    pytest = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Helpers — pure-Python, mirror the style of ctf-misc/*.md code fences
# ---------------------------------------------------------------------------


def try_xor(data: bytes | str, key_hint: str = "flag") -> bytes | None:
    """Single-byte brute 256 + repeating-key hint; xor_flag heuristic.

    Mirrors ctf-misc/encodings.md try_xor with exact-match priority
    to avoid 0x20-case collisions (flag vs FLAG).
    """
    raw = data.encode() if isinstance(data, str) else data
    best: bytes | None = None
    # First pass: exact hint match (case-sensitive) — avoids FLAG false positive
    for key in range(256):
        decoded = bytes(b ^ key for b in raw)
        if key_hint and decoded.count(key_hint.encode()) > 0:
            return decoded
    # Second pass: case-insensitive flag + printable fallback
    for key in range(256):
        decoded = bytes(b ^ key for b in raw)
        printable = all(32 <= b < 127 or b in b"\n\r\t" for b in decoded[:64]) if decoded else False
        if printable and b"flag" in decoded.lower():
            return decoded
        if printable and best is None:
            best = decoded
    if key_hint:
        kh = key_hint.encode()
        decoded = bytes(b ^ kh[i % len(kh)] for i, b in enumerate(raw))
        if b"flag{" in decoded or b"CTF{" in decoded:
            return decoded
    return best


def _repo_read_text(rel: str) -> str:
    """Read repo-relative file, handling pytest cwd variations."""
    p = pathlib.Path(rel)
    if p.exists():
        return p.read_text(encoding="utf-8", errors="replace")
    alt = pathlib.Path(__file__).resolve().parent.parent / rel
    return alt.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMiscSnippets(unittest.TestCase):
    """Deterministic known-answer vectors for misc helpers."""

    def test_nfkc_search_finds_fullwidth(self) -> None:
        """Fullwidth U+FF45 NFKC-normalizes to ASCII 'e'."""
        self.assertEqual(unicodedata.normalize("NFKC", "\uff45"), "e")
        self.assertEqual(unicodedata.normalize("NFKC", "\uff45\uff56\uff41\uff4c"), "eval")
        # Brute-force scan mirrors pyjails.md snippet — check e mapping
        found_e = False
        for cp in range(0x10000):
            c = chr(cp)
            n = unicodedata.normalize("NFKC", c)
            if n == "e" and cp == 0xFF45:
                found_e = True
                break
        self.assertTrue(found_e, "NFKC scan should map U+FF45 to 'e'")
        # Also verify scan finds at least one fullwidth eval char
        fullwidth_hits = []
        for cp in range(0x10000):
            c = chr(cp)
            n = unicodedata.normalize("NFKC", c)
            if n in {"e", "v", "a", "l"}:
                fullwidth_hits.append((cp, n))
        self.assertGreaterEqual(len(fullwidth_hits), 4)

    def test_xor_flag_decode(self) -> None:
        """Single-byte XOR with key ord('f') round-trips via base64 + try_xor."""
        plaintext = b"flag{test}"
        key = ord("f")
        xored = bytes(b ^ key for b in plaintext)
        b64 = base64.b64encode(xored).decode()
        self.assertEqual(b64, base64.b64encode(bytes(b ^ ord("f") for b in b"flag{test}")).decode())
        raw = base64.b64decode(b64)
        decoded = try_xor(raw, key_hint="flag")
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded, plaintext)
        self.assertIn(b"flag", decoded.lower())  # type: ignore[union-attr]

    def test_audit_hook_families_present(self) -> None:
        """pyjails.md documents Audit-Hook trampoline families."""
        text = _repo_read_text("ctf-misc/pyjails.md")
        self.assertIn("Audit-Hook", text)

    def test_qr_polyglot_workflow_present(self) -> None:
        """encodings-advanced.md documents pngcheck/binwalk QR polyglot workflow."""
        text = _repo_read_text("ctf-misc/encodings-advanced.md")
        self.assertTrue("pngcheck" in text or "binwalk" in text)

    def test_bash_env_vector_present(self) -> None:
        """bashjails.md documents BASH_ENV env vector."""
        text = _repo_read_text("ctf-misc/bashjails.md")
        self.assertIn("BASH_ENV", text)
