"""Validate that core CTF skills remain discoverable from realistic prompts.

This test is intentionally lightweight: it uses only SKILL.md frontmatter
descriptions plus a small synonym map to simulate first-pass routing.
If a future edit makes descriptions blur together, these cases should fail
before the regression reaches real challenge-solving sessions.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CORE_SKILLS = {
    "ctf-web",
    "ctf-pwn",
    "ctf-reverse",
    "ctf-misc",
    "solve-challenge",
}

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "be",
    "before",
    "but",
    "by",
    "category",
    "categories",
    "challenge",
    "challenges",
    "clear",
    "core",
    "ctf",
    "do",
    "dominant",
    "family",
    "first",
    "for",
    "from",
    "genuine",
    "gives",
    "how",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "know",
    "main",
    "must",
    "need",
    "not",
    "of",
    "on",
    "or",
    "out",
    "performing",
    "point",
    "primarily",
    "problems",
    "provides",
    "real",
    "right",
    "skill",
    "solve",
    "solves",
    "specialized",
    "start",
    "still",
    "such",
    "target",
    "that",
    "the",
    "their",
    "them",
    "then",
    "this",
    "to",
    "use",
    "user",
    "vague",
    "we",
    "when",
    "where",
    "which",
    "with",
    "you",
}

TOKEN_ALIASES = {
    "http": {"http", "https", "web", "website", "browser", "endpoint", "api"},
    "xss": {"xss", "dom", "cookie", "adminbot", "admin", "bot"},
    "sqli": {"sqli", "sql", "database", "union", "blind"},
    "ssti": {"ssti", "template", "jinja2", "twig", "erb"},
    "jwt": {"jwt", "jwe", "token", "jwks", "oauth", "oidc", "saml"},
    "upload": {"upload", "multipart", "polyglot"},
    "buffer": {"overflow", "buffer", "smash"},
    "format": {"format", "printf"},
    "heap": {"heap", "tcache", "uaf", "unlink"},
    "rop": {"rop", "ret2libc", "gadget", "shellcode", "seccomp"},
    "kernel": {"kernel", "kaslr", "slub"},
    "binary": {"binary", "elf", "executable"},
    "obfuscated": {"obfuscated", "packed", "virtualized", "vm", "bytecode"},
    "firmware": {"firmware", "apk", "wasm", "loader"},
    "reverse": {"reverse", "ghidra", "ida", "decompile", "stripped", "protocol"},
    "pyjails": {"pyjail", "python", "jail", "sandbox"},
    "audio": {"audio", "spectrogram", "dtmf", "wav"},
    "qr": {"qr", "barcode"},
    "unicode": {"unicode", "encoding", "esoteric"},
    "dns": {"dns", "zone"},
    "challenge": {"challenge", "bundle", "zip", "pcap", "service", "remote", "nc"},
    "vague": {"unknown", "unsure", "mystery", "suspicious"},
}


def _parse_frontmatter(text: str) -> dict[str, str] | None:
    """Parse the flat frontmatter style used by SKILL.md files."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None

    end = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = i
            break
    if end is None:
        return None

    result: dict[str, str] = {}
    current_block: str | None = None
    for line in lines[1:end]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":") and ":" not in stripped[:-1]:
            current_block = stripped[:-1]
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip().strip('"')
        if current_block:
            result[f"{current_block}.{key}"] = value
        else:
            result[key] = value
    return result


def _tokenize(text: str) -> set[str]:
    """Tokenize text and expand common CTF aliases."""
    raw_tokens = set(re.findall(r"[a-z0-9_./+-]+", text.lower()))
    base_tokens = {
        token
        for token in raw_tokens
        if len(token) >= 3 and token not in STOPWORDS
    }
    expanded = set(base_tokens)
    for canonical, variants in TOKEN_ALIASES.items():
        if base_tokens & variants:
            expanded.add(canonical)
            expanded.update(variants)
    return expanded


def _load_descriptions() -> dict[str, dict[str, set[str]]]:
    """Load positive and negative tokens from each core skill description."""
    descriptions: dict[str, dict[str, set[str]]] = {}
    for skill_dir in sorted(REPO_ROOT.glob("*/SKILL.md")):
        name = skill_dir.parent.name
        if name not in CORE_SKILLS:
            continue
        text = skill_dir.read_text(encoding="utf-8")
        fm = _parse_frontmatter(text)
        if fm is None:
            continue
        desc = fm["description"]
        positive_text, _, negative_text = desc.partition("Do not use")
        descriptions[name] = {
            "positive": _tokenize(positive_text),
            "negative": _tokenize(negative_text),
        }
    return descriptions


def _recommend_skill(prompt: str, descriptions: dict[str, dict[str, set[str]]]) -> str:
    """Recommend the best-matching skill from a prompt."""
    prompt_tokens = _tokenize(prompt)
    best_skill = ""
    best_score = -10**9
    strong_specific = {"xss", "sqli", "ssti", "jwt", "buffer", "heap", "rop", "reverse", "pyjails"}

    for skill, buckets in descriptions.items():
        positive_hits = len(prompt_tokens & buckets["positive"])
        negative_hits = len(prompt_tokens & buckets["negative"])
        score = positive_hits * 3 - negative_hits * 4

        if skill == "ctf-misc":
            if {"pyjails", "audio", "qr", "unicode", "dns"} & prompt_tokens:
                score += 8
            else:
                score -= 8

        # Prefer the dispatcher only when the prompt really is vague.
        if skill == "solve-challenge":
            if {"challenge", "bundle", "zip"} & prompt_tokens:
                score += 2
            if {"unknown", "unsure", "mystery", "suspicious", "vague"} & prompt_tokens:
                score += 5
            if strong_specific & prompt_tokens:
                score -= 8

        if score > best_score:
            best_skill = skill
            best_score = score

    return best_skill


class TestSkillDiscoverability(unittest.TestCase):
    """Core routing descriptions should still separate major CTF categories."""

    @classmethod
    def setUpClass(cls):
        cls.descriptions = _load_descriptions()
        missing = CORE_SKILLS - cls.descriptions.keys()
        if missing:
            raise AssertionError(f"Missing descriptions for: {sorted(missing)}")

    def test_core_skills_win_expected_scenarios(self):
        cases = [
            (
                "ctf-web",
                "The target is a Flask website with JWT cookies, an upload form, and an admin bot that renders HTML. We already see SSTI and possible XSS.",
            ),
            (
                "ctf-pwn",
                "We already confirmed a heap UAF in an ELF service, have a libc leak, and need a tcache poisoning plus ROP chain to get shell.",
            ),
            (
                "ctf-reverse",
                "The challenge gives a stripped binary with a custom VM and obfuscated bytecode. The blocker is understanding what the executable does before exploitation.",
            ),
            (
                "ctf-misc",
                "The service is a Python jail with weird unicode filtering and QR clues. It looks like a hybrid sandbox puzzle rather than web or binary exploitation.",
            ),
            (
                "solve-challenge",
                "Here is a zip bundle from a CTF and a remote nc service. I do not know the category yet and need to figure out where to start.",
            ),
        ]

        for expected, prompt in cases:
            with self.subTest(expected=expected, prompt=prompt):
                actual = _recommend_skill(prompt, self.descriptions)
                self.assertEqual(actual, expected)

    def test_boundary_between_reverse_and_pwn(self):
        cases = [
            (
                "ctf-reverse",
                "We have a packed ELF with anti-debug tricks and no known vulnerability. First we need to reverse the binary and recover the protocol.",
            ),
            (
                "ctf-pwn",
                "We already know the bug is a format string in a native service. The remaining task is stack control, libc leak, and ret2libc exploitation.",
            ),
        ]

        for expected, prompt in cases:
            with self.subTest(expected=expected, prompt=prompt):
                actual = _recommend_skill(prompt, self.descriptions)
                self.assertEqual(actual, expected)

    def test_misc_is_fallback_not_default(self):
        prompt = (
            "The website exposes OAuth redirects, JWT sessions, and a browser admin panel. "
            "It feels unusual, but the core bug family is still web."
        )
        actual = _recommend_skill(prompt, self.descriptions)
        self.assertEqual(actual, "ctf-web")


if __name__ == "__main__":
    unittest.main()
