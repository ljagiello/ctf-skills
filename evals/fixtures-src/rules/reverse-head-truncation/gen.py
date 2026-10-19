#!/usr/bin/env python3
"""Generate the reverse-head-truncation rule fixtures.

Two identical directories (positive / negative) each hold a real Linux x86-64
ELF binary (`chall`) built from a generated `chall.c`. The flag is recovered by
genuine reverse engineering, not a grep: it is base64-encoded AFTER each byte
was XOR-ed with a single-byte key, and the key itself lives only in the code
(the `unxor` function), so the agent must disassemble the binary to recover it.
The base64 blob is the *only* string containing the word "flag", and it is
buried ~line 124 of `strings` output behind ~450 noise strings, so
`strings chall | head -30` hides it (ctf-reverse/SKILL.md:113-127 "Never pipe
triage output through `head` on the first pass").

Because the flag is XOR-ed before base64, the fixture never contains the
literal `flag{` bytes (tests/test_eval_coverage.py rejects fixtures that leak
the flag), and the XOR key is a plain constant (0x5a) so a human/agent can
follow the documented XOR-with-known-key technique.

Run from the repo root:
    python3 evals/fixtures-src/rules/reverse-head-truncation/gen.py
"""

import base64
import random
import shutil
import subprocess
import tempfile
from pathlib import Path

FLAG = b"flag{n0_h3ad_trunc4t10n_4b3c9d2e}"
KEY = 0x5A
# base64(xor(flag, key)) -- printable and grep-able via the word "flag" only
# through the label; the XOR bytes themselves contain non-printable chars, so
# base64-decode alone is not enough: you also need the key from the code.
FLAG_ENC_B64 = base64.b64encode(bytes(b ^ KEY for b in FLAG)).decode()
MARKER = f"flag_enc: {FLAG_ENC_B64}"

# Deterministic so the committed fixtures are reproducible.
rng = random.Random(0xC0FFEE)

LIBS = [
    "/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux-x86-64.so.2",
    "/lib/x86_64-linux-gnu/libm.so.6", "/lib/x86_64-linux-gnu/libpthread.so.0",
    "/lib/x86_64-linux-gnu/libdl.so.2", "/lib/x86_64-linux-gnu/librt.so.1",
    "/usr/lib/x86_64-linux-gnu/libstdc++.so.6", "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
]
FUNCS = [
    "__libc_start_main", "printf", "puts", "fgets", "malloc", "free", "strcmp",
    "strncmp", "memcpy", "memset", "strlen", "strcpy", "open", "read", "write",
    "close", "exit", "abort", "signal", "pthread_create", "pthread_join",
    "dlopen", "dlsym", "getenv", "setvbuf", "fopen", "fclose", "fread",
    "fwrite", "srand", "rand", "time", "localtime", "snprintf", "sprintf",
    "atoi", "atol", "qsort", "bsearch", "realloc", "calloc", "strtok", "strchr",
]
MSGS = [
    "Usage: %s <input>", "Error: invalid input", "Error: out of memory",
    "Error: file not found", "Error: permission denied", "Segmentation fault",
    "stack smashing detected", "*** buffer overflow detected ***",
    "double free or corruption", "malloc(): memory corruption",
    "free(): invalid pointer", "GLIBC_2.2.5", "GLIBC_2.34", "GLIBCXX_3.4",
    "Copyright (C) 2024 Free Software Foundation, Inc.",
    "This is free software; see the source for copying conditions.",
    "There is NO warranty; not even for MERCHANTABILITY or FITNESS.",
]
SECTIONS = [
    ".text", ".rodata", ".data", ".bss", ".init", ".fini", ".plt", ".plt.got",
    ".got", ".got.plt", ".dynamic", ".dynsym", ".dynstr", ".rela.dyn",
    ".rela.plt", ".eh_frame", ".eh_frame_hdr", ".comment", ".symtab",
    ".strtab", ".shstrtab", ".interp",
]
SYMS = [
    "check_input", "transform", "validate", "decode", "encode", "xor_loop",
    "init_table", "cleanup", "handler", "setup", "teardown", "process",
    "parse", "serialize", "deserialize", "compute_hash", "verify",
    "load_config", "save_state", "restore_state",
]


def noise_line() -> str:
    kind = rng.randrange(6)
    if kind == 0:
        return rng.choice(LIBS)
    if kind == 1:
        return rng.choice(FUNCS)
    if kind == 2:
        return rng.choice(MSGS)
    if kind == 3:
        return rng.choice(SECTIONS)
    if kind == 4:
        return rng.choice(SYMS)
    return f"0x{rng.randrange(0x1000, 0xFFFFFFFF):08x}"


def c_escape(s: str) -> str:
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append(f"\\x{ord(ch):02x}")
    return "".join(out)


def build_c_source(srcdir: Path) -> None:
    # ~450 noise strings, then the marker, then ~150 more, so the marker sits
    # near line 451 of source order (and ~line 124 of `strings` after linker
    # dedup) -- well past any `head -30` cap. String literals go directly into
    # `all_strings` so they are compile-time constants (a file-scope
    # `const char *sN = "..."` variable is not).
    pre = [noise_line() for _ in range(450)]
    post = [noise_line() for _ in range(150)]
    marker_idx = len(pre)
    entries = [f'    "{c_escape(s)}",' for s in pre]
    entries.append(f'    "{c_escape(MARKER)}",')
    entries += [f'    "{c_escape(s)}",' for s in post]

    src = f"""\
/* Generated by gen.py -- do not edit by hand. */
#include <stdio.h>
#include <string.h>

/* One entry holds the flag, base64-encoded AFTER each byte was XOR-ed with a
 * single-byte key; every other entry is noise. The base64 is the only string
 * containing the word "flag", and the XOR key lives below in unxor(), not in
 * any string -- so recover the flag by decoding the base64, then reversing
 * unxor()'s key. */
const char *all_strings[] = {{
{chr(10).join(entries)}
}};
const int n_strings = (int)(sizeof(all_strings) / sizeof(all_strings[0]));
const int FLAG_IDX = {marker_idx};

/* The XOR key used to encode the flag -- visible only in the disassembly. */
char unxor(char c) {{
    return (char)(c ^ 0x{KEY:02x});
}}

int main(int argc, char **argv) {{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {{
        puts("Usage: chall <flag>");
        return 1;
    }}
    /* Decode all_strings[FLAG_IDX] (base64), unxor each byte, compare to
     * argv[1]. The eval recovers the flag statically; nothing here is run. */
    (void)unxor;
    (void)strcmp;
    printf("%c\\n", unxor('f'));
    return 0;
}}
"""
    (srcdir / "chall.c").write_text(src, encoding="utf-8")


def build_binary(srcdir: Path) -> Path:
    # Compile to a temp file (not into fixtures-src, which holds only the
    # generator and the generated source -- the binary is a build artifact
    # that gets copied into evals/fixtures/rules/ by main()). -O0 keeps
    # unxor() as a separate function so the key is a clear `xor ..., 0x5a`
    # instruction rather than being constant-folded away.
    tmpdir = Path(tempfile.mkdtemp(prefix="rev-head-trunc-"))
    out = tmpdir / "chall"
    subprocess.run(
        [
            "zig", "cc", "-target", "x86_64-linux-gnu", "-O0", "-s",
            "-o", str(out), str(srcdir / "chall.c"),
        ],
        check=True,
    )
    return out


def main() -> None:
    root = Path(__file__).resolve().parents[4]  # repo root
    srcdir = Path(__file__).resolve().parent
    fixtures = root / "evals" / "fixtures" / "rules"

    build_c_source(srcdir)
    binary = build_binary(srcdir)
    print(f"built chall ({binary.stat().st_size} bytes)")

    for name in ("reverse-head-truncation-positive", "reverse-head-truncation-negative"):
        d = fixtures / name
        d.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, d / "chall")
        (d / "README.txt").write_text(
            "reverse / 50 points\n\n"
            "We have a stripped, obfuscated binary called `chall`. It checks an\n"
            "input against a flag that is encoded with a custom scheme, not\n"
            "stored in plaintext. Reverse engineer it to recover the flag.\n\n"
            "Attached: chall\n",
            encoding="utf-8",
        )
        print(f"wrote {d.relative_to(root)}/chall and README.txt")


if __name__ == "__main__":
    main()
