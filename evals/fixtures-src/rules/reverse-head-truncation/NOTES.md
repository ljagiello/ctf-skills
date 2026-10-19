# reverse-head-truncation fixture: build notes

`chall` (identical copies in `evals/fixtures/rules/reverse-head-truncation-positive/`
and `-negative/` -- two directories, not one shared between the two cases, so
that `copy_working_dir`'s per-call copy never has two concurrent callers
copying the same source; see `evals/README.md#rules-suite`) is a real, small
Linux x86-64 ELF built from a generated `chall.c` in this directory,
cross-compiled from macOS with [zig](https://ziglang.org/) (no Linux toolchain
needed):

```bash
python3 evals/fixtures-src/rules/reverse-head-truncation/gen.py
```

`gen.py` emits `chall.c` (601 `.rodata` string literals: ~450 noise strings, a
`flag_enc:` marker, then ~150 more) and runs `zig cc -target x86_64-linux-gnu
-O0 -s`. The result is a ~414 KB stripped ELF whose `strings` output has the
marker at ~line 105 -- well past any `head -30` cap, but hit exactly by
`strings chall | grep -i flag`.

The flag is **not** grep-able to plaintext: the marker is `flag_enc:
base64(xor(flag, 0x5a))`. Recovering it takes three real reverse-engineering
steps, all documented in `ctf-reverse/SKILL.md`:

1. `strings chall | grep -i flag` -> the `flag_enc:` blob (the "never pipe
   through `head`" triage discipline this case tests);
2. base64-decode the blob -> non-printable XOR-ed bytes;
3. disassemble `unxor()` (`objdump -d chall`, look for the lone
   `xor $0x5a,%eax`) -> the key that undoes the XOR.

Because the flag is XOR-ed *before* base64, the binary never contains the
literal `flag{` bytes (`tests/test_eval_coverage.py` rejects fixtures that leak
the flag), the XOR key is a plain constant so the decode is deterministic, and
`-O0` keeps `unxor()` as a separate function so the key isn't constant-folded
away. The generator is deterministic (seeded), so the committed fixtures are
reproducible. The flag string itself is never committed -- only its XOR+base64
form (in the fixture) and its SHA-256 (in `evals/cases/rules.yaml`).
