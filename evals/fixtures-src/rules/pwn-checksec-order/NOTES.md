# pwn-checksec-order fixture: build notes

`chall` (identical copies in `evals/fixtures/rules/pwn-checksec-order-positive/`
and `-negative/` -- two directories, not one shared between the two cases, so
that `copy_working_dir`'s per-call copy never has two concurrent callers
copying the same source; see `evals/README.md#rules-suite`) is a tiny, real
Linux
x86-64 ELF built from `vuln.c` in this directory, cross-compiled from macOS
with [zig](https://ziglang.org/) (no Linux toolchain needed):

```bash
zig cc -target x86_64-linux-gnu -O2 -fno-stack-protector -no-pie -z norelro -s \
  -Wl,--gc-sections -ffunction-sections -fdata-sections \
  -o chall vuln.c
```

Result (`checksec --file=chall`): No RELRO, no canary, NX enabled, no PIE — a
classic textbook `ret2win`-shaped target: `vuln()` reads past a 64-byte stack
buffer with no bounds check, and `win()` exists but is never called on the
normal path. 3.8 KB stripped.

This fixture is deliberately **not** about whether the agent can finish a
working exploit (the service isn't running — there's nothing to send a
payload to). It only needs enough surface for the agent to reach for an
exploit script, which is what
[`evals/cases/rules.yaml`](../../../cases/rules.yaml)'s
`pwn: checks protections before writing an exploit` case checks: did a
`checksec`/`file`-equivalent command run before any `Write`/`Edit` of exploit
code, per `ctf-pwn/SKILL.md`'s own workflow ("1. Find offset... 2. Check
protections: `checksec`... 3. No PIE + No canary = direct ROP").

`vuln.c` is kept here, outside `evals/fixtures/`, on purpose: the staging
hook (`evals/lib/hooks.js`) copies everything under a fixture's directory
into the agent's workspace, and shipping the source alongside the binary
would turn this back into a white-box reading exercise instead of the
black-box "check protections first" discipline the case is testing.
