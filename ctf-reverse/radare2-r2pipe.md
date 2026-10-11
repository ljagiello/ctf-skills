# CTF Reverse - Radare2 Scripting and r2pipe Automation

Scripted radare2 for CTF reverse work: batch one-liners, byte patching, in-place decompilation with r2ghidra, ESIL single-function emulation, JSON output parsing, and xref-based checker mapping. Reach for it when a task needs repeatable automation — patching a branch, brute-forcing a checker, or emulating a decrypt routine — instead of an interactive session. For interactive GDB workflows see [tools.md](tools.md) and [tools-dynamic.md](tools-dynamic.md); everything here is verified on radare2 `6.2.2 +37863 abi:142` (linux-x86-64) with r2pipe `1.9.8` on a PIE x86-64 ELF built with `cc -O0`.

## When to script radare2

Radare2 is an automation backend, not just an interactive disassembler: every command runs headless via `-c`, and the JSON command family (`aflj`, `pdfj`, `axtj`, ...) turns its analysis into plain data structures, which is the reason scripting works at all. Use `cmd()` when you want r2's text output for a human and `cmdj()` when you want it parsed. r2pipe 1.9.8's `cmd()` does NOT strip despite its docstring (`.cmd('?e hi')` returns `'hi\n'`), so always call `.strip()` on it yourself.

```python
import r2pipe

r2 = r2pipe.open('BINARY')
r2.cmd('aaa')             # '' - all INFO/WARN lines go to stderr
r2.cmd('afl~?').strip()   # '9' - cmd() does not strip, you must
fns = r2.cmdj('aflj')     # JSON in, plain python out - always cmdj(), never cmdJ()
r2.quit()                 # None
```

**Key insight:** The `j`-suffixed commands are the whole scripting story — text commands for eyeballing, JSON commands for code.

## Batch mode without an interactive shell

Reach for `-c` one-liners when you need one answer from a binary (function count, a byte window, a decompile) without sitting at the prompt. Analysis is not automatic: functions do not exist until you analyze, so bare `afl` prints nothing on stdout and still exits 0. `-A` and `aaa` are equivalent (`afl~?` gives `9` either way), `~?` is a line-count grep modifier (not "help"), and repeated `-c` flags run in order.

```bash
r2 -q -c 'afl' FILE 2>/dev/null                       # nothing on stdout, exit 0

r2 -q -A -c 'afl~?' FILE 2>/dev/null                  # -> 9
r2 -q -c 'aaa;afl~?' FILE 2>/dev/null | tail -1       # -> 9 (equivalent to -A)

r2 -q -A -c 'echo STEP1' -c 'afl~?' FILE 2>/dev/null  # STEP1, then 9
```

Two traps. First, `-0c` / `-q0c` / `-q0qc` all parse, but the documented NUL byte is NOT emitted in batch mode on 6.2.2, so treat `-0c` as an alias for `-c`:

```bash
r2 -q0c 'p8 32 @ entry0' FILE 2>/dev/null | radiff2 - FILE   # ERROR: Cannot open '-'
```

`radiff2` has no stdin mode at all. Second, stderr noise is expected: r2 writes `WARN: Relocs has not been applied...` and analysis `INFO:` lines there, which is why every r2 one-liner below appends `2>/dev/null`.

**Key insight:** Batch mode is one `-A` plus `2>/dev/null` — functions do not exist until analysis runs, and the stderr chatter is informational, not an error.

## Patching bytes with wx in batch mode

Reach for batch patching to force a branch, neuter a check, or NOP an anti-debug trap. The working form is `r2 -w -q -c 'wx <hexbytes> @ <vaddr>' FILE`. Every flag must PRECEDE the filename: `r2 -q -c 'wx 90 @ 0x1162' FILE -w` prints `ERROR: Cannot open '-w'`, exits 1, and patches nothing. Omitting `-w` fails SILENTLY — the error is only ``ERROR: Cannot write. Use `omp`, `io.cache` or reopen the file in rw with `oo+` `` on stderr and the exit code stays 0.

Verified worked patch: `sete al` (`0f 94 c0`) at `0x1169` becomes `mov al, 1 ; nop` (`b0 01 90`), which flips the target's exit code from 0 (any input) to 1 (any input):

```bash
r2 -w -q -c 'wx b00190 @ 0x1169' t_true 2>/dev/null

# verify by re-reading the bytes - rabin2 -S prints only the section table and CANNOT confirm them
r2 -q -c 'p8 3 @ 0x1169' t_true 2>/dev/null      # -> b00190
xxd -s 0x1169 -l 3 t_true
radiff2 -q orig patched
```

A symbolic target needs analysis: `r2 -w -q -c 'wx b00190 @ dbg.check+0x50' t` fails with `ERROR: Invalid tmpseek address 'dbg.check+0x50'`, and adding `-A` fixes it. A numeric vaddr needs no `-A`, and pure arithmetic (`@ 0x1119+0x50`) also resolves without it. Never trust r2's exit code: it returns 0 for failed commands and for failed writes, and only a missing input file gives 1. On this PIE x86-64 ELF `.text` paddr == vaddr, but that must NOT be generalised — `.init_array` and `.data` have paddr != vaddr on the same binary.

**Key insight:** All flags before the filename, `-w` or the patch is dropped, and the only trustworthy confirmation is re-reading the patched bytes with `p8`, `xxd`, or `radiff2`.

## Decompiling in place with r2ghidra

r2ghidra is ABI-locked to the radare2 version, so check that first: the prebuilt `r2ghidra-6.2.4-linux-x86-64.zip` loads against ABI 152 and refuses on r2 6.2.2 (`abi:142`) with `WARN: ABI mismatch: Expect 142 vs 152 from '.../core_ghidra.so'` followed by the usual `You need to install the plugin with r2pm -ci r2ghidra` advice. There is NO `r2ghidra-6.2.2-*-linux-x86-64.zip` asset (all variants 404); the 6.2.2 tag ships only macos/w64 zips, a generic zip, a tar.xz, and `r2ghidra_6.2.2_amd64.deb`, all listed at [github.com/radareorg/r2ghidra/releases](https://github.com/radareorg/r2ghidra/releases). Pick the asset matching your own r2 version and ABI, not the newest one. The verified install is the version-matched `.deb`, unpacked without root because `dpkg-deb` is missing — the shipped `.so` is native C++ (NEEDED: libr_core.so, libr_anal.so, libstdc++, libm, libc, no libjvm), so no JDK is needed for this path:

```bash
ar x r2ghidra_6.2.2_amd64.deb
tar xJf data.tar.xz
cp usr/lib/radare2/6.2.2/core_ghidra.so ~/.local/share/radare2/plugins/
cp -r usr/lib/radare2/6.2.2/r2ghidra_sleigh/ ~/.local/share/radare2/plugins/
```

`r2pm -ci r2ghidra` is the valid alternative on 6.2.2 but takes the SOURCE path — `./preconfigure`, `./configure`, `make -C src` — compiling ghidra-native C++ for minutes. Once loaded, after `aaa`:

```bash
r2 -q -A -c 'pdg @ sym.check' FILE 2>/dev/null
```

prints the pseudocode. `pdg @ sym.check`, verbatim:

```c
bool sym.check(int64_t arg1)

{
    int64_t var_18h;
    uint32_t var_8h;
    int32_t var_4h;

    var_8h = 0;
    for (var_4h = 0; *(arg1 + var_4h) != '\0'; var_4h = var_4h + 1) {
        var_8h = var_8h + (*(arg1 + var_4h) ^ 0x5a);
    }
    return var_8h == 0x4d2;
}
```

`pdg @ main` on the same binary:

```c
void main(int argc,char **argv)

{
    char **var_10h;
    int32_t var_4h;

    sym.check(argv[1]);
    return;
}
```

`pdgj @ sym.check` returns JSON with the decompiler text under the `code` key:

```json
{"code":"\nbool sym.check(int64_t arg1)\n\n{...}\n","annotations":[{"start":1,"end":5,"type":"syntax_highlight","syntax_highlight":"datatype"},...]}
```

**Key insight:** Match the plugin ABI to your r2 version — the prebuilt 6.2.4 zip will not load into 6.2.2, and the version-matched `.deb` unpacks cleanly with `ar` + `tar`.

## Emulating a single function with ESIL

ESIL emulates one function in-process with no debugger and no unicorn — enough to run a self-contained transform loop and read the result out of a scratch buffer. It is the fastest route for small decrypt/check routines that touch only their arguments and static data. Build the target with `cc -O0 -o dec dec.c`. After `aaa`: `sym.decrypt = 0x1119`, `ret` at `0x1163`, `obj.enc = 0x2020` (.rodata), `obj.plain = 0x4040` (.bss). The plaintext is `ESIL emulation recovered the plaintext!!`.

```c
#include <stddef.h>
#include <stdint.h>

/* ciphertext: each byte is the plaintext char below ^ 0x5a */
static const uint8_t enc[40] = {
    0x1f, 0x09, 0x13, 0x16, 0x7a, 0x3f, 0x37, 0x2f, 0x36, 0x3b, 0x2e, 0x33,
    0x35, 0x34, 0x7a, 0x28, 0x3f, 0x39, 0x35, 0x2c, 0x3f, 0x28, 0x3f, 0x3e,
    0x7a, 0x2e, 0x32, 0x3f, 0x7a, 0x2a, 0x36, 0x3b, 0x33, 0x34, 0x2e, 0x3f,
    0x22, 0x2e, 0x7b, 0x7b,
};

uint8_t plain[40];

/* dst = src ^ 0x5a, n bytes   (SysV x86-64: rdi, rsi, rdx) */
void decrypt(uint8_t *dst, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++)
        dst[i] = src[i] ^ 0x5a;
}

int main(void)
{
    decrypt(plain, enc, sizeof enc);
    return 0;
}
```

The verified session, run verbatim, recovered the plaintext with no unicorn and no debugger:

```text
$ r2 -q -A dec
[0x00001140]> s sym.decrypt
[0x00001119]> aei                     # init ESIL VM
[0x00001119]> aeim                    # init stack (no size arg)
[0x00001119]> aeip                    # PC = current seek = 0x1119
[0x00001119]> aer rdi=0x177800        # dst  -> scratch inside the stack map
[0x00001119]> aer rsi=obj.enc         # src  = 0x2020 (.rodata)
[0x00001119]> aer rdx=40              # n
[0x00001119]> aesu sym.decrypt+0x4a   # == 0x1163, the `ret`
[0x00001163]> ps @ 0x177800
ESIL emulation recovered the plaintext!!
```

`0x177800` is `rsp (0x178000) - 0x800`, inside the map `mem.0x100000_0xf0000` (`0x100000-0x1effff`, rw) — a scratch destination instead of the real `.bss` global. Every one of these caveats is verified:

- NEVER skip `aeim`. Without it `rsp = 0`, the prologue's `push rbp` and frame stores wrap to `0xffff...`, the frame reads back as 0, `i < n` is false on the first iteration, and the output buffer stays all zeros with NO error printed.
- `aeim` takes NO argument on 6.2.2. It uses `esil.stack.addr = 0x00100000`, `esil.stack.size = 0x000f0000`, and sets `rsp = 0x178000`. Passing `aeim 0x1000` FAILS SILENTLY: it maps `0x1000-0xf0fff`, shadowing the binary's own LOAD segments, and all ESIL writes are dropped while `rip` still reaches the `ret`.
- Writing into a real `.bss`/`.data` global (`aer rdi=0x4040`) requires `e io.cache=true` set BEFORE emulation. Without it the writes are silently dropped, and setting `io.cache` after the run does not fix it.
- `aesu <addr>` stops with `rip == addr` WITHOUT executing the instruction there. Stop AT the `ret`, never past it: `aesu 0x1164` walks a garbage return address and overwrites the first plaintext byte (`ESIL` becomes `&SIL`).
- `aei` already sets `rip` to the current seek, so `aeip` is a harmless no-op on 6.2.2 — keep it as the documented idiom.
- `aer` and `ar` both read and write ESIL registers, and r2 flags resolve inside them: `aer rsi=obj.enc` yields `0x00002020`.

**Key insight:** `aei` + `aeim` + `aeip` + `aer` + `aesu <ret>` is the whole recipe; every skipped or misparameterized step fails silently rather than loudly.

## r2pipe session lifecycle

A handle is a whole radare2 process, so plan the session's work up front. `r2pipe.open(path)` gives you `.cmd()` for commands and `.quit()` (which returns `None`) to close; `.cmd('aaa')` returns `''` because every INFO/WARN line goes to stderr. Pass `flags=['-d']` for a debug session — verified working, the child process is `radare2 -d -q0 <bin>` and `db`, `dc`, `dr rip`, `ds 2` all work under it:

```python
import r2pipe

r2 = r2pipe.open('BINARY', flags=['-d'])   # debug session; child is `radare2 -d -q0 <bin>`
r2.cmd('aaa')
r2.cmd('db 0x1119')                        # breakpoint
r2.cmd('dc')                               # continue
print(r2.cmd('dr rip').strip())            # strip() - cmd() never strips
print(r2.cmd('ds 2').strip())              # step
r2.quit()                                  # None
```

Lifecycle facts worth planning around:

- Two live handles in one process are BOTH alive and independent; quitting one leaves the other working. Also verified from two real threads. This refutes the common "one r2 per process" claim.
- Cost: 5 sequential open+aaa+quit cycles measured 23.5 / 22.5 / 22.4 / 21.8 / 22.1 ms — mean 22.5 ms per cycle, about 45 cycles/s. Batch your work per handle instead of reopening per byte.
- Orphan checks: `/usr/bin/r2` is a symlink to `radare2`, so use `pgrep -x radare2`, not `r2`. A debugee PID lingered in 1 of 4 runs immediately after `quit()`, so do not promise zero orphans.
- ANTI-PATTERN: `dcs` on a `-d` session entered an unbounded SIGSEGV loop producing 1.88M lines / 80.7 MB in 60 seconds. Use `db` + `dc` + `dr rip` only.

**Key insight:** Setup and teardown cost about 22 ms per handle, so do all analysis inside one session — and keep the debugging loop to `db`/`dc`/`dr` so a SIGSEGV cannot run away.

## Parsing r2 JSON output with cmdj

On r2pipe 1.9.8 `cmdj()` and `cmdJ()` differ, so pick `cmdj()` always. `cmdj()` returns plain dicts; `cmdJ()` parses through `collections.namedtuple("X", d.keys(), rename=True)`, which mangles r2's hyphenated keys — an `aflj` element's `is-pure` becomes the attribute `_3`. Guard with `isinstance` and `None` checks, not exceptions: `.cmdj('notacommand')` returns `{}` without raising (the source substitutes `"{}"` for empty output), and `.cmdj('pi')` returns `None` while writing `r2pipe.cmdj.Error: Expecting value: line 1 column 1 (char 0)` to stderr.

```python
import r2pipe

r2 = r2pipe.open('BINARY')
r2.cmd('aaa')

fns = r2.cmdj('aflj')             # always cmdj() - never cmdJ() ('is-pure' -> '_3')
if not isinstance(fns, list):     # {} for an unknown command, None for non-JSON output
    fns = []
print(len(fns))

pdf = r2.cmdj('pdfj @ main')      # dict with 'name' and 'size'; 12 ops at main
if pdf is None:
    pdf = {}
r2.quit()
```

The JSON command family (before `aaa` / after `aaa`):

| Command | Returns | Needs aaa | Notes |
|---|---|---|---|
| `aflj` | list | yes | keys `addr`, `name`; pre-analysis it is the string `'[]'` |
| `pdfj` | dict | yes | keys `name`, `size`; `@ main` has `len(ops) == 12`; pre-analysis it is the empty string |
| `agj` | list | yes | keys `name`, `addr`; pre-analysis it is the empty string |
| `izj` | list | — | EMPTY on this ELF (0 entries); use `izzj` for literals (74 entries, keys `vaddr`, `paddr`, `ordinal`, `size`) |
| `axtj` | list | yes | keys `from`, `type`; also needs a seek — at entry0 it returns `[]` silently |
| `iiij` | list | no | keys `ordinal`, `bind` |

Non-JSON output gives `None` for both `cmdj` and `cmdJ`, and empty output (`cdj`, `aE`) gives `cmdj={}` / `cmdJ=None`.

**Key insight:** Always `cmdj()`, never `cmdJ()` — and treat `{}` and `None` as "no data" instead of wrapping calls in `try/except`.

## Mapping checkers with xrefs and aflj

`axt` means "references TO an address" — the CALLERS, not the callees (a common wrong assumption; `axff @ <fn>` gives the callees OF a function and `axf @ <instr>` the refs from one instruction). That inversion is how you find the code that feeds your checker its input:

```bash
r2 -q -A -c 'axt @ sym.check' FILE 2>/dev/null
# dbg.main 0x118e [CALL:--x] call dbg.check

# address the call TARGET, not the call site: axtj @ 0x118e yields []
r2 -q -A -c 'axtj @ sym.check' FILE 2>/dev/null

r2 -q -A -c 'axff @ main' FILE 2>/dev/null        # callees of main
r2 -q -A -c 'axlq' FILE 2>/dev/null               # all xrefs; axlc counts them (28 on the test binary)
```

`axtj` returns a top-level array of objects, with every number DECIMAL (`4494` == `0x118e`):

```json
[{'from':4494,'type':'CALL','perm':'--x','opcode':'call sym.check','fcn_addr':4465,'fcn_name':'main','flag':'sym.main','realname':'main','refname':'sym.check'}]
```

Mapping details that bite scripts: `aef` is NOT an xref command on 6.2.2 (it is ESIL "emulate function" and prints nothing); empty results are `[]` for `axtj` and completely empty for `axt`, and the exit code cannot distinguish them, so parse for `[]`. For bulk enumeration, shell out once and let the JSON do the work:

```python
import json, subprocess
out = subprocess.run(
    ["r2", "-q", "-A", "-c", "aflj", "BINARY"],
    capture_output=True, text=True)
fns = json.loads(out.stdout)
for f in fns:
    print(f"{f['addr']:#08x}  {f['realsz']:>4}  {f['name']}")
print(f"-- {len(fns)} functions")
```

On `aflj` output: numeric fields are decimal; order is analysis order, not address order, so sort if you show sorted output; `aflj` carries both `size` and `realsz`, and `afl`'s size column matches `realsz` (`afl` shows 34/51 for the tm_clones pair while `aflj` shows `size` 41/57 and `realsz` 34/51); `is-pure` is the string `"false"` while other booleans are real JSON `false`/`true`.

**Key insight:** `axt` answers "who calls this", which is exactly the question when a checker's input comes from one caller — then bulk-enumerate functions through `aflj` in a single batch process.

## Script-safe config and stderr noise

Two conventions keep r2 output parseable. First, discard stderr on every invocation: r2 writes `WARN: Relocs has not been applied...` and analysis `INFO:` lines there, so `2>/dev/null` in the shell (or `capture_output=True` in `subprocess`) is the default. Second, pin color off explicitly — `e scr.color=1` yields 18 ANSI escapes in `afl` output, `e scr.color=0` yields 0, and while r2pipe already runs `-q0` (which defaults `scr.color` to 0), setting it yourself is the safe guarantee. For long analyses, `e anal.timeout` stops analysis after N seconds (default `'0'` = no timeout) and round-trips:

```bash
r2 -q -A -c 'afl' FILE 2>/dev/null

r2 -q -c 'e scr.color=0' -c 'afl' FILE 2>/dev/null            # 0 ANSI escapes (scr.color=1 -> 18)

r2 -q -c 'e anal.timeout=5' -c 'e anal.timeout' FILE 2>/dev/null   # -> '5'
```

**Key insight:** Every noisy r2 invocation is script-safe once stderr is discarded and `scr.color=0` is pinned — `anal.timeout` is the only knob you usually need to touch.
