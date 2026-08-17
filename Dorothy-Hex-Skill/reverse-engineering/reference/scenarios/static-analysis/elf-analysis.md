# ELF Analysis — Static Recipe

## When this applies

- Target is a Linux executable, shared library, or kernel module: `file` reports `ELF 32-bit/64-bit LSB`.
- You need to understand functions, strings, imports, and architecture before any deeper analysis.
- Trigger: any reverse engineering task starting from a Linux binary with no source available.

## Technique

Walk the ELF from the outside in: header → sections → strings → symbols → imports → disassembly. Use a layered toolchain — fast triage with `file/strings/readelf`, then deep dive in Ghidra / IDA / radare2 / Binary Ninja.

## Steps

### 1. Triage with file metadata

```bash
file binary
readelf -h binary           # ELF header: arch, entry point, type
readelf -S binary           # section headers
readelf -d binary           # dynamic section (libraries, RPATH)
readelf -l binary           # program headers (segments, RWX)
checksec --file=binary      # NX, PIE, RELRO, canary, fortify
```

Note arch (x86_64, aarch64, ARM, MIPS), endianness, and whether it's stripped.

### 2. Extract strings

```bash
strings -n 8 binary > strings.txt
strings -el binary >> strings.txt   # 16-bit (UTF-16LE) — rare on Linux
```

Look for: opcode mnemonics, error messages, library paths, key constants, format strings, embedded URLs / IPs / paths, "you win" / "correct" / "flag{" markers.

### 3. Symbols and imports

```bash
nm -D binary                # dynamic symbols
nm binary                   # all symbols (fails if stripped)
objdump -T binary           # dynamic symbol table
ldd binary                  # shared library dependencies
```

For stripped binaries: import names + library function calls (`puts`, `strcmp`, `memcpy`) + control-flow give enough hints to reconstruct logic.

### 4. Disassembly

| Tool | Strength | When |
|---|---|---|
| `objdump -d` | Fast, scriptable, no GUI | Quick check of a single function |
| `radare2` / `r2` | CLI, scriptable, free | Automated analysis pipelines |
| `Ghidra` | Best decompiler, free | Decompile pseudo-C, deep dive |
| `IDA Pro` | Industry standard | If licensed; best for ARM/MIPS/exotic arch |
| `Binary Ninja` | Modern, scriptable, paid | Decompiler quality between Ghidra and IDA |
| `Cutter` | GUI for radare2 | Free Ghidra alternative with r2 backend |

```bash
# r2 quick recipe
r2 -A binary
[0x00400000]> aaaa            # auto-analyze
[0x00400000]> afl              # function list
[0x00400000]> s main; pdf      # disassemble main
[0x00400000]> izz              # all strings
[0x00400000]> /R "ret"         # ROP gadget search
```

### 5. Find entry / main

`readelf -h` reports the entry point. For statically linked binaries, walk through `_start` → `__libc_start_main` to find user `main`. For stripped binaries: cross-reference the string `"%s"` or the binary name argv[0] to anchor.

### 6. Recognize compiler patterns

- **Stack canary**: `mov rax, fs:0x28` at function prologue.
- **PIC/PIE**: relative addressing, `lea rax, [rip+offset]`.
- **C++ vtables**: `.rodata` blocks of function pointers; `mov rax, [rdi]; call [rax+0x10]` at use site.
- **Rust**: heavy paneling code, mangled symbols (`_ZN…`), unique `core::` references.
- **Go**: `runtime.morestack`, single huge binary, embedded type info in `.gopclntab`.

## Verifying success

- You can name the entry point and main check function.
- You've identified the data flow: input source → transformation → comparison → output.
- Strings cross-reference to specific functions (constants used, success/failure messages).

## Common pitfalls

- **Skipping `checksec`.** Knowing canary/NX/PIE first informs whether buffer overflow is even a vector.
- **Missing dynamic symbols.** Stripped binaries still expose dynamic symbols (`nm -D`) — use them.
- **Confusing stripped with packed.** Stripped = symbols removed, code intact. Packed = code encrypted/compressed (see `obfuscation/packed-binaries.md`). `readelf -h` entry pointing to a tiny `.text` section near a giant `.rodata` is packed.
- **Ignoring relocations.** `.rela.dyn` / `.rela.plt` reveal which addresses are runtime-resolved — important when an address looks "zero" in static dump (it's resolved at load time).
- **One-tool tunnel vision.** Ghidra decompiler may stumble where IDA succeeds, or vice-versa. Cross-check obscure functions in 2 tools.

## Tools

- `binutils` (objdump, readelf, nm, strings) — always available.
- `Ghidra` (free, NSA) — best free decompiler.
- `radare2` / `r2` (free) — CLI / scripting.
- `IDA Pro` / `Binary Ninja` (paid) — when licensed.
- `pwntools` Python — quick wrappers (`ELF('binary').symbols`, `.got`, `.plt`).
- `checksec.sh` — security feature dump.
- `bindiff` / `diaphora` — cross-binary diffing for variant analysis.
