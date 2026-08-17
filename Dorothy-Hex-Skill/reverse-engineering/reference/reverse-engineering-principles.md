# Reverse Engineering Principles

Entry point for reverse engineering scenarios. Use `INDEX.md` to pick a scenario by trigger; this file holds the decision tree and cross-cutting guidance.

## Decision tree

Triage the binary first. Match the most specific fingerprint:

| Fingerprint | Scenario family | First read |
|---|---|---|
| Linux ELF, need first-pass triage | `scenarios/static-analysis/elf-analysis.md` | readelf, strings, checksec |
| Windows PE (or .NET) | `scenarios/static-analysis/pe-analysis.md` | dnSpy if .NET, IDA/Ghidra otherwise |
| Stripped binary, need to find functions | `scenarios/static-analysis/disassembly-recipe.md` | Auto-analyze, find main, rename |
| `strings` mostly empty | `scenarios/static-analysis/string-extraction.md` | FLOSS for stack/decoded |
| Two files: host binary + program data | `scenarios/custom-vm/bytecode-disassembly.md` | Identify dispatcher loop, opcode map |
| `.text` tiny, `.data` huge entropy, IAT minimal | `scenarios/obfuscation/packed-binaries.md` | Detect packer, manual unpack |
| Thousands of `pop r8 ; body ; call next` chunks | `scenarios/obfuscation/callfuscation.md` | Linearize via DFS |
| Operators wrapped in 50-200 byte junk functions | `scenarios/obfuscation/mba-deobfuscation.md` | Probe with small inputs |
| Decoder function called before each string use | `scenarios/obfuscation/string-obfuscation.md` | Static decode or hook decoder |
| Linux binary exits under GDB | `scenarios/anti-debug/ptrace-bypass.md` | LD_PRELOAD or patch `ptrace` |
| Windows binary exits under x64dbg | `scenarios/anti-debug/isdebuggerpresent-bypass.md` | ScyllaHide profile |
| Behavior changes under any debugger (timing) | `scenarios/anti-debug/timing-checks-bypass.md` | RDTSC intercept or patch comparison |
| Standard breakpoints don't land / self-checksums | `scenarios/anti-debug/int3-detection-bypass.md` | Hardware breakpoints |
| Need to observe / modify function-call boundary | `scenarios/dynamic-analysis/frida-hooking.md` | Interceptor.attach |
| Need to see what files / network it touches | `scenarios/dynamic-analysis/ltrace-strace.md` | strace -f -e trace=... |
| Need scripted introspection across many BP hits | `scenarios/dynamic-analysis/gdb-scripting.md` | gdb Python API |

## Sequencing principles

1. **Triage before deep dive.** Always start with `file`, `strings`, `checksec` / `Detect It Easy`. A 2-minute fingerprint saves hours.
2. **Static first, dynamic second.** Static analysis is faster, more reliable, and doesn't trigger anti-debug. Reach for Frida/GDB only when static is insufficient.
3. **Identify the language / runtime.** .NET in dnSpy beats IDA. Go has its own metadata. Rust has mangled symbols. Pick the right tool.
4. **Read the obvious before the obscure.** Strings, imports, exports, error messages are the highest-yield signals — read them before disassembling.
5. **Recognize patterns, don't trace bytes.** A `while(true){op=mem[pc++]; switch(op){...}}` is a VM. A function full of `pop/call` is callfuscation. A function full of `imul`/`not`/`and` is MBA. Pattern-match first.
6. **Re-emulate to validate.** Whenever you derive a "solver" (e.g. inverted custom-VM logic), re-run the original through your model and confirm it matches before submitting.
7. **Patch the comparison, not the primitive.** When defeating anti-debug / timing checks, the comparison `jb threshold` is one byte to flip. Spoofing the timer / debugger state often takes more code.
8. **Pure Python is enough for inversion.** ≤200 instructions of custom VM, ≤256-bit GF(2) linear collapse, custom permutations — all faster in Python than in Ghidra scripting.

## Cross-cutting gotchas

- **Calling convention.** x86_64 Linux uses RDI/RSI/RDX/RCX/R8/R9 for args; Windows x64 uses RCX/RDX/R8/R9. Wrong convention → wrong arg inference.
- **Bitness mismatch.** 32-bit binary on 64-bit Frida-server crashes. Always match arch.
- **Stripped vs packed.** Stripped = symbols removed but code intact. Packed = code encrypted. Different responses.
- **Position-Independent Code.** PIE / ASLR shifts addresses each run; hardcoded addresses break. Use `Module.findBaseAddress + offset` (Frida) or `info proc mappings` (GDB).
- **Int width truncation.** 32-bit `+` in a 64-bit world masks to `0xFFFFFFFF`. MBA probing must match the width.
- **Endian / sign extension.** `mov edi, [rax]; mov [..], rdi` zero-extends; sign-extension breaks equality chains for negative constants. Always mask explicitly when re-emulating.
- **Anti-Frida / anti-VM.** Same theme as anti-debug — detection of the analysis tool. Stealth modes / DKOM-level tricks defeat most detection.
- **Don't run untrusted binaries on host.** Sandbox / VM / `firejail` always. Especially for unknown malware samples.
