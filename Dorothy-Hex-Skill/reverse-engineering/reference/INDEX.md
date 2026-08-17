# Reverse Engineering — Scenario Index

Read `reverse-engineering-principles.md` first for the decision tree. This index maps fingerprints to scenario files.

## Static Analysis

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Linux ELF triage | `scenarios/static-analysis/elf-analysis.md` | readelf + strings + checksec + Ghidra |
| Windows PE / .NET triage | `scenarios/static-analysis/pe-analysis.md` | DIE + dnSpy or IDA |
| Stripped binary, find functions | `scenarios/static-analysis/disassembly-recipe.md` | Auto-analyze, find main, rename, retype |
| `strings` mostly empty | `scenarios/static-analysis/string-extraction.md` | FLOSS for stack / decoded strings |
| Unity IL2CPP game (`GameAssembly.dll` + `global-metadata.dat`) | `scenarios/static-analysis/unity-il2cpp-recipe.md` | Il2CppDumper + dnSpy on DummyDll; resolve metadata tokens via script.json |

## Custom VM

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Host binary + program-data file with custom ISA | `scenarios/custom-vm/bytecode-disassembly.md` | Map opcodes, invert transformations |

## Kernel / Rootkit

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Linux `.ko` rootkit hides flag at runtime; fake flag in static `.rodata`; ftrace/kprobe hooks on `sys_read` | `scenarios/kernel/kernel-rootkit-module.md` | Identify dentry-name filter, dump `/proc/kcore` PT_LOAD covering `0xffffffffc0000000`, strings-grep for the flag |

## Obfuscation

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Tiny `.text`, huge entropy, packer signature | `scenarios/obfuscation/packed-binaries.md` | UPX, manual unpack at OEP |
| Thousands of pop/body/call chunks | `scenarios/obfuscation/callfuscation.md` | DFS linearization |
| D-language binary with 200+ functions each with `cmp [slot], -1; je init; mov [slot], N` lazy-init guard + pattern-AA dispatch (DFA) | `scenarios/obfuscation/d-fiber-callfuscation.md` | Extract DFA, Hamiltonian-path search |
| Operators wrapped in MBA junk | `scenarios/obfuscation/mba-deobfuscation.md` | Probe with small inputs |
| Decoder function called before each string | `scenarios/obfuscation/string-obfuscation.md` | XOR brute / hook decoder |
| Hundreds of `f<N>EPKc` dispatchers, polynomial-hash gates, deterministic output | `scenarios/obfuscation/hash-dispatcher-chain.md` | Z3 over the chain + terminator equations |
| Base64-encoded `marshal` blob (Keras Lambda, pickle `__reduce__`, stripped `.pyc`) | `scenarios/obfuscation/python-bytecode-payload.md` | Disassemble statically, peel XOR/marshal stages, recover secret without `exec` |

## Anti-Debug

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Linux PTRACE_TRACEME / /proc/self/status | `scenarios/anti-debug/ptrace-bypass.md` | LD_PRELOAD shim or patch |
| Windows IsDebuggerPresent / PEB | `scenarios/anti-debug/isdebuggerpresent-bypass.md` | ScyllaHide profile |
| RDTSC / GetTickCount timing | `scenarios/anti-debug/timing-checks-bypass.md` | Hook timer or patch comparison |
| INT3 / 0xCC scan / self-checksum | `scenarios/anti-debug/int3-detection-bypass.md` | Hardware breakpoints, patch check |

## Dynamic Analysis

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Need function-boundary visibility / modification | `scenarios/dynamic-analysis/frida-hooking.md` | Interceptor.attach + replace |
| Need syscall / library call trace | `scenarios/dynamic-analysis/ltrace-strace.md` | strace -f -e trace=file,network |
| Need scripted breakpoint introspection | `scenarios/dynamic-analysis/gdb-scripting.md` | gdb Python API + Breakpoint subclass |
| Stripped Android `.so` compares input via libc strcmp / memcmp | `../../mobile-security/reference/scenarios/android/native-lib-host-extraction.md` | host-side `dlopen` + Bionic→glibc forwarder, hook the compare |

## Reference Sheets (legacy)

| File | Coverage |
|---|---|
| `custom-vm-bytecode.md` | Original custom-VM pattern reference (also in `scenarios/custom-vm/`) |
