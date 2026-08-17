# PE Analysis — Windows Executables and .NET Assemblies

## When this applies

- Target is a Windows executable (`.exe`, `.dll`, `.sys`), `file` reports `PE32` or `PE32+`.
- Could be native (C/C++/Rust/Go) or managed (.NET CLR, IL bytecode).
- Trigger: any RE task starting from a Windows binary or driver.

## Technique

PE structure mirrors ELF in spirit but with Windows-specific quirks: imports via IAT, exports via EAT, resource section for strings/icons/versioninfo, and an entirely separate ecosystem (.NET) for managed assemblies.

## Steps

### 1. Triage

```bash
file binary.exe
pe-bear binary.exe             # GUI: header + sections + imports
peid binary.exe                # detect packers / compilers (legacy but useful)
die binary.exe                 # Detect It Easy — modern PEiD replacement
```

Check:
- 32 vs 64-bit (`PE32` vs `PE32+`).
- Subsystem (CONSOLE / WINDOWS / NATIVE — drivers and rootkits).
- Compile timestamp (often forged or zero).
- Sections: `.text`, `.rdata`, `.data`, `.rsrc`, plus packer-specific (`UPX0`, `.aspack`, etc.).

### 2. Imports (IAT)

```bash
dumpbin /imports binary.exe         # MSVC build tools
objdump -p binary.exe               # MinGW
```

Functions imported from `kernel32.dll`, `advapi32.dll`, `wininet.dll`, `crypt32.dll` indicate behavior:
- `CreateProcess`, `WriteProcessMemory` → process injection.
- `RegOpenKey`, `RegSetValue` → registry persistence.
- `InternetOpen`, `HttpSendRequest` → C2 traffic.
- `CryptAcquireContext`, `CryptEncrypt` → ransomware-style crypto.

### 3. Resources and strings

```bash
# Extract resources
resource_hacker binary.exe
# or via radare2: izz / iz
```

Check for:
- VersionInfo (often forged).
- Embedded payload (large `.rsrc` entry of unknown type).
- Manifest XML (UAC / DPI awareness).
- Bitmaps / icons (visual fingerprint).

### 4. Disassembly

| Tool | Strength | When |
|---|---|---|
| `IDA Pro` | Best Windows support | Industry standard for malware RE |
| `Ghidra` | Free, decompiler | Default open-source choice |
| `x64dbg` | Live debugger | Dynamic analysis / unpacking |
| `Binary Ninja` | Scriptable | Automation pipelines |
| `radare2` | CLI | Scripted batch analysis |

### 5. Native vs managed

If `dumpbin /headers` shows `IMAGE_COR20_HEADER` ("CLR Header"), the binary is .NET. Use:

| Tool | Purpose |
|---|---|
| `dnSpy` | Decompile + edit + debug .NET assemblies |
| `ILSpy` | Decompile only, modern |
| `dotPeek` | JetBrains, polished |
| `de4dot` | Deobfuscate ConfuserEx/SmartAssembly/etc. |

.NET decompilation produces near-source-quality C#. Always try .NET tools first when you see CLR header — disassembling IL bytecode in IDA is wasted effort.

### 6. Calling conventions

- **x86 32-bit Windows**: `__stdcall` (callee cleans stack), `__cdecl` (caller cleans), `__fastcall` (ECX/EDX in regs).
- **x86_64 Windows**: Microsoft x64 ABI — RCX, RDX, R8, R9 then stack. Different from System V (Linux) which uses RDI, RSI, RDX, RCX, R8, R9.
- **__stdcall** name decoration: `_FunctionName@N` where N = stack bytes consumed.

Wrong calling convention = wrong argument inference in decompiler.

### 7. Driver-specific

For `.sys` files (kernel drivers):
- `IRP_MJ_DEVICE_CONTROL` dispatch routine = main entry for IOCTL handlers.
- `DriverEntry` = init function (called once).
- IDA's "Driver" file type yields IRP-aware analysis.

## Verifying success

- Imports match observed behavior (network calls, registry edits, file writes).
- Decompiled main / DllMain reads as understandable code.
- Resource section accounted for (if large unknown blob, suspect packed/embedded).

## Common pitfalls

- **Mistaking .NET for native.** Hours wasted in IDA on what dnSpy decompiles in seconds.
- **Forged timestamps.** Don't trust compile time; `Rich` header (MSVC build tool fingerprint) is harder to forge.
- **Packed PE.** `.text` section size << expected, single-import like `LoadLibraryA` only, high entropy in `.data` — packed. See `obfuscation/packed-binaries.md`.
- **Subsystem mismatch.** Kernel driver opened in user-mode debugger crashes. Use WinDbg + VM.
- **64-bit gotcha.** Always confirm bitness; cross-bit assumptions corrupt argument passing.
- **Ignoring DllMain.** Many DLLs do interesting work in `DllMain` (DLL_PROCESS_ATTACH branch) before the exported functions.

## Tools

- `IDA Pro` / `Ghidra` / `Binary Ninja` — disassemblers / decompilers.
- `dnSpy` / `ILSpy` / `dotPeek` — .NET decompilation.
- `de4dot` — .NET deobfuscation.
- `PE-bear` / `Detect It Easy (DIE)` / `pestudio` — PE structure inspection.
- `x64dbg` / `WinDbg` — dynamic / kernel debugging.
- `Resource Hacker` — extract resources / icons.
- `pefile` Python module — programmatic PE parsing.
