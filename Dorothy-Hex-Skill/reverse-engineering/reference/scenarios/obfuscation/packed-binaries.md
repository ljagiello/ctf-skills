# Packed Binaries — UPX, Custom Packers, Manual Unpacking

## When this applies

- Binary's `.text` section is small but `.data`/`.rsrc` is large with high entropy.
- Section names look unusual (`UPX0`, `UPX1`, `.aspack`, `.themida`, `.vmp0`).
- IAT shows few imports, often just `LoadLibraryA` and `GetProcAddress` (resolved at runtime).
- Strings yield almost nothing useful — only unpacker stub messages.
- Trigger keywords: "packed", "UPX", "Themida", "VMProtect", "ASPack".

## Technique

Recognize → identify packer → unpack with appropriate method:

1. **Known public packer** (UPX, Aspack): use the official unpacker.
2. **Custom or unknown packer**: dump from memory after the unpacker has run but before the original entry point (OEP).

## Steps

### 1. Detect packing

```bash
file binary.exe
detect-it-easy binary.exe       # signature-based packer detection
peid binary.exe                 # legacy but still useful
```

Indicators:
- Section names (UPX0, UPX1, .aspack).
- High entropy in non-`.rsrc` sections (`> 7.0` of 8.0 means almost-random / encrypted).
- Tiny IAT.
- Very few strings.

### 2. Try public unpackers

```bash
# UPX (handles standard UPX-packed binaries)
upx -d packed.exe -o unpacked.exe

# AspackDie for Aspack
# CFF Explorer + manual rebuild for many older packers
```

If public unpacker complains about modified header, the packer is custom or has been tweaked. Move to manual unpacking.

### 3. Manual unpacking — find the OEP

The unpacker stub decodes the original code in memory and jumps to OEP. Catch execution at OEP and dump.

**x64dbg recipe (Windows native PE):**

1. Open in x64dbg, run.
2. Set breakpoint on `VirtualAlloc` / `VirtualProtect` (memory-allocating APIs that the stub uses).
3. After several allocations, the OEP becomes a `jmp` or `call` to a freshly-allocated executable region.
4. Use `Scylla` (built into x64dbg) to dump the process and rebuild the IAT:
   - Attach Scylla to the running process.
   - "IAT Autosearch" + "Get Imports" → Scylla rebuilds the import table.
   - "Dump" → save dumped binary.
   - "Fix Dump" → patches the OEP and IAT in the dumped file.

**Linux ELF:**

```bash
# gdb approach
gdb ./packed
(gdb) catch syscall mmap mprotect
(gdb) run
# at each catch, check /proc/PID/maps for new RWX regions
# eventually a jmp into a new region = OEP
(gdb) dump memory unpacked.bin 0x401000 0x500000
```

Then reconstruct ELF headers manually or use `dumpd` / `objcopy`.

### 4. Tracing-based unpacking

For VM-based packers (VMProtect, Themida) where there's no clean OEP:

- Use **Tracer** (Hex-Rays plugin) or **TinyTracer** to record full execution traces.
- Identify "user code" regions vs "VM dispatcher" regions by entropy and call patterns.
- Replay the trace symbolically with **Triton** or **angr** to extract the original logic.

This is the hardest tier — VMProtect+Themida-protected binaries can take weeks.

### 5. Validate unpacked binary

```bash
file unpacked.exe
strings unpacked.exe | head -50    # should now show meaningful strings
checksec unpacked.exe              # verify standard structure
```

Run the unpacked binary in a sandbox and confirm it behaves identically to the packed original.

## Verifying success

- Strings now yield expected content (URLs, error messages, paths).
- IAT is fully populated (not just `LoadLibraryA` / `GetProcAddress`).
- Decompiled code matches dynamic behavior of the packed binary.
- Hash of decompressed code matches expected (if known target).

## Common pitfalls

- **Skipping detection step.** `upx -d` fails on modified UPX, but the binary may still be UPX-style — manual fixup is shorter than custom-unpacker work.
- **Wrong OEP.** Dumping before unpacking completes leaves encrypted code; dumping after OEP runs may have already mutated heap state. The OEP is usually the *first* control transfer into the freshly-decoded region.
- **Anti-debug in unpacker.** Many packers detect debuggers via `IsDebuggerPresent`, `NtQueryInformationProcess`, hardware breakpoints, RDTSC timing. Use ScyllaHide / TitanHide x64dbg plugin to suppress.
- **Multi-layer packing.** Some samples are packed twice (UPX inside ASPack). Unpack once, re-detect, repeat.
- **Protected region not dumped.** Themida/VMProtect protect specific functions individually rather than the whole binary; whole-image dump leaves those functions encrypted.

## Tools

- `upx -d` — UPX official.
- `Detect It Easy` — packer fingerprinting.
- `x64dbg` + `Scylla` — Windows manual unpacking.
- `ScyllaHide` / `TitanHide` — anti-anti-debug.
- `IDA Pro` + Universal Unpacker plugin.
- `unipacker` (Python, Unicorn-based) — emulator for common packers.
- `TitanEngine` — Windows unpacking framework.
- `Triton` / `angr` — symbolic execution for VM-packers.
