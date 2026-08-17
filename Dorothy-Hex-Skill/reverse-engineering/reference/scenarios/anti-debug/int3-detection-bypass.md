# INT3 (0xCC) Breakpoint Detection Bypass

## When this applies

- Binary scans its own code (or a critical function's bytes) for `0xCC` (INT3) bytes — software breakpoints set by debuggers.
- Trigger: standard breakpoints don't seem to land properly, or the binary checksums itself and exits.
- Often combined with code obfuscation that XOR-decrypts critical functions just before use, then re-encrypts after.

## Technique

Two strategies:

1. **Use hardware breakpoints (DRx)** — these don't modify code bytes; INT3 scans don't see them.
2. **Patch the integrity check.** Find the routine that scans for `0xCC` or computes the code checksum, and skip / falsify it.

## Steps

### 1. Detect the check

Common patterns:

```asm
; Linear scan for 0xCC
mov     rdi, target_function
mov     rcx, function_size
mov     al, 0xCC
repne scasb
jz      debugger_detected
```

```c
// Checksum-based
unsigned int sum = 0;
for (int i = 0; i < size; i++) sum += target_function[i];
if (sum != EXPECTED_SUM) exit(1);
```

```c
// Compare-against-stored-copy
if (memcmp(target_function, original_bytes, size) != 0) exit(1);
```

### 2. Use hardware breakpoints

Hardware breakpoints (DR0-DR3) don't modify code:

- **GDB**: `hbreak *0x401234` (instead of `b *0x401234`).
- **WinDbg**: `ba e 1 0x401234` (break access execute, length 1).
- **x64dbg**: Right-click instruction → "Set Hardware Breakpoint on Execution".

Limitations:
- Only 4 hardware breakpoints per thread.
- Some samples enumerate DRx (see `timing-checks-bypass.md`'s related DRx detection topic).
- New threads inherit no DRx — set per-thread.

### 3. Patch the check

If the binary scans memory regions, patch out the check:

```python
# Find the rep scasb / memcmp / checksum loop
# Replace with unconditional success branch
patch_addr = 0x401a30   # the conditional jump
patch_byte(patch_addr, 0xEB)   # JZ → JMP
```

For checksum-based: replace `cmp eax, EXPECTED_SUM` with `cmp eax, eax` (always equal).

### 4. Update the expected checksum

If you patched the binary but the binary checksums itself, your patch breaks the checksum. Two options:

- **Skip the check first** (preferred): patch the comparison before patching anything else.
- **Recompute and update the constant**: after your patch, compute the new checksum and patch the expected value too.

### 5. Use software breakpoints carefully

If you must use INT3 software breakpoints despite the check, place them only at addresses the integrity check doesn't cover. Identify the protected range and avoid setting breakpoints there.

### 6. Emulator-based

Run the binary under `Unicorn` / `qemu-user`. The emulator doesn't use INT3 for breakpoints; it traps on instruction fetches. Anti-INT3 checks see no `0xCC` because none are present.

```python
mu = Unicorn(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(...)
mu.mem_write(...)
mu.hook_add(UC_HOOK_CODE, callback, begin=0x401234, end=0x401234+1)
```

### 7. Watch for re-encryption

Some samples decrypt a function only briefly:

```c
decrypt_function(critical_func);
critical_func();
encrypt_function(critical_func);
```

Setting a breakpoint inside `critical_func` while encrypted does nothing. Set the breakpoint at the *call site*, step into, then breakpoint inside the now-decrypted body.

## Verifying success

- Hardware breakpoints fire as expected.
- Binary's integrity-check function returns "no debugger" or is skipped.
- No `exit(1)` / `ExitProcess` from the anti-debug path.

## Common pitfalls

- **DRx scarcity.** 4 hardware BPs per thread is tight. Multi-thread programs need careful BP placement.
- **DRx detection.** Some samples enumerate DR0-DR3 — bypass via ScyllaHide DRx intercept.
- **Per-byte checksums.** A subtle integrity check XORs a key into the comparison; patching alone breaks both. Trace the check fully.
- **TLS callbacks.** Windows binaries can do anti-debug in TLS callbacks before main runs. Set initial BP on TLS callback addresses (visible in PE header `IMAGE_DIRECTORY_ENTRY_TLS`).
- **Self-modifying code.** Code that rewrites itself moves the goalposts; static analysis lies, dynamic is required, and the integrity check may verify a snapshot taken at startup.

## Tools

- `gdb` `hbreak`, `WinDbg` `ba`, `x64dbg` HWBP — hardware breakpoints.
- `ScyllaHide` (DRx intercept) — protects DRx from enumeration.
- `Unicorn-engine` — INT3-free emulation.
- `Frida` — Stalker-based execution tracing without breakpoints.
- `bindiff` (between original + patched) to verify only intended bytes changed.
