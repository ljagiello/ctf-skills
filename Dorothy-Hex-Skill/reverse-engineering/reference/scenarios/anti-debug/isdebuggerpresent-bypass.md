# Windows IsDebuggerPresent / PEB BeingDebugged Bypass

## When this applies

- Windows binary uses `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()`, or directly reads `PEB.BeingDebugged` to detect debuggers.
- Trigger: x64dbg / WinDbg attach succeeds, but the program exits early or takes a "trap" path with no useful behavior.
- May be combined with NtGlobalFlag, ProcessDebugPort, or hardware breakpoint detection.

## Technique

Three complementary fixes:

1. **Patch the PEB.** `PEB.BeingDebugged` (offset `0x2` in 32-bit, `0x2` in 64-bit) is a single byte; zero it after attach.
2. **Patch out the call.** Replace `IsDebuggerPresent()` with a function that always returns 0.
3. **Use anti-anti-debug plugin.** ScyllaHide / TitanHide do all of this automatically.

## Steps

### 1. Detect the check

In disassembly:

```asm
call    IsDebuggerPresent
test    eax, eax
jnz     bad_path

; or PEB-direct read:
mov     rax, gs:[0x60]      ; PEB on x86_64
movzx   eax, byte ptr [rax+2]   ; BeingDebugged
test    eax, eax
jnz     bad_path
```

`gs:[0x60]` is x64 Windows PEB; `fs:[0x30]` is 32-bit Windows PEB.

Other common APIs to check for:
- `CheckRemoteDebuggerPresent` (out-param boolean).
- `NtQueryInformationProcess(ProcessDebugPort)` — returns -1 if debugged.
- `NtQueryInformationProcess(ProcessDebugFlags)` — 0 if debugged.
- `NtGlobalFlag` (PEB+0xBC) — has `0x70` mask if heap-debugger active.

### 2. PEB patch via ScyllaHide

Easiest: ScyllaHide x64dbg plugin — checkboxes for each anti-debug technique. Configure profile:

- BeingDebugged: enabled.
- NtGlobalFlag: enabled.
- HeapFlags: enabled.
- KdDebuggerEnabled: enabled.
- DRx: enabled.
- ProcessDebugPort/Flags: enabled.

Click "Apply" — ScyllaHide intercepts the relevant kernel calls and PEB reads.

### 3. PEB patch via WinDbg manual

```
0:000> .reload /f
0:000> r $peb           ; get PEB address
0:000> eb @$peb+2 0     ; zero BeingDebugged byte
0:000> g
```

Useful right after attach, before the binary's first anti-debug call.

### 4. Patch the API itself

Replace the first byte of `IsDebuggerPresent` with `XOR EAX, EAX; RET` (3 bytes: `33 C0 C3`). Original function is:

```asm
mov rax, gs:[0x60]
movzx eax, byte ptr [rax+2]
ret
```

Patch:
```asm
xor eax, eax
ret
```

In x64dbg: navigate to `IsDebuggerPresent` (`Symbols` tab > `kernel32.dll`), `Ctrl+E`, write `33 C0 C3`.

### 5. NtQueryInformationProcess hook

For `ProcessDebugPort` checks, hook `NtQueryInformationProcess` to fake the result:

```c
// Inject DLL via HollowsHunter or x64dbg's plugin loader
NTSTATUS WINAPI hooked_NtQuery(HANDLE proc, PROCESSINFOCLASS class,
                                PVOID buf, ULONG len, PULONG ret) {
    NTSTATUS s = real_NtQuery(proc, class, buf, len, ret);
    if (class == ProcessDebugPort) *(HANDLE*)buf = NULL;
    if (class == ProcessDebugFlags) *(ULONG*)buf = 1;
    if (class == ProcessDebugObjectHandle) *(HANDLE*)buf = NULL;
    return s;
}
```

Again, ScyllaHide does all of this without manual hooking.

### 6. Hardware breakpoint detection (DRx)

Some binaries enumerate DR0-DR3 via `GetThreadContext` and bail if non-zero. ScyllaHide's "DRx" option intercepts and clears.

## Verifying success

- Binary continues past the check into the "real" code path.
- Process Monitor / API Monitor shows `IsDebuggerPresent` returning 0.
- No exit() / ExitProcess() called from the anti-debug branch.

## Common pitfalls

- **Late checks.** Some malware checks every N seconds in a thread; a one-time PEB patch is overwritten / re-checked. Use ScyllaHide's persistent hooks.
- **Bug-bounty bait.** Some binaries deliberately corrupt themselves under debugger (decrypt keys with debugger-status as input). Patching is futile — must run without debugger and observe via instrumentation (Frida / ETW).
- **Invalid handle on patch.** If you patch `IsDebuggerPresent` after a snapshot is taken (DLL relocation), addresses shift. Re-resolve on each session.
- **VM detection mistaken for anti-debug.** Some "anti-debug" symptoms are actually VM-detection (CPUID, RDTSC timing). Confirm via Process Monitor before patching.
- **Windows 11 ETW-based checks.** Newer techniques use ETW providers to detect attach. ScyllaHide may not cover; manual ETW intercept needed.

## Tools

- `ScyllaHide` (x64dbg / OllyDbg plugin) — comprehensive anti-anti-debug.
- `TitanHide` (driver-mode) — Ring0 anti-anti-debug for tougher samples.
- `x64dbg` — manual patching, debugging.
- `WinDbg` — kernel-mode debugging, PEB inspection.
- `API Monitor` (Rohitab) — see all calls to anti-debug APIs.
- `Process Monitor` (Sysinternals) — registry/file/process events.
- `Frida` (Windows) — runtime hooking without debugger attached.
