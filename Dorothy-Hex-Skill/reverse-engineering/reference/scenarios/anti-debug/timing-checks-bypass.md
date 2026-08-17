# Timing-Based Anti-Debug Bypass (RDTSC, GetTickCount, QueryPerformanceCounter)

## When this applies

- Binary measures elapsed time between two points and exits / takes a different path if the gap is "too large" — debugger single-stepping inflates the gap.
- Timing primitives: `RDTSC` (cycle counter, x86), `GetTickCount` (ms, Windows), `QueryPerformanceCounter` (high-res, Windows), `clock_gettime` / `gettimeofday` (Linux).
- Trigger: binary runs fine standalone, but exits / misbehaves under any debugger — even attached but not stepping.

## Technique

Two approaches:

1. **Patch the comparison.** Identify the `cmp` against a threshold, patch to always-take the "fast" path.
2. **Spoof the timer.** Hook `RDTSC` / timer APIs to return monotonically advancing values regardless of real time elapsed.

## Steps

### 1. Detect timing checks

Look for paired calls or instructions:

```asm
rdtsc                   ; read low/high cycle count
mov     [rbp-0x10], eax
mov     [rbp-0xc], edx
; ... do work being measured ...
rdtsc
sub     eax, [rbp-0x10]
sbb     edx, [rbp-0xc]
cmp     eax, 0x100000   ; threshold: 1M cycles
jb      ok
; debugger detected branch
```

Or:

```c
DWORD t1 = GetTickCount();
// work
DWORD t2 = GetTickCount();
if (t2 - t1 > 50) ExitProcess(1);
```

### 2. Patch the comparison

Replace `jb ok` with unconditional `jmp ok`:

```python
# Replace JB (0x72) with JMP (0xEB), keep operand
patch_byte(addr_of_jb, 0xEB)
```

Or NOP out the timing primitive entirely (replace `rdtsc` with `xor eax, eax; xor edx, edx`).

### 3. Hook RDTSC

x64dbg + ScyllaHide has `RDTSC` checkbox — intercepts and returns synthetic increasing value. Manual approach:

- Set hardware breakpoint on `rdtsc` instruction (DR0).
- On hit, manually populate `EAX:EDX` from a counter and skip the instruction.

```python
# x64dbg scripting
rdtsc_counter = 0x10000
# script triggered on RDTSC bp
mov eax, rdtsc_counter
mov edx, 0
add rdtsc_counter, 1
add rip, 2   # skip rdtsc instruction
```

Or compile a `.dll` injector that:

```c
// Patch the RDTSC instruction to a CPUID + read of an emulated counter
// (x86 lacks single-instruction RDTSC trap; need full emulator or VEH)
```

### 4. Hook timer APIs

For `GetTickCount` / `QueryPerformanceCounter`:

```c
// LD_PRELOAD-style on Windows: use Detours, MinHook, or Frida
DWORD WINAPI hooked_GetTickCount(void) {
    static DWORD c = 0;
    return c++;       // monotonic, single-millisecond increments
}
```

Frida script:

```javascript
Interceptor.attach(Module.findExportByName('kernel32.dll', 'GetTickCount'), {
    onLeave(retval) { retval.replace(this.fakeTime); this.fakeTime += 1; }
});
```

### 5. Use VirtualBox / VM with frozen TSC

Some VMs offer "TSC offsetting" — makes `RDTSC` advance only when guest is running, hiding host pause time. Useful for VM-based dynamic analysis without debugger.

### 6. Emulator-based execution

For tough samples, emulate execution under `Unicorn` and stub timer reads. The whole binary runs without ever invoking real timers — no anti-debug triggers.

## Verifying success

- Binary completes its main logic under debugger / single-step.
- Two consecutive runs (one normal, one debugged) produce identical execution traces.
- Timing-comparison branches consistently take the "no debugger" path.

## Common pitfalls

- **Multiple checks.** A single binary can have 10+ timing checks. Patching each is tedious; ScyllaHide's RDTSC intercept is preferred.
- **Threshold variance.** Some samples use adaptive thresholds (calibrated at startup against a known-fast operation). Patching the comparison may be more robust than spoofing the timer.
- **Hardware breakpoint scarcity.** Only 4 hardware breakpoints (DR0-DR3) per thread. Multi-threaded programs needing many `RDTSC` intercepts overflow them — use Frida or kernel-mode hook instead.
- **Side-channel time measurement.** Some samples use loops counting iterations (no syscall) — neither timer hooks nor `RDTSC` patches help. Patch the comparison directly.
- **Network-based timing.** Sample queries an NTP server or its own server for "real time" — exhaustively patch all time sources or block network.

## Tools

- `ScyllaHide` — RDTSC intercept built-in.
- `Frida` — hook `GetTickCount` / `QueryPerformanceCounter` / `clock_gettime`.
- `MinHook` / `Detours` — inline API hooking.
- `x64dbg` scripting — runtime patches.
- `Unicorn-engine` — emulate without real timers.
- `bochs` / `qemu-tcg` — instruction-accurate emulator with synthetic timer.
