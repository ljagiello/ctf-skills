# Linux ptrace Anti-Debug Bypass

## When this applies

- Linux binary uses `ptrace(PTRACE_TRACEME, ...)` to detect debuggers (a process can be traced by only one process at a time).
- Or reads `/proc/self/status` and looks for non-zero `TracerPid:`.
- Trigger: GDB attach fails with "Operation not permitted" mid-execution, or the binary takes a different code path under GDB.

## Technique

Two complementary approaches:

1. **Patch out the check.** Replace the `ptrace(PTRACE_TRACEME)` syscall with a no-op or modify the conditional that follows.
2. **Defeat it from the debugger side.** LD_PRELOAD a shim that lies about `ptrace` results; or use `strace -f -e trace=ptrace` to see the call and its return value.

## Steps

### 1. Detect the check

In the disassembler, search for cross-references to `ptrace`:

```bash
objdump -d binary | grep -B2 -A2 'call.*ptrace'
strings binary | grep -i 'TracerPid\|/proc/self'
```

Common patterns:

```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) exit(1);     // simple

// or via syscall directly
if (syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0) == -1) exit(1);

// or via /proc parsing
fp = fopen("/proc/self/status", "r");
while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        if (atoi(line + 10) != 0) exit(1);
    }
}
```

### 2. Bypass — patch binary

For small ELFs, patch the call directly. Replace `call ptrace@plt` with `xor eax, eax ; nop ; nop ; nop ; nop` (5 bytes total: `31 C0 90 90 90`).

```python
import lief
binary = lief.parse('target')
# find the call instruction at known offset
patch = bytes.fromhex('31C0909090')
binary.patch_address(0x401234, list(patch))
binary.write('target.patched')
```

Or use `radare2`:
```bash
r2 -w target
[0x004012a0]> s 0x401234
[0x00401234]> wa xor eax, eax; nop; nop; nop
```

### 3. Bypass — LD_PRELOAD shim

Avoid touching the binary entirely:

```c
// preload.c — compile with: gcc -shared -fPIC preload.c -o preload.so
#include <sys/ptrace.h>
long ptrace(enum __ptrace_request request, ...) {
    return 0;          // pretend success regardless
}
```

```bash
LD_PRELOAD=./preload.so gdb --args ./target
```

For `/proc/self/status` checks, also override `fopen`:

```c
FILE *fopen(const char *path, const char *mode) {
    if (strcmp(path, "/proc/self/status") == 0) {
        return fopen("/tmp/fake_status", mode);    // crafted fake
    }
    return real_fopen(path, mode);
}
```

### 4. Bypass — debugger-side

GDB Python plugin to skip the check:

```python
# .gdbinit
catch syscall ptrace
commands
  # Force return value to success
  set $rax = 0
  continue
end
```

Or set a breakpoint immediately after the check and skip the comparison:

```
(gdb) b *0x401240          # right after the cmp/exit
(gdb) jump *0x401240       # bypass the check
```

### 5. Detect anti-PTRACE-loop tricks

Some binaries have **multiple** PTRACE_TRACEME calls, or call PTRACE_TRACEME in a thread, or use the ptrace check as a measurement (timing) rather than a binary gate. Check thoroughly via dynamic strace:

```bash
strace -f -e trace=ptrace ./target
```

## Verifying success

- The binary executes normal code paths under GDB without aborting.
- `strace` shows `ptrace` calls return 0 (or aren't called at all after patch).
- Comparison: trace identical execution under bare run vs under GDB — no divergence.

## Common pitfalls

- **Multiple checks.** Bypassing one PTRACE_TRACEME doesn't help if there are five. Find them all (`xref ptrace`).
- **Inline syscall.** A direct `syscall` instruction with `rax=101` (sys_ptrace) bypasses libc — patching `ptrace@plt` does nothing. Patch the inline syscall site or use a kernel-level tracer.
- **Return value used.** Some checks compare `ptrace(...)` to a specific constant, not just `-1`. Verify what value the patch needs to deliver.
- **TracerPid via fork.** A child process that periodically reads `TracerPid` from a parent — bypass requires `fopen` shim plus child-injection awareness.
- **Self-debug with double-fork.** Some binaries `fork()`, then the parent ptraces the child. The child's PTRACE_TRACEME is benign (parent is the legitimate debugger). Detect by scanning for `fork` + `waitpid` + `ptrace(PTRACE_ATTACH)` patterns.

## Tools

- `ltrace`, `strace -f -e trace=ptrace` — visibility into the calls.
- `LD_PRELOAD` shim — pure-userspace bypass.
- `lief` (Python) — programmatic binary patching.
- `radare2 -w` — live binary editor.
- `gdb` Python scripting — runtime intervention.
- `Frida` — for cross-language hooking when LD_PRELOAD isn't enough.
- `ScyllaHide` (Windows port — different OS but same idea).
