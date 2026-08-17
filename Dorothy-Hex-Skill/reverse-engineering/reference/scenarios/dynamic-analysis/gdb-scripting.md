# GDB Python Scripting — Programmatic Introspection

## When this applies

- You need to extract structured data from a running process — variable values across many breakpoint hits, memory snapshots at specific events, automated tracing.
- The task is too repetitive for manual GDB, too specific for `strace` / `ltrace`.
- Trigger: "trace every call to this function and dump arg + return value", "find when this variable becomes X", "log memory state at every loop iteration".

## Technique

GDB embeds a Python interpreter — full access to GDB internals via the `gdb` module. Use breakpoints, watchpoints, and event hooks to drive automated inspection.

## Steps

### 1. Inline Python from `.gdbinit` or CLI

```bash
gdb -ex 'python ...' --args ./target arg
```

Or `~/.gdbinit`:

```python
python
import gdb
class MyBP(gdb.Breakpoint):
    def stop(self):
        val = gdb.parse_and_eval("password")
        print(f"hit, password = {val}")
        return False    # don't actually stop, just log
MyBP("check_password")
end
```

### 2. Programmatic breakpoint with handler

```python
# script.py
import gdb

class TraceBP(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec, internal=True)
    def stop(self):
        # Read first arg from rdi (System V x86_64 ABI)
        rdi = int(gdb.parse_and_eval("$rdi"))
        try:
            s = gdb.inferiors()[0].read_memory(rdi, 64).tobytes()
            s = s.split(b'\x00')[0].decode('latin1', errors='replace')
        except Exception:
            s = '<unreadable>'
        print(f"check called with: {s}")
        return False

TraceBP("check_input")

gdb.execute("run")
```

```bash
gdb -batch -x script.py ./target
```

### 3. Watchpoints

```python
class WatchVar(gdb.Breakpoint):
    def __init__(self, expr):
        super().__init__(expr, type=gdb.BP_WATCHPOINT, wp_class=gdb.WP_WRITE)
    def stop(self):
        print("variable changed:", gdb.parse_and_eval('var'))
        return False

WatchVar("global_state")
gdb.execute("continue")
```

### 4. Read structured memory

```python
inf = gdb.inferiors()[0]
data = inf.read_memory(addr, length).tobytes()

# Or via gdb's type system:
ptr_t = gdb.lookup_type('struct sockaddr_in').pointer()
sa = gdb.Value(addr).cast(ptr_t).dereference()
print(sa['sin_port'])
```

### 5. Walk linked lists / trees

```python
node = gdb.parse_and_eval("head")
while int(node) != 0:
    val = node.dereference()['data']
    print(val)
    node = node.dereference()['next']
```

### 6. Inject calls

```python
gdb.execute("call (int)malloc(1024)")
val = gdb.parse_and_eval("(int)getuid()")
```

Useful for testing what a function returns under specific contexts — e.g. call `decrypt(buf)` directly to dump the plaintext.

### 7. Hook events

```python
def on_stop(event):
    if isinstance(event, gdb.BreakpointEvent):
        print(f"hit bp at {event.breakpoints[0].location}")
gdb.events.stop.connect(on_stop)
```

### 8. Solve simple challenges programmatically

```python
import gdb
gdb.execute("set pagination off")
gdb.execute("file ./crackme")

# Bypass anti-debug
gdb.execute("catch syscall ptrace")
gdb.execute("commands\nset $rax = 0\ncontinue\nend")

# Run with arbitrary input, capture printf
class CaptureBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("printf", internal=True)
    def stop(self):
        fmt = gdb.parse_and_eval("$rdi")
        print("printf:", fmt.string())
        return False
CaptureBP()
gdb.execute("run < input.txt")
```

## Verifying success

- Script produces expected per-breakpoint output without manual interaction.
- Reproducible across multiple runs (no flakiness from race conditions in event handlers).
- Structured output (CSV, JSON) suitable for downstream analysis.

## Common pitfalls

- **`stop()` returning True vs False.** Returning `True` halts (interactive). For automated tracing, return `False` to continue.
- **Event handler exceptions silently kill the BP.** Wrap in try/except and print errors explicitly.
- **Calling `gdb.execute('continue')` recursively.** Don't issue `continue` from within a `stop()` — return `False` instead. Calling `continue` re-enters and may deadlock.
- **String reading from arbitrary pointers.** `read_memory` may fault on unmapped pages. Always try/except.
- **Volatile registers.** Reading `$rdi` works only at function entry — after a few instructions it may have changed. Set BP at the very first instruction of the target function.
- **GDB version differences.** Python API has shifted between GDB 8 / 9 / 10. Test the script on the target version.

## Tools

- `gdb` (built-in Python).
- `pwndbg`, `gef`, `peda` — GDB plugins with prebuilt commands for exploit dev / RE; coexist with custom Python scripts.
- `gdb-multiarch` for cross-architecture debugging (ARM, MIPS).
- `gdbserver` for remote target attach (Android, embedded, VMs).
