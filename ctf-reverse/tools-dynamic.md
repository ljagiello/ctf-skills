# CTF Reverse - Dynamic Analysis Tools

## Table of Contents
- [Frida (Dynamic Instrumentation)](#frida-dynamic-instrumentation)
  - [Basic Function Hooking](#basic-function-hooking)
  - [Anti-Debug Bypass](#anti-debug-bypass)
  - [Memory Scanning and Patching](#memory-scanning-and-patching)
  - [Function Replacement](#function-replacement)
  - [Tracing and Stalker](#tracing-and-stalker)
  - [r2frida (Radare2 + Frida Integration)](#r2frida-radare2--frida-integration)
  - [Frida for Android/iOS](#frida-for-androidios)
- [angr (Symbolic Execution)](#angr-symbolic-execution)
  - [Basic Path Exploration](#basic-path-exploration)
  - [Symbolic Input with Constraints](#symbolic-input-with-constraints)
  - [Hook Functions to Simplify Analysis](#hook-functions-to-simplify-analysis)
  - [Exploring from Specific Address](#exploring-from-specific-address)
  - [Common Patterns and Tips](#common-patterns-and-tips)
  - [Dealing with Path Explosion](#dealing-with-path-explosion)
  - [angr CFG Recovery](#angr-cfg-recovery)
- [lldb (LLVM Debugger)](#lldb-llvm-debugger)
- [x64dbg (Windows Debugger)](#x64dbg-windows-debugger)

---

## Frida (Dynamic Instrumentation)

Frida injects JavaScript into running processes for real-time hooking, tracing, and modification. Essential for anti-debug bypass, runtime inspection, and mobile RE.

### Installation

```bash
pip install frida-tools frida
# Verify
frida --version
```

### Basic Function Hooking

```javascript
// hook.js — intercept a function and log arguments/return value
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        this.arg0 = Memory.readUtf8String(args[0]);
        this.arg1 = Memory.readUtf8String(args[1]);
        console.log(`strcmp("${this.arg0}", "${this.arg1}")`);
    },
    onLeave: function(retval) {
        console.log(`  → ${retval}`);
    }
});
```

```bash
# Attach to running process
frida -p $(pidof binary) -l hook.js

# Spawn and instrument from start
frida -f ./binary -l hook.js --no-pause

# One-liner: hook strcmp and dump comparisons
frida -f ./binary --no-pause -e '
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        console.log("strcmp:", Memory.readUtf8String(args[0]), Memory.readUtf8String(args[1]));
    }
});
'
```

### Anti-Debug Bypass

```javascript
// Bypass ptrace(PTRACE_TRACEME) — returns 0 (success) without calling
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.request === 0) { // PTRACE_TRACEME
            retval.replace(ptr(0));
            console.log("[*] ptrace(TRACEME) bypassed");
        }
    }
});

// Bypass IsDebuggerPresent (Windows)
var isDbg = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
Interceptor.attach(isDbg, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});

// Bypass timing checks — hook clock_gettime to return constant
Interceptor.attach(Module.findExportByName(null, "clock_gettime"), {
    onLeave: function(retval) {
        // Force constant timestamp to defeat timing checks
        var ts = this.context.rsi || this.context.x1; // x86 or ARM
        Memory.writeU64(ts, 0);        // tv_sec
        Memory.writeU64(ts.add(8), 0); // tv_nsec
    }
});
```

### Memory Scanning and Patching

```javascript
// Scan for flag pattern in memory
Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scan(range.base, range.size, "66 6c 61 67 7b", { // "flag{"
        onMatch: function(address, size) {
            console.log("[FLAG] Found at:", address, Memory.readUtf8String(address, 64));
        },
        onComplete: function() {}
    });
});

// Patch instruction (NOP out a check)
var addr = Module.findBaseAddress("binary").add(0x1234);
Memory.patchCode(addr, 2, function(code) {
    var writer = new X86Writer(code, { pc: addr });
    writer.putNop();
    writer.putNop();
    writer.flush();
});
```

### Function Replacement

```javascript
// Replace a validation function to always return true
var checkFlag = Module.findExportByName(null, "check_flag");
Interceptor.replace(checkFlag, new NativeCallback(function(input) {
    console.log("[*] check_flag called with:", Memory.readUtf8String(input));
    return 1; // always valid
}, 'int', ['pointer']));
```

### Tracing and Stalker

```javascript
// Trace all calls in a function (Stalker — instruction-level tracing)
var targetAddr = Module.findExportByName(null, "main");
Stalker.follow(Process.getCurrentThreadId(), {
    transform: function(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            if (instruction.mnemonic === "call") {
                iterator.putCallout(function(context) {
                    console.log("CALL at", context.pc, "→", ptr(context.pc).readPointer());
                });
            }
            iterator.keep();
        }
    }
});
```

### r2frida (Radare2 + Frida Integration)

```bash
# Attach radare2 to process via Frida
r2 frida://spawn/./binary

# r2frida commands
\ii                    # List imports
\il                    # List loaded modules
\dt strcmp             # Trace strcmp calls
\dc                    # Continue execution
\dm                    # List memory maps
```

### Frida for Android/iOS

```bash
# Android (requires rooted device or Frida server)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# Hook Android Java methods
frida -U -f com.example.app -l hook_android.js --no-pause
```

```javascript
// hook_android.js — hook Java method
Java.perform(function() {
    var MainActivity = Java.use("com.example.app.MainActivity");
    MainActivity.checkPassword.implementation = function(input) {
        console.log("[*] checkPassword called with:", input);
        var result = this.checkPassword(input);
        console.log("[*] Result:", result);
        return result;
    };
});
```

**Key insight:** Frida excels where static analysis fails — obfuscated code, packed binaries, and runtime-generated data. Hook comparison functions (`strcmp`, `memcmp`, custom validators) to extract expected values without reversing the algorithm. Use `Interceptor.attach` for observation, `Interceptor.replace` for modification.

**When to use:** Anti-debugging bypass, extracting runtime-computed keys, hooking crypto functions to dump plaintext, mobile app analysis, packed binary inspection.

---

## angr (Symbolic Execution)

angr automatically explores program paths to find inputs satisfying constraints. Solves many flag-checking binaries in minutes that take hours manually.

### Installation

```bash
pip install angr
```

### Basic Path Exploration

```python
import angr
import claripy

# Load binary
proj = angr.Project('./binary', auto_load_libs=False)

# Find address of "Correct!" print, avoid "Wrong!" print
# Get these from disassembly (objdump -d or Ghidra)
FIND_ADDR = 0x401234    # Address of success path
AVOID_ADDR = 0x401256   # Address of failure path

# Create simulation manager and explore
simgr = proj.factory.simgr()
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    found = simgr.found[0]
    # Get stdin that reaches the target
    print("Flag:", found.posix.dumps(0))  # fd 0 = stdin
```

### Symbolic Input with Constraints

```python
import angr
import claripy

proj = angr.Project('./binary', auto_load_libs=False)

# Create symbolic input (e.g., 32-byte flag)
flag_len = 32
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# Constrain to printable ASCII
state = proj.factory.entry_state(stdin=flag)
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# Constrain known prefix: "flag{"
state.solver.add(flag_chars[0] == ord('f'))
state.solver.add(flag_chars[1] == ord('l'))
state.solver.add(flag_chars[2] == ord('a'))
state.solver.add(flag_chars[3] == ord('g'))
state.solver.add(flag_chars[4] == ord('{'))
state.solver.add(flag_chars[flag_len-1] == ord('}'))

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401256)

if simgr.found:
    found = simgr.found[0]
    result = found.solver.eval(flag, cast_to=bytes)
    print("Flag:", result.decode())
```

### Hook Functions to Simplify Analysis

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)

# Hook printf to avoid path explosion in I/O
@proj.hook(0x401100, length=5)  # Address of call to printf
def skip_printf(state):
    pass  # Do nothing, just skip

# Hook sleep/anti-debug functions
@proj.hook(0x401050, length=5)  # Address of call to sleep
def skip_sleep(state):
    pass

# Replace a function with a summary
class AlwaysSucceed(angr.SimProcedure):
    def run(self):
        return 1

proj.hook_symbol('check_license', AlwaysSucceed())
```

### Exploring from Specific Address

```python
# Start from middle of function (skip initialization)
state = proj.factory.blank_state(addr=0x401200)

# Set up registers/memory manually
state.regs.rdi = 0x600000  # Pointer to input buffer
state.memory.store(0x600000, b"AAAA" + b"\x00" * 28)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401300, avoid=0x401350)
```

### Common Patterns and Tips

```python
# Pattern 1: argv-based input
state = proj.factory.entry_state(args=['./binary', flag_sym])

# Pattern 2: Multiple find/avoid addresses
simgr.explore(
    find=[0x401234, 0x401300],     # Any success path
    avoid=[0x401256, 0x401400]     # All failure paths
)

# Pattern 3: Find by output string (no address needed)
def is_successful(state):
    stdout = state.posix.dumps(1)  # fd 1 = stdout
    return b"Correct" in stdout

def should_avoid(state):
    stdout = state.posix.dumps(1)
    return b"Wrong" in stdout

simgr.explore(find=is_successful, avoid=should_avoid)

# Pattern 4: Timeout protection
simgr.explore(find=0x401234, avoid=0x401256, num_find=1)
# Or use exploration techniques:
simgr.use_technique(angr.exploration_techniques.DFS())  # Depth-first
simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=500))
```

### Dealing with Path Explosion

```python
# Use DFS instead of BFS (default) for flag checkers
simgr.use_technique(angr.exploration_techniques.DFS())

# Limit symbolic memory operations
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

# Hook expensive functions (crypto, hashing) to avoid explosion
import hashlib
class SHA256Hook(angr.SimProcedure):
    def run(self, data, length, output):
        # Concretize input and compute hash
        concrete_data = self.state.solver.eval(
            self.state.memory.load(data, self.state.solver.eval(length)),
            cast_to=bytes
        )
        h = hashlib.sha256(concrete_data).digest()
        self.state.memory.store(output, h)

proj.hook_symbol('SHA256', SHA256Hook())
```

### angr CFG Recovery

```python
# Control flow graph for understanding structure
cfg = proj.analyses.CFGFast()
print(f"Functions found: {len(cfg.functions)}")

# Find main
for addr, func in cfg.functions.items():
    if func.name == 'main':
        print(f"main at {addr:#x}")
        break

# Cross-references
node = cfg.model.get_any_node(0x401234)
print("Predecessors:", [hex(p.addr) for p in cfg.model.get_predecessors(node)])
```

**Key insight:** angr works best on flag-checker binaries with clear success/failure paths. For complex binaries, hook expensive functions (crypto, I/O) and use DFS exploration. Start with the simplest approach (just find/avoid addresses) before adding constraints. If angr is slow, constrain input to printable ASCII and add known prefix.

**When to use:** Flag validators with branching logic, maze/path-finding binaries, constraint-heavy checks, automated binary analysis. Less effective for: heavy crypto, floating-point math, complex heap operations.

---

## lldb (LLVM Debugger)

Primary debugger for macOS/iOS. Also works on Linux. Preferred for Swift/Objective-C and Apple platform binaries.

### Basic Commands

```bash
lldb ./binary
(lldb) run                          # Run program
(lldb) b main                       # Breakpoint on main
(lldb) b 0x401234                   # Breakpoint at address
(lldb) breakpoint set -r "check.*"  # Regex breakpoint
(lldb) c                            # Continue
(lldb) si                           # Step instruction
(lldb) ni                           # Next instruction
(lldb) register read                # Show all registers
(lldb) register write rax 0         # Modify register
(lldb) memory read 0x401000 -c 32   # Read 32 bytes
(lldb) x/s $rsi                     # Examine string (GDB-style)
(lldb) dis -n main                  # Disassemble function
(lldb) image list                   # Loaded modules + base addresses
```

### Scripting (Python)

```python
# lldb Python scripting
import lldb

def hook_strcmp(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    arg0 = frame.FindRegister("rdi").GetValueAsUnsigned()
    arg1 = frame.FindRegister("rsi").GetValueAsUnsigned()
    s0 = process.ReadCStringFromMemory(arg0, 256, lldb.SBError())
    s1 = process.ReadCStringFromMemory(arg1, 256, lldb.SBError())
    print(f'strcmp("{s0}", "{s1}")')

# Register in lldb: command script add -f script.hook_strcmp hook_strcmp
```

**Key insight:** Use lldb for macOS binaries (Mach-O), iOS apps, and when GDB isn't available. `image list` gives ASLR slide for PIE binaries. Scripting API is more structured than GDB's.

---

## x64dbg (Windows Debugger)

Open-source Windows debugger with modern UI. Alternative to OllyDbg/WinDbg for Windows RE challenges.

### Key Features

```bash
# Launch
x64dbg.exe binary.exe         # 64-bit
x32dbg.exe binary.exe         # 32-bit

# Essential shortcuts
F2      → Toggle breakpoint
F7      → Step into
F8      → Step over
F9      → Run
Ctrl+G  → Go to address
Ctrl+F  → Find pattern in memory
```

### Scripting

```bash
# x64dbg command line
bp 0x401234                    # Breakpoint
SetBPX 0x401234, 0, "log {s:utf8@[esp+4]}"  # Log string arg on hit
run                            # Continue
StepOver                       # Step over
```

### Common CTF Workflow

1. Set breakpoint on `GetWindowTextA`/`MessageBoxA` for GUI crackers
2. Trace back from success/failure message
3. Use **Scylla** plugin for IAT reconstruction on packed binaries
4. **Snowman** decompiler plugin for quick pseudo-C

**Key insight:** x64dbg has built-in pattern scanning, hardware breakpoints, and conditional logging. For Windows CTF binaries, it's often faster than IDA/Ghidra for dynamic analysis. Use the **xAnalyzer** plugin for automatic function argument annotation.
