# Frida Hooking — Function Hooks and Return Value Modification

## When this applies

- You need to observe or modify behavior at function-call boundaries without modifying the binary.
- Cross-platform: Linux, Windows, macOS, Android, iOS.
- Targets can be native (C/C++), managed (.NET via Frida-clr, Java via Frida Android), or scripted (Node.js).
- Trigger: any RE / pentest task that benefits from runtime visibility — value tracing, fuzzing inputs, bypassing checks, dumping decrypted strings.

## Technique

Frida injects a JavaScript runtime (V8 / QuickJS) into the target process. Scripts use `Interceptor`, `Stalker`, `Memory`, and `Module` APIs to read/write memory and intercept calls. Two operating modes:

1. **frida-trace**: command-line, generates per-function handler stubs you edit.
2. **frida CLI / Python bindings**: full scripting control, injects custom JS.

## Steps

### 1. Install and attach

```bash
pip install frida-tools
frida-ps -U                    # list processes (Android)
frida -p <pid> -l hook.js      # local
frida -U -p <pid> -l hook.js   # USB-connected device
frida -U -f com.example.app    # spawn-and-attach
```

### 2. Basic hook

`hook.js`:

```javascript
const target = Module.findExportByName(null, 'check_password');
Interceptor.attach(target, {
    onEnter(args) {
        console.log('check_password called with:', args[0].readCString());
        this.input = args[0];
    },
    onLeave(retval) {
        console.log('returned:', retval.toInt32());
        retval.replace(1);    // force success
    }
});
```

### 3. Hook by address (no symbols)

```javascript
const base = Module.findBaseAddress('libtarget.so');
const offset = 0x12a0;
Interceptor.attach(base.add(offset), { ... });
```

### 4. Read/write memory

```javascript
const buf = Memory.alloc(64);
buf.writeUtf8String("hello");

const ptr_a = ptr('0x7ffe1234abcd');
console.log(ptr_a.readU64());

// hexdump
console.log(hexdump(ptr_a, { length: 64, header: true, ansi: true }));
```

### 5. Replace function entirely

```javascript
const target = Module.findExportByName(null, 'IsDebuggerPresent');
Interceptor.replace(target, new NativeCallback(function() {
    return 0;
}, 'int', []));
```

### 6. Stalker — instruction-level trace

```javascript
Stalker.follow(Process.getCurrentThreadId(), {
    transform(iterator) {
        let inst;
        while ((inst = iterator.next()) !== null) {
            console.log(inst.address, inst.mnemonic);
            iterator.keep();
        }
    }
});
```

Use sparingly — Stalker slows execution by 10-100x.

### 7. Java / Android specific

```javascript
Java.perform(function() {
    const Activity = Java.use('com.example.app.MainActivity');
    Activity.checkLicense.implementation = function(key) {
        console.log('checkLicense', key);
        return true;
    };
});
```

### 8. iOS / Objective-C

```javascript
const NSString = ObjC.classes.NSString;
const orig = ObjC.classes.AppDelegate['- isJailbroken'];
Interceptor.attach(orig.implementation, {
    onLeave(retval) { retval.replace(0); }
});
```

### 9. Python orchestration

```python
import frida, sys
def on_message(msg, data):
    print(msg)
session = frida.attach('target')
script = session.create_script(open('hook.js').read())
script.on('message', on_message)
script.load()
sys.stdin.read()    # keep alive
```

## Verifying success

- Console output shows expected interception (function called, args / retvals match).
- Modified return values affect program behavior (auth bypass, license accept, etc.).
- No crashes or anti-Frida triggers — process continues normally.

## Common pitfalls

- **Anti-Frida detection.** Apps may scan for `frida-agent`, `gum-js-loop` thread, `LD_PRELOAD` artifacts, port 27042 (Frida default). Use `frida-stealth` / `objection patchapk` to evade.
- **Wrong arch.** Mismatched frida-server (32 vs 64-bit) crashes the daemon. Match host process arch.
- **Spawn vs attach.** Some checks happen at startup before you can attach. Use `frida -f <package>` to spawn and freeze immediately.
- **Symbol stripped.** Use `Module.findBaseAddress + offset`, or `DebugSymbol.fromAddress` if PDBs available.
- **Multi-process.** Frida attaches one process per session; Chromium-style multi-process apps need `--enable-jit` and per-renderer attach.
- **Forks lose hooks.** Hooks installed in parent don't propagate to child unless you intercept fork/exec and re-inject.

## Tools

- `frida-tools` (Python) — `frida`, `frida-trace`, `frida-ps`, `frida-discover`.
- `frida-server` (on target Android/iOS) — paired with host frida.
- `objection` — high-level wrapper, common-task templates.
- `r2frida` — radare2 plugin using Frida as the I/O backend.
- `Brida` (Burp plugin) — bridges Frida and Burp for instrumented HTTP fuzzing.
- `frida-il2cpp-bridge` — Unity IL2CPP-aware Frida helper.
