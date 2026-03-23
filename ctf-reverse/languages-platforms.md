# CTF Reverse - Platform & Framework-Specific Techniques

## Table of Contents
- [Roblox Place File Analysis](#roblox-place-file-analysis)
- [Godot Game Asset Extraction](#godot-game-asset-extraction)
- [Rust serde_json Schema Recovery](#rust-serde_json-schema-recovery)
- [Android JNI RegisterNatives Obfuscation (HTB WonderSMS)](#android-jni-registernatives-obfuscation-htb-wondersms)
- [Frida Firebase Cloud Functions Bypass (BSidesSF 2026)](#frida-firebase-cloud-functions-bypass-bsidessf-2026)
- [Verilog/Hardware Reverse Engineering (srdnlenCTF 2026)](#veriloghardware-reverse-engineering-srdnlenctf-2026)
- [Prefix-by-Prefix Hash Reversal (Nullcon 2026)](#prefix-by-prefix-hash-reversal-nullcon-2026)
- [Ruby/Perl Polyglot Constraint Satisfaction (BearCatCTF 2026)](#rubyperl-polyglot-constraint-satisfaction-bearcatctf-2026)
- [Electron App + Native Binary Reversing (RootAccess2026)](#electron-app--native-binary-reversing-rootaccess2026)
- [Node.js npm Package Runtime Introspection (RootAccess2026)](#nodejs-npm-package-runtime-introspection-rootaccess2026)

For core language reversing (Python, BF/esolangs, DOS, Unity, OPAL), see [languages.md](languages.md).
For Go and Rust binary reversing, see [languages-compiled.md](languages-compiled.md).

---

## Roblox Place File Analysis

**Pattern (MazeRunna, 0xFun 2026):** Roblox game with flag hidden in older version; latest version contains decoy.

**Version history via Asset Delivery API:**
```bash
# Extract placeId and universeId from game page HTML
# Query each version (requires .ROBLOSECURITY cookie):
curl -H "Cookie: .ROBLOSECURITY=..." \
  "https://assetdelivery.roblox.com/v2/assetId/{placeId}/version/1"
# Download location URL → place_v1.rbxlbin
```

**Binary format parsing:** `.rbxlbin` files contain chunks:
- **INST** — class buckets and referent IDs
- **PROP** — per-instance fields (including `Script.Source`)
- **PRNT** — parent-child relationships (object tree)

Decode chunk payloads, walk PROP entries for `Source` field, dump `Script.Source` / `LocalScript.Source` per version, then diff.

**Key lesson:** Always check version history. Latest version may contain decoy flag while real flag is in an older version. Diff script sources across versions.

---

## Godot Game Asset Extraction

**Pattern (Steal the Xmas):** Encrypted Godot .pck packages.

**Tools:**
- [gdsdecomp](https://github.com/GDRETools/gdsdecomp) - Extract Godot packages
- [KeyDot](https://github.com/Titoot/KeyDot) - Extract encryption key from Godot executables

**Workflow:**
1. Run KeyDot against game executable → extract encryption key
2. Input key into gdsdecomp
3. Extract and open project in Godot editor
4. Search scripts/resources for flag data

---

## Rust serde_json Schema Recovery

**Pattern (Curly Crab, PascalCTF 2026):** Rust binary reads JSON from stdin, deserializes via serde_json, prints success/failure emoji.

**Approach:**
1. Disassemble serde-generated `Visitor` implementations
2. Each visitor's `visit_map` / `visit_seq` reveals expected keys and types
3. Look for string literals in deserializer code (field names like `"pascal"`, `"CTF"`)
4. Reconstruct nested JSON schema from visitor call hierarchy
5. Identify value types from visitor method names: `visit_str` = string, `visit_u64` = number, `visit_bool` = boolean, `visit_seq` = array

```json
{"pascal":"CTF","CTF":2026,"crab":{"I_":true,"cr4bs":1337,"crabby":{"l0v3_":["rust"],"r3vv1ng_":42}}}
```

**Key insight:** Flag is the concatenation of JSON keys in schema order. Reading field names in order reveals the flag.

---

## Android JNI RegisterNatives Obfuscation (HTB WonderSMS)

**Pattern:** Android app loads native library with `System.loadLibrary()`, but uses `RegisterNatives` in `JNI_OnLoad` instead of standard JNI naming convention (`Java_com_pkg_Class_method`). This hides which C++ function handles each Java native method.

**Identification:**
```java
// In decompiled Java (jadx):
static { System.loadLibrary("audio"); }
private final native ProcessedMessage processMessage(SmsMessage msg);
```
Standard JNI would have a symbol `Java_com_rloura_wondersms_SmsReceiver_processMessage`. If that symbol is missing from the `.so`, `RegisterNatives` is being used.

**Finding the real handler in Ghidra:**
1. Locate `JNI_OnLoad` (exported symbol, always present)
2. Trace to `RegisterNatives(env, clazz, methods, count)` call
3. The `methods` array contains `{name, signature, fnPtr}` structs
4. Follow `fnPtr` to find the actual native function

```c
// JNI_OnLoad registers functions manually:
static JNINativeMethod methods[] = {
    {"processMessage", "(Landroid/telephony/SmsMessage;)LProcessedMessage;", (void*)real_handler}
};
(*env)->RegisterNatives(env, clazz, methods, 1);
```

**Architecture selection for analysis:**
```bash
# x86_64 gives best Ghidra decompilation (most similar to desktop code)
# Extract from APK:
unzip WonderSMS.apk -d extracted/
ls extracted/lib/x86_64/  # Prefer this over arm64-v8a for static analysis
```

**Key insight:** `RegisterNatives` is a deliberate obfuscation technique — it decouples Java method names from native symbol names, making it impossible to find handlers by string search alone. Always check `JNI_OnLoad` first when reversing Android native libraries with stripped symbols.

**Detection:** Native method declared in Java + no matching JNI symbol in `.so` + `JNI_OnLoad` present. The library is typically stripped (no debug symbols).

---

## Frida Firebase Cloud Functions Bypass (BSidesSF 2026)

**Pattern (vinyl-drop, doremi):** Android app validates actions (QR codes, purchases) via Firebase Cloud Functions. The expected payload format includes the Firebase UID, a value, and a timestamp. Use Frida to hook the app post-login, construct a valid payload, and call the Cloud Function directly.

```javascript
// Frida hook to bypass QR validation
Java.perform(function() {
    var FirebaseFunctions = Java.use('com.google.firebase.functions.FirebaseFunctions');
    var FirebaseAuth = Java.use('com.google.firebase.auth.FirebaseAuth');

    // Get current user UID after login
    var auth = FirebaseAuth.getInstance();
    var uid = auth.getCurrentUser().getUid();

    // Construct valid payload: uid + amount + timestamp
    var unixMs = Java.use('java.lang.System').currentTimeMillis();
    var payload = uid + "+100+" + unixMs;

    // Call the Cloud Function directly
    var functions = FirebaseFunctions.getInstance();
    var data = Java.use('java.util.HashMap').$new();
    data.put("payload", payload);
    functions.getHttpsCallable("validateScanPayload").call(data);
});
```

**Key insight:** Firebase AppCheck and Cloud Functions rely on the client to construct valid payloads. Post-authentication, Frida can hook the app to call any Cloud Function with arbitrary parameters, bypassing client-side validation (QR scanning, payment processing, etc.).

**When to recognize:** Android app with `google-services.json`, Firebase dependencies in `build.gradle`, Cloud Function calls in decompiled code.

**References:** BSidesSF 2026 "vinyl-drop"

---

## Verilog/Hardware Reverse Engineering (srdnlenCTF 2026)

**Pattern (Rev Juice):** Verilog HDL source for a vending machine with hidden product unlocked by specific coin insertion and selection sequence.

**Approach:**
1. Analyze Verilog modules to understand state machine and history tracking
2. Identify hidden conditions (e.g., product 8 enabled only when `COINS_HISTORY` array has specific values at specific taps)
3. Build timing model for each action type (how many clock cycles each operation takes)
4. Work backward from required history values to construct the correct input sequence

**Timing model construction:**
```python
# Map each action to its cycle count (determined from Verilog state machines)
TIMING = {
    "insert_coin": 3,       # 3 cycles per coin insertion
    "select_success": 7,    # 7 cycles for successful product selection
    "select_fail": 5,       # 5 cycles for failed selection attempt
    "cancel_with_coins": 4, # 4 cycles for cancel when coins > 0
    "cancel_at_zero": 2,    # 2 cycles for cancel when coins = 0
}

# COINS_HISTORY is a shift register updated each cycle
# History tap requirements (from Verilog conditions):
# H[0]=1, H[7]=4, H[28]=H[33]=H[38]=6
# H[63]=H[73]=2, H[80]=9
# (H[19]+H[21]+H[56]+H[69]) mod 32 = 0
```

**Key insight:** Hardware challenges require understanding the exact timing model — each operation takes a specific number of clock cycles, and shift registers record history at fixed tap positions. Work backward from the required tap values to determine what action must have occurred at each cycle. The solution is often a specific sequence notation (e.g., `I9C_SP6_CNL_I2C_SP2_I6C_SP6_SP6_SP5_CNL_I4C_SP1`).

**Detection:** Look for `.v` or `.sv` (Verilog/SystemVerilog) files, `always @(posedge clk)` blocks, shift register patterns, and state machine `case` statements with hidden conditions gated on history values.

---

## Prefix-by-Prefix Hash Reversal (Nullcon 2026)

See [patterns-ctf-2.md](patterns-ctf-2.md#prefix-hash-brute-force-nullcon-2026) for the full technique. This section covers language-specific considerations.

**Language-specific notes:**
- Hash algorithm may be uncommon (MD2, custom) — don't need to identify it, just match outputs by running the binary
- Use `subprocess.run()` with `timeout=2` to handle binaries that hang on bad input
- For stripped binaries, check if `ltrace` reveals the hash function name (e.g., `MD2_Update`)

---

## Ruby/Perl Polyglot Constraint Satisfaction (BearCatCTF 2026)

**Pattern (Polly's Key):** A single file valid in both Ruby and Perl. Each language imposes different validation constraints on a 50-character key. Satisfy both simultaneously to decrypt the flag.

**Polyglot structure exploits:**
- Ruby: `=begin`...`=end` is a block comment
- Perl: `=begin`...`=cut` is POD (Plain Old Documentation), `=end` is ignored
- Different code runs in each language based on comment block boundaries

**Typical constraints:**
- **Ruby:** Character set must form a mathematical property (e.g., all 50 printable ASCII chars except `^` used exactly once, each satisfying `XOR(val, (val-16) % 257)` is a primitive root mod 257)
- **Perl:** Ordering constraint via insertion sort inversion count (hardcoded inversion table determines exact permutation)

**Solution approach:**
1. Find the valid character set (mathematical constraint from one language)
2. Use the ordering constraint (from other language) to determine exact arrangement
3. Compute key hash (e.g., MD5) and decrypt

```python
# Determine character ordering from inversion counts
def reconstruct_from_inversions(chars, inv_counts):
    result = []
    remaining = sorted(chars)
    for i in range(len(chars) - 1, -1, -1):
        # inv_counts[i] = number of elements to the left that are greater
        idx = inv_counts[i]
        result.insert(idx, remaining.pop(i))
    return result
```

**Key insight:** Polyglot files exploit language-specific comment/block syntax to run different code in each interpreter. The constraints from both languages intersect to uniquely determine the key. Identify which code runs in which language by testing the file with both interpreters and comparing behavior.

**Detection:** File that runs under multiple interpreters (`ruby file && perl file`). Challenge mentions "polyglot" or provides a file ending in `.rb` that also looks like Perl.

---

## Electron App + Native Binary Reversing (RootAccess2026)

**Pattern (Rootium Browser):** Electron desktop app bundles a native ELF/DLL binary for sensitive operations (vault, crypto, auth). The Electron layer is a wrapper; the real flag logic is in the native binary.

**Extraction workflow:**
1. **Unpack Electron ASAR archive:**
```bash
# Install ASAR tool
npm install -g @electron/asar

# Extract the app.asar archive
asar extract resources/app.asar app_extracted/
ls app_extracted/
```

2. **Locate native binary:** Search for ELF/DLL files called from JavaScript:
```bash
# Find native binaries
find app_extracted/ -name "*.node" -o -name "*.so" -o -name "*vault*" -o -name "*auth*"

# Check JS for child_process.spawn or ffi-napi calls
grep -r "spawn\|execFile\|ffi\|require.*native" app_extracted/
```

3. **Reverse the native binary** (XOR + rotation cipher example):
```python
def decrypt_password(encrypted_bytes, key):
    """Common pattern: XOR with constant + bit rotation + key XOR."""
    result = []
    for i, byte in enumerate(encrypted_bytes):
        decrypted = ((byte ^ 0x42) >> 3) ^ key[i % len(key)]
        result.append(chr(decrypted))
    return ''.join(result)

def decrypt_flag(encrypted_flag, password):
    """Flag uses password as key with position-dependent rotation."""
    result = []
    for i, byte in enumerate(encrypted_flag):
        key_byte = ord(password[i % len(password)])
        decrypted = ((byte ^ 0x7E) >> (i % 8)) ^ key_byte
        result.append(chr(decrypted))
    return ''.join(result)
```

**Key insight:** Electron apps are JavaScript wrapping native code. Extract with `asar`, then focus on the native binary. The JS layer often contains the password verification flow in plaintext, revealing what the native binary expects. Look for encrypted data in the `.data` or `.rodata` sections of the ELF.

**Detection:** `.asar` files in `resources/` directory, Electron framework files, `package.json` with electron dependency.

---

## Node.js npm Package Runtime Introspection (RootAccess2026)

**Pattern (RootAccess CLI):** Obfuscated npm package with RC4 encoding, control flow flattening, and flag split across multiple fragments. Static analysis is impractical — use runtime introspection instead.

**Dynamic analysis approach:**
```javascript
#!/usr/bin/env node

// 1. Load obfuscated modules
const cryptoMod = require('target-package/dist/lib/crypto.js');
const vaultMod = require('target-package/dist/lib/vault.js');

// 2. Enumerate all exported properties
for (const mod of [cryptoMod, vaultMod]) {
    for (const key of Object.keys(mod)) {
        const obj = mod[key];
        console.log(`Export: ${key}`);
        // List all methods including hidden ones
        const props = Object.getOwnPropertyNames(obj);
        const proto = Object.getOwnPropertyNames(obj.prototype || {});
        console.log('  Own:', props);
        console.log('  Proto:', proto);
    }
}

// 3. Extract flag fragments
const Engine = cryptoMod.CryptoEngine;
const total = Engine.getTotalFragments();
let flag = '';
for (let i = 1; i <= total; i++) {
    flag += Engine.getFragment(i);
}
console.log('Flag:', flag);

// 4. Check for hidden methods (common: __getFullFlag__, _debug, _raw)
const hidden = Object.getOwnPropertyNames(Engine)
    .filter(p => p.startsWith('__') || p.startsWith('_'));
console.log('Hidden methods:', hidden);
```

**Key insight:** Heavily obfuscated JavaScript (control flow flattening, RC4 string encoding, dead code) makes static analysis prohibitively slow. Runtime introspection via `Object.getOwnPropertyNames()` reveals all methods including hidden ones. The module's own decryption runs automatically when loaded — just call the decoded functions directly.

**Detection:** npm package with minified/obfuscated `dist/` directory, challenge says "reverse engineer the CLI tool", `package.json` with custom commands.
