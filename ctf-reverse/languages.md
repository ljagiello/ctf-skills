# CTF Reverse - Language & Platform-Specific Techniques

## Table of Contents
- [Python Bytecode Reversing (dis.dis output)](#python-bytecode-reversing-disdis-output)
  - [Common Pattern: XOR Validation with Split Indices](#common-pattern-xor-validation-with-split-indices)
  - [Bytecode Analysis Tips](#bytecode-analysis-tips)
- [Python Opcode Remapping](#python-opcode-remapping)
  - [Identification](#identification)
  - [Recovery](#recovery)
- [Pyarmor 8/9 Static Unpack (1shot)](#pyarmor-89-static-unpack-1shot)
- [DOS Stub Analysis](#dos-stub-analysis)
- [Unity IL2CPP Games](#unity-il2cpp-games)
- [HarmonyOS HAP/ABC Reverse (abc-decompiler)](#harmonyos-hapabc-reverse-abc-decompiler)
- [Brainfuck/Esolangs](#brainfuckesolangs)
- [UEFI Binary Analysis](#uefi-binary-analysis)
- [Transpilation to C](#transpilation-to-c)
- [Code Coverage Side-Channel Attack](#code-coverage-side-channel-attack)
- [Functional Language Reversing (OPAL)](#functional-language-reversing-opal)
- [Python Version-Specific Bytecode (VuwCTF 2025)](#python-version-specific-bytecode-vuwctf-2025)
- [Non-Bijective Substitution Cipher Reversing](#non-bijective-substitution-cipher-reversing)
- [Roblox Place File Analysis](#roblox-place-file-analysis)
- [Godot Game Asset Extraction](#godot-game-asset-extraction)
- [Rust serde_json Schema Recovery](#rust-serde_json-schema-recovery)
- [Android JNI RegisterNatives Obfuscation (HTB WonderSMS)](#android-jni-registernatives-obfuscation-htb-wondersms)
- [Verilog/Hardware Reverse Engineering (srdnlenCTF 2026)](#veriloghardware-reverse-engineering-srdnlenctf-2026)
- [Prefix-by-Prefix Hash Reversal (Nullcon 2026)](#prefix-by-prefix-hash-reversal-nullcon-2026)
- [Ruby/Perl Polyglot Constraint Satisfaction (BearCatCTF 2026)](#rubyperl-polyglot-constraint-satisfaction-bearcatctf-2026)
- [Electron App + Native Binary Reversing (RootAccess2026)](#electron-app--native-binary-reversing-rootaccess2026)
- [Node.js npm Package Runtime Introspection (RootAccess2026)](#nodejs-npm-package-runtime-introspection-rootaccess2026)

For Go and Rust binary reversing, see [languages-compiled.md](languages-compiled.md).

---

## Python Bytecode Reversing (dis.dis output)

### Common Pattern: XOR Validation with Split Indices

Challenge gives raw CPython bytecode (dis.dis disassembly). Common pattern:
1. Check flag length
2. XOR chars at even indices with key1, compare to list p1
3. XOR chars at odd indices with key2, compare to list p2

**Reversing:**
```python
# Given: p1, p2 (expected values), key1, key2 (XOR keys)
flag = [''] * flag_length
for i in range(len(p1)):
    flag[2*i] = chr(p1[i] ^ key1)      # Even indices
    flag[2*i+1] = chr(p2[i] ^ key2)    # Odd indices
print(''.join(flag))
```

### Bytecode Analysis Tips
- `LOAD_CONST` followed by `COMPARE_OP` reveals expected values
- `BINARY_XOR` identifies the transformation
- `BUILD_TUPLE`/`BUILD_LIST` with constants = expected output array
- Loop structure: `FOR_ITER` + `BINARY_SUBSCR` = iterating over flag chars
- `CALL_FUNCTION` on `ord` = character-to-int conversion

---

## Python Opcode Remapping

### Identification
Decompiler fails with opcode errors.

### Recovery
1. Find modified `opcode.pyc` in PyInstaller bundle
2. Compare with original Python opcodes
3. Build mapping: `{new_opcode: original_opcode}`
4. Patch target .pyc
5. Decompile normally

---

## Pyarmor 8/9 Static Unpack (1shot)

- Tool: `Lil-House/Pyarmor-Static-Unpack-1shot`
- Use for Pyarmor 8.x/9.x armored scripts without executing sample code
- Quick signature check: payload typically starts with `PY` + six digits (Pyarmor 7 and earlier `PYARMOR` format is not supported)

Workflow:
1. Ensure target directory contains armored scripts and matching `pyarmor_runtime` library.
2. Run one-shot unpack to emit `.1shot.` outputs (disassembly + experimental decompile).
3. Treat disassembly as ground truth; verify decompiled source with bytecode when inconsistent.

```bash
python /path/to/oneshot/shot.py /path/to/scripts
```

Optional flags:
```bash
# Specify runtime explicitly
python /path/to/oneshot/shot.py /path/to/scripts -r /path/to/pyarmor_runtime.so

# Write outputs to another directory
python /path/to/oneshot/shot.py /path/to/scripts -o /path/to/output
```

Notes:
- `oneshot/pyarmor-1shot` executable must exist before running `shot.py`.
- PyInstaller bundles or archives should be unpacked first, then processed with 1shot.

---

## DOS Stub Analysis

PE files can hide code in DOS stub:
1. Check for large DOS stub in Ghidra/IDA
2. Run in DOSBox
3. Load in IDA as 16-bit DOS
4. Look for `int 16h` (keyboard input)

---

## Unity IL2CPP Games

- Use Il2CppDumper to dump symbols
- If Il2CppDumper fails, consider that `global-metadata.dat` may be encrypted; search strings/xrefs in the main binary and inspect the metadata loading path for custom decryption before dump.
- Look for `Start()` functions
- Key derivation: `key = SHA256(companyName + "\n" + productName)`
- Decrypt server responses with derived key

Please note most of that the executable file for the PC platform is GameAssembly.dll or *Assembly.dll, for the Android is libil2cpp.so.

---

## HarmonyOS HAP/ABC Reverse (abc-decompiler)

- Target files: `.hap` package and embedded `.abc` bytecode
- Tool: `https://github.com/ohos-decompiler/abc-decompiler`
- Download `jadx-dev-all.jar` from releases

Critical startup note:
- `java -jar` may enter GUI mode
- For CLI mode, always use:

```bash
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI [options] <input>
```

Most common commands:
```bash
# Basic decompile to directory
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -d "out" ".abc"

# Decompile .abc (recommended for this scenario)
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple -d "out_hap" "modules.abc"
```

Recommended parameters for this challenge:
- `-m simple`: reduce high-level reconstruction to avoid SSA/PHI-heavy failures
- `--log-level ERROR`: keep only critical errors
- Full recommended command:

```bash
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple --log-level ERROR -d "out_abc_simple" "modules.abc"
```

Parameter quick reference:
- `-d` output directory
- `--help` help

Notes:
- `.hap` is a package: extract it first (zip), then locate and analyze `.abc`
- Quote paths containing spaces or non-ASCII characters
- Use a new output directory name per run to avoid stale results
- Errors do not always mean full failure; prioritize `out_xxx/sources/`
- If `auto` fails, switch to `-m simple` first

Standard workflow:
1. Run with `-m simple --log-level ERROR`
2. Inspect key business files in output (for example `pages/Index.java`)
3. If cleaner output is needed, retry with `-m auto` or `-m restructure`
4. If some methods still fail, keep the `simple` output and continue logic analysis via alternate paths

---

## Brainfuck/Esolangs

- Check if compiled with known tools (BF-it)
- Understand tape/memory model
- Static analysis of cell operations

---

## UEFI Binary Analysis

```bash
7z x firmware.bin -oextracted/
file extracted/* | grep "PE32+"
```

- Bootkit replaces boot loader
- Custom VM protects decryption
- Lift VM bytecode to C

---

## Transpilation to C

For heavily obfuscated code:
```python
for opcode, args in instructions:
    if opcode == 'XOR':
        print(f"r{args[0]} ^= r{args[1]};")
    elif opcode == 'ADD':
        print(f"r{args[0]} += r{args[1]};")
```

Compile with `-O3` for constant folding.

---

## Code Coverage Side-Channel Attack

**Pattern (Coverup, Nullcon 2026):** PHP challenge provides XDebug code coverage data alongside encrypted output.

**How it works:**
- PHP code uses `xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE | XDEBUG_CC_BRANCH_CHECK)`
- Encryption uses data-dependent branches: `if ($xored == chr(0)) ... if ($xored == chr(1)) ...`
- Coverage JSON reveals which branches were executed during encryption
- This leaks the set of XOR intermediate values that occurred

**Exploitation:**
```python
import json

# Load coverage data
with open('coverage.json') as f:
    cov = json.load(f)

# Extract executed XOR values from branch coverage
executed_xored = set()
for line_no, hit_count in cov['encrypt.php']['lines'].items():
    if hit_count > 0:
        # Map line numbers to the chr(N) value in the if-statement
        executed_xored.add(extract_value_from_line(line_no))

# For each position, filter candidates
for pos in range(len(ciphertext)):
    candidates = []
    for key_byte in range(256):
        xored = plaintext_byte ^ key_byte  # or reverse S-box lookup
        if xored in executed_xored:
            candidates.append(key_byte)
    # Combined with known plaintext prefix, this uniquely determines key
```

**Key insight:** Code coverage is a powerful oracle — it tells you which conditional paths were taken. Any encryption with data-dependent branching leaks information through coverage.

**Mitigation detection:** Look for branchless/constant-time crypto implementations that defeat this attack.

---

## Functional Language Reversing (OPAL)

**Pattern (Opalist, Nullcon 2026):** Binary compiled from OPAL (Optimized Applicative Language), a purely functional language.

**Recognition markers:**
- `.impl` (implementation) and `.sign` (signature) source files
- `IMPLEMENTATION` / `SIGNATURE` keywords
- Nested `IF..THEN..ELSE..FI` structures
- Functions named `f1`, `f2`, ... `fN` (numeric naming)
- Heavy use of `seq[nat]`, `string`, `denotation` types

**Reversing approach:**
1. Pure functions are mathematically invertible — reverse each step in the pipeline
2. Identify the transformation chain: `f_final(f_n(...f_2(f_1(input))...))`
3. For each function, build the inverse

**Aggregate brute-force for scramble functions:**
When a transformation accumulates state that depends on original (unknown) values:
```python
# Example: f8 adds cumulative offset based on parity of original bytes
# offset contribution per element depends on whether pre-scramble value is even/odd
# Total offset S = sum of contributions, but S mod 256 has only 256 possibilities

decoded = base64_decode(target)
for total_offset_S in range(256):
    candidate = [(b - total_offset_S) % 256 for b in decoded]
    # Verify: recompute S from candidate values
    recomputed_S = sum(contribution(i, candidate[i]) for i in range(len(candidate))) % 256
    if recomputed_S == total_offset_S:
        # Apply remaining inverse steps
        result = apply_inverse_substitution(candidate)
        if all(32 <= c < 127 for c in result):
            print(bytes(result))
```

**Key lesson:** When a scramble function has a chicken-and-egg dependency (result depends on original, which is unknown), brute-force the aggregate effect (often mod 256 = 256 possibilities) rather than all possible states (exponential).

---

## Python Version-Specific Bytecode (VuwCTF 2025)

**Pattern (A New Machine):** Challenge targets specific Python version (e.g., 3.14.0 alpha).

**Key requirement:** Compile that exact Python version to disassemble bytecode — alpha/beta versions have different opcodes than stable releases.

```bash
# Build specific Python version
wget https://www.python.org/ftp/python/3.14.0/Python-3.14.0a4.tar.xz
tar xf Python-3.14.0a4.tar.xz
cd Python-3.14.0a4 && ./configure && make -j$(nproc)
./python -c "import dis, marshal; dis.dis(marshal.loads(open('challenge.pyc','rb').read()[16:]))"
```

**Common validation:** Flag compared against tuple of squared ASCII values:
```python
# Reverse: flag[i] = sqrt(expected_tuple[i])
import math
flag = ''.join(chr(int(math.isqrt(v))) for v in expected_values)
```

---

## Non-Bijective Substitution Cipher Reversing

**Pattern (Coverup, Nullcon 2026):** S-box/substitution table has collisions (multiple inputs map to same output).

**Detection:**
```python
sbox = [...]  # substitution table
if len(set(sbox)) < len(sbox):
    print("Non-bijective! Collisions exist.")
```

**Building reverse lookup:**
```python
from collections import defaultdict
rev_sub = defaultdict(list)
for i, v in enumerate(sbox):
    rev_sub[v].append(i)
# rev_sub[output] = [list of possible inputs]
```

**Disambiguation strategies:**
1. Known plaintext format (e.g., `ENO{`, `flag{`) fixes key bytes at known positions
2. Side-channel data (code coverage, timing) eliminates impossible candidates
3. Printable ASCII constraint (32-126) reduces candidate space
4. Re-encrypt candidates and verify against known ciphertext

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
