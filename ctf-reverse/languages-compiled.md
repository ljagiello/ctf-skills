# CTF Reverse - Compiled Language Reversing (Go, Rust)

## Table of Contents
- [Go Binary Reversing](#go-binary-reversing)
  - [Recognition](#recognition)
  - [Symbol Recovery](#symbol-recovery)
  - [Go Memory Layout](#go-memory-layout)
  - [Goroutine and Concurrency Analysis](#goroutine-and-concurrency-analysis)
  - [Common Go Patterns in Decompilation](#common-go-patterns-in-decompilation)
  - [Go Binary Reversing Workflow](#go-binary-reversing-workflow)
- [Rust Binary Reversing](#rust-binary-reversing)
  - [Recognition](#recognition-1)
  - [Symbol Demangling](#symbol-demangling)
  - [Common Rust Patterns in Decompilation](#common-rust-patterns-in-decompilation)
  - [Rust-Specific Analysis Tools](#rust-specific-analysis-tools)

---

## Go Binary Reversing

Go binaries are increasingly common in CTF challenges due to Go's popularity for CLI tools, network services, and malware.

### Recognition

```bash
# Detect Go binary
file binary | grep -i "go"
strings binary | grep "go.buildid"
strings binary | grep "runtime.gopanic"

# Go version embedded in binary
strings binary | grep "^go1\."
```

**Key indicators:**
- Very large static binary (even "hello world" is ~2MB)
- Embedded `go.buildid` string
- `runtime.*` symbols (even in stripped binaries, some remain)
- `main.main` as entry point (not `main`)
- Strings like `GOROOT`, `GOPATH`, `/usr/local/go/src/`

### Symbol Recovery

Go embeds rich type and function information even in stripped binaries:

```bash
# GoReSym - recovers function names, types, interfaces from Go binaries
# https://github.com/mandiant/GoReSym
./GoReSym -d binary > symbols.json

# Parse output
python3 -c "
import json
with open('symbols.json') as f:
    data = json.load(f)
for fn in data.get('UserFunctions', []):
    print(f\"{fn['Start']:#x}  {fn['FullName']}\")
"
```

**Ghidra with golang-loader:**
```bash
# Install: Ghidra → Window → Script Manager → search "golang"
# Or use: https://github.com/getCUJO/ThreatFox/tree/main/ghidra-golang
# Recovers function names, string references, interface tables
```

**redress (Go binary analysis):**
```bash
# https://github.com/goretk/redress
redress -src binary         # Reconstruct source tree
redress -pkg binary         # List packages
redress -type binary        # List types and methods
redress -interface binary   # List interfaces
```

### Go Memory Layout

Understanding Go's data structures in decompilation:

```c
# String: {pointer, length} (16 bytes on 64-bit)
# NOT null-terminated! Length field is critical.
struct GoString {
    char *ptr;    // pointer to UTF-8 data
    int64 len;    // byte length
};

# Slice: {pointer, length, capacity} (24 bytes on 64-bit)
struct GoSlice {
    void *ptr;    // pointer to backing array
    int64 len;    // current length
    int64 cap;    // allocated capacity
};

# Interface: {type_descriptor, data_pointer} (16 bytes)
struct GoInterface {
    void *type;   // points to type metadata (itab for non-empty interface)
    void *data;   // points to actual value
};

# Map: pointer to runtime.hmap struct
# Channel: pointer to runtime.hchan struct
```

**In Ghidra/IDA:** When you see a function taking `(ptr, int64)` — it's likely a Go string. Three-field `(ptr, int64, int64)` is a slice.

### Goroutine and Concurrency Analysis

```bash
# Identify goroutine spawns in disassembly
strings binary | grep "runtime.newproc"
# newproc1 is the internal goroutine creation function

# In GDB with Go support:
gdb ./binary
(gdb) source /usr/local/go/src/runtime/runtime-gdb.py
(gdb) info goroutines          # List all goroutines
(gdb) goroutine 1 bt          # Backtrace for goroutine 1
```

**Channel operations in disassembly:**
- `runtime.chansend1` → `ch <- value`
- `runtime.chanrecv1` → `value = <-ch`
- `runtime.selectgo` → `select { case ... }`
- `runtime.closechan` → `close(ch)`

### Common Go Patterns in Decompilation

**Defer mechanism:**
- `runtime.deferproc` → registers deferred function
- `runtime.deferreturn` → executes deferred functions at function exit
- Deferred calls execute in LIFO order — relevant for cleanup/crypto key wiping

**Error handling (the `if err != nil` pattern):**
```text
# In disassembly, this appears as:
# call some_function        → returns (result, error) as two values
# test rax, rax             → check if error (second return value) is nil
# jne error_handler
```

**String concatenation:**
- `runtime.concatstrings` → `s1 + s2 + s3`
- `fmt.Sprintf` → formatted string building
- Look for format strings in `.rodata`: `"%s%d"`, `"%x"`

**Common stdlib patterns in CTF:**
```go
// Crypto operations → look for these in strings/imports:
// "crypto/aes", "crypto/cipher", "crypto/sha256", "encoding/hex", "encoding/base64"

// Network operations:
// "net/http", "net.Dial", "bufio.NewReader"

// File operations:
// "os.Open", "io.ReadAll", "os.ReadFile"
```

### Go Binary Reversing Workflow

```bash
1. file binary                          # Confirm Go, get arch
2. GoReSym -d binary > syms.json       # Recover symbols
3. strings binary | grep -i flag        # Quick win check
4. Load in Ghidra with golang-loader    # Apply recovered symbols
5. Find main.main                       # Entry point
6. Identify string comparisons          # GoString {ptr, len} pairs
7. Trace crypto operations              # crypto/* package usage
8. Check for embedded resources         # embed.FS in Go 1.16+
```

**Go embed.FS (Go 1.16+):** Binaries can embed files at compile time:
```bash
# Look for embedded file data
strings binary | grep "embed"
# Embedded files appear as raw data in the binary
# Search for known file signatures (PK for zip, PNG header, etc.)
```

**Key insight:** Go's runtime embeds extensive metadata even in stripped binaries. Use GoReSym before any manual analysis — it often recovers 90%+ of function names, making decompilation dramatically easier. Go strings are `{ptr, len}` tuples, not null-terminated — Ghidra's default string analysis will miss them without the golang-loader plugin.

**Detection:** Large static binary (2MB+ for simple programs), `go.buildid`, `runtime.gopanic`, source paths like `/home/user/go/src/`.

---

## Rust Binary Reversing

Rust binaries are common in modern CTFs, especially for crypto, systems, and security tooling challenges.

### Recognition

```bash
# Detect Rust binary
strings binary | grep -c "rust"
strings binary | grep "rustc"             # Compiler version
strings binary | grep "/rustc/"           # Source paths
strings binary | grep "core::panicking"   # Panic infrastructure
```

**Key indicators:**
- `core::panicking::panic` in strings
- Mangled symbols starting with `_ZN` (Itanium ABI) — e.g., `_ZN4main4main17h...`
- `.rustc` section in ELF
- References to `/rustc/<commit_hash>/library/`
- Large binary size (Rust statically links by default)

### Symbol Demangling

```bash
# Rust uses Itanium ABI mangling (same as C++)
# rustfilt demangles Rust-specific symbols
cargo install rustfilt
nm binary | rustfilt | grep "main"

# Or use c++filt (works for most Rust symbols)
nm binary | c++filt | grep "main"

# In Ghidra: Window → Script Manager → search "Demangler"
# Enable "DemangleAllScript" for automatic demangling
```

### Common Rust Patterns in Decompilation

**Option/Result enum:**
```text
# Option<T> in memory: {discriminant (0=None, 1=Some), value}
# Result<T, E>: {discriminant (0=Ok, 1=Err), union{ok_val, err_val}}

# In disassembly:
# cmp byte [rbp-0x10], 0    → check if None/Err
# je handle_none_case
```

**Vec<T> (same as Go slice):**
```c
struct RustVec {
    void *ptr;      // heap pointer
    uint64 cap;     // capacity
    uint64 len;     // length
};
```

**String / &str:**
```text
# String (owned): {ptr, capacity, length} — 24 bytes, heap-allocated
# &str (borrowed): {ptr, length} — 16 bytes, can point anywhere

# In decompilation, look for:
# alloc::string::String::from    → String creation
# core::str::from_utf8           → byte slice to str
```

**Iterator chains:**
```text
# .iter().map().filter().collect() compiles to loop fusion
# In disassembly: tight loop with inlined closures
# Look for: core::iter::adapters::map, filter, etc.
```

**Panic unwinding:**
```bash
# Panic strings reveal source locations and error messages
strings binary | grep "panicked at"
strings binary | grep "called .unwrap().. on"
# These often contain file paths, line numbers, and variable names
```

### Rust-Specific Analysis Tools

```bash
# cargo-bloat: analyze binary size by function
cargo install cargo-bloat
cargo bloat --release -n 50

# Ghidra Rust helper scripts
# https://github.com/AmateursCTF/ghidra-rust (community scripts for Rust RE)
```

**Key insight:** Rust panic messages are goldmines — they contain source file paths, line numbers, and descriptive error strings even in release builds. Always `strings binary | grep "panicked"` first. Rust's monomorphization means generic functions get duplicated per type — expect many similar-looking functions.

**Detection:** `core::panicking`, `.rustc` section, `/rustc/` paths, `_ZN` mangled symbols with Rust-style module paths.
