# Binary Analysis - Quick Start Guide

Static analysis techniques for reverse engineering executable files in pentesting and CTF challenges.

---

## When to Use

**Reverse Engineering CTF challenges** — Extract flags, passwords, or logic from compiled binaries without execution.

**Compiled exploit validation** — Verify exploit behavior before running.

**Malware analysis** — Understand what a binary does before dynamic testing.

---

## Static Analysis Workflow

### Step 1: Identify the Binary Type
```bash
file <binary>
# Output: ELF 64-bit LSB pie executable, x86-64, or similar
```

### Step 2: Extract Readable Strings
```bash
strings <binary> | grep -E "password|flag|secret|key"
# Often reveals hardcoded credentials or hints
```

### Step 3: Examine Binary Sections
```bash
objdump -h <binary>
# Lists sections: .text (code), .data (initialized data), .rodata (read-only), .bss (uninitialized)
```

### Step 4: Disassemble Key Functions
```bash
objdump -d <binary> | grep -A 30 "<main>:"
# Focus on: cmp (comparisons), je/jne (conditional jumps), call (function calls)
```

### Step 5: Dump Data Sections
```bash
objdump -s -j .data <binary>
objdump -s -j .rodata <binary>
# Reveals hardcoded values, obfuscated strings, arrays
```

---

## Common Patterns in Very Easy Challenges

### Pattern 1: Hardcoded Passwords
**Indicator:** String output from `strings`, readable in .rodata section  
**Approach:** Extract via `strings`, verify with `objdump -s`

### Pattern 2: Obfuscated Output Arrays
**Indicator:** Data section contains 32-bit or 64-bit values, program outputs multiple characters  
**Approach:**
1. Identify array address from disassembly
2. Dump section with `objdump -s`
3. Extract least significant byte (LSB) from each value
4. Convert hex bytes to ASCII characters

**Example:** Little-endian 32-bit array `0x48000000 0x54000000` decodes to `H` (0x48) + `T` (0x54)

### Pattern 3: Reversed Strings
**Indicator:** `reverse` function in symbol table, string in .data looks like gibberish but is readable backwards  
**Approach:**
1. Dump .data section with `objdump -s -j .data`
2. Reverse the string: `python3 -c "print('0wTdr0wss4P'[::-1])"`
3. Look for `reverse()` calls in disassembly to confirm

### Pattern 4: XOR-Encoded Strings
**Indicator:** `xor` function in symbol table, .data contains non-printable or garbled bytes, disassembly shows a byte key loaded into register (e.g., `movl $0x13, %ecx`)  
**Approach:**
1. Find XOR key from disassembly (register argument to xor function)
2. Find data address and length from the calling code
3. Dump bytes: `objdump -s -j .data <binary>`
4. Decode: `python3 -c "data=bytes([0x47,0x7b,...]); print(''.join(chr(b^KEY) for b in data))"`

### Pattern 5: Password-Gated Flag Output
**Indicator:** Program reads input, compares against hardcoded value, outputs flag on match  
**Approach:**
1. Extract password from strings or data section
2. Provide password via stdin
3. Capture flag output

### Pattern 6: "Decoy" Flags That Are Real
**Indicator:** Binary contains an obvious flag-like string (e.g., `FLAG{younevergoingtofindme}`) alongside complex obfuscation  
**Approach:** Always try submitting obvious strings FIRST before deep analysis. Challenges sometimes hide the real flag in plain sight as a misdirection tactic.

### Pattern 7: .NET Metadata String Extraction
**Indicator:** PE32 .NET assembly, `file` shows "Mono/.Net assembly"  
**Approach:**
1. Find `BSJB` marker (CLR metadata header) in binary
2. Parse stream headers to locate `#US` (User Strings) heap
3. Extract all user string literals — these contain hardcoded passwords, usernames, flag components
4. `python3 -c "data=open('binary','rb').read(); idx=data.find(b'BSJB'); ..."` for manual parsing when ILSpy unavailable

### Pattern 8: Python Bytecode Decompilation
**Indicator:** `.pyc` file or embedded Python bytecode (marshal data)  
**Approach:**
1. Python 2.7 `.pyc`: 4-byte magic (`03f30d0a`) + 4-byte timestamp + marshalled code
2. `python3 -c "import marshal,dis; co=marshal.loads(data[8:]); dis.dis(co)"` for disassembly
3. Inspect `co.co_consts` recursively — flags often stored as string constants in nested code objects

### Pattern 9: Quiz/Exam Services
**Indicator:** Challenge has a docker container that asks questions about the binary (file format, architecture, function addresses, passwords)  
**Approach:**
1. Complete full static analysis FIRST (all patterns above)
2. Connect to service and answer questions programmatically via socket
3. Common questions: file format, CPU arch, linked libraries, function addresses, call counts, decoded passwords, encoding keys (often wants decimal, not hex)

---

## Tool Reference

| Tool | Purpose | Example |
|------|---------|---------|
| `file` | Identify binary type | `file pass` → ELF 64-bit |
| `strings` | Extract readable text | `strings pass \| grep password` |
| `objdump -h` | List sections | Identify .data, .rodata locations |
| `objdump -d` | Disassemble code | Follow program flow, spot comparisons |
| `objdump -s` | Dump sections as hex | Read obfuscated data |
| `od` | Octal/hex dump | Alternative to objdump for raw inspection |
| `readelf` (Linux) | ELF metadata | Symbol tables, relocations |

---

## Common Mistakes

❌ **Running untrusted binaries** — Always verify file type and permissions first  
❌ **Ignoring strings output** — Often contains the answer directly  
❌ **Assuming big-endian** — Most modern systems (Intel, ARM) use little-endian; LSB is first byte  
❌ **Forgetting to parse arrays** — 32-bit/64-bit encoded values require LSB extraction  
❌ **Cross-platform issues** — Linux binaries may not run on macOS; use `objdump` instead  

---

## Cross-Platform Execution

| Platform | How to Run ELF 64-bit |
|----------|----------------------|
| Linux | `./binary` (directly) |
| macOS | No native ELF support; use `objdump`, `strings`, disassemblers |
| Windows | WSL, Docker, or Cygwin |

**Recommendation:** Use static analysis (`objdump`, `strings`) to avoid platform dependencies.

---

## One-Liner Cheat Sheet

**Find all strings containing "password":**
```bash
strings <binary> | grep -i password
```

**Extract 32-bit little-endian array and decode to ASCII:**
```bash
objdump -s -j .data <binary> | tail -n +2 | grep -oE '[0-9a-f]{8}' | xargs -I {} python3 -c "import sys; print(chr(int('{}',16) & 0xFF), end='')"
```

**Disassemble main function only:**
```bash
objdump -d <binary> | sed -n '/<main>:/,/^[0-9a-f]* <.*>:/p' | head -50
```

**List section offsets and sizes:**
```bash
objdump -h <binary> | grep -E "\.data|\.rodata|\.text"
```

---

## Generalization Rules

**Apply this workflow to:**
- Very Easy/Easy CTF reverse engineering challenges
- Any compiled binary with suspected hardcoded secrets
- Exploit validation (verify compiled exploit matches source)
- Malware triage (understand structure before dynamic analysis)

**Do NOT use for:**
- Running untrusted binaries as primary analysis (static first)
- Complex obfuscation or encryption (requires dynamic debugging)
- Time-critical exploit development (focus on dynamic analysis in those cases)
