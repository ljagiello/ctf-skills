---
tags:
  - canary-bypass
  - stack-buffer-overflow
  - ret2libc
platform: pwnable.tw
points: 300
arch: i386
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "Sending non-digit input to scanf skips array slot assignment without writing, bypassing the stack canary during sorting and allowing ret2libc."
proof-of-concept: no
---

# dubblesort — pwnable.tw (300 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10101`
>
> Flag: `FLAG{Dubo_duBo_dub0_s0rttttttt}`

## Challenge Overview

A 32-bit bubble-sort program (i386, Full RELRO, PIE, NX, Stack Canary, FORTIFY) built against glibc 2.23. It reads a name, asks how many unsigned integers to sort, reads them into a fixed-size stack buffer, bubble-sorts them, and prints the result.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## Program Logic (Decompiled)

```c
int main() {
    unsigned int canary = __readgsdword(0x14u);
    unsigned int count;                     // [esp+0x18]
    int array[24];                          // [esp+0x1c] — 0x60 bytes
    char name_buf[0x40];                    // [esp+0x3c] — overlaps array!
    // canary at [esp+0x7c] == array[24]

    printf("What your name :");
    read(0, name_buf, 0x40);               // V1: no NUL terminator
    printf("Hello %s,...");                 // leaks uninitialized stack data

    scanf("%u", &count);                    // no upper-bound check
    for (i = 0; i < count; i++) {           // V2: writes past array[24]
        printf("Enter the %d number : ");
        scanf("%u", &array[i]);             // V3: non-numeric input skips write
    }
    bubble_sort(array, count);
    // print sorted results...
}
```

**Key stack layout** (offsets from `esp`):

| Offset | Content |
|--------|---------|
| `0x1c` | `array[0]` |
| `0x3c` | `name_buf` (overlaps `array[8]`..`array[23]`) |
| `0x7c` | Stack canary = `array[24]` |
| `0x80`–`0x98` | Saved registers / padding (7 dwords) = `array[25]`..`array[31]` |
| `0x9c` | **Saved return address** = `array[32]` |
| `0xa0` | First argument to return-target = `array[33]` |

## Vulnerabilities

### V1 — Uninitialized Name Buffer Leaks libc Address

**Root Cause:** `read(0, name_buf, 0x40)` does NOT NUL-terminate the input. The name buffer at `esp+0x3c` overlaps the stack area where a libc data-segment pointer resides at `esp+0x54` (= `name_buf+0x18`, = `array[14]`). This pointer equals `libc_base + 0x1b0000` (the start of libc's `.got.plt` / RW segment), which is page-aligned so its low byte is always `0x00`.

```c
read(0, &buf, 0x40u);                    // does NOT append NUL
__printf_chk(1, "Hello %s,...");          // %s reads until NUL → leaks past input
```

**Trigger:** Send exactly 24–28 bytes of padding (e.g., `"A"*24` + newline or `"A"*28`). The `\n` or padding overwrites the `0x00` low byte. `printf("%s")` then prints through the padding into the libc pointer's upper 3 bytes.

**Impact:** Leak 3 high bytes of `libc_base + 0x1b0000`. Since the low byte is known (`0x00`), reconstruct the full pointer → compute `libc_base`.

```python
# Typical leak code from solutions
r.send(b"A" * 24 + b"\n")
r.recvuntil(b"A" * 24 + b"\n")
libc_leak = u32(b"\x00" + r.recv(3))   # restore known 0x00 low byte
libc_base = libc_leak - 0x1b0000
```

**Variant (28-byte leak):** Some solutions send 28 bytes (`"A"*28`) and read a full 4-byte dword at `name_buf+0x1c`. This leaks a different libc pointer (`libc_base + 0x1ae244`, the `__libc_start_main` return path). Both approaches work.

### V2 — Unbounded Array Write (Stack Buffer Overflow)

**Root Cause:** The `count` variable has no upper bound check. The program reads `count` unsigned integers into `array[24]` with no bounds validation, allowing writes past the 24-element buffer into the canary, saved registers, return address, and beyond.

```c
scanf("%u", &count);           // user controls count, no max check
for (i = 0; i < count; i++)
    scanf("%u", &array[i]);    // writes to array[0]..array[count-1]
```

**Impact:** Direct stack buffer overflow. With `count >= 35`, the attacker can overwrite:
- `array[24]` = stack canary
- `array[25]`–`array[31]` = saved registers / padding
- `array[32]` = **return address**
- `array[33]` = first argument to the called function
- `array[34]` = second argument / further chain

### V3 — `scanf("%u")` Canary Bypass via Non-Numeric Input

**Root Cause:** When `scanf("%u", &dst)` encounters input that is not a valid unsigned integer (like `"+"`, `"-"`, `"a"`, `"nope"`), it returns **without writing** to the destination. The existing stack value (the canary) is preserved.

```c
// When user inputs "+" for array[24]:
scanf("%u", &array[24]);  // scanf returns 0, array[24] unchanged
// The real canary at this position survives!
```

**Impact:** The attacker can skip overwriting the canary at `array[24]` by sending a non-numeric string. The canary check at function epilogue passes.

**Note:** `"+"` and `"-"` are the cleanest choices — they are consumed from the input stream (unlike `"a"` which stays in the buffer and can cause `scanf` to loop forever on subsequent calls).

### V4 — Bubble Sort Constraint on Payload

**Not a vulnerability** but a critical exploit constraint. After all numbers are written, the array is bubble-sorted in ascending order (unsigned comparison). The payload must be crafted so that after sorting, the values land at the correct stack positions:

- `array[0]`–`array[23]`: Must be ≤ canary (fill with `0` or small values)
- `array[24]`: Canary (preserved via V3, must stay in place)
- `array[25]`–`array[31]`: Must be ≥ canary and ≤ `system` address
- `array[32]`: `system` address (return address)
- `array[33]`+: `"/bin/sh"` address (argument)

Since `system` and `"/bin/sh"` are both in the `0xf7xxxxxx` range and `canary` is random, the sort order is usually: `{zeros} < canary < system < bin_sh`. This works ~97% of the time. The ~3% failure case is when `canary > bin_sh`, causing the values to mis-sort.

## Exploit Path — ret2libc via Stack Overflow + Canary Bypass

**Used by:** All 168 solutions (unanimous approach with minor variations)

**Steps:**

1. **Leak libc base (V1):** Send 24–28 `'A'` bytes as the name. `printf("%s")` leaks past the input into a libc data-segment pointer on the stack. Mask and subtract `0x1b0000` to get `libc_base`.

2. **Compute addresses:**
   ```python
   system  = libc_base + 0x3a940
   bin_sh  = libc_base + 0x158e8b
   ```

3. **Request 35 numbers (V2):** This gives enough slots to overflow past the canary and return address.

4. **Fill payload surviving bubble sort:**
   - Indices 0–23: `0` (small values, sort to bottom)
   - Index 24: `"+"` — bypasses canary via V3
   - Indices 25–33: `system` address (9 copies ensure it covers the return address at index 32 after sorting)
   - Index 34: `"/bin/sh"` address (argument to `system()`)

5. **After sort, stack looks like:**
   ```
   [0, 0, ..., 0, canary, system, system, ..., system, bin_sh]
    ^--- 24 ---^   ^24     ^--- indices 25..33 ---^     ^34
   ```
   Main returns → `system("/bin/sh")` → shell.

**Reliability:** ~97% per connection (fails only when random canary > `"/bin/sh"` address, causing mis-sort).

### Variations Across Solutions

| Variation | Solutions | Description |
|-----------|-----------|-------------|
| **24-byte name leak** | ~60% | Send `"A"*24`, leak 3 bytes after `\n`, reconstruct with `\x00` low byte. Offset `0x1b0000`. |
| **28-byte name leak** | ~30% | Send `"A"*28`, leak full 4-byte dword at different offset. Offset `0x1ae244`. |
| **Canary skip with `"+"`** | ~80% | Most popular; cleanly consumed by `scanf`. |
| **Canary skip with `"-"`** | ~10% | Same mechanism as `"+"`. |
| **Canary skip with `"a"`/`"nope"`** | ~10% | Works but can leave chars in input buffer. |
| **Two-round exploit** | Solution 1384, 13484 | First round: overflow with `main` addr + `"+"` to leak canary from sorted output. Second round: use known canary for precise placement. More complex, no real advantage. |
| **PIE leak** | Solution 1384, 13060 | 28-byte name also leaks a binary address at `name_buf+0x20`. Used to compute `main` for the two-round approach. |
| **Fill pattern: 9×system + bin_sh** | ~70% | Most common; system is replicated to cover indices 25–33. |
| **Fill pattern: 8×system + 2×bin_sh** | ~20% | Adds extra `bin_sh` for safety. |
| **Large count (40–50)** | ~15% | Over-allocates slots; uses `0xFFFFFFFF` or large values after the payload. |

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc data-segment leak | V1: uninitialized `name_buf` + `printf("%s")` | Deterministic |
| Stack overflow past canary | V2: unbounded `count` in array write loop | Deterministic |
| Canary preservation | V3: `scanf("%u")` skips write on non-numeric input | Deterministic |
| ret2libc (`system("/bin/sh")`) | Payload survives ascending bubble sort | ~97% (canary-dependent) |

## Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23 i386)

```python
# Leak offset (libc RW segment / .got.plt start)
libc_data_segment = 0x1b0000    # via 24-byte name leak
libc_start_main_ret = 0x1ae244  # via 28-byte name leak (alternative)

# Exploitation
system  = 0x3a940
bin_sh  = 0x158e8b    # "/bin/sh" string in libc
```

## Solution Write-ups

| File | Leak Method | Canary Bypass | Notes |
|------|-------------|---------------|-------|
| `138.md` | 24-byte, Ruby | `"+"` | Ruby pwnlib; converts to signed for negative addrs |
| `100.md` | 24-byte `"A"*24+"Z"` | `"a"` | Brute-force retry loop; unsorted payload order |
| `1006.md` | 24-byte | `"nope"` | Notes 3-byte leak limitation on remote |
| `1172.md` | 24-byte | `"+"`/no-byte | Simple approach with inline Chinese notes |
| `1220.md` | 24-byte | `"-"` | Clean minimal exploit |
| `1251.md` | 24-byte | `"-"` | Minimal; debug flag for local/remote offsets |
| `1269.md` | 25-byte | `"+"` | Uses pwntools `libc.symbols` |
| `1316.md` | 24-byte | `"zz"` | Uses `libc.search('/bin/sh')` |
| `1351.md` | 24-byte | `"+"` | Notes `scanf` "+-" behavior explicitly |
| `1384.md` | **Two-round** | Reads canary from sorted output | Leaks PIE base too; re-runs main |
| `1428.md` | 23+`"B"` byte | `"+"` | Full 4-byte dword leak via `"B"` marker |
| `10115.md` | 28-byte | `"+"` | Uses offset `0x1ae244` for 28-byte variant |
| `10302.md` | 25-byte | `"-"` | Clean Python3 exploit |
| `11540.md` | 28-byte | `"a"` | Brute-force canary validation; ~70% success claim |
| `12245.md` | 28-byte | `"+"` | Chinese writeup with detailed stack analysis |
| `12973.md` | — | — | One-liner summary: unlimited size + non-number canary bypass |
| `13060.md` | 28-byte | `"-"` | Full pwntools template with `libc_base-1` padding |
| `13484.md` | **Two-round** | Reads canary from sorted output | Uses magic gadget instead of system |
| `14479.md` | 28-byte | `"+"`/`"scanf bypass"` | Messy padding with `0xf0000000` values; leak includes binary base |
| `15134.md` | 28-byte | `"+"` | Clean with explicit offset derivation from `readelf` |
| `15273.md` | 24-byte | `"+"` | Detailed writeup explaining all three bugs |
| `15724.md` | Detailed stack analysis | `"+"` | Chinese writeup with `vmmap` / `readelf` analysis |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/dubblesort` | Original challenge binary (i386) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, i386) |
| `solution/*.md` | Community write-ups (168 solutions) |
