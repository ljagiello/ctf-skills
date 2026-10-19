---
tags:
  - information-leak
  - brute-force-oracle
  - stack-buffer-overflow
  - rop
platform: pwnable.tw
points: 250
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A password verification oracle using strncmp enables byte-by-byte recovery of the stack canary and randomized password, permitting stack buffer overflow into a ROP chain."
proof-of-concept: no
---

# BabyStack — pwnable.tw (250 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10205`
>
> Flag: `FLAG{Its_juS7_a_st4ck0v3rfl0w}`

## Challenge Overview

A stripped x86-64 PIE binary with full protections, linked against glibc 2.23. The program implements a simple login/logout menu with a 16-byte random password read from `/dev/urandom`. The password also serves as a custom "canary" — it must remain intact for the program to `return` cleanly from `main` (checked via `memcmp` against an mmap'd backup). Two helper functions (`Login` and `Copy`) share the same stack frame location, enabling a `strcpy`-based overflow.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    Canary found         # custom canary, not glibc __stack_chk
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## Program Logic

### `main` Stack Frame (`sub rsp, 0x60`)

| Offset from rbp | Field | Size |
|------------------|-------|------|
| `rbp-0x60` | `copy_dest` — Copy writes here via `strcpy` | 64 bytes |
| `rbp-0x20` | `password` — 16 random bytes from `/dev/urandom` | 16 bytes |
| `rbp-0x10` | `choice` — menu input buffer | 16 bytes |
| `rbp+0x00` | saved rbp | 8 bytes |
| `rbp+0x08` | **return address** (to `__libc_start_main`) | 8 bytes |

Distance from `copy_dest` to return address: **0x68 = 104 bytes**.

### Menu

```c
while (1) {
    __read_chk(0, choice, 16, 16);
    switch (choice[0]) {
        case '1':
            if (logged_in) logged_in = 0;   // logout
            else Login(password);            // authenticate
            break;
        case '2':
            if (logged_in) {
                if (memcmp(password, mmap_backup, 16) == 0) {
                    eax = 0; return;         // clean exit — triggers ret
                } else __stack_chk_fail();   // password tampered
            } else exit(0);
            break;
        case '3':
            if (logged_in) Copy(copy_dest);  // magic copy
            break;
    }
}
```

### `Login(passwd)` — `sub rsp, 0x90`, buf at `Login_rbp-0x80`

```c
printf("Your passowrd :");
my_read(buf, 0x7f);                          // read up to 127 bytes
if (strncmp(buf, passwd, strlen(buf)) == 0)
    logged_in = 1;                            // "Login Success !"
```

### `Copy(dst)` — `sub rsp, 0x90`, buf at `Copy_rbp-0x80`

```c
printf("Copy :");
my_read(buf, 0x3f);                          // read up to 63 bytes
strcpy(dst, buf);                             // dst = main's rbp-0x60
puts("It is magic copy !");
```

### `my_read(buf, n)`

```c
r = read(0, buf, n);
if (buf[r-1] == '\n') buf[r-1] = '\0';       // NUL-terminates ONLY if last byte is '\n'
```

**Critical:** `Login` and `Copy` are called from `main` at the same call depth → their local buffers (`rbp-0x80`) occupy the **exact same stack memory**.

## Vulnerabilities

### V1 — `strncmp` with `strlen(input)` — Password Oracle / Auth Bypass

**Root Cause:** `Login` compares the user-supplied buffer against the password using `strncmp(buf, passwd, strlen(buf))`. The comparison length is controlled by the attacker.

```c
strncmp(buf, passwd, strlen(buf))
```

**Auth Bypass:** Sending `\x00` (empty string, `strlen == 0`) → `strncmp(..., 0) == 0` → Login Success. This sets `logged_in = 1` without knowing the password.

**Byte-by-Byte Oracle:** Sending `known_prefix + guess_byte + \x00` causes `strncmp` to compare exactly `len(prefix)+1` bytes. "Login Success" means the guess byte matched → brute-force the 16-byte password one byte at a time (~128 avg attempts per byte, ~2048 total queries).

### V2 — `strcpy` Overflow via Shared Stack Frame

**Root Cause:** `Login` and `Copy` share the same stack buffer location. `Login` can write up to 127 bytes into the buffer, but `Copy` only reads 63 bytes into it via `my_read`. When `Copy` then calls `strcpy(dst, buf)`, it copies from the shared buffer — but `strcpy` only stops at NUL. If `Login` previously filled bytes 63–126 with non-NUL data, `strcpy` copies **far past 63 bytes**, overflowing into `main`'s password slot, saved rbp, and return address.

```
Login fills: buf[0..126]  (127 bytes, no NUL at end if no '\n')
Copy reads:  buf[0..62]   (63 bytes, overwrites only first 63)
strcpy:      copies buf[0..NUL) → main's copy_dest (rbp-0x60)
             continues past 63 bytes using Login's leftover data
             → overwrites password (rbp-0x20) and return address (rbp+0x08)
```

**Impact:** Full control over main's return address (offset 0x68 from `copy_dest`). The password slot (offset 0x40) must be restored to its original value for the `memcmp` check to pass on exit.

### V3 — Libc Pointer Residue on Stack

**Root Cause:** After `Copy` calls `strcpy` and `puts`, libc-internal function calls leave return addresses and other libc pointers on the stack frame. Because `Login` and `Copy` share the same frame, a subsequent `Login` call can observe these residual libc pointers at known offsets within the buffer.

**Impact:** By first overwriting the password slot with known non-NUL bytes (e.g., `'C'*8`) via the overflow, then using the oracle to brute-force the 6 bytes that follow, the attacker recovers a libc address. The leaked value is typically `_IO_file_setbuf+9` or `_IO_file_overflow+235` (offset `0x78439` or `0x7a81b` from libc base).

## Exploit Paths

All solutions share the same fundamental primitives: V1 (oracle) for leaking, V2 (strcpy overflow) for control. They differ in what they leak and what they overwrite the return address with.

---

### Path A — Leak Password + Leak libc + One-Gadget (Most Common)

**Used by:** Solutions 8, 370, 821, 3498, 7905, 25572, 34817, 38891, and many others

1. **Brute-force the 16-byte password** via the `strncmp` oracle. If any byte is `\x00`, reconnect (fresh random password).

2. **Leak libc address:**
   - `Login` with `\x00 + 'A'*63 + 'A'*8` (no newline) → fills buffer past 63 bytes. The `\x00` first byte bypasses auth (`strlen == 0` → success, `logged_in = 1`).
   - `Copy` with any short input → `strcpy` copies the full buffer into `main`'s `copy_dest`. The residual libc pointer from the shared stack overwrites the password slot.
   - Toggle logout (`'1'`), then brute-force the new "password" bytes — these are now the libc pointer.
   - `leaked - 0x78439 = libc_base` (or `leaked - 0x7a81b` depending on runtime).

3. **Overwrite return address:**
   - `Login` with `\x00 + 'A'*63 + password + 'B'*24 + p64(one_gadget)` (no newline).
   - `Copy` → `strcpy` overflows `copy_dest`, restoring password at offset 0x40 and placing `one_gadget` at offset 0x68 (return address).

4. **Trigger:** Send `'2'` → `memcmp` passes (password restored) → `mov eax, 0; leave; ret` → jumps to one_gadget. Since `eax == 0` (set by memcmp return), the `rax == NULL` constraint is satisfied.

**One-gadget offsets (glibc 2.23):**
```python
0x45216   # rax == NULL (preferred — satisfied by memcmp eax=0)
0x4526a   # [rsp+0x30] == NULL
0xef6c4   # [rsp+0x50] == NULL
0xf0567   # [rsp+0x70] == NULL
```

**Reliability:** ~94% per connection. Fails only if the random password contains a NUL byte (~6% chance), since `strcpy` stops at NUL and can't restore it.

---

### Path B — Leak Password + Leak PIE Base + ROP Chain

**Used by:** Solutions 59, 278, 533, 2605, 9952, 10128, 13019

This variant additionally leaks the PIE base to build a ROP chain using binary gadgets:

1. **Brute-force password** (same as Path A).

2. **Leak PIE base:** After the password (offset 0x40 in `copy_dest`), the next stack slot at `main_rbp-0x10` contains `__libc_csu_init` (PIE address `0x1060`). Use the overflow + oracle to read 6 bytes beyond the password → `PIE_base = leaked - 0x1060`.

3. **First overflow → ret to `read_n`:** Overwrite return address with the binary's `my_read` gadget (`PIE+0xca0`). When main returns, it calls `my_read` with whatever `rdi`/`rsi` happen to be, enabling a **second, larger stack overflow** with arbitrary bytes (no `strcpy` NUL limitation).

4. **Second overflow → full ROP:**
   - `pop rdi; ret` + GOT entry + `puts@plt` → leak libc at runtime.
   - `pop rdi; ret` + `"/bin/sh"` + `system` → shell.
   - Or pivot stack to BSS, chain `read` for a third payload.

**Advantages:** Can write NUL bytes in ROP chain (second overflow uses `read`, not `strcpy`). Can use `system("/bin/sh")` instead of one-gadget constraints.

**Disadvantages:** Requires PIE leak (~2048 more oracle queries), two return-to-main cycles (re-leak password on second iteration if main restarts), more complex.

---

### Path C — Leak Password + Libc Leak + `system` via Choice Buffer

**Used by:** Solutions 331, 821 (variant)

A simpler variation that avoids one-gadget constraints:

1. **Password + libc leak** (same as Path A).
2. **Overwrite return address with `system`.**
3. **Trigger with `'2;sh;\x00'`** as the menu choice — the 16-byte choice buffer starts with `'2'` (triggers exit path), but the same buffer at `choice+2` contains `"sh"`. Since `system` receives `rdi` pointing to the choice buffer region on the stack, it executes `system("sh")`.

**Note:** This is fragile — `rdi` must point to the right stack location containing `"sh"`. Some solutions use `"2;bash\x00"` or `"2;/bin/sh;"`.

---

### Path D — Null-Byte-Safe ROP via Incremental Writes

**Used by:** Solutions 278, 9952

Addresses containing NUL bytes can't be written via `strcpy` in one shot. This approach writes the ROP chain incrementally:

1. For each NUL byte in the target ROP payload, write everything **after** that NUL in a separate `Login+Copy` cycle. Each cycle places a NUL-terminated string at a different offset.
2. Process NUL positions from highest to lowest, building up the full payload across multiple rounds.
3. Finally restore the password and trigger return.

This allows arbitrary ROP chains without NUL byte restrictions.

## Key Observations

### Stack Layout — Login/Copy Shared Buffer

```
             Login/Copy frame               main frame
             ┌──────────────┐          ┌──────────────────┐
rbp-0x80     │ buf[0..126]  │          │                  │
             │  (Login: 127)│          │ copy_dest[0..63] │ rbp-0x60
             │  (Copy:   63)│          │                  │
             │              │          │ password[0..15]  │ rbp-0x20
             │              │          │ choice[0..15]    │ rbp-0x10
             └──────────────┘          │ saved rbp        │ rbp+0x00
                                       │ return address   │ rbp+0x08
                                       └──────────────────┘
```

Login's `buf[0..62]` maps to `copy_dest[0..62]` after `strcpy`.
Login's `buf[63..78]` maps to `copy_dest[63..78]` = password slot + beyond.
Login's `buf[79..103]` maps to the saved rbp and return address region.

### Oracle Interaction Protocol

The menu reads exactly 16 bytes via `__read_chk(0, choice, 16, 16)`. Pipelining is possible by sending `"1" + 15_pad_bytes + password_guess` in one TCP segment. Login's `my_read` reads up to 127 bytes greedily, so padding the body to exactly 127 bytes self-frames each query.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Password oracle (byte-by-byte) | V1: `strncmp` + `strlen(input)` | Deterministic (~2048 queries) |
| Auth bypass (empty string) | V1: `strlen("\x00") == 0` | Deterministic |
| Stack overflow via `strcpy` | V2: shared frame + `strcpy` past 63 | Deterministic (no NUL in payload) |
| Libc leak (residual pointer) | V3: shared frame + overflow + oracle | Deterministic |
| PIE leak (optional) | V3: overflow deeper + oracle | Deterministic |
| Return address overwrite | V2: `copy_dest + 0x68 = ret addr` | Deterministic |
| `memcmp` bypass | Restore password at `copy_dest + 0x40` | Fails if password has NUL (~6%) |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
# Libc leak offsets (residual pointer on stack)
_IO_file_setbuf_plus_9  = 0x78439    # common in direct process
_IO_file_overflow_plus_235 = 0x7a81b # common under fork-server/socat

# Gadgets
one_gadget_rax_null  = 0x45216   # rax == NULL (best — memcmp sets eax=0)
one_gadget_rsp30     = 0x4526a   # [rsp+0x30] == NULL
one_gadget_rsp50     = 0xef6c4   # [rsp+0x50] == NULL
one_gadget_rsp70     = 0xf0567   # [rsp+0x70] == NULL
system               = 0x45390
bin_sh               = 0x18c177
__libc_start_main    = 0x20740
puts                 = 0x6f690

# PIE offsets (if PIE leak used)
__libc_csu_init      = 0x1060
main                 = 0xecf
my_read              = 0xca0
puts_plt             = 0xae0
pop_rdi_ret          = 0x10c3
pop_rsi_r15_ret      = 0x10c1
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `8.md` | A | password oracle → libc leak → one_gadget | Clean Python, detailed comments |
| `59.md` | B | password + PIE oracle → ret-to-read → ROP | Two-stage ROP; stack pivot to BSS |
| `278.md` | B + D | PIE leak → incremental NUL-safe ROP → puts leak | Ruby; handles NUL bytes in ROP chain |
| `331.md` | C | password → libc → `system` via choice buf | Uses `"2;bash\x00"` as choice to trigger system |
| `370.md` | A | password → libc → one_gadget (0xf0567) | Also leaks PIE but uses one_gadget |
| `533.md` | B | PIE leak → ret-to-read → `execve` ROP | Full `execve` call via ROP |
| `821.md` | A | pipelined oracle → libc → `system` | Batched queries for speed |
| `2605.md` | B | PIE + stack leak → ret-to-read → one_gadget | Leaks stack address for pivot |
| `3498.md` | A | password → libc → one_gadget (0xf0567) | Concise; `flat()` for payload |
| `7905.md` | A | password → libc → one_gadget (0x45216) | Most detailed writeup; full Chinese analysis |
| `9952.md` | B + D | PIE → incremental write → puts leak → ROP | `build_rop` handles NUL-free writes |
| `10128.md` | B | PIE + stack → ret-to-read → stack pivot | Uses `pop rsp` gadget |
| `25572.md` | A | password → libc → one_gadget | Detailed taintedbits.com writeup |
| `34817.md` | A | password → libc (`_IO_file_setbuf+9`) → one_gadget | Clean Python3 |
| `38891.md` | A | password → libc → one_gadget (0x45216) | Minimal code |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (pure sockets, no pwntools) |
| `desc.txt` | Challenge description |
| `artifacts/babystack` | Original challenge binary (stripped PIE ELF) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (132 solutions) |
