---
tags:
  - integer-overflow
  - stack-pivoting
  - rop
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
description: "A negative index in the menu jump table allows reading outside the table, triggering stack pivoting onto user input to execute a ROP chain."
proof-of-concept: no
---

# Starbound — pwnable.tw (200 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10202`
>
> Flag: `FLAG{st4r_st4r_st4r_b0und}`

## Challenge Overview

A "Starbound" space-themed game binary (i386, No PIE, Partial RELRO, NX, No Canary) built against glibc 2.23. The player interacts through a numbered main menu (1–7) offering actions like exploring, fighting, inventory, map viewing, settings, and multiplayer. The settings menu allows changing the player's name and IP address. The main dispatcher uses `strtol` to parse the menu choice and indexes into a **function pointer table** with **no bounds check**.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
```

## Key Memory Layout (No PIE — fixed addresses)

| Address | Content |
|---------|---------|
| `0x08057F80` | `me` struct (global player state) |
| `0x080580C8` | `me.ip` — IP address buffer |
| `0x080580D0` | `me.name` — player name buffer (4+ bytes) |
| `0x08058154` | Function pointer table (`cmds[]`) — 7 entries for menu options 1–7 |
| `0x0805509C` | `puts@GOT` |
| `0x08055050` | `__libc_start_main@GOT` |
| `0x08055054` | `read@GOT` |

The function pointer table at `0x08058154` lives at the **tail** of the `me` struct. The player name buffer at `0x080580D0` is at offset `-0x84` (i.e., -33 dwords) from the table base.

## Vulnerabilities

### V1 — Function Pointer Table Index OOB (Primary, Exploitable)

**Root Cause:** The main-menu dispatcher reads the user's choice via `strtol()` and uses it as an index into a function pointer table with **no bounds check**:

```asm
; main dispatch (0x0804A65D)
call    strtol          ; eax = user choice (signed)
call    DWORD PTR [eax*4 + 0x8058154]  ; NO bounds check on eax
```

Since `eax` can be **any signed integer** (including negative), the attacker can make the program call **any 4-byte-aligned dword in memory** as a function pointer.

**Key Index:** Index **-33** makes the dispatch read from `0x08058154 + (-33)*4 = 0x080580D0` — which is the **player name buffer**. Since the name is set by the user via the settings menu, this gives a call to an **attacker-controlled address**.

```
cmds[-33] = *(0x080580D0) = name[0:4]
```

**Impact:** Arbitrary code execution — the first 4 bytes of the player's name are called as a function pointer.

### V2 — Stack Leak via Large Negative Index (Exploitable)

**Root Cause:** Using a large negative index (e.g., `-3118`) points the function table lookup into the stack region. Since the input buffer is also on the stack, the resulting output from `puts` or the menu system can leak **stack addresses**.

```python
# -3118 index leaks a stack pointer through puts output
io.send("-3118")
stack_leak = u32(io.recv(4))
```

**Impact:** Leaks stack addresses, enabling precise stack pivoting or ROP chain placement.

### V3 — Format String via `do_bye` Gadget (Exploitable)

**Root Cause:** Setting the name to point at a mid-function address `0x08049C16` inside `do_bye()` causes the dispatch to land at:

```asm
; 0x08049C16 (inside do_bye)
mov     [esp], 1
call    __printf_chk    ; __printf_chk(1, input_buffer)
```

This turns the **user's input buffer** into a format string argument to `__printf_chk`.

**Impact:** A fully controlled, **returning** format string. By embedding a return address (e.g., `MAIN_LOOP = 0x0804A664`) in the input buffer and using `%s` with an embedded GOT pointer, the attacker gets an arbitrary read that cleanly returns to the main loop.

### V4 — Name Buffer Overflow into Settings Struct (Enabler)

The name read function (`readn`) reads up to a fixed number of bytes. The name buffer at `0x080580D0` sits within the larger `me` struct. Writing past the name can overwrite other struct fields, though the primary use is simply placing the 4-byte function pointer.

## Exploit Paths

All solutions exploit V1 (function pointer table OOB) by setting the player name to a controlled value, then entering index `-33` (or a computed negative index) to call it. They diverge on the pivot/leak/shell strategy.

---

### Path A — Stack Pivot → ROP → Leak libc → `system("/bin/sh")`

**Used by:** Solutions 100, 184, 1172, 1290, 1297, 1303, 1316, 1351, 1395, 14605, 18331, and many others

**The dominant approach (~80% of solutions).**

1. **Set name** to a stack-pivot gadget (e.g., `add esp, 0x1c; ret` at `0x08048e48` or `add esp, 0x10; pop; pop; pop; ret` at `0x0804a171`).

2. **Send `-33` + padding + ROP chain** as the menu input. When the dispatcher calls `name[0:4]`, the pivot adjusts `esp` to point into the attacker-controlled input buffer, landing in the ROP chain.

3. **ROP chain stage 1 — leak libc:**
   ```python
   # Typical ROP: puts(GOT_entry) → return to main
   rop = p32(puts_plt) + p32(main) + p32(puts_got)
   ```
   Leaks a resolved libc address (usually `puts`, `read`, or `__libc_start_main`).

4. **ROP chain stage 2 — shell:**
   After re-entering main with the libc base known:
   ```python
   rop = p32(system) + p32(0xdeadbeef) + p32(binsh_addr)
   ```
   Calls `system("/bin/sh")`.

**Common stack pivot gadgets:**

| Address | Gadget | Effect |
|---------|--------|--------|
| `0x08048e48` | `add esp, 0x1c; ret` | Skip 7 dwords into input |
| `0x0804a171` | `add esp, 0x10; pop; pop; pop; ret` | Skip 7 dwords |
| `0x0804997E` | `add esp, 0x1c; ret` (alternate) | Skip 7 dwords |
| `0x080498e8` | `add esp, 0x88; pop; pop; ret` | Large skip |
| `0x0804b36d` | `popal; ret` | Pop all registers from stack |
| `0x0804a5fe` | `add esp, 0x20; pop; pop; pop; ret` | Skip 8 dwords |

**Common ROP gadgets:**

| Address | Gadget |
|---------|--------|
| `0x08048939` | `pop ebx; ret` |
| `0x080499ef` | `pop esi; ret` |
| `0x080494da` | `pop ebx; pop esi; pop edi; ret` |
| `0x080491ba` | `pop ebx; pop esi; pop edi; pop ebp; ret` |
| `0x08048c58` | `leave; ret` |
| `0x080491bc` | `pop ebp; ret` |

---

### Path B — Format String Leak → One-Gadget Shell

**Used by:** exp.py (the repository's exploit)

1. **Set name** = `p32(0x08049C16)` (mid-function `do_bye` gadget).

2. **Send format string payload as `-33` input:**
   ```python
   fmt = b"-33|" + p32(PUTS_GOT) + p32(MAIN_LOOP) + b"%p%p%p%p" + b"MARK" + b"%s"
   ```
   - `strtol("-33|...")` → index -33 → calls the `do_bye` gadget
   - The gadget calls `__printf_chk(1, input_buffer)` — a format string
   - `%p%p%p%p` burns varargs 1–4, then `%s` dereferences `PUTS_GOT` → **libc leak**
   - `MAIN_LOOP` at input[8] serves as the return address for the gadget's `add esp; ret`

3. **Set name** = `p32(libc_base + one_gadget)`.

4. **Send `-33` with NUL-filled input** → calls `one_gadget` → shell.

**Advantage:** No multi-stage ROP needed, simpler payload. **Constraint:** Requires `[esp+0x2c]==NULL` for the one-gadget.

---

### Path C — Open/Read/Write Flag (No libc Needed)

**Used by:** Solutions 138, 174, 185, 1727, 16991

1. **Set name** = pivot gadget + `"/home/starbound/flag\0"`.

2. **ROP chain** uses only binary PLT stubs (no libc):
   ```python
   rop  = p32(open_plt)  + p32(pppr) + p32(flag_str_addr) + p32(0) + p32(0)
   rop += p32(read_plt)  + p32(pppr) + p32(3) + p32(bss_buf) + p32(0x100)
   rop += p32(write_plt) + p32(pppr) + p32(1) + p32(bss_buf) + p32(0x100)
   ```
   Opens the flag file, reads its contents to BSS, writes them to stdout.

**Advantage:** Deterministic — no libc leak needed, no ASLR dependency. Works on first try.

---

### Path D — Stack Pointer Leak → Computed Index → Direct Call

**Used by:** Solutions 1763, 18324, 10840

1. **Leak a stack address** by using a large negative index (e.g., `-3118` or the `puts@GOT` index) that causes output containing stack data.

2. **Compute the exact index** so the dispatch table lookup points into the **attacker's input on the stack**, which contains the target function address.

3. **Call directly** into the stack-placed payload (e.g., `system` address placed in the input).

**Variant (18324):** Leaks both stack and libc by sending oversized inputs with index `-10`. Then computes an index pointing into the input buffer itself, where `system` is placed, and appends `;/bin/sh\0` to the input (since the input doubles as both the `strtol` argument and the `system` argument).

---

### Path E — GOT Overwrite → `strtol` → `system`

**Used by:** Solution 1316

1. **Leak libc** via ROP (puts GOT entry).
2. **Use `read` to overwrite `strtol@GOT`** with `system`.
3. **Send `/bin/sh\0`** as the next menu input → `strtol("/bin/sh")` becomes `system("/bin/sh")`.

---

### Path F — Syscall ROP (No libc, No `system`)

**Used by:** Solution 1324

1. **Leak `read` address** from GOT. Compute `int 0x80` syscall gadget at `read + 0x1c`.
2. **Use `xchg eax, ebx` / `xchg eax, ecx` / `xchg eax, edx` gadgets** to set registers for `execve("/bin/sh", NULL, NULL)` (syscall number 11).
3. **Set name** to pivot + `"/bin/sh\0"`.
4. **Overwrite `exit@GOT`** with the `int 0x80` address via `read`, then call `exit@PLT` → triggers `execve`.

**Advantage:** Works without knowing libc version at all.

---

### Path G — `system(" -33;/bin/sh")` (Minimal)

**Used by:** Solution 18324 (easier variant)

1. **Set name** = `p32(puts_plt)`, index `-33` → leaks libc via `puts(input_buffer)`.
2. **Set name** = `p32(system)`.
3. **Send ` -33;/bin/sh\0`** — `strtol` parses `-33` (with leading space), dispatches to `system`, and `system` receives the full string ` -33;/bin/sh` which executes `/bin/sh` after the semicolon.

**Advantage:** Extremely elegant — the same input string serves as both the dispatch trigger AND the shell command.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Arbitrary function call | V1: name[0:4] via index -33 | Deterministic |
| Stack pivot into input | V1 + gadget in name | Deterministic |
| libc leak via puts/write ROP | Stack pivot + GOT read | Deterministic |
| libc leak via format string | V3: `do_bye` mid-function gadget | Deterministic |
| Stack address leak | V2: large negative index | Deterministic |
| ORW flag read (no libc) | ROP using only PLT stubs | Deterministic |
| Code execution | `system`/one-gadget/`execve` syscall | Deterministic |

## Offsets (Remote libc: Ubuntu GLIBC 2.23-0ubuntu10, i386)

```python
puts              = 0x5fca0
__libc_start_main = 0x18540
system            = 0x3ada0
read              = 0xd5980
"/bin/sh"         = 0x15b82b
one_gadget        = 0x3ac5e   # execve("/bin/sh", esp+0x2c, environ)
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `100.md` | A | Stack pivot → `puts` leak → `read` GOT overwrite → `system` | Two-stage ROP |
| `138.md` | C | Stack pivot → ORW flag read | Ruby; no libc needed |
| `174.md` | C | `add esp, 0x1c` pivot → open/read/write flag | Minimal, clean |
| `184.md` | A | `add esp, 0x28` pivot → leak `__libc_start_main` → `system` | Stack pivot to BSS via `leave;ret` |
| `185.md` | C | `popal;ret` pivot → open/read/write flag | Uses `popal` gadget |
| `1006.md` | A | Stack pivot → `puts` leak → re-enter main → `system` | Two-stage, sets `/bin/bash` in name |
| `1172.md` | A | `add esp, 0x1c` → `puts` leak → GOT overwrite `strtol` → `system` | |
| `1290.md` | A | `puts` leak → `read` GOT overwrite → `puts("/bin/sh")` as system | |
| `1297.md` | A | Uses `pop esi;ret` → `call esi` gadget chain | Unique calling convention approach |
| `1303.md` | E | `puts` leak → `read` overwrites `strtol@GOT` → `system` | GOT overwrite |
| `1316.md` | E | DynELF to resolve `system` → GOT overwrite | Most complex; uses DynELF |
| `1324.md` | F | Leak `read` → compute `int 0x80` → `execve` syscall ROP | No libc version needed |
| `1351.md` | A | `puts` leak → stack pivot to BSS via `leave;ret` → `system` | |
| `1395.md` | A | `write` leak → two-stage ROP → `system("/bin/sh")` | |
| `1727.md` | C | `add esp, 0x1c` pivot → ORW flag | Explicit flag path string in name |
| `1763.md` | D | Leak stack via `-3118` index → compute index → `system` | Stack address brute |
| `1803.md` | A | Ruby; `add esp, 0x88` pivot → `puts` leak → `system` | |
| `10840.md` | D | Leak stack → compute index into input → `system` | |
| `13019.md` | A | `add esp, 0x1c` pivot → `puts` leak → syscall `execve` | Uses `xchg` gadgets for registers |
| `14605.md` | A | `add esp, 0x1c` pivot → `puts` leak → `system` | Clean two-stage |
| `16991.md` | C | `popal;ret` → open/read/write flag | No libc needed |
| `17704.md` | A | ret2libc (tried ret2dlresolve first) | |
| `18324.md` | D+G | Leak stack+libc via `-10` → `system(" -33;/bin/sh")` | Elegant semicolon trick |
| `18331.md` | A | LibcSearcher → `puts` leak → `system` | |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit (Path B: format string leak → one-gadget) |
| `desc.txt` | Challenge description |
| `artifacts/starbound` | Original challenge binary (i386, stripped) |
| `solution/*.md` | Community write-ups (120 solutions) |
