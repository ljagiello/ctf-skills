---
tags:
  - out-of-bounds-write
  - alpha-shellcode
  - got-overwrite
platform: pwnable.tw
points: 300
arch: i386
libc: static
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A negative index in note selection allows writing an address into the GOT array, redirecting execution to printable alphanumeric shellcode stored on an executable heap."
proof-of-concept: no
---

# Death Note — pwnable.tw (300 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10201`
>
> "Write the shellcode on your Death Note."

## Challenge Overview

A simple note management binary (i386, no PIE, Partial RELRO, **NX nominally enabled but heap is executable** due to missing `PT_GNU_STACK` header → `READ_IMPLIES_EXEC` on the old remote kernel). The program lets the user add, show, and delete notes stored in a global array. Input content is filtered to only allow **printable ASCII** bytes (0x20–0x7e).

```
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled           # but heap is executable (READ_IMPLIES_EXEC)
  PIE:      No PIE
```

Binary is **not stripped**, named functions visible: `add_note`, `show_note`, `del_note`, `read_input`, `read_int`, `is_printable`, `menu`, `main`.

## Binary Reconstructed Logic

```c
// Global note array at 0x804a060
char *note[11];  // note[0]..note[10]

void add_note() {
    char buf[0x50];
    printf("Index :");
    int idx = read_int();
    if (idx > 10) { puts("Out of bound!!"); exit(0); }  // BUG: no lower bound check
    printf("Name :");
    read_input(buf, 0x50);
    if (!is_printable(buf)) { puts("It must be printable"); exit(-1); }
    note[idx] = strdup(buf);    // heap alloc, stores pointer at note[idx]
    puts("Done !");
}

void show_note() {
    printf("Index :");
    int idx = read_int();
    if (idx > 10) { puts("Out of bound!!"); exit(0); }  // BUG: no lower bound check
    if (note[idx])
        printf("Name : %s\n", note[idx]);
}

void del_note() {
    printf("Index :");
    int idx = read_int();
    if (idx > 10) { puts("Out of bound!!"); exit(0); }  // BUG: no lower bound check
    free(note[idx]);            // calls free@plt → jmp *free@got
    note[idx] = 0;
}

int is_printable(char *s) {
    for (int i = 0; i < strlen(s); i++)
        if (s[i] <= 0x1f || s[i] == 0x7f) return 0;
    return 1;
}
```

## Vulnerabilities

### V1 — Negative Index OOB Write/Read (Primary, Exploitable)

**Root Cause:** `add_note`, `show_note`, and `del_note` all check `if (idx > 10) exit(0)` but **never check `idx < 0`**. Since `idx` is a signed `int` and the array access is `note[idx]` (i.e., `*(note_base + idx*4)`), a negative index accesses memory **below** the `note` array — straight onto the GOT.

```asm
; add_note — the critical store
movl %edx, 0x804a060(,%eax,4)   ; note[idx] = strdup(buf)
; when idx = -19:  0x804a060 + (-19)*4 = 0x804a014 = free@got
```

**Key GOT Addresses vs. `note` base (0x804a060):**

| GOT Entry | Address | Index |
|-----------|---------|-------|
| `read@got` | `0x804a00c` | -21 |
| `printf@got` | `0x804a010` | -20 |
| `free@got` | `0x804a014` | **-19** |
| `strdup@got` | `0x804a018` | -18 |
| `__stack_chk_fail@got` | `0x804a01c` | -17 |
| `puts@got` | `0x804a020` | **-16** |
| `exit@got` | `0x804a024` | -15 |
| `strlen@got` | `0x804a028` | -14 |

**Impact:** Writing at a negative index overwrites a GOT entry with the heap pointer returned by `strdup()`. Since the heap is executable, the GOT entry now points to attacker-controlled shellcode on the heap.

### V2 — Negative Index OOB Read (Leak)

Using `show_note` with a negative index reads `note[idx]` from before the array — which includes the GOT. Since GOT entries contain resolved libc function pointers after first call, this leaks libc addresses.

```c
// show_note with idx = -21 reads note[-21] = read@got → leaks &read in libc
```

**Impact:** Leak libc base for computing `system()` address (used by some exploit variants).

### V3 — Printable-Only Filter Constraint

```c
int is_printable(char *s) {
    for (int i = 0; i < strlen(s); i++)
        if (s[i] <= 0x1f || s[i] == 0x7f) return 0;  // reject < 0x20 or == 0x7f
    return 1;
}
```

All shellcode bytes must be in range `[0x20, 0x7e]`. This means bytes like `\xcd\x80` (`int 0x80`), `\x31\xc0` (`xor eax,eax`), `\x89\xe3` (`mov ebx,esp`), and `\x0b` (`mov eax, 11`) are **forbidden**. Shellcode must be **printable/alphanumeric** or **self-modifying**.

## Key Data Structures

### Memory Layout (BSS)

```
0x804a000  GOT start
0x804a00c  read@got
0x804a010  printf@got
0x804a014  free@got          ← index -19
0x804a018  strdup@got        ← index -18
0x804a01c  __stack_chk_fail@got
0x804a020  puts@got          ← index -16
0x804a024  exit@got          ← index -15
0x804a028  strlen@got        ← index -14
...
0x804a060  note[0]           ← base (index 0)
0x804a064  note[1]
...
0x804a088  note[10]
```

## Exploit Paths

All solutions exploit V1 (negative index GOT overwrite). They differ in which GOT entry to overwrite, shellcode encoding strategy, and whether they need a leak.

---

### Path A — Overwrite `free@got` → Printable Shellcode (Most Common)

**Used by:** Solutions 184, 1236, 1303, 1351, 1395, 1715, 1780, 1803, 1852, 1922, 2121, 14032, 21260, 22696, exp.py

**Steps:**

1. **`add_note(-19, shellcode)`**: `strdup(shellcode)` copies the printable shellcode to a heap chunk `H` and writes `H` into `note[-19]` = `free@got`.

2. **`del_note(-19)`**: Calls `free(note[-19])` → `free@plt` → `jmp *free@got` = `jmp H`. The argument to `free()` is `H` itself, so **EAX = H** (the shellcode's own address on the heap), giving the shellcode a base register.

3. The shellcode uses self-modifying code to produce `int 0x80` (`\xcd\x80`) at runtime, since those bytes aren't printable.

**Shellcode Strategies for Printable `execve("/bin//sh")`:**

- **Self-patching XOR:** Use `push eax; pop esi` to get shellcode base address, then `xor word [esi+offset], cx` where `cx` is crafted so the XOR of a printable placeholder yields `\xcd\x80`. Example from exp.py:
  ```asm
  push eax ; pop esi          ; esi = shellcode base (H)
  ; ... build cx = 0xc18c via printable sub chain ...
  xor word [esi+0x4b], cx     ; patches placeholder 0x4141 → 0x80cd = int 0x80
  ```

- **Self-patching SUB:** Use `sub byte [eax+offset], dl` with printable `dl` values to subtract down to `\xcd` and `\x80`.

- **Stack pivot + push:** Pivot `esp` to the heap (since EAX = heap addr), push the `int 0x80` opcode bytes onto the heap via arithmetic, then execute them in-line.

- **`inc eax` × 11:** Build `eax = 0xb` (execve syscall) using 11 `inc eax` instructions (opcode `\x40`, printable).

**Register Setup for `execve`:**
```asm
; eax = 0xb (via inc eax * 11, or push 0x3b; pop eax; xor al, 0x30)
; ebx → "/bin//sh" (push 0x68732f2f; push 0x6e69622f; push esp; pop ebx)
; ecx = 0 (push edx; pop ecx, or inherited from caller)
; edx = 0 (inherited or push ecx; pop edx)
; int 0x80 (self-patched at runtime)
```

**Reliability:** 100% — no ASLR/randomness involved. Fixed addresses, deterministic.

---

### Path B — Overwrite `puts@got` → Shellcode

**Used by:** Solutions 184 (first script), 1251, 15134

**Steps:**

1. **`add_note(-16, shellcode)`**: Overwrites `puts@got` with heap shellcode pointer.

2. Any subsequent call to `puts()` (e.g., from menu printing or "Done!") jumps to shellcode.

**Variant — Two-stage shellcode:** Some solutions split the shellcode across two heap allocations (due to size constraints), with the first stage jumping to the second.

**Note:** The initial register state differs from Path A — EAX does not contain the shellcode address, so some solutions use different approaches (e.g., reading EAX from the stack via `pop` gadgets).

---

### Path C — Overwrite `strlen@got` → ROP/Stage2

**Used by:** Solutions 2239, 1006

**Steps:**

1. **`add_note(-14, shellcode_stub)`**: Overwrites `strlen@got`. Since `is_printable()` calls `strlen()` on user input, the next `add_note` call triggers the overwritten `strlen@got` with the user's input buffer on the stack.

2. The stub patches itself or pivots the stack to perform a second-stage `read_input()` call that reads unrestricted shellcode (no printable filter) into a known writable/executable address.

3. Jump to the second-stage shellcode → `execve("/bin/sh")`.

**Advantage:** Bypasses the printable filter entirely for the real shellcode — only the stub needs to be printable.

---

### Path D — Leak libc + Overwrite GOT → `system`

**Used by:** Solutions 1384, 1715 (variant)

**Steps:**

1. **Leak libc:** `show_note(-21)` reads `note[-21]` = `read@got` → prints resolved `read` address → compute libc base.

2. **Compute `system` address:** `libc_base + system_offset`.

3. **Check if `system` address is printable** (middle bytes). If not, retry or use a different approach.

4. **Overwrite `free@got` with printable shellcode** that patches the GOT entry of another function to `system`, then calls it with `"/bin/sh"` as argument.

**Variant — `__malloc_hook`:** Some solutions overwrite `__malloc_hook` via the negative index (requires computing the correct index from the BSS) and trigger `malloc` (via `strdup` in `add_note`).

---

### Path E — Alphanumeric Encoder Stub

**Used by:** Solutions 1395 (msfvenom), 15134

**Steps:**

1. Use `msfvenom -e x86/alpha_mixed BufferRegister=EDX` or a hand-crafted alphanumeric decoder stub.

2. The stub decodes an in-line encoded payload at runtime, producing arbitrary shellcode bytes.

3. Jump to decoded shellcode → `execve("/bin/sh")`.

**Example (msfvenom):**
```
echo '\x83\xC4\x30\xC3' | msfvenom -a x86 --platform linux -p - -e x86/alpha_mixed BufferRegister=EDX
```

## Shellcode Encoding Techniques Summary

| Technique | How `int 0x80` is Produced | Printable? | Size |
|-----------|---------------------------|------------|------|
| XOR self-patch | `xor word [esi+off], cx` where placeholder ⊕ cx = `\xcd\x80` | Yes | ~60-77 bytes |
| SUB self-patch | `sub byte [eax+off], dl` to decrement printable bytes down | Yes | ~50-70 bytes |
| Stack pivot + push | Pivot ESP to heap, push `\xcd\x80` as computed dword | Yes | ~60-80 bytes |
| `inc eax` × 11 | N/A for int 0x80; patches via XOR/SUB | Yes | ~40-60 bytes |
| msfvenom alpha_mixed | Full decoder stub | Alphanumeric | ~80+ bytes |
| Two-stage (read + jmp) | Second stage is unrestricted | Only stub | ~30 + unlimited |

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| GOT overwrite (write) | V1: negative index in add_note | Deterministic |
| GOT read (leak) | V2: negative index in show_note | Deterministic |
| Heap code execution | Missing PT_GNU_STACK → READ_IMPLIES_EXEC | Deterministic on remote |
| Printable shellcode | Self-modifying / encoded | Deterministic |
| Shell | `execve("/bin/sh")` via int 0x80 | Deterministic |

## Offsets

```python
# Binary addresses (no PIE)
note_base   = 0x0804a060
free_got    = 0x0804a014   # index -19
puts_got    = 0x0804a020   # index -16
strlen_got  = 0x0804a028   # index -14
read_got    = 0x0804a00c   # index -21

# Useful gadgets
pop_edi_pop_ebp_ret = 0x08048a8a
read_input          = 0x0804862b
```

## Solution Write-ups

| File | Primary Path | GOT Target | Shellcode Technique | Notes |
|------|-------------|------------|---------------------|-------|
| `184.md` | A/B | puts@got (-16) | Alphanumeric, two-stage with jno jump | Two chunks, sc1→sc2 |
| `196.md` | Custom | N/A | Heap spray + printable stub | 222 brute-force allocs |
| `1006.md` | C | strlen@got (-14) | Stub + ROP to read_input for stage2 | Bypasses printable filter |
| `1236.md` | A | free@got (-19) | XOR self-patch + `inc eax`×11 | Compact, direct |
| `1251.md` | A | puts@got (-16) | Alphanumeric (pwntools asm) | Self-modifying xor+xor |
| `1303.md` | A | free@got (-19) | Stack pivot to heap, push int 0x80 | Clever stack migration |
| `1351.md` | A | free@got (-19) | Stack pivot + xor ax sequences | Uses `push edi; pop esp` |
| `1384.md` | D | __malloc_hook | libc leak via show + heap shellcode | Uses negative show for leak |
| `1395.md` | E | free@got (-19) | msfvenom alpha_mixed encoder | One-liner shellcode |
| `1715.md` | A | free@got (-19) | XOR self-patch, sub chain for eax=0xb | Clean modular approach |
| `1780.md` | A | free@got (-19) | XOR + sub byte, `jno` for conditional flow | Stores /bin/sh in note[0] |
| `1803.md` | A | free@got (-19) | AND+SUB chains for `int 0x80` bytes | Ruby solver |
| `1852.md` | A | free@got (-19) | Stack pivot via `pop esp` | Pushes `int 0x80` onto heap |
| `1922.md` | A | free@got (-19) | XOR `[ebx+off]` self-patch | Patches 2 bytes via `al=0x80` |
| `1980.md` | A | puts@got (-16) | SUB byte chain for cd/80 | Stores /bin/sh separately |
| `2121.md` | A | free@got (-19) | XOR + dec ecx chain for self-patch | Uses `esi+ecx*2` addressing |
| `2239.md` | C | strlen@got (-14) | Stub → leak heap → ROP → read stage2 | Most complex, two stages |
| `10128.md` | A | free@got (-19) | DEC+XOR byte self-patch | Stores /bin/sh in note[0] |
| `14032.md` | A | free@got (-19) | XOR self-patch using `[eax+off]` | Compact, `\x61\x61` = `int 0x80` patch |
| `15134.md` | E | puts@got (-16) | Alphanumeric decoder (`sub` + `xor`) | Encodes each forbidden byte |
| `21260.md` | A | free@got (-19) | SUB chain: `sub [esi+off], eax` | Dual sub for `cd80` word |
| `22696.md` | A | free@got (-19) | Stack pivot + XOR ax chain | Includes NASM source |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script (printable self-patching execve shellcode) |
| `desc.txt` | Challenge description |
| `artifacts/death_note` | Original challenge binary (i386, not stripped) |
| `solution/*.md` | Community write-ups (141 solutions) |
