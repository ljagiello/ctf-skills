---
tags:
  - type-confusion
  - out-of-bounds-write
  - got-overwrite
platform: pwnable.tw
points: 600
arch: x86-64
libc: glibc-2.23
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "Coordinate encoding confusion on the Go board permits out-of-bounds array indexing, enabling arbitrary GOT overwrite to hijack program execution."
proof-of-concept: no
---

# OmegaGo — pwnable.tw (600 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10405`
>
> Flag: `FLAG{now_you_can_try_to_fight_with_AlphaGo~}`

## Challenge Overview

A simplified Go game (19x19 board) binary (x86-64, No PIE, Partial RELRO, NX, No Canary) linked against glibc 2.23. The player plays black stones (`X`) against an AI opponent (`O`). The game supports commands: coordinate moves (e.g. `D19`), `regret` (undo last move pair), and `surrender`. The board state is stored as a 2-bit-per-cell bitmap in BSS, and a **history array** records pointers to heap-allocated board snapshots for each move.

```
file ./omegago
  ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

checksec:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
```

## Key Data Structures

### Board Bitmap (BSS `g_cur_state`, ~0x609FC0)

The 19x19 board is encoded as a 2-bit-per-cell bitmap (12 qwords):

| 2-bit value | Display | Meaning |
|-------------|---------|---------|
| `0b00` | `.` | Empty |
| `0b01` | `O` | White (AI) |
| `0b10` | `X` | Black (Player) |
| `0b11` | `\x00` | (Invalid/leak marker) |

Each qword encodes 32 cells. The board is 361 cells = 11.28 qwords, stored as 12 qwords (the last partially used).

### History Array (BSS `g_history`, ~0x609460)

A fixed-size array of pointers to heap-allocated board snapshots. Each move (player + AI response = 2 entries) pushes a new snapshot pointer. The array has capacity for **364 entries** (182 move pairs), but there is **no bounds check**.

### AI Player Object (Heap, 0x10 bytes)

The AI player is a C++ object allocated via `new` (fastbin 0x20 chunk). Its first field is a **vtable pointer**. When the AI makes a move, a virtual function is called through this vtable.

### Input Buffer (BSS `g_input`, 0x60943C)

The player's coordinate input is read via `scanf("%10s", g_input)` into a fixed BSS buffer at `0x60943C`. The effective usable address (after the 4-byte coordinate prefix) is `0x609440`.

## Vulnerabilities

### V1 — History Array Overflow (Primary, Exploitable)

**Root Cause:** The history array at `g_history` (~0x609460) has space for 364 pointers, but the code never checks the index against this limit. By exploiting Go's **ko rule** (repeated capture cycles), a player can generate far more than 182 move pairs in a single game, causing the history pointer writes to overflow past the array into the adjacent **`g_cur_state` board bitmap**.

```
BSS layout:
  0x609460: g_history[0..363]    (364 × 8 = 0xB60 bytes)
  0x609FC0: g_cur_state          (board bitmap, 12 qwords)
```

When `history_count > 364`, new history entries overwrite `g_cur_state.bitmap[0]`, `bitmap[1]`, etc. Since history entries are **heap pointers**, the board bitmap now contains heap addresses that can be **read back** by viewing the board.

**Impact:**
- **Heap pointer leak**: The overwritten bitmap cells display as board characters, which can be decoded back to the 2-bit representation and reassembled into the original pointer value.
- **Controlled pointer manipulation**: A single additional move changes the pointer by a predictable delta (e.g., +0x80 per move). Combined with `regret`, this creates an arbitrary-address-read primitive.

### V2 — Regret Dereferences Corrupted History Pointer (Exploitable)

**Root Cause:** The `regret` command undoes the last move by loading the board from `g_history[last]`. If the history has overflowed and `g_history[last]` now points to an attacker-controlled address (via V1), `regret` loads arbitrary heap/memory contents into the displayed board.

```
regret flow:
  1. Remove last 2 history entries
  2. Copy board from g_history[new_last] into g_cur_state
  3. Display the new board to the player
```

**Impact:** By first modifying the overflowed pointer (via one more move that shifts it by a known offset) and then calling `regret`, the player can **read arbitrary memory** — the board displays the memory at the pointer's target as 2-bit-encoded cells.

### V3 — Fake Fastbin via Board State (House of Spirit)

**Root Cause:** The board state is stored on the heap (as part of history snapshots). Since the player controls which cells are `X` (0b10), `O` (0b01), or `.` (0b00), they can encode arbitrary 2-bit patterns into the board. Crucially, a board state containing `..X.....` at the right offset encodes the value `0x20` — a valid fastbin chunk size header.

By encoding two `0x21` size fields at appropriate qword offsets in the board and then arranging for `surrender` to free a pointer that lands in this region, the player creates a **fake fastbin chunk** on the heap.

**Impact:** The next `new` allocation for an AI Player object (size 0x10, fastbin 0x20) returns the fake chunk, which overlaps with a board state the player can later overwrite.

### V4 — Input Buffer as Vtable (Code Execution)

**Root Cause:** The BSS input buffer `g_input` at `0x609440` (No PIE, fixed address) can hold attacker-controlled data from `scanf`. If the AI Player object's vtable pointer is overwritten to point to `0x609440`, the next virtual call dereferences `*(0x609440)` as a function pointer.

**Impact:** By encoding `0x609440` into the board bitmap (using specific stone placements that produce this value in 2-bit encoding), and having the overflow reach the AI object's vtable field, the player controls the virtual function pointer. Sending a move like `"D1\x00\x00" + p64(one_gadget)` places a one_gadget address at `0x609440`, and the next AI virtual call jumps to it → shell.

## Exploit Paths

### Path A — History Overflow → Leak → House of Spirit → Vtable Hijack (Most Common)

**Used by:** Solutions 59, 821, 2121, 5586, 6247, 6748, 8153, 11954, 14523, 22319, 34817

**Steps:**

1. **Heap Alignment:** Surrender 1-2 times to align the heap layout so that history pointers have favorable low bytes (no `0b11` pairs, which cannot be represented on the board).

2. **Overflow History for Leaks:**
   - Fill the board using ko-rule cycles (alternating captures at fixed positions) to generate ~365+ history entries.
   - When history[364] overwrites `g_cur_state.bitmap[0]`, a **heap pointer** appears on the board → **heap leak**.
   - Make one more move (e.g., `D19`) to shift the pointer by `+0x80`.
   - Call `regret` → the board is now loaded from `*(shifted_pointer)`, which points to a region containing a **libc address** (e.g., `main_arena` or `_IO_wfile_jumps`) → **libc leak**.

3. **Create Fake Fastbin Chunk:**
   - Surrender and restart. Surrender 4-6 more times to align the heap.
   - In a new game, place stones to encode `0x21` size fields at two qword-aligned positions in the board (e.g., `R8` → encodes 0x20 at the right bit position; `D12` → second size field).
   - Overflow history again, using the overflow to make a history pointer point to the fake chunk region.
   - Surrender → the fake chunk is freed into fastbin(0x20).

4. **Allocate AI Object in Fake Chunk:**
   - Start a new game. The AI Player `new` call allocates from fastbin(0x20), landing in the previously freed fake chunk.
   - This fake chunk lies within a board state bitmap that the player will later overwrite.

5. **Overwrite Vtable:**
   - Place stones to encode `0x609440` (the BSS input buffer address) at the qword offset that overlaps the AI object's vtable field.
   - Fill the board to trigger the overflow, positioning the encoded address over the vtable.

6. **Trigger One-Gadget:**
   - Send a move command with appended binary data: `"F8\x00\x00" + p64(one_gadget)` or similar. The coordinate part is parsed as a move, while the trailing bytes write the one_gadget address into the input buffer at `0x609440`.
   - The AI's next virtual call dereferences `g_input` → `one_gadget` → shell.

**Reliability:** ~50-80% per attempt. Fails when heap addresses contain `0b11` bit-pairs (unrepresentable on the board). Most solutions retry in a loop.

---

### Path B — History Overflow → stdin Buffer Manipulation → Vtable Hijack

**Used by:** Solution 2311

**Variation:** Instead of encoding addresses on the board, this approach manipulates the **stdin buffer** on the heap. By sending long padded input during `surrender` prompts (e.g., `"surrender\0".rjust(0x2e0, '\n')`), the solver writes controlled data deep into the stdin buffer. This buffer lives on the heap at a predictable offset from the heap base.

1. Overflow history to leak heap and set up a pointer to the stdin buffer region.
2. Write fake chunk headers (`0x31` size) into the stdin buffer via padded `surrender`/`regret` commands.
3. Free the fake chunk by arranging the history overflow pointer to target it.
4. The AI object is allocated in the stdin buffer. Overwrite the vtable via further stdin writes.
5. Use `setcontext+87` gadget for a more reliable `execve("/bin/sh")` instead of one_gadget.

---

### Path C — History Overflow → House of Orange

**Used by:** Solution 26957

**Variation:** Instead of fastbin manipulation, this approach uses the **House of Orange** technique:

1. Leak heap and libc via history overflow + regret (same as Path A).
2. Write a fake `0x1a1`-sized chunk header into the stdin buffer via padded commands.
3. Free the fake chunk into the unsorted bin (it's too large for fastbin).
4. Corrupt the unsorted bin to perform an unsorted bin attack, overwriting `_IO_list_all`.
5. Forge a fake `_IO_FILE` struct with a vtable pointing to `system`, triggered on the next `malloc` error path.

---

### Path D — Ko Cycles + Fill Strategy (Mirror Go Variant)

**Used by:** Solutions 59, 8153

**Variation:** These solutions use a **"mirror Go"** strategy to efficiently fill the board. By playing at symmetric positions, the AI's responses are predictable (it mirrors the player). This avoids the need for complex ko setups and reliably generates the required number of moves to overflow.

Pre-computed move sequences are stored in external files (`mirror1`, `super_mirror`, `super_mirror2`) and replayed to achieve exact control over the board state and overflow count.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| History array overflow | V1: No bounds check on history index | Deterministic |
| Heap pointer leak | V1: Overflowed pointer displayed as board | Deterministic |
| libc leak | V1+V2: Regret loads arbitrary memory to board | Deterministic |
| Fake fastbin chunk | V3: Board bitmap encodes 0x21 chunk header | Deterministic |
| Vtable hijack | V4: AI object allocated in controlled region | After successful alignment |
| Code execution | One-gadget/setcontext via vtable call | Deterministic after vtable control |

## Encoding Constraint

The board can only represent 2-bit values 0, 1, 2 per cell. Value 3 (`0b11`) displays as `\x00` and **cannot be placed by the player** (only `X`=2 or `O`=1 via AI mirror). This means any address or value to be encoded on the board must not contain any `0b11` pairs in its 2-bit decomposition. This is the primary source of exploit unreliability — if the heap base has such pairs, the attempt must be retried.

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
# BSS addresses (No PIE)
g_input       = 0x60943C   # scanf input buffer
g_input_plus4 = 0x609440   # usable vtable target
g_history     = 0x609460   # history array start
g_cur_state   = 0x609FC0   # board bitmap start

# libc offsets
main_arena+88 = 0x3c3b78   # unsorted bin leak marker
one_gadgets   = [0xf0567, 0xf1247, 0x4527a]
system        = 0x45390
setcontext+87 = ...         # for setcontext-based exploits
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `59.md` | A (mirror) | Mirror Go + fake fastbin + vtable | Uses external move files; detailed game strategy |
| `821.md` | A | Ko overflow + regret leak + fastbin | Clean writeup with encoding helpers |
| `2121.md` | A | Fill board + leak + fastbin | Concise; direct fill approach |
| `2311.md` | B | stdin buffer manipulation + setcontext | Alternative to board encoding; also has one_gadget variant |
| `2972.md` | A | Ko + regret + fake chunk | Detailed bug description |
| `5586.md` | A | Fill + regret + House of Spirit | Two exploit scripts (one_gadget + setcontext variants) |
| `6247.md` | A | Fill rows + encode address | Simple and clean implementation |
| `6748.md` | A | Ko-based overflow with Pos class | Well-structured OOP approach |
| `8153.md` | A (mirror) | Mirror Go automation | Extensive oracle/mirror strategy; very long exploit |
| `11954.md` | A | Direct fill + stdin padding | Uses stdin buffer for fake chunk headers |
| `14523.md` | A | Ko cycles + encode | Direct implementation |
| `22319.md` | A | Fill + overflow + vtable | Clear step-by-step with comments |
| `26957.md` | C | House of Orange | Uses unsorted bin attack + fake _IO_FILE |
| `34817.md` | A | Ko + fill + vtable | Clean final exploit with DECODE helper |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Working exploit script |
| `desc.txt` | Challenge description |
| `flag.txt` | Captured flag |
| `artifacts/omegago` | Challenge binary (stripped ELF x86-64) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (14 solutions) |
