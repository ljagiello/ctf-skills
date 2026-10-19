---
tags:
  - use-after-free
  - race-condition
  - vtable-hijack
platform: pwnable.tw
points: 600
arch: x86-64
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A race condition between concurrent battle threads creates a use-after-free on Digimon objects, allowing virtual method table pointer overwrite."
proof-of-concept: no
---

# Digimon — pwnable.tw (600 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10501`
>
> Flag: `FLAG{You_have_conquered_the_world_of_digimon!}`

## Challenge Overview

A multithreaded Digimon "game" binary (x86-64, PIE, Partial RELRO, NX, Stack Canary) built against glibc 2.23. The player navigates a 20x20 map, encounters wild digimon, battles/befriends them, manages a partner roster, runs tasks via `pthread` workers, visits a shop, and can recruit a hidden boss (Toolmon). The game parses commands from stdin using `strtok`.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## Vulnerabilities

### V1 — `strtok` Overwrites Stack Variable (Primary, Exploitable)

**Root Cause:** The main loop reads commands into a `0x68`-byte stack buffer via `read_line(buf, 0x68)` which does **not** NUL-terminate when the buffer is fully filled. Adjacent on the stack is the `partner_index` variable used by the `task` command.

```c
// main_loop (simplified)
char command_buf[0x68];    // +0x00
// uint32_t partner_idx;   // +0x68  (immediately after buffer on stack)
// uint32_t task_type;     // +0x6c

memset(command_buf, 0, sizeof(command_buf));
read_line(command_buf, sizeof(command_buf));  // NO NUL terminator if full
strtok(command_buf, " ");                    // first token = command

if (!strncmp(command_buf, "task", 4)) {
    char *s1 = strtok(NULL, " ");   // partner index token
    arg1 = atoi(s1);                // parsed as partner index
    if (arg1 < num_partners && !partners[arg1].is_busy) {
        char *s2 = strtok(NULL, " ");  // <-- THIS strtok walks off buffer
        arg2 = atoi(s2);              //     and NUL-overwrites arg1
        add_task(arg1, arg2);          //     now arg1 == 0, not 32
    }
}
```

**Trigger:** Send `'task 32'.ljust(0x66, '_') + ' 3n   '` (0x6c bytes). The parsing flow:
1. `strtok` finds `"task"`, NUL-replaces the space → `"task\x0032..."`.
2. Second `strtok` finds `"32"` → `arg1 = 32`. Busy-check passes on partner 32.
3. Third `strtok` seeks past `arg1` on the stack, NUL-overwrites its low byte → `arg1` becomes **0**.
4. `add_task(0, task_type)` executes — tasks are appended to **partner 0** (which *is* busy), bypassing the busy check.

**Impact:** Unbounded writes to partner 0's `task_queue[4]` array, overflowing into the **next heap-allocated Partner struct** with bytes `\x01`, `\x02`, or `\x03` (the task type values).

```c
// enqueue_task — no bounds check on task_count
partner->task_queue[partner->task_count] = task;  // OOB write
partner->task_count++;
```

### V2 — Toolmon `scanf` Uninitialized Variable Leak (Exploitable)

**Root Cause:** The Toolmon menu uses `scanf("%u", &action)` / `scanf("%u", &amount)` / `scanf("%u %u", &x, &y)`. If the user inputs `"+"` or `"-"`, `scanf` fails without writing the variable, printing back **uninitialized stack data**.

```c
// talk_toolmon
scanf("%u", &action);
printf("%u is not available, sir:(\n", action);  // leaks stack garbage
```

**Impact:**
- **PIE base leak**: Input `"+"` for the action menu → leaks low 32 bits; then `"+"` for the "how much money" prompt → leaks high 32 bits. Combine to get a code pointer, subtract known offset → PIE base.
- **Stack cookie leak**: When Toolmon is adjacent to the shop NPC, the NPC-selection function places the canary on the stack where the Toolmon menu later reads uninitialized data. Input `"+ +"` for coordinates → leaks canary as `(low32, high32)`.

### V3 — Item Index OOB Read (Minor, Situational)

**Root Cause:** `use_item()` checks `item_id >= ITEM_COUNT` but the "you don't have any" error path in `show_bag`-style code uses the index to read from `g_item_names` without full validation.

```c
printf("You don't have any %s!\n", g_item_names[item_idx]);
// if item_idx is large, reads OOB from .rodata/.data/.bss
```

**Impact:** Arbitrary OOB read from the item names array. Can leak pointers from BSS/GOT if the indexed memory happens to be mapped (unreliable, ~1/0x2000 chance).

### V4 — `read_line` Missing NUL Terminator (Enabler)

```c
// read_line: reads up to max_len bytes, NO NUL termination
static uint32_t read_line(char *buf, uint32_t max_len) {
    // ... reads byte-by-byte, returns on '\n' or max_len
    // never appends '\0'
}
```

This is the root enabler for V1 — `strtok` walks past the buffer boundary because no NUL terminator marks the end of user input.

### V5 — `sprintf` Stack Buffer Overflow in Battle Status (Not Exploitable)

```c
static void print_battle_status(...) {
    char line_buf[24];
    sprintf(line_buf, "%.2lf / %.2lf", partner->hp, partner->max_hp);
    // Large trained stats can overflow the 24-byte buffer
}
```

**Impact:** Overflows the stack buffer, but the written bytes are floating-point digits — cannot control them to bypass the stack canary.

### V6 — Race Condition in Evolve (Not Exploitable)

Training via task thread and using Philosopher's Stone item simultaneously can trigger a double evolve, setting `stage > 3`. This causes an OOB read on the image pointer array, which crashes the program.

### V7 — Toolmon "Die for me" Stale Index (Not Exploitable)

Killing Toolmon via "Die for me" uses `memmove` to compact the partner array but doesn't update `g_active_partner_index`. The resulting OOB index doesn't point to anything useful.

### V8 — Task Thread Stack Overflow via `strncat` (Exploitable, Impractical)

```c
// task_worker
char notification_buf[1024];
strncat(notification_buf, line_buf, 0x100);  // repeated per task
```

If `task_count` is corrupted (via V1) to a large value, the thread processes hundreds of tasks, each `strncat`-ing ~256 bytes into a 1024-byte stack buffer → stack buffer overflow in the worker thread. However, this requires leaking the canary first and waiting for all tasks to finish (potentially hours).

## Key Data Structures

### Partner Struct (0xa0 bytes)

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `name` | `char[24]` (inline, from species DB) |
| `0x18` | `species_id` | `uint16_t` |
| `0x1a` | `stage` | `uint8_t` (0=Rookie, 3=Mega) |
| `0x1b` | `charge_count` | `uint8_t` |
| `0x20` | `speed` | `uint32_t` |
| `0x24` | `luck` | `uint32_t` |
| `0x28` | `max_hp` | `double` |
| `0x30` | `hp` | `double` |
| `0x38` | `atk` | `double` |
| `0x40` | `potential` | `double` |
| `0x50` | `notification` | `char *` (realloc'd) |
| `0x58` | **`nickname`** | `char *` (malloc(0x80)) |
| `0x60` | `pending_money` | `uint32_t` |
| `0x64` | `away` (busy flag) | `uint8_t` |
| `0x68` | `mutex` | `pthread_mutex_t` |
| `0x90` | `task_thread` | `pthread_t *` (malloc(8)) |
| `0x98` | `task_count` | `uint32_t` |
| `0x9c` | `task_queue` | `uint8_t[4]` ← overflow starts here |

## Exploit Paths

All known solutions share the same core bug (V1: strtok overflow). They diverge on the leak strategy and the write-what-where target.

---

### Path A — Heap Overflow → Nickname Pointer Corruption → Arbitrary R/W → `__free_hook`/`__malloc_hook`

**Used by:** Solutions 370 (exp.py), 821, 2311, 3148, 3498, 7905, 8153, 15989, 31599, 34817

**Prerequisites:**
- 33 partners (to have partner index 32 = ASCII space, needed for the strtok trick)
- Naming Document purchased (to use the `nick` command)

**Steps:**

1. **Game Grind:** Befriend enough digimon, train to level up the world, collect 33 partners total (including Toolmon).

2. **Trigger Heap Overflow (V1):** Send `'task 32'.ljust(0x66, '_') + ' 3'` repeatedly. Each iteration appends one byte (`\x01`, `\x02`, or `\x03`) past partner 0's `task_queue[4]`, overflowing into the adjacent Partner struct (partner 1).

3. **Corrupt Partner 1's Nickname Pointer:** The overflow writes `\x01`/`\x02`/`\x03` bytes through partner 1's `name[24]` field (leaking a heap pointer since the name is read back by `mons`) and eventually corrupts the **low byte of `partner[1].nickname`** (at offset `+0x58`).

4. **Achieve Overlap:** If the corrupted nickname pointer's low byte aligns to point into another Partner struct, writing to partner 1's nickname now writes into that struct's fields. This gives control over another partner's `notification` and `nickname` pointers → **arbitrary read/write**.

5. **Leak Chain:**
   - **Heap:** Read partner 1's overflowed name to get the original nickname pointer value.
   - **libc:** Point the fake nickname at a known heap offset containing a `pthread_t` address (mmap region), or at a GOT entry (if PIE base is known), or use the notification-free trick to get a freed chunk's fd pointer into an unsorted bin → libc main_arena.
   - **Stack (optional):** Read `__environ` from libc to get a stack address.

6. **Hijack Control Flow:**
   - **`__free_hook` = `system`**: Write `system` to `__free_hook`, then set a partner's nickname to `"/bin/sh"` and free it (e.g., kill Toolmon via "Die for me" which calls `free(toolmon->nickname)` then `free(toolmon)`).
   - **`__malloc_hook` = one_gadget**: Write a one-gadget to `__malloc_hook`, then trigger `malloc` (e.g., `nick <new_partner>` allocates 0x80 bytes).
   - **ROP on stack**: Write a ROP chain (`pop rdi; ret; "/bin/sh"; system`) to the return address of `nick()` on the main thread's stack.

**Reliability:** ~50% per connection due to heap layout randomness (nickname low-byte alignment must land in another Partner struct). Most solvers retry in a loop.

---

### Path B — Heap Overflow + Toolmon `scanf` Leak → PIE/Canary → `__free_hook`

**Used by:** Solutions 370 (second script), 2311, 9251

This variant uses V2 (Toolmon scanf leak) in addition to V1:

1. **Leak PIE base** via Toolmon's `scanf` failure: input `"+"` as the action → prints uninitialized low-32 stack value; input `"+"` as amount → prints high-32 bits. Combine and subtract offset → PIE base.

2. **Leak stack canary** (optional): Talk to Toolmon when adjacent to shop → NPC selection function leaves canary on stack → Toolmon's `scanf("%u %u", &x, &y)` with `"+ +"` prints it as coordinates.

3. **With PIE base known**, directly point the corrupted nickname at a GOT entry to leak libc without the heap-scanning egg hunt.

4. **Same finish** as Path A: `__free_hook = system` + free a `"/bin/sh"` nickname.

---

### Path C — Heap Overflow + Task Thread Stack BOF

**Used by:** Solution 2311 (noted as primary path)

1. **Trigger V1** to corrupt partner 0's `task_count` to a large value.
2. **Increase partner 0's potential** massively (buy and use many Potential Arousers) so that each training task's HP gain string is long enough (~133 chars) to overflow `notification_buf[1024]` in the task thread via `strncat`.
3. **Leak canary** via V2 (Toolmon scanf).
4. **Write ROP payload** into partner 0's nickname buffer. When the thread's `notification_buf` overflows, it overwrites the thread's stack frame. The nickname content (which contains the ROP chain) ends up overwriting the return address.
5. **Restore canary null byte** by shortening the nickname.
6. **Wait ~1 hour** for all queued tasks to complete and the thread to return → ROP fires → shell.

**Downside:** Extremely slow (~3500 seconds wait). The author notes this is impractical compared to Path A.

---

### Path D — Item OOB Read (V3) + Heap Overflow

**Used by:** Solution 2311 (alternative mentioned), 15989 (commented out code)

1. **Leak a code/heap pointer** via `item <large_index>` which reads OOB from `g_item_names`. Only works if the target memory is mapped (~1/0x2000).
2. **Proceed with Path A** using the leaked pointer to skip the heap egg-hunt phase.

**Downside:** Very unreliable due to the mapping requirement.

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Heap overflow (byte values 1-3) | V1: strtok + task queue OOB | Deterministic |
| Nickname pointer corruption | V1 overflow reaching `+0x58` | ~50% alignment |
| PIE base leak | V2: Toolmon scanf | Deterministic (once Toolmon acquired) |
| Stack canary leak | V2: Toolmon scanf + NPC adjacency | Deterministic |
| Arbitrary R/W | Corrupted nickname → overlapping struct | After successful alignment |
| GOT/libc leak | Arbitrary read on GOT or heap pointers | Deterministic after arb R/W |
| Code execution | `__free_hook`/`__malloc_hook` or stack ROP | Deterministic after arb R/W |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
environ     = 0x3c5f38
system      = 0x45390
__free_hook = 0x3c57a8
__malloc_hook = 0x3c3b10
bin_sh      = 0x18c177
pop_rdi     = 0x21102   # pop rdi; ret
one_gadgets = [0x4526a, 0xef6c4, 0xf0567]
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | A + B | strtok → heap egg-hunt → stack ROP | Two full scripts; detailed writeup |
| `821.md` | A + B | strtok → `__free_hook` | PIE leak via scanf, canary leak, massive game automation |
| `2311.md` | A (+ C) | strtok → heap overlap → `__malloc_hook` | Most detailed bug analysis; also describes thread BOF path |
| `3148.md` | A + B | strtok → `__free_hook` | Concise; PIE leak via scanf; overwrite free_hook → system |
| `3498.md` | A | strtok → heap overlap → `__free_hook` | Detailed data structure analysis; heap spray + brute N |
| `7905.md` | A | strtok → heap overlap → `__malloc_hook` | Methodical; nickname all partners to control heap layout |
| `8153.md` | A + B | strtok → `__free_hook` | PIE base leak via scanf; libc leak via GOT |
| `9251.md` | A + B | strtok → `__malloc_hook` (+ thread BOF) | Documents thread BOF path (1hr wait); leaks via image cache + pthread |
| `15989.md` | A | strtok → heap scan → libc leak → `__free_hook` | Simple approach; scans heap for libc pointer |
| `31599.md` | A + B | strtok → arb R/W → `__malloc_hook` | Extensive game automation with digimon tracking |
| `34817.md` | A | strtok → heap overlap → libc leak → `__malloc_hook` | Clean code; uses one_gadget |

## Files

| File | Description |
|------|-------------|
| `digimon.c` | Reconstructed C source (logic-equivalent, from Ghidra) |
| `exp.py` | Working exploit script |
| `desc.txt` | Challenge description |
| `artifacts/digimon.tar.gz` | Original challenge binary |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `solution/*.md` | Community write-ups (11 solutions) |
