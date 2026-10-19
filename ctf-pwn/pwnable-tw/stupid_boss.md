---
tags:
  - use-after-free
  - type-confusion
  - got-overwrite
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "A use-after-free vulnerability in employee class structures allows corrupting function pointers to hijack execution flow to system."
proof-of-concept: no
---

# Stupid Boss — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10409`
>
> Flag: `FLAG{My_5+up1d_B0s5es_ar3_s0_dumb_th3y_Thlnk_J4v4_&_J4v45cripT_4r3_th3_s4m3}`

## Challenge Overview

A C++11 "programmer RPG" binary (x86-64, PIE, Full RELRO, NX, Canary) built against glibc 2.23. The player fights slimes in a rock-paper-scissors-like game to gain per-language EXP. When skill thresholds are met, the "stupid bosses" assign two projects (Trojan and Web), each containing two `Language*` slots that can be viewed and changed. The source (`stupid.cpp`) is provided.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## Key Data Structures

### Language Subclass Layout (all subclasses, 64 bytes)

| Offset | Field | Notes |
|--------|-------|-------|
| `0x00` | `vptr` | Virtual table pointer (`info()` is virtual) |
| `0x08` | `LANG lang` | Enum value |
| `0x10` | `std::string name` | 32 bytes (SSO) |
| `0x30` | `unsigned long ratio` | Printed exactly by `basic_info()` as `"Ratio: <ratio> %"` |
| `0x38` | `version` | **`char*`** for `L_C` / `L_Javascript`; **`double`** for `L_Python` / `L_Java` / `L_Ruby` |

`info()` is virtual (dispatched via vptr); `set_version()` is **not virtual** (dispatched by the static type in `set_lang()`).

### Projects

- **Trojan**: languages ASM, C, Python (Python unlocked at 500 skill)
- **Web**: languages Ruby, Java, Javascript (Javascript unlocked at 500 skill)

## Vulnerabilities

### V1 — Type Confusion via `compatible()` (Primary, Exploitable)

**Root Cause:** `change_language()` decides whether to *edit in place* or *replace* based on `compatible()`. When "compatible", `set_lang()` uses `reinterpret_cast` to call the **new type's** non-virtual `set_version()` on the **old object** — without changing the vptr or the memory layout.

```cpp
if (compatible(new_lang, lang_list[i]->get_lang())) {
    lang_list[i]->set_ratio(r);
    set_lang(&lang_list[i], new_lang, r, /*just_edit=*/true);  // reinterpret_cast!
} else {
    delete lang_list[i];
    set_lang(&lang_list[i], new_lang, r, /*just_edit=*/false); // new object
}
```

The two buggy `compatible()` implementations:

```cpp
// Web::compatible — "I hate my stupid Boss A" — SUBSTRING test
bool Web::compatible(LANG l1, LANG l2) {
    return strstr(LANG_NAME[l2].c_str(), LANG_NAME[l1].c_str());
}
// "Java" is a substring of "Javascript" => treating L_Javascript as L_Java is "compatible"

// Trojan::compatible — "Stupid Boss B thinks C and Python are pretty similar"
bool Trojan::compatible(LANG l1, LANG l2) {
    ...
    if (big == "Python" && small == "C") return true;
    ...
}
// C <-> Python confusion is explicitly allowed
```

**Impact — Arbitrary Read (Trojan: C ↔ Python):**
1. Start with an `L_C` object (has `char* version` at offset `0x38`).
2. "Change" to Python (compatible) → calls `L_Python::set_version()` = `scanf("%lf", &version)` → writes a `double` (8 bytes, encoding the target address) over the `char*`.
3. The vptr is still `L_C`'s → `L_C::info()` does `cout << "C standard version: " << (char*)version` → **prints the string at an arbitrary address**.

```python
# Encode address as double, read back as C string
addr_as_double = struct.unpack('<d', p64(target_addr))[0]
set_python(ratio, repr(addr_as_double))
show()  # "C standard version: <bytes at target_addr>"
```

**Impact — Arbitrary Write (Web: Javascript ↔ Java):**
1. Start with an `L_Javascript` object (has `char* version` at offset `0x38`).
2. "Change" to Java (compatible because `"Java" ⊂ "Javascript"`) → calls `L_Java::set_version()` = `scanf("%lf", &version)` → overwrites `char*` with target address encoded as double.
3. "Change" back to Javascript → calls `L_Javascript::set_version()` = `read(0, version, 20)` → **writes 20 bytes to the arbitrary address**.

### V2 — `scanf` Uninitialized Variable Leak (Exploitable)

**Root Cause:** `create()` and `change_language()` read the ratio with `scanf("%lu", &r)`. If the input is non-numeric (e.g., `"+"`, `"-"`, `".5"`), `scanf` fails without writing `r`, leaving it **uninitialized**. The stale stack value becomes the object's `ratio` and is later printed exactly by `basic_info()`.

```cpp
unsigned long r;          // uninitialized
scanf("%lu", &r);         // "+" → conversion fails → r untouched
set_lang(&lang_list[i], lang, r, false);  // r = stale stack pointer
// Later: basic_info() prints "Ratio: <stale_value> %"
```

**Impact:** During `create()` (called from deep in the call stack: `main → fight_slime → boss → make_web → create`), the uninitialized `r` holds a **stale stack pointer**. This exact pointer is printed as a decimal integer, giving a precise stack address leak with no uncertainty.

### V3 — `read()` Non-Crash on Invalid Address (Minor, Enabler)

**Root Cause:** `L_Javascript::set_version()` uses `read(0, version, 20)`. If `version` points to an unmapped address, `read()` returns `-1` (EFAULT) but does **not** crash the process. The input remains unconsumed in the stdin buffer.

**Impact:** Used as an **address oracle** — send a probe payload and check if the input was consumed or remained (indicating invalid vs. valid address). This enables heap base brute-forcing when the `scanf` leak (V2) is not used.

### V4 — Predictable RNG for Slime Battles (Enabler)

**Root Cause:** Minion slimes use `srand(0x44444444 + 4444 * k)` with a deterministic static seed. King slimes use `srand(time(NULL))`.

```cpp
// SlimeMinion::genNum()
static int seed = 0x44444444;
seed += 4444;
srand(seed);
for (int i = 0; i < 5; i++) number[i] = rand() % 5;

// SlimeKing::fight()
srand(time(NULL));
number = rand() % 5;
```

**Impact:** By replicating glibc's `rand()` (via `ctypes.CDLL`), all slime numbers can be predicted and won deterministically, automating the grind to reach 500 EXP in 4 languages (~15-30 fights).

## Exploit Paths

### Path A — `scanf` Stack Leak → Type Confusion Read/Write → `__free_hook = system` (Most Common)

**Used by:** Solutions 370, 821, 2311, 3148, 7905, 22319, 5586, 6748, 18331, and the provided `exp.py`

1. **Grind:** Predict RNG, win fights until both Trojan and Web projects are created. During `create()`, feed `"+"` / `"-"` for the ratio → V2 leaks a stack pointer.

2. **Leak stack pointer:** `show_info()` on the project prints the leaked stack address as `"Ratio: <decimal> %"`.

3. **Arbitrary read (Trojan):** Set up `L_C` in slot, then "change" to Python with `version = addr_as_double` → read the C string at the target address via `show_info()`.
   - Read a **PIE pointer** from the leaked stack area (typically `binary_base + 0x20d048`).
   - Read a **libc pointer** from the binary's GOT or BSS (e.g., `GOT[read]`, `GOT[scanf]`, or `stdin`).

4. **Arbitrary write (Web):** Set up `L_Javascript` in slot, then "change" to Java with `version = addr_as_double` → overwrite the `char*`. Then "change" back to Javascript → `read(0, version, 20)` writes 20 bytes to the target address.

5. **Get shell:** Write `system` to `__free_hook`. Place `"/bin/sh\0"` at a known writable address. Trigger `free("/bin/sh")` by switching a Javascript slot to an incompatible language (Ruby), causing `delete` → `~L_Javascript()` → `free(version)` → `system("/bin/sh")`.

   The `~L_Javascript` destructor calls `memset(version, 0, malloc_usable_size(version))` before `delete[] version`. To prevent `/bin/sh` from being zeroed, the fake chunk is crafted so `malloc_usable_size()` returns 0 (next chunk's `PREV_INUSE` bit = 0).

**Reliability:** ~95%+ per connection (only fails if the leaked stack value is unusual).

---

### Path B — `scanf` Leak → Type Confusion → One-Gadget via `__malloc_hook` / `__realloc_hook`

**Used by:** Solutions 821, 6748, 34817

Same leak chain as Path A, but instead of `__free_hook + system`, writes a `one_gadget` address to `__malloc_hook` (or the `__realloc_hook` + `realloc` trampoline trick for stack alignment). Triggered by any subsequent `new` / `malloc` call.

**Caveat:** `one_gadget` constraints (`[rsp+X]==NULL`, `rax==NULL`) are often not satisfied at C++ `new`/`delete` call sites. Several solutions report needing to carefully choose the trigger point or use the `realloc` trampoline.

---

### Path C — `scanf` Leak → Type Confusion → Stack ROP

**Used by:** Solutions 2311, 18331

1. Leak stack + libc as in Path A.
2. Read `__environ` from libc to get an exact stack frame pointer.
3. Use the arbitrary write to plant a ROP chain (`pop rdi; ret; "/bin/sh"; system`) at the return address of `manage_project()` or another function.
4. Return from the function → ROP fires → shell.

---

### Path D — `stdout` Vtable Hijack (FSOP)

**Used by:** Solution 9251

1. Leak PIE base and libc via type confusion read.
2. Write a `one_gadget` into the `stdout` vtable's `__xsputn` slot.
3. Any subsequent `cout <<` triggers the corrupted vtable → shell.

**Note:** Only works on glibc 2.23 (no vtable validation).

---

### Path E — Heap Brute-Force (No `scanf` Leak)

**Used by:** Solutions 8153, 9251, 564 (before discovering V2), 1351

Some solvers didn't discover the `scanf` uninitialized variable trick. Instead:
1. Leak ~16 bits of a heap address via Python→C confusion (printing `double` loses precision for pointer values, but reveals the high bits).
2. **Brute-force the remaining bits** using V3 (the `read()` oracle): test candidate addresses by pointing `L_Javascript::version` at them and checking if `read()` succeeds or fails.
3. Once heap base is found, scan heap for vtable pointers → PIE base → GOT → libc.

**Reliability:** Much slower (hundreds of probes), some report 1/1500 success rate; others ~1min with optimizations (enlarged heap via large ASM strings, binary search).

## Exploit Primitive Summary

| Primitive | Source | Reliability |
|-----------|--------|-------------|
| Stack pointer leak | V2: `scanf` fail on `"+"` | Deterministic |
| Arbitrary read (C string) | V1: C↔Python confusion | Deterministic (after leak) |
| Arbitrary write (20 bytes) | V1: Java↔Javascript confusion | Deterministic (after leak) |
| Address oracle | V3: `read()` EFAULT non-crash | Deterministic but slow |
| RNG prediction | V4: replicate glibc `rand()` | Deterministic |
| Code execution | `__free_hook`/`__malloc_hook`/stack ROP | Deterministic (after arb R/W) |

## Offsets (pwnable.tw `libc_64.so.6`, glibc 2.23)

```python
__free_hook  = 0x3c57a8
__malloc_hook = 0x3c3b10
system       = 0x45390
one_gadgets  = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
stdin        = 0x3c48e0
environ      = 0x3c5f38
```

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | A | scanf leak → C↔Python read → Java↔JS write → `__free_hook` | Two complete scripts |
| `821.md` | A + B | scanf leak → stack/PIE/libc read → `__malloc_hook` one_gadget | Remote rand server for prediction |
| `2311.md` | A + C | scanf `"++"` leak → read libc from stack → write one_gadget to stack | Concise bug description |
| `3148.md` | A | scanf `"+"` leak → read GOT → `__free_hook` + system | Messy but functional |
| `564.md` | E | Python→C partial heap leak → `read()` brute-force → heap scan | Reports 1/1500 success rate |
| `7905.md` | A | scanf `"+"` leak → comprehensive writeup with fake chunk | Most detailed analysis |
| `8153.md` | E | No scanf trick; `read()` oracle brute-force + heap scan | Custom IEEE754 converter |
| `9251.md` | E + D | Heap brute-force → vtable scan → `stdout` vtable hijack | No scanf leak used |
| `34817.md` | E + B | Python→C leak → heap brute-force → PIE → `__malloc_hook` | Long binary search approach |
| `31599.md` | — | States "worst possible way, 1/1500 success" | Minimal detail |
| `375.md` | E | Heap brute-force via `read()` oracle → PIE → libc → `__free_hook` | Cyclic heap spray for faster scan |
| `1351.md` | E | `read()` oracle + heap walk → vtable → PIE → `__free_hook` | ASM heap spray for larger target |
| `10128.md` | A | scanf `"++"` → heap search → vtable → `__free_hook` | Binary search over heap ranges |
| `14523.md` | A | scanf `"+"` → stack → PIE via GOT → libc → `__free_hook` | Clean approach |
| `18331.md` | A | scanf `"+"` → stack → `read()` brute-force fallback | No slime prediction (just retries) |
| `22319.md` | A | scanf `"+"` → stack → PIE → libc → `__free_hook` | No slime prediction |
| `5586.md` | A | scanf `"+"` → stack → libc → `__free_hook` | King-only slime strategy |
| `6748.md` | A + B | scanf `"+"` → stack → `__realloc_hook` + `realloc` trampoline | Stack alignment trick |

## Files

| File | Description |
|------|-------------|
| `artifacts/stupid.cpp` | Challenge source code (provided by author) |
| `artifacts/stupid` | Challenge binary (stripped, PIE) |
| `artifacts/libc_64.so.6` | Remote libc (glibc 2.23) |
| `exp.py` | Working exploit script (Path A: scanf leak + type confusion R/W + `__free_hook`) |
| `desc.txt` | Challenge description |
| `solution/*.md` | Community write-ups (27 solutions) |
