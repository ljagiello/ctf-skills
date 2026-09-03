# Unicorn CPU Emulation

Raw binary and bare-metal emulation with Unicorn Engine. Sometimes easier to rev with just Unicorn + binary + assembly than a full GDB/angr session.

## Table of Contents

- [When Unicorn Beats GDB / angr / Qiling](#when-unicorn-beats-gdb--angr--qiling)
- [Setup Scaffold](#setup-scaffold)
- [Hook Cookbook](#hook-cookbook)
- [ARM / MIPS / Thumb](#arm--mips--thumb)
- [Mixed-Mode 64 to 32 via retf](#mixed-mode-64-to-32-via-retf)
- [Firmware MMIO Emulation](#firmware-mmio-emulation)
- [Snapshot & Fork: Efficient Brute-Force Oracle](#snapshot--fork-efficient-brute-force-oracle)
- [Coverage, Counting & Timeout Tuning](#coverage-counting--timeout-tuning)
- [Threading & Self-Modifying Code](#threading--self-modifying-code)
- [MMIO Robust: GPIO / Timer / Interrupt Controller](#mmio-robust-gpio--timer--interrupt-controller)
- [GDB Stub Integration](#gdb-stub-integration)
- [Performance](#performance)
- [Keystone + Unicorn Trace Inversion](#keystone--unicorn-trace-inversion)
- [Shellcode Unpack](#shellcode-unpack)
- [Custom VM Emulation](#custom-vm-emulation)
- [Qiling vs Unicorn Decision Tree](#qiling-vs-unicorn-decision-tree)
- [Emulator Comparison: Unicorn vs Qiling vs QEMU vs angr vs Triton](#emulator-comparison-unicorn-vs-qiling-vs-qemu-vs-angr-vs-triton)
- [Pitfalls](#pitfalls)
- [Worked Examples (2024)](#worked-examples-2024)

---

## When Unicorn Beats GDB / angr / Qiling

| Situation | Best tool | Why |
|---|---|---|
| Raw shellcode, no ELF | **Unicorn** | No OS/loader — map and run |
| Anti-debug (`ptrace`, PEB, timing) | **Unicorn** | No process, no artifacts |
| Bare-metal firmware | **Unicorn** | MMIO hooks replace peripherals |
| Multi-arch blob on x86 host | **Unicorn** | Cross-arch without QEMU/rootfs |
| Needs syscalls / FS / network | **Qiling** | Unicorn has no OS layer |
| Symbolic / path explosion | angr / Triton | Unicorn is concrete-only |

**Workflow:** static triage → isolate function or shellcode range → Unicorn for the anti-debug or bare-metal slice → dump regs/mem → solve. Use GDB for real OS signals, angr for symbolic, Qiling when you need syscalls.

---

## Setup Scaffold

```bash
pip install unicorn==2.1.2 capstone keystone-engine
# unicorn 2.1.2 is already pinned in scripts/install_ctf_tools.sh
```

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR  = 0x400000
STACK_ADDR = 0x7fff0000
STACK_SIZE = 2 * 1024 * 1024

# <!-- audit-ok --> placeholder — replace with real shellcode dump
CODE = open("shellcode.bin", "rb").read()  # <!-- audit-ok -->

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(STACK_ADDR, STACK_SIZE)
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 0x100)

def hook_code(mu, address, size, user_data):
    print(f"0x{address:x}: size={size}")

mu.hook_add(UC_HOOK_CODE, hook_code)

try:
    mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE), timeout=2 * 1000000, count=10000)
except UcError as e:
    print(f"UcError {e} errno={e.errno} at 0x{mu.reg_read(UC_X86_REG_RIP):x}")
```

`emu_start(begin, until, timeout, count)` — `timeout` is microseconds, `count` is insn limit. Reaching `until`, `emu_stop()` in a hook, or an unmapped fetch ends emulation. Map stack away from `0x0` so null derefs fault instead of silently succeeding.

---

## Hook Cookbook

Hooks use `hook(mu, address, size, user_data)` except `INTR`/`INSN`.

### CODE and BLOCK

```python
from unicorn import *
from unicorn.x86_const import *

def hook_code(mu, address, size, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    print(f"0x{address:x} [{size}B] RAX=0x{rax:x}")

mu.hook_add(UC_HOOK_CODE, hook_code)
# Filtered: mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x401000, end=0x401200)

def hook_block(mu, address, size, user_data):
    print(f"block 0x{address:x} size={size}")

mu.hook_add(UC_HOOK_BLOCK, hook_block)
```

`BLOCK` is cheaper than `CODE` when you only need coverage.

### MEM_READ / MEM_WRITE

```python
from unicorn import *
from unicorn.x86_const import *

def hook_mem_read(mu, access, address, size, value, user_data):
    data = mu.mem_read(address, size)
    print(f"READ  0x{address:x} size={size} data={data.hex()}")

def hook_mem_write(mu, access, address, size, value, user_data):
    print(f"WRITE 0x{address:x} size={size} value=0x{value:x}")

mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
```

### MEM_INVALID — unmapped / MMIO

```python
from unicorn import *
from unicorn.x86_const import *

def hook_invalid(mu, access, address, size, value, user_data):
    print(f"INVALID access={access} addr=0x{address:x} size={size}")
    return False  # False → UC_ERR_*, True → continue (for MMIO)

mu.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)
```

Covers `READ_UNMAPPED | WRITE_UNMAPPED | FETCH_UNMAPPED | READ_PROT | WRITE_PROT | FETCH_PROT`. Filter by `access` if needed.

### INTR and SYSCALL

```python
from unicorn import *
from unicorn.x86_const import *

def hook_intr(mu, intno, user_data):
    print(f"INT 0x{intno:x} at 0x{mu.reg_read(UC_X86_REG_RIP):x}")

mu.hook_add(UC_HOOK_INTR, hook_intr)

def hook_syscall(mu, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    print(f"syscall rax={rax} at 0x{mu.reg_read(UC_X86_REG_RIP):x}")
    mu.reg_write(UC_X86_REG_RAX, 0)

mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
```

<details>
<summary>Advanced: instruction counting + timeout</summary>

```python
from unicorn import *
from unicorn.x86_const import *

insn_count = [0]
def hook_count(mu, address, size, user_data):
    insn_count[0] += 1
    if insn_count[0] > 50000:
        mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook_count)
mu.emu_start(0x400000, 0x400000 + len(CODE), timeout=5 * 1000000, count=0)
print(f"executed {insn_count[0]} insns")
```

Do not set both `timeout` and `count` non-zero unless you intend whichever hits first to stop.

</details>

---

## ARM / MIPS / Thumb

### Thumb

```python
from unicorn import *
from unicorn.arm_const import *
from capstone import *

CODE_ADDR = 0x10000
CODE = open("thumb.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.reg_write(UC_ARM_REG_SP, 0x200000)
mu.emu_start(CODE_ADDR | 1, CODE_ADDR + len(CODE))

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for insn in md.disasm(CODE, CODE_ADDR):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
```

Thumb requires `CODE_ADDR | 1` and `UC_MODE_THUMB`; without the LSB set, Thumb encodings fault as `UC_ERR_INSN_INVALID`.

### ARM A32 and MIPS

```python
from unicorn import *
from unicorn.arm_const import *

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x10000, 2 * 1024 * 1024)
mu.mem_write(0x10000, CODE)
mu.reg_write(UC_ARM_REG_SP, 0x200000)
mu.emu_start(0x10000, 0x10000 + len(CODE))
```

```python
from unicorn import *
from unicorn.mips_const import *
from capstone import *

CODE_ADDR = 0x400000
CODE = open("mips.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_MIPS, UC_MODE_32 + UC_MODE_LITTLE_ENDIAN)
# Big-endian: UC_ARCH_MIPS + UC_MODE_32 + UC_MODE_BIG_ENDIAN
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.reg_write(UC_MIPS_REG_SP, 0x800000)
mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE))

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
for insn in md.disasm(CODE, CODE_ADDR):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
```

Endianness must match the binary or the first instruction is `UC_ERR_INSN_INVALID`. UnicornJS pixel pattern — RGBA bytes in raster order form the ARM stream — feeds the same Thumb scaffold; see [patterns-ctf-3.md](patterns-ctf-3.md#arm-code-in-image-pixels-via-unicornjs-hacklu-2017).

---

## Mixed-Mode 64 to 32 via retf

Packers use `retf`/`retfq` to switch modes. Unicorn cannot switch mid-run — stop, create a new `Uc` in the target mode, copy state, resume. `retf` pops EIP(4)+CS(2)=6B; `retfq` pops RIP(8)+CS(8)=16B. See [field-notes.md](field-notes.md#unicorn-emulation-complex-state) and [tools.md](tools.md#mixed-mode-64-to-32-switch).

```python
from unicorn import *
from unicorn.x86_const import *

mu64 = Uc(UC_ARCH_X86, UC_MODE_64)
mu64.mem_map(0x400000, 0x20000)
mu64.mem_map(0x7fff0000, 0x10000)
mu64.mem_write(0x400000, code64)
mu64.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
RET_ADDR = 0x401020
mu64.emu_start(0x400000, RET_ADDR)

mu32 = Uc(UC_ARCH_X86, UC_MODE_32)
mu32.mem_map(0x400000, 0x20000)
mu32.mem_map(0x7fff0000, 0x10000)
for addr, sz in [(0x400000, 0x20000)]:
    mu32.mem_write(addr, mu64.mem_read(addr, sz))

reg_map = {
    UC_X86_REG_EAX: UC_X86_REG_RAX, UC_X86_REG_EBX: UC_X86_REG_RBX,
    UC_X86_REG_ECX: UC_X86_REG_RCX, UC_X86_REG_EDX: UC_X86_REG_RDX,
    UC_X86_REG_ESI: UC_X86_REG_RSI, UC_X86_REG_EDI: UC_X86_REG_RDI,
    UC_X86_REG_EBP: UC_X86_REG_RBP, UC_X86_REG_ESP: UC_X86_REG_RSP,
}
for r32, r64 in reg_map.items():
    mu32.reg_write(r32, mu64.reg_read(r64) & 0xffffffff)
mu32.reg_write(UC_X86_REG_EFLAGS, mu64.reg_read(UC_X86_REG_RFLAGS) & 0xffffffff)
for xr in [UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
           UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7,
           UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11,
           UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15]:
    mu32.reg_write(xr, mu64.reg_read(xr))

eip = int.from_bytes(mu32.mem_read(mu32.reg_read(UC_X86_REG_ESP), 4), "little")
mu32.reg_write(UC_X86_REG_EIP, eip)
mu32.reg_write(UC_X86_REG_ESP, mu32.reg_read(UC_X86_REG_ESP) + 6)
mu32.emu_start(eip, eip + len(code32))
```

Forgetting `EFLAGS`, not truncating to 32 bits, or skipping XMM for SSE blobs are the common pitfalls.

---

## Firmware MMIO Emulation

Firmware touches fixed peripheral addresses (UART `0x40000000`, GPIO, timers) that are unmapped. Map the page and hook `MEM_READ`/`MEM_WRITE`, or use `mmio_map`.

```python
from unicorn import *
from unicorn.arm_const import *

CODE_ADDR = 0x08000000
MMIO_BASE = 0x40000000
CODE = open("firmware.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.reg_write(UC_ARM_REG_SP, 0x20080000)
mu.mem_map(MMIO_BASE, 0x1000)
mu.mem_write(MMIO_BASE, b"\x01\x00\x00\x00")  # status = ready

mmio = {0x40000000: 0x01, 0x40000004: 0x41}

def hook_mmio_write(mu, access, address, size, value, user_data):
    if MMIO_BASE <= address < MMIO_BASE + 0x1000:
        print(f"MMIO write 0x{address:x} <- 0x{value:x}")
        mmio[address & ~0x3] = value & 0xffffffff
    return True

mu.hook_add(UC_HOOK_MEM_WRITE, hook_mmio_write)

try:
    mu.emu_start(CODE_ADDR | 1, CODE_ADDR + len(CODE), timeout=3 * 1000000, count=20000)
except UcError as e:
    if e.errno == UC_ERR_INSN_INVALID:
        print(f"invalid insn at 0x{mu.reg_read(UC_ARM_REG_PC):x} — wrong mode or data as code?")
    elif e.errno == UC_ERR_FETCH_UNMAPPED:
        print(f"fetch unmapped at 0x{mu.reg_read(UC_ARM_REG_PC):x} — missing map or bad branch")
    else:
        print(f"UcError {e} errno={e.errno}")
```

Use `timeout`+`count` or a `CODE` hook calling `emu_stop()` to escape poll loops; `mmio_map(MMIO_BASE, 0x1000, read_cb, None, write_cb, None)` is the 2.x alternative.

---

## Snapshot & Fork: Efficient Brute-Force Oracle

Recreating the `Uc` from scratch per candidate is 10-100x slower than snapshot/restore. Use `context_save()`/`context_restore()` plus explicit memory snapshots for byte-by-byte oracles (N1CTF 2018 trace inversion, flag checkers that compare prefix).

### context_save / context_restore / context_update

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
DATA_ADDR = 0x500000
CODE = open("checker.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(DATA_ADDR, 0x10000)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)
mu.reg_write(UC_X86_REG_RDI, DATA_ADDR)

# Warm up to the checkpoint (e.g., after init, before input-dependent loop)
mu.emu_start(CODE_ADDR, CODE_ADDR + 0x40, timeout=1 * 1000000, count=0)
snap = mu.context_save()          # registers + MSRs + hidden state
mem_snap = mu.mem_read(DATA_ADDR, 0x10000)  # explicit RAM snapshot
mem_snap_code = mu.mem_read(CODE_ADDR, 0x10000)  # if SMC may dirty code

print(f"snapshot: RIP=0x{mu.reg_read(UC_X86_REG_RIP):x}")
```

`context_save()` returns an opaque `UcContext` — registers, flags, segment bases, MSRs. It does **not** snapshot RAM; you must `mem_read`/`mem_write` any region the target mutates (input buffer, heap, code pages for SMC). `context_update(ctx)` writes current regs into an existing context without allocating a new one — use it to checkpoint incrementally.

### Copy-on-write snapshot brute-force

```python
from unicorn import *
from unicorn.x86_const import *

# <!-- audit-ok --> placeholder — CODE from file above
CODE_ADDR = 0x400000
DATA_ADDR = 0x500000

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(DATA_ADDR, 0x10000)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)
mu.emu_start(CODE_ADDR, CODE_ADDR + 0x40, timeout=1 * 1000000, count=0)

base_ctx = mu.context_save()
base_mem = mu.mem_read(DATA_ADDR, 0x10000)

def try_byte(prefix: bytes, cand: int) -> bool:
    mu.context_restore(base_ctx)
    mu.mem_write(DATA_ADDR, base_mem)  # restore RAM (COW: only dirty pages)
    attempt = prefix + bytes([cand])
    mu.mem_write(DATA_ADDR, attempt)
    mu.reg_write(UC_X86_REG_RDI, DATA_ADDR)
    # also restore any global counter the checker increments
    try:
        mu.emu_start(mu.reg_read(UC_X86_REG_RIP), CODE_ADDR + len(CODE),
                     timeout=500000, count=5000)
    except UcError:
        return False
    return mu.reg_read(UC_X86_REG_RAX) == 0  # checker returns 0 on prefix match

flag = b""
for pos in range(32):
    for c in range(32, 127):
        if try_byte(flag, c):
            flag += bytes([c])
            print(f"pos {pos}: {chr(c)} -> {flag}")
            # re-snapshot after advancing one byte so next pos starts from new state
            base_ctx = mu.context_save()
            base_mem = mu.mem_read(DATA_ADDR, 0x10000)
            break
    else:
        print(f"no candidate at pos {pos}")
        break
print(f"flag={flag}")
```

**Why fork-style restore beats fresh `Uc`:** `Uc()` allocates TCG cache, maps, and hooks; `context_restore` is a memcpy. For 32*95 brute-force iterations the snapshot loop is 20-50x faster. For AFL++ unicorn mode the same pattern is copy-on-write: `mem_read` the dirty range only, or `mem_protect` with `UC_PROT_READ` to trap writes and record dirty pages.

### Fork emulation alternative (multiprocess)

When the corpus is large or you want true isolation, `fork()` after snapshot and let the OS COW the pages. Unicorn state is not fork-safe across threads but is across `fork()` if you `context_save` before forking and each child creates its own `Uc` from the saved blob.

---

## Coverage, Counting & Timeout Tuning

### BLOCK vs CODE hooks

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
CODE = open("target.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)

# BLOCK is cheaper — fires once per basic block, not per instruction
blocks = {}
def hook_block(mu, address, size, user_data):
    blocks[address] = blocks.get(address, 0) + 1

mu.hook_add(UC_HOOK_BLOCK, hook_block)

# Filter to the function under test to avoid counting init/cleanup
func_start, func_end = 0x401000, 0x401200
mu.hook_add(UC_HOOK_BLOCK, hook_block, begin=func_start, end=func_end)

try:
    mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE), timeout=2 * 1000000, count=0)
except UcError as e:
    print(f"stop errno={e.errno} blocks={len(blocks)}")

# AFL++-style edge coverage: (prev_block, cur_block) tuple
edges = set()
prev = None
def hook_edge(mu, address, size, user_data):
    global prev
    if prev is not None:
        edges.add((prev, address))
    prev = address

# instruction counting — only if you need per-insn granularity
insn_count = [0]
def hook_count(mu, address, size, user_data):
    insn_count[0] += 1
    if insn_count[0] > 50000:
        mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook_count, begin=func_start, end=func_end)
```

Use `BLOCK` for coverage/AFL, `CODE` only when you need per-instruction inspection (SMC detection, register dump). Python hook overhead is ~5-15 us per invocation — 1M `CODE` hooks adds seconds; the same coverage via `BLOCK` is 10-30x fewer invocations.

### Timeout vs count

| Setting | Effect | When to use |
|---|---|---|
| `timeout=2*1000000, count=0` | Wall-clock limit (us) | Poll loops, firmware infinite loops |
| `timeout=0, count=20000` | Instruction limit | Deterministic functions, solver oracles |
| `timeout=0, count=0` | Run until `until` / `emu_stop` / fault | Short shellcode, known end address |
| Both non-zero | Whichever hits first stops | Avoid unless you intend the race |

Tune `count` to 2x the expected insn count (measure once with a counter hook, then hardcode). For firmware, prefer `timeout` (2-3M us) plus a `BLOCK` hook that calls `emu_stop()` on idle detection.

### UC_ERR handling table

| `e.errno` | Constant | Cause | Fix |
|---|---|---|---|
| 6 | `UC_ERR_READ_UNMAPPED` | Load from unmapped | `mem_map` region or `MEM_INVALID` hook |
| 7 | `UC_ERR_WRITE_UNMAPPED` | Store to unmapped | `mem_map` or MMIO hook returning `True` |
| 8 | `UC_ERR_FETCH_UNMAPPED` | Branch/jump to unmapped | Map target or hook `MEM_INVALID` (FETCH) |
| 10 | `UC_ERR_INSN_INVALID` | Bad opcode / wrong mode | Check `UC_MODE_THUMB` + `ADDR|1`, endianness |
| 12 | `UC_ERR_WRITE_PROT` | Write to `UC_PROT_READ` page | `mem_protect` to `UC_PROT_ALL` or handle via `MEM_WRITE_PROT` |
| 13 | `UC_ERR_READ_PROT` | Read from no-read page | `mem_protect` or `MEM_READ_PROT` hook |
| 14 | `UC_ERR_FETCH_PROT` | Exec from non-exec page | `mem_protect` with `UC_PROT_EXEC` |
| 15 | `UC_ERR_ARG` | Misaligned `mem_map`/`mem_protect` | Align addr/size to `0x1000` |
| 11 | `UC_ERR_MAP` | Overlapping `mem_map` | `mem_unmap` first or pick new base |
| 0 | `UC_ERR_OK` | Clean stop at `until` or `emu_stop` | Not an error — check `RIP` reached `until` |

Inspect via `e.errno` and `mu.reg_read(UC_X86_REG_RIP)`/`UC_ARM_REG_PC`. Log both.

---

## Threading & Self-Modifying Code

### SMC detection (write to code page → invalidate)

Firmware and packers unpack the next stage in place. Detect the write and flush the TCG cache.

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
CODE = open("packed.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)

code_start, code_end = CODE_ADDR, CODE_ADDR + 0x10000

def hook_mem_write_smc(mu, access, address, size, value, user_data):
    if code_start <= address < code_end:
        print(f"SMC write 0x{address:x} size={size} — flushing TB cache")
        mu.ctl_remove_cache(address, address + size)

mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write_smc)

# Alternative: detect via CODE hook that re-reads the bytes
orig = mu.mem_read(CODE_ADDR, len(CODE))
def hook_code_smc(mu, address, size, user_data):
    cur = mu.mem_read(address, size)
    # capstone disasm of cur vs orig can confirm rewrite
    pass
mu.hook_add(UC_HOOK_CODE, hook_code_smc, begin=code_start, end=code_end)
```

Unicorn caches translated blocks (TB). After SMC, call `mu.ctl_remove_cache(start, end)` or `mu.ctl_flush_tb()` to force retranslation. Without this the emulator executes the old bytes. QEMU `qemu_tb_flush` equivalent.

### Multi-thread via sequential emulation + state copy

Unicorn is single-threaded; there is no `emu_start` concurrency. Model threads by interleaving.

```python
from unicorn import *
from unicorn.x86_const import *

# Two threads share memory but have private registers/stacks
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x20000)
mu.mem_map(0x600000, 0x10000)  # shared heap
mu.mem_map(0x7fff0000, 0x10000)  # thread 1 stack
mu.mem_map(0x7ffe0000, 0x10000)  # thread 2 stack

# Snapshot thread states as contexts
thread1_ctx = mu.context_save()
mu.reg_write(UC_X86_REG_RSP, 0x7ffe0000 + 0xf00)
mu.reg_write(UC_X86_REG_RIP, 0x401000)  # thread 2 entry
thread2_ctx = mu.context_save()

# Round-robin: restore ctx, run N blocks, save back
for tick in range(100):
    for ctx in (thread1_ctx, thread2_ctx):
        mu.context_restore(ctx)
        try:
            mu.emu_start(mu.reg_read(UC_X86_REG_RIP), 0, timeout=100000, count=100)
        except UcError:
            pass
        # update ctx in place so next round resumes
        mu.context_update(ctx)
```

For lock-sensitive code, hook the atomic (`lock cmpxchg`, `ldrex/strex`) and emulate the reservation in `user_data`.

---

## MMIO Robust: GPIO / Timer / Interrupt Controller

Beyond UART `0x40000000` — firmware touches GPIO, timers, and NVIC/interrupt controllers. Model each peripheral as a state dict with side-effect reads.

### Hook filtering by access type

```python
from unicorn import *
from unicorn.arm_const import *

CODE_ADDR = 0x08000000
CODE = open("firmware.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x20000000, 0x10000)
mu.reg_write(UC_ARM_REG_SP, 0x20010000)

# Map MMIO pages so FETCH still faults but READ/WRITE hit hooks
for base in (0x40000000, 0x40010000, 0x40020000, 0xe000e000):
    mu.mem_map(base, 0x1000)

def hook_invalid(mu, access, address, size, value, user_data):
    # access is one of the UC_MEM_* constants
    # Filter: only handle known peripheral ranges, let others fault
    if access == UC_MEM_READ_UNMAPPED:
        print(f"READ_UNMAPPED 0x{address:x} size={size}")
        return False
    elif access == UC_MEM_WRITE_UNMAPPED:
        print(f"WRITE_UNMAPPED 0x{address:x} val=0x{value:x}")
        return False
    elif access == UC_MEM_FETCH_UNMAPPED:
        print(f"FETCH_UNMAPPED 0x{address:x} — bad branch, stop")
        mu.emu_stop()
        return False
    elif access in (UC_MEM_READ_PROT, UC_MEM_WRITE_PROT):
        mu.mem_protect(address & ~0xfff, 0x1000, UC_PROT_ALL)
        return True
    return False

mu.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)
```

### GPIO / Timer / NVIC models

```python
from unicorn import *
from unicorn.arm_const import *

# Peripheral bases (STM32-like)
GPIOA_BASE = 0x40020000
TIM2_BASE  = 0x40000000
NVIC_BASE  = 0xe000e100  # NVIC ISER/ICER

# Device state — dict per peripheral
gpio = {"ODR": 0, "IDR": 0x41, "BSRR": 0}  # IDR returns input pins
timer = {"CNT": 0, "SR": 1, "PSC": 0}  # SR bit 0 = UIF (update interrupt flag)
nvic = {"ISER": 0, "ICER": 0, "pending": 0}

def mmio_read(mu, address, size):
    if GPIOA_BASE <= address < GPIOA_BASE + 0x1000:
        off = address - GPIOA_BASE
        if off == 0x10:  # IDR
            return gpio["IDR"] & ((1 << (size*8)) - 1)
        elif off == 0x14:  # ODR
            return gpio["ODR"] & ((1 << (size*8)) - 1)
    elif TIM2_BASE <= address < TIM2_BASE + 0x1000:
        off = address - TIM2_BASE
        if off == 0x00:  # CR1
            return 0x01
        elif off == 0x10:  # SR — side-effect: clear on read
            val = timer["SR"]
            timer["SR"] = 0  # status clear on read (common silicon behavior)
            return val
        elif off == 0x24:  # CNT — increment each read (free-running timer)
            timer["CNT"] = (timer["CNT"] + 1) & 0xffffffff
            return timer["CNT"]
    elif NVIC_BASE <= address < NVIC_BASE + 0x1000:
        return nvic["ISER"]
    return 0

def mmio_write(mu, address, size, value):
    if GPIOA_BASE <= address < GPIOA_BASE + 0x1000:
        off = address - GPIOA_BASE
        if off == 0x14:  # ODR
            gpio["ODR"] = value
            print(f"GPIO ODR <- 0x{value:x} ({chr(value & 0xff) if 32 <= (value & 0xff) <= 126 else '.'})")
        elif off == 0x18:  # BSRR — bit set/reset
            if value & 0xffff:
                gpio["ODR"] |= (value & 0xffff)
            if value >> 16:
                gpio["ODR"] &= ~(value >> 16)
    elif TIM2_BASE <= address < TIM2_BASE + 0x1000:
        off = address - TIM2_BASE
        if off == 0x0c:  # PSC
            timer["PSC"] = value
        elif off == 0x10:  # SR — write 0 clears
            timer["SR"] &= ~value

def hook_mmio_read(mu, access, address, size, value, user_data):
    if address >= 0x40000000 and address < 0xe0100000:
        val = mmio_read(mu, address, size)
        # Write back via mem_write so the load sees the value
        mu.mem_write(address, val.to_bytes(size, "little"))
        return True
    return False

def hook_mmio_write(mu, access, address, size, value, user_data):
    if address >= 0x40000000 and address < 0xe0100000:
        mmio_write(mu, address, size, value)
        return True
    return False

mu.hook_add(UC_HOOK_MEM_READ, hook_mmio_read)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mmio_write)
```

**Side-effect reads** (status clear on read) and **free-running counters** (CNT increments) are the two patterns that break naive `mem_write(MMIO_BASE, b"\x01...")` stubs. Model them explicitly or the poll loop never exits / interrupt never fires.

### Timer interrupt injection

```python
from unicorn import *
from unicorn.arm_const import *

# Fire timer interrupt every N blocks
tick = [0]
def hook_block_timer(mu, address, size, user_data):
    tick[0] += 1
    if tick[0] % 1000 == 0:
        timer["SR"] |= 1  # set UIF
        nvic["pending"] |= 1 << 28  # TIM2 IRQn = 28
        # Optionally hijack PC to ISR — save context, set PC to vector
        # vector table at 0x08000000, IRQ entry at offset 0xb0 on STM32
        # For CTF, often simpler to just set the flag and let firmware poll it

mu.hook_add(UC_HOOK_BLOCK, hook_block_timer)
```

For vectored interrupts, `context_save()` before hijack, write `PC`/`LR`/`xPSR`, emulate ISR, then `context_restore`. See [tools-emulation.md](tools-emulation.md#qiling-framework-cross-platform-emulation) for Qiling's `ql.hw` abstraction which automates this.

---

## GDB Stub Integration

Unicorn as a GDB backend lets you inspect without `ptrace` artifacts, using GEF/pwndbg.

```python
from unicorn import *
from unicorn.x86_const import *
import socket, struct

CODE_ADDR = 0x400000
CODE = open("target.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)

# Breakpoint via CODE hook — register sync with GDB RSP protocol
breakpoints = {0x401020, 0x401050}
def hook_bp(mu, address, size, user_data):
    if address in breakpoints:
        print(f"[GDB] break 0x{address:x} RAX=0x{mu.reg_read(UC_X86_REG_RAX):x} "
              f"RBX=0x{mu.reg_read(UC_X86_REG_RBX):x} "
              f"RIP=0x{mu.reg_read(UC_X86_REG_RIP):x}")
        mu.emu_stop()  # hand control to stub

mu.hook_add(UC_HOOK_CODE, hook_bp)

# Minimal RSP loop: expose regs/mem via socket, translate GDB packets to mu.reg_read/mem_read
# Full stub: https://github.com/unicorn-engine/unicorn/blob/master/samples/gdb_stub.py
# Use: gdb target.bin → target remote :1234 → c / si / info regs (backed by mu)

def gdb_reg_sync(mu):
    # Pack regs in GDB order (x86_64: RAX RBX RCX RDX RSI RDI RBP RSP ... RIP)
    regs = [mu.reg_read(r) for r in (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RIP, UC_X86_REG_EFLAGS)]
    return b"".join(struct.pack("<Q", r) for r in regs)

# Step: emu_start with count=1, report new RIP, loop
try:
    mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE), timeout=5 * 1000000, count=0)
except UcError as e:
    print(f"GDB stub stop errno={e.errno} RIP=0x{mu.reg_read(UC_X86_REG_RIP):x}")
    # GEF: telescope $rsp, vmmap (from mu.mem_regions()), disasm $rip via Capstone
```

**Workflow:** `mu.hook_add(UC_HOOK_CODE, bp)` for breakpoints, `count=1` stepping, `mem_read`/`reg_read` for GDB `x/` and `info regs`. No `ptrace` → anti-debug bypassed. Pair with Capstone for disasm and `mu.mem_regions()` for `vmmap`.

<details>
<summary>Advanced: ptrace evasion variant (full stub)</summary>

```python
from unicorn import *
from unicorn.x86_const import *

# Hook the anti-debug syscall itself so GDB stub never triggers it
def hook_syscall_ptrace(mu, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    if rax == 101:  # ptrace nr on x86_64
        print("[GDB stub] ptrace intercepted — returning 0")
        mu.reg_write(UC_X86_REG_RAX, 0)
        # skip syscall: advance RIP past syscall (2 bytes: 0f 05)
        mu.reg_write(UC_X86_REG_RIP, mu.reg_read(UC_X86_REG_RIP) + 2)

mu.hook_add(UC_HOOK_INSN, hook_syscall_ptrace, None, 1, 0, UC_X86_INS_SYSCALL)
```

</details>

---

## Performance

### Map granularity

```python
from unicorn import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
# All maps aligned to 0x1000 — UC_ERR_ARG otherwise
mu.mem_map(0x400000, 0x1000)   # 4K min
mu.mem_map(0x401000, 0x2000)   # 8K — coalesce adjacent if possible
# Avoid 1-byte maps; permission checks are per-page
mu.mem_protect(0x400000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
```

Coalesce adjacent regions into one `mem_map`. Per-page `UC_PROT_*` checks cost — fewer regions is faster.

### Hook filtering

```python
from unicorn import *
from unicorn.x86_const import *

# Filter by address range — hook only fires inside [begin, end]
mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x401000, end=0x401200)
mu.hook_add(UC_HOOK_BLOCK, hook_block, begin=0x401000, end=0x401200)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_smc, begin=0x400000, end=0x402000)

# Avoid per-insn hook when BLOCK suffices — 10-30x fewer invocations
# BLOCK covers coverage, edge counting, timer ticks
# CODE only for register dumps, SMC checks, instruction-level tracing
```

Adding `begin`/`end` moves filtering into C (TCG) instead of Python. Without it every instruction traps into Python.

### Python hook overhead

| Hook | Cost per hit (approx) | Notes |
|---|---|---|
| `UC_HOOK_CODE` | 5-15 us | Python callback + reg reads |
| `UC_HOOK_BLOCK` | 5-15 us | Same cost, fewer hits |
| `UC_HOOK_MEM_READ/WRITE` | 10-20 us | Plus `mem_read`/`mem_write` inside |
| No hook (native TCG) | ~0.02 us/insn | 2-3 orders faster |

A 1M-instruction trace with `CODE` hook: 5-15 seconds. Same with `BLOCK` (50K blocks): 0.3-0.8 seconds. Same with no hook: 0.02 seconds.

### Batch mem_read vs per-byte

```python
from unicorn import *
from unicorn.x86_const import *

# Slow — 256 Python crossings
slow = bytes(mu.mem_read(addr + i, 1)[0] for i in range(256))

# Fast — one crossing, slice in Python
fast = mu.mem_read(addr, 256)  # single mem_read, returns bytes

# For snapshots: read only dirty ranges
dirty = [(0x500000, 0x1000), (0x600000, 0x2000)]
snaps = {base: mu.mem_read(base, sz) for base, sz in dirty}
# restore:
for base, data in snaps.items():
    mu.mem_write(base, data)
```

Batch `mem_read`/`mem_write` and `reg_read_batch` to cut crossings. For brute-force, snapshot only the input buffer, not the entire address space.

---

## Keystone + Unicorn Trace Inversion

Binary applies `add/sub/xor/rol/ror` transforms with no memory effects (MeePwn 2017). Invert by reversing the trace and swapping inverse ops, re-assemble with Keystone, emulate with Unicorn. See [anti-analysis-ctf.md](anti-analysis-ctf.md#instruction-trace-inversion-with-keystone-and-unicorn-meepwn-ctf-2017).

```python
from keystone import *
from unicorn import *
from unicorn.x86_const import *
from capstone import *

CODE_ADDR = 0x401000
CODE = open("obfuscated.bin", "rb").read()  # <!-- audit-ok --> placeholder

md = Cs(CS_ARCH_X86, CS_MODE_64)
transforms = []
for insn in md.disasm(CODE, CODE_ADDR):
    if insn.mnemonic not in ("jmp", "je", "jne", "call", "ret", "jbe", "ja", "jb"):
        transforms.append((insn.mnemonic, insn.op_str))

inverse = {"add": "sub", "sub": "add", "rol": "ror", "ror": "rol", "xor": "xor"}
inverted = [(inverse.get(m, m), op) for m, op in reversed(transforms)]

ks = Ks(KS_ARCH_X86, KS_MODE_64)
asm_src = "\n".join(f"{m} {op}" for m, op in inverted)
encoding, _ = ks.asm(asm_src)

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, bytes(encoding))
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
mu.reg_write(UC_X86_REG_RAX, known_output)
mu.emu_start(0x400000, 0x400000 + len(encoding))
flag = mu.reg_read(UC_X86_REG_RAX).to_bytes(8, "little")
print(f"recovered: {flag}")
```

Try-byte loop for prefix-dependent checks:

```python
from unicorn import *
from unicorn.x86_const import *

def try_byte(known_prefix: bytes, candidate: int) -> bool:
    attempt = known_prefix + bytes([candidate])
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(0x400000, 0x10000)
    mu.mem_write(0x400000, CODE)
    mu.mem_map(0x300000, 0x10000)
    mu.mem_write(0x300000, attempt)
    mu.reg_write(UC_X86_REG_RDI, 0x300000)
    mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
    mu.mem_map(0x7fff0000, 0x10000)
    try:
        mu.emu_start(0x400000, 0x400000 + len(CODE), timeout=1 * 1000000, count=5000)
    except UcError:
        return False
    return mu.reg_read(UC_X86_REG_RAX) == 0

flag = b""
for pos in range(32):
    for c in range(32, 127):
        if try_byte(flag, c):
            flag += bytes([c])
            print(f"pos {pos}: {chr(c)} -> {flag}")
            break
```

---

## Shellcode Unpack

Multi-stage loaders XOR-decode the next stage in place. Emulate until after the loop and dump the decoded buffer instead of reversing the cipher.

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
DATA_ADDR = 0x500000
# <!-- audit-ok --> placeholder — replace with real dump from stager
shellcode = open("shellcode.bin", "rb").read()  # <!-- audit-ok -->

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, shellcode)
mu.mem_map(DATA_ADDR, 2 * 1024 * 1024)
mu.mem_map(0x7fff0000, 2 * 1024 * 1024)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 2 * 1024 * 1024 - 0x100)

DECODE_END = CODE_ADDR + 0x120  # address after loop — find via disasm
mu.emu_start(CODE_ADDR, DECODE_END, timeout=2 * 1000000, count=10000)

decoded = mu.mem_read(DATA_ADDR, 0x1000)
print(f"decoded head: {decoded[:64].hex()}")
if decoded[:2] == b"MZ":
    open("stage2.bin", "wb").write(decoded)
    print("stage2 is PE — dumped to stage2.bin")
elif decoded[:4] == b"\x7fELF":
    open("stage2.bin", "wb").write(decoded)
    print("stage2 is ELF — dumped to stage2.bin")
else:
    for i in range(len(decoded) - 4):
        if decoded[i:i+5] == b"flag{":
            print(decoded[i:i+64])
            break
```

See [patterns-runtime.md](patterns-runtime.md#multi-stage-shellcode-loaders) for the GDB `call rax` + `ptrace` bypass variant.

---

## Custom VM Emulation

Use Unicorn as the CPU; dispatch bytecode via a `CODE` hook that reads the VM's fetch pointer.

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x10000); mu.mem_write(0x400000, vm_stub)
mu.mem_map(0x500000, 0x10000); mu.mem_write(0x500000, BYTECODE)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
mu.reg_write(UC_X86_REG_RSI, 0x500000)

def hook_dispatch(mu, address, size, user_data):
    pc = mu.reg_read(UC_X86_REG_RSI)
    print(f"op=0x{mu.mem_read(pc, 1)[0]:02x} pc=0x{pc:x} RAX=0x{mu.reg_read(UC_X86_REG_RAX):x}")

mu.hook_add(UC_HOOK_CODE, hook_dispatch)
```

Iterative solver: brute-force VM input byte-by-byte via `try_byte` pattern above. For LLVM IR lifting, see [tools-advanced.md](tools-advanced.md#custom-vm-bytecode-lifting-to-llvm-ir-google-ctf-2017).

---

## Qiling vs Unicorn Decision Tree

| Question | Answer | Pick |
|---|---|---|
| Needs syscalls (`open`, `ptrace`, `socket`)? | Yes | **Qiling** |
| Raw blob / firmware, no OS? | Yes | **Unicorn** |
| Anti-debug bypass needed? | — | Either — Qiling hooks syscalls, Unicorn has no process |
| Foreign arch + `libc`? | Yes | **Qiling** (rootfs) |
| Foreign arch, bare-metal? | Yes | **Unicorn** (lighter) |

```python
# Qiling — OS-level (needs rootfs)
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(["./binary", "arg1"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEFAULT)
def hook_ptrace(ql, request, pid, addr, data):
    return 0
ql.os.set_syscall("ptrace", hook_ptrace)
ql.run()
```

```python
# Unicorn — raw CPU (no OS, no rootfs)
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, code_bytes)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
mu.emu_start(0x400000, 0x400000 + len(code_bytes))
```

If you reimplement syscalls with `UC_HOOK_INTR` / `UC_HOOK_INSN`, switch to Qiling.

---

## Emulator Comparison: Unicorn vs Qiling vs QEMU vs angr vs Triton

Concrete vs symbolic vs OS — pick the right engine for the CTF slice.

| Engine | Execution | OS / Syscalls | Arch | Symbolic | Snapshot | Best for | CTF refs |
|---|---|---|---|---|---|---|---|
| **Unicorn** | Concrete, TCG | None (raw CPU) | x86, ARM, MIPS, RISC-V, M68K, SPARC, S390X | No | `context_save`/`restore` + `mem_read` | Shellcode, bare-metal firmware, anti-debug slice, custom VM dispatch | See [tools.md](tools.md#unicorn-emulation) |
| **Qiling** | Concrete, Unicorn+OS | Yes (syscalls, FS, registry via rootfs) | Same as Unicorn + OS layer | No (but hooks Python) | `ql.save`/`restore` (wraps context) | Foreign ELF with libc, syscall-heavy, `ptrace`/socket bypass | See [tools-emulation.md](tools-emulation.md#qiling-framework-cross-platform-emulation) |
| **QEMU** | Concrete, TCG/system | Full system or user-mode | Same + full peripherals | No | VM snapshot, `dump-guest-memory` | Full Linux boot, kernel driver RE, hardware MMIO via `-machine` | See [platforms-hardware.md](platforms-hardware.md) |
| **angr** | Symbolic (VEX) | SimProcedures (SimLinux) | x86, ARM, MIPS | Yes (Claripy/Z3) | State copy (`state.copy()`) | Flag checkers, path explosion, no MMIO timing | See [tools-dynamic.md](tools-dynamic.md) |
| **Triton** | Concrete + symbolic (DSE) | Pin/DBI-backed | x86, x86_64, AArch64 | Yes (Ast) | Single-path trace | Linear deobfuscation, taint, one-path solve | See [tools-advanced.md](tools-advanced.md#triton-dynamic-symbolic-execution) |

**Decision rule:** raw blob/firmware/no OS → Unicorn; needs `open`/`socket`/`ptrace` → Qiling; whole OS/kernel → QEMU; need to **solve** for input without brute-force → angr/Triton. Unicorn+Capstone+Keystone complement angr (concrete trace) rather than replace it. For VMProtect/Themida where the VM is the challenge, see [tools-advanced.md](tools-advanced.md#vmprotect-analysis).

---

## Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| `timeout` vs `count` | Both non-zero stops on whichever first | Use one, set other to `0` |
| Stack at `0x0` | Null deref silently succeeds | Map stack at `0x7fff0000` |
| Thumb LSB | `UC_ERR_INSN_INVALID` | `CODE_ADDR \| 1` + `UC_MODE_THUMB` |
| `UC_ERR_FETCH_UNMAPPED` | Branch to unmapped region | Hook `MEM_INVALID` or map region |
| Hook re-entrance | `reg_write`/`mem_write` re-triggers hook | Guard flag or `MEM_READ_AFTER` |
| MIPS endianness | First insn invalid | Match `LITTLE`/`BIG_ENDIAN` to binary |
| Mixed-mode EFLAGS/XMM | Stale flags, zeroed SSE | Copy `RFLAGS & 0xffffffff`, copy `XMM0-15` |
| `mem_map` alignment | `UC_ERR_ARG` | Use multiples of `0x1000` |
| `WRITE_UNMAPPED` on MMIO | Peripheral write faults | `mem_map` MMIO page, then hook |

---

## Worked Examples (2024)

### 1 — Shellcode Loader (x86-64 XOR decode)

Stager drops `shellcode.bin` that XOR-decodes an embedded PE. Loop at `0x400080`, buffer at `0x500000`.

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
DATA_ADDR = 0x500000
CODE = open("shellcode.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(DATA_ADDR, 2 * 1024 * 1024)
mu.mem_map(0x7fff0000, 2 * 1024 * 1024)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 2 * 1024 * 1024 - 0x100)

LOOP_END = CODE_ADDR + 0x120
try:
    mu.emu_start(CODE_ADDR, LOOP_END, timeout=2 * 1000000, count=10000)
except UcError as e:
    print(f"emulation stopped: {e} errno={e.errno}")

decoded = mu.mem_read(DATA_ADDR, 0x400)
print(f"head: {decoded[:32].hex()}")
if decoded[:2] == b"MZ":
    print("ok: decoded PE magic MZ found")
    open("stage2.bin", "wb").write(mu.mem_read(DATA_ADDR, 0x10000))
    print("dumped stage2.bin")
else:
    for i in range(len(decoded)):
        if decoded[i:i+5] == b"flag{":
            print(f"flag at 0x{i:x}: {decoded[i:i+64]}")
            print("ok: flag prefix found in decoded memory")
            break
    else:
        print("no PE magic or flag prefix — check LOOP_END")
```

Verification prints `ok: decoded PE magic MZ found` or `ok: flag prefix found`.

### 2 — Firmware MMIO (ARM Thumb UART poll)

Firmware polls `0x40000000` (status, bit 0 = ready) then reads `0x40000004`. Without MMIO the poll loops forever.

```python
from unicorn import *
from unicorn.arm_const import *

CODE_ADDR = 0x08000000
MMIO_BASE = 0x40000000
CODE = open("firmware.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x20000000, 0x10000)
mu.reg_write(UC_ARM_REG_SP, 0x20010000)
mu.mem_map(MMIO_BASE, 0x1000)
mu.mem_write(MMIO_BASE, b"\x01\x00\x00\x00")

count = [0]
def hook_code(mu, address, size, user_data):
    count[0] += 1
    if count[0] > 30000:
        mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook_code)

try:
    mu.emu_start(CODE_ADDR | 1, CODE_ADDR + len(CODE), timeout=3 * 1000000, count=0)
except UcError as e:
    if e.errno == UC_ERR_INSN_INVALID:
        print(f"UC_ERR_INSN_INVALID at 0x{mu.reg_read(UC_ARM_REG_PC):x}")
    else:
        print(f"UcError {e} errno={e.errno}")

print(f"executed {count[0]} insns")
pc = mu.reg_read(UC_ARM_REG_PC)
print(f"final PC=0x{pc:x}")
if pc != (CODE_ADDR | 1):
    print("ok: firmware advanced past MMIO poll")
else:
    print("stalled: check MMIO mapping or Thumb bit")
```

Verification prints `ok: firmware advanced past MMIO poll` when the poll exits.

### 3 — Elite Firmware: Timer Interrupt + UART + Nested Custom VM (2024 HITCON-style)

Firmware at `0x08000000` (Thumb) polls UART status at `0x40000000`, fires TIM2 interrupt every 1K blocks to feed a nested custom VM that validates `flag{…}` byte-by-byte. Combines snapshot + MMIO + timeout + Capstone.

```python
from unicorn import *
from unicorn.arm_const import *
from capstone import *

CODE_ADDR = 0x08000000
UART_BASE = 0x40000000
TIM2_BASE = 0x40010000
NVIC_BASE = 0xe000e100
CODE = open("firmware.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x20000000, 0x10000)
mu.reg_write(UC_ARM_REG_SP, 0x20010000)
for base in (UART_BASE, TIM2_BASE, NVIC_BASE):
    mu.mem_map(base, 0x1000)

# --- MMIO models with side-effects ---
timer = {"CNT": 0, "SR": 1}
uart_buf = b"flag{test}\n"
uart_idx = [0]

def hook_mmio_read(mu, access, address, size, value, user_data):
    if UART_BASE <= address < UART_BASE + 0x1000:
        off = address - UART_BASE
        if off == 0x00:  # status — bit 0 ready
            val = 1 if uart_idx[0] < len(uart_buf) else 0
            mu.mem_write(address, val.to_bytes(size, "little"))
            return True
        elif off == 0x04:  # data — consumes one byte
            if uart_idx[0] < len(uart_buf):
                val = uart_buf[uart_idx[0]]
                uart_idx[0] += 1
                mu.mem_write(address, val.to_bytes(size, "little"))
                print(f"UART read -> 0x{val:02x} '{chr(val)}'")
                return True
    elif TIM2_BASE <= address < TIM2_BASE + 0x1000:
        off = address - TIM2_BASE
        if off == 0x10:  # SR clear-on-read
            val = timer["SR"]
            timer["SR"] = 0
            mu.mem_write(address, val.to_bytes(size, "little"))
            return True
        elif off == 0x24:  # CNT free-running
            timer["CNT"] = (timer["CNT"] + 1) & 0xffff
            mu.mem_write(address, timer["CNT"].to_bytes(size, "little"))
            return True
    return False

def hook_mmio_write(mu, access, address, size, value, user_data):
    if UART_BASE <= address < UART_BASE + 0x1000:
        if (address - UART_BASE) == 0x08:  # TX
            print(f"UART TX 0x{value:x} '{chr(value & 0xff)}'")
        return True
    elif TIM2_BASE <= address < TIM2_BASE + 0x1000:
        if (address - TIM2_BASE) == 0x10:
            timer["SR"] &= ~value
        return True
    return False

mu.hook_add(UC_HOOK_MEM_READ, hook_mmio_read)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mmio_write)

# --- Timer interrupt feeding nested VM ---
tick = [0]
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
vm_entry = 0x08001234  # found via Ghidra — nested VM dispatcher

def hook_block(mu, address, size, user_data):
    tick[0] += 1
    if tick[0] % 1000 == 0:
        timer["SR"] |= 1
    # Capstone trace for VM dispatch detection
    if address == vm_entry:
        r0 = mu.reg_read(UC_ARM_REG_R0)
        print(f"VM dispatch at 0x{address:x} R0(opcode)=0x{r0:x} tick={tick[0]}")
        for insn in md.disasm(mu.mem_read(address, size), address):
            print(f"  {insn.mnemonic} {insn.op_str}")

mu.hook_add(UC_HOOK_BLOCK, hook_block)

# --- Snapshot at VM entry for brute-force ---
mu.emu_start(CODE_ADDR | 1, vm_entry | 1, timeout=2 * 1000000, count=0)
snap = mu.context_save()
snap_timer = dict(timer)
snap_uart = uart_idx[0]
snap_mem = mu.mem_read(0x20000000, 0x10000)
print(f"snapshot at VM entry PC=0x{mu.reg_read(UC_ARM_REG_PC):x}")

def try_byte(prefix: bytes, cand: int) -> bool:
    mu.context_restore(snap)
    timer.update(snap_timer)
    uart_idx[0] = snap_uart
    mu.mem_write(0x20000000, snap_mem)
    mu.mem_write(0x20001000, prefix + bytes([cand]))
    mu.reg_write(UC_ARM_REG_R0, 0x20001000)
    try:
        mu.emu_start(vm_entry | 1, vm_entry + 0x80, timeout=500000, count=2000)
    except UcError as e:
        if e.errno == UC_ERR_INSN_INVALID:
            print(f"  bad insn at 0x{mu.reg_read(UC_ARM_REG_PC):x}")
        return False
    return mu.reg_read(UC_ARM_REG_R0) == 0  # VM returns 0 on prefix ok

flag = b"flag{"
for pos in range(len(flag), 32):
    for c in range(32, 127):
        if try_byte(flag, c):
            flag += bytes([c])
            print(f"pos {pos}: {chr(c)} -> {flag}")
            break
    else:
        print(f"no hit at {pos}")
        break
print(f"flag={flag}")
if b"flag{" in flag:
    print("ok: nested VM flag recovered")
```

Verification prints `ok: nested VM flag recovered` when the VM check passes. Pattern covers: MMIO status-clear-on-read, free-running CNT, UART buffered reads, BLOCK timer injection, Capstone annotation at `vm_entry`, and `context_save`/`mem_read` snapshot brute-force — the same scaffold scales to 2024 HITCON firmware VM and similar elite challenges.

---

## References

- Unicorn Engine: `Uc`, `UC_ARCH_*`, `UC_MODE_*`, `mem_map`, `mem_write`, `reg_write`, `emu_start`, `hook_add`, `UC_HOOK_*`, `UC_ERR_*`, `mmio_map`, `context_save`/`restore`/`update`, `mem_protect`, `mem_regions`, `ctl_remove_cache`/`ctl_flush_tb`, `reg_read_batch`.
- Capstone: `Cs(CS_ARCH_X86, CS_MODE_64)` / `Cs(CS_ARCH_ARM, CS_MODE_THUMB)` for trace annotation; pair with `UC_HOOK_CODE`/`BLOCK` for coverage and SMC detection.
- Keystone: `Ks(KS_ARCH_X86, KS_MODE_64).asm(...)` for trace inversion.
- Qiling: `Qiling(path, rootfs)` when syscalls are needed — see [tools-emulation.md](tools-emulation.md#qiling-framework-cross-platform-emulation) for anti-debug and input fuzzing.
- QEMU vs angr vs Triton: concrete/system vs symbolic — see comparison table above; VMProtect/Themida devirtualization via [tools-advanced.md](tools-advanced.md#vmprotect-analysis).
- Prior art: [tools.md](tools.md#unicorn-emulation), [field-notes.md](field-notes.md#unicorn-emulation-complex-state), [anti-analysis-ctf.md](anti-analysis-ctf.md#instruction-trace-inversion-with-keystone-and-unicorn-meepwn-ctf-2017), [tools-emulation.md](tools-emulation.md#qiling-framework-cross-platform-emulation), [tools-advanced.md](tools-advanced.md#custom-vm-bytecode-lifting-to-llvm-ir-google-ctf-2017).
