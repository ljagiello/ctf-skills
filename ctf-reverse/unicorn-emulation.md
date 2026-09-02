# Unicorn CPU Emulation

Raw binary and bare-metal emulation with Unicorn Engine. Sometimes easier to rev with just Unicorn + binary + assembly than a full GDB/angr session.

## Table of Contents

- [When Unicorn Beats GDB / angr / Qiling](#when-unicorn-beats-gdb--angr--qiling)
- [Setup Scaffold](#setup-scaffold)
- [Hook Cookbook](#hook-cookbook)
- [ARM / MIPS / Thumb](#arm--mips--thumb)
- [Mixed-Mode 64 to 32 via retf](#mixed-mode-64-to-32-via-retf)
- [Firmware MMIO Emulation](#firmware-mmio-emulation)
- [Keystone + Unicorn Trace Inversion](#keystone--unicorn-trace-inversion)
- [Shellcode Unpack](#shellcode-unpack)
- [Custom VM Emulation](#custom-vm-emulation)
- [Qiling vs Unicorn Decision Tree](#qiling-vs-unicorn-decision-tree)
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
CODE = open("shellcode.bin", "rb").read()

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
    print(f"UcError {e} errno={mu.errno} at 0x{mu.reg_read(UC_X86_REG_RIP):x}")
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
# Filtered: mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x401000, end=0x401000)

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
           UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7]:
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
shellcode = open("shellcode.bin", "rb").read()

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

Iterative solver: brute-force VM input byte-by-byte via `try_byte` pattern above. For LLVM IR lifting, see [tools-advanced.md](tools-advanced.md#custom-vm-bytecode-lifting-to-llvm-ir).

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

## Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| `timeout` vs `count` | Both non-zero stops on whichever first | Use one, set other to `0` |
| Stack at `0x0` | Null deref silently succeeds | Map stack at `0x7fff0000` |
| Thumb LSB | `UC_ERR_INSN_INVALID` | `CODE_ADDR \| 1` + `UC_MODE_THUMB` |
| `UC_ERR_FETCH_UNMAPPED` | Branch to unmapped region | Hook `MEM_INVALID` or map region |
| Hook re-entrance | `reg_write`/`mem_write` re-triggers hook | Guard flag or `MEM_READ_AFTER` |
| MIPS endianness | First insn invalid | Match `LITTLE`/`BIG_ENDIAN` to binary |
| Mixed-mode EFLAGS/XMM | Stale flags, zeroed SSE | Copy `RFLAGS & 0xffffffff`, copy `XMM0-7` |
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
    print(f"emulation stopped: {e} errno={mu.errno}")

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

---

## References

- Unicorn Engine: `Uc`, `UC_ARCH_*`, `UC_MODE_*`, `mem_map`, `mem_write`, `reg_write`, `emu_start`, `hook_add`, `UC_HOOK_*`, `UC_ERR_*`, `mmio_map`.
- Capstone: `Cs(CS_ARCH_X86, CS_MODE_64)` / `Cs(CS_ARCH_ARM, CS_MODE_THUMB)` for trace annotation.
- Keystone: `Ks(KS_ARCH_X86, KS_MODE_64).asm(...)` for trace inversion.
- Qiling: `Qiling(path, rootfs)` when syscalls are needed.
- Prior art: [tools.md](tools.md#unicorn-emulation), [field-notes.md](field-notes.md#unicorn-emulation-complex-state), [anti-analysis-ctf.md](anti-analysis-ctf.md#instruction-trace-inversion-with-keystone-and-unicorn-meepwn-ctf-2017), [tools-emulation.md](tools-emulation.md#qiling-framework-cross-platform-emulation).
