# Callfuscation — Control-Flow Chunking via call/ret

## When this applies

- A binary contains thousands of tiny code chunks of shape `pop r8 ; <body> ; call <next>`.
- The `call` is functionally a `jmp` — the popped return address (the `pop r8`) is dead.
- Disassembler shows extremely fragmented control flow; no recognizable functions of length > 30 instructions.
- Trigger keywords: "callfuscation", "call/ret obfuscation", "control flow flattening", "code chunking".

## Technique

Each chunk is a node in a directed graph; each `call` is an edge to the next chunk. Walk the graph from the entry to reconstruct linear assembly. The chunks themselves are usually unobfuscated — once concatenated in DFS order, normal RE proceeds.

## Steps

### 1. Confirm the pattern

In disassembly, look at multiple "functions": each starts with `pop` (consuming the dead return address) followed by 5-30 instructions and ends with `call <imm>`. The `<imm>` jumps to another such block.

```asm
chunk_004012a0:
    pop    r8
    mov    rax, qword ptr [rbp - 0x10]
    add    rax, 1
    mov    qword ptr [rbp - 0x10], rax
    call   chunk_00405b30        ; not a real call — a `jmp`

chunk_00405b30:
    pop    r8
    cmp    qword ptr [rbp - 0x10], 0x10
    jz     chunk_004099c0
    call   chunk_00408120
    ...
```

### 2. Parse chunks programmatically

```python
# Capstone-based linearization
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

with open('binary.bin', 'rb') as f:
    code = f.read()

base = 0x400000

def parse_chunk(addr):
    """Return (instructions, next_chunk_addr or None, is_conditional, alt_addr)."""
    insns = []
    pc = addr - base
    for i in md.disasm(code[pc:], addr):
        if i.mnemonic == 'pop' and not insns:
            continue   # skip prologue pop
        insns.append(i)
        if i.mnemonic in ('call', 'jmp'):
            # immediate target only
            try:
                target = int(i.op_str, 16)
            except ValueError:
                target = None
            return insns, target, False, None
        if i.mnemonic.startswith('j'):
            # conditional branch: chunk continues at fallthrough AND at jump target
            target = int(i.op_str, 16)
            return insns, i.address + i.size, True, target
    return insns, None, False, None
```

### 3. Walk DFS from entry

```python
visited = {}
order = []

def walk(addr):
    if addr in visited: return
    visited[addr] = True
    insns, nxt, cond, alt = parse_chunk(addr)
    order.append((addr, insns))
    if cond:
        walk(alt)
        walk(nxt)
    elif nxt:
        walk(nxt)

walk(entry)
```

### 4. Concatenate in DFS order

Emit a linear assembly listing where each chunk is preceded by a label and conditional jumps remain (now pointing to local labels). This produces a normal-looking function ready for further analysis.

```python
for (addr, insns) in order:
    print(f"L_{addr:x}:")
    for i in insns:
        if i.mnemonic in ('call',):  # rewrite as jmp comment
            print(f"    jmp L_{int(i.op_str, 16):x}    ; was call")
        else:
            print(f"    {i.mnemonic} {i.op_str}")
```

### 5. Feed back into disassembler

If the binary is large, write the linearized listing as a new ELF/PE or patch the original to replace `call` with `jmp` (one-byte opcode change: `E8 → E9`). Then auto-analysis recovers the original function shape and the decompiler works normally.

### 6. Recognize the next layer

Often callfuscation hides a custom VM. After linearization, look for dispatcher loops — see `scenarios/custom-vm/bytecode-disassembly.md`.

## Verifying success

- Linearized listing reads as normal assembly with no `pop` prologue noise.
- Decompiler now produces reasonable pseudo-C.
- Cross-references work (functions are recognized as such).
- Dynamic test: the linearized version, if assembled and run, exhibits the same behavior.

## Common pitfalls

- **Indirect calls.** `call rax` cannot be statically resolved — annotate as unknown and continue with both fallthrough and known targets.
- **Tail-call vs callfuscation.** Real tail calls also use `jmp` — don't rewrite legitimate library calls.
- **`pop` is real.** Some prologues genuinely use `pop` (callee-saved register restore). Confirm by checking the value popped is `r8`/`rax` (typical dead register) and never read.
- **Stack imbalance.** If you patch `call → jmp` without adjusting the stack, real follow-up `ret` instructions misbehave. Either patch all `call`s to `jmp`s consistently, or also remove the matching dead `pop`s.
- **Conditional fallthrough.** A `jcc` chunk has two successors; missing one half of the graph silently drops branches.

## Tools

- `Capstone` (Python bindings) — chunk parser.
- `Keystone` — for re-assembling the linearized output if patching the binary.
- `IDA Pro` plugins: `D810` (deobfuscator), `HexRaysDeob`.
- `Ghidra` Sleigh + custom processor module — patch call instructions for analysis.
- `bin-diff` between original and linearized — sanity check.
