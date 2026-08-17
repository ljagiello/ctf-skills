# Reversing — Custom Stack/Register VM Pattern

A common Reversing-challenge pattern: a small ELF host binary that loads a "program" file (often a `.bin`, `.asm`, `.txt`, or a domain-themed extension like `.recipe`) and interprets it under a custom ISA. The check logic lives in the program, not the host.

## Recognising it
- Two-file delivery: `host_binary` + `programdata`.
- `strings` on the host shows opcode mnemonics, register names, themed words.
- Disassembly reveals a dispatcher loop: `while(true){ op = mem[pc++]; switch(op){...}; }` or a jump table indexed by opcode.
- Often a small fixed-size buffer (e.g. 256 bytes — the "tape", "kitchen", "world") with a cursor.
- A baked-in constant is compared against transformed user input.

## Step-by-step recovery (static, no execution required)

1. **Inventory the dispatcher.** Find the main loop. List every opcode handler. Map each handler to a Python lambda mirroring its semantics (read regs/mem, modify regs/mem, advance PC).
2. **Identify side-channel ops.** Look for I/O (read input, print result), comparison (success/failure path), and "win" string (e.g. `Nice!`, `Correct`).
3. **Disassemble the program file.** Walk it linearly with the opcode map, producing a human-readable listing.
4. **Trace forward symbolically.** Treat the input bytes as 32 (or N) symbolic vars; apply each transformation; arrive at the comparison. The comparison constant is your target.
5. **Invert.** Each transformation is usually a permutation/scatter/XOR — all bijective. Compose inverses in reverse order to recover the input that produces the win-state.
6. **Validate.** Run the recovered input through your re-emulated VM in Python and confirm it triggers the success branch. Only then submit.

## Common ISAs seen
- **Stack VM**: PUSH, POP, ADD, SUB, MUL, XOR, AND, OR, NOT, DUP, SWAP, LDM, STM, JMP, JZ, JNZ, CALL, RET, IN, OUT.
- **Register VM**: RA, RB, RC… with MOV REG, REG / MOV REG, IMM / arithmetic / branch.
- **Tape VM** (Brainfuck-style): single tape pointer, +/-/</>/[/]/.,
- **Mixed**: domain-themed ISA where opcode bytes are picked to look like ASCII letters.

## Python re-emulator skeleton

```python
def emulate(program: bytes, input_bytes: bytes) -> bytes:
    tape = bytearray(256)
    cursor = 0x100  # check the disassembly for actual cursor base
    pc = 0
    in_idx = 0
    while pc < len(program):
        op = program[pc]; pc += 1
        if op == OP_READ:
            tape[cursor] = input_bytes[in_idx]; in_idx += 1
        elif op == OP_PERMUTE:  # custom shuffle on a window
            ...
        elif op == OP_CMP:
            target = program[pc:pc+32]; pc += 32
            return tape[cursor-32:cursor] == target
        # ... etc
    return False
```

Use the emulator both for **forward** (solver verification) and as a **reference oracle** when bytes/order in your inversion feel wrong.

## Worked examples

- **Domain-themed ISA + scatter permute**: a host binary with a themed ISA (e.g. cooking-themed: `cook` host + `recipe.asm` program), 13 opcodes, 256-byte working area, per-4-byte-block permute `(a,b,c,d)→(c,b,d,a)` then scatter via a 32-entry index list to a compare-region. Invert in pure Python and validate by full re-emulation; doable entirely static even when the host won't execute on the solver's CPU.
- **XOR-encrypted handlers + stack VM**: 28-opcode stack VM with **24 handlers XOR-encrypted in `.data`** under a 6-byte rolling key, decrypted+mmap'd RWX at startup; 4 handlers in `.text`. Bytecode reads a 32-char password, permutes into 8 LE u32 words, ROL32 each by fixed amounts, subtracts 8 hardcoded constants and JNZ-chains. Inversion: `w_i = ROR32(constant_i, rot_i)`. **Gotcha:** if PUSH uses `mov edi,[rax]; mov [..],rdi` it **zero-extends** 32-bit imm to 64-bit — emulator must mask with `0xFFFFFFFF`, sign-extension breaks the equality chain on negative constants.

## Callfuscation (control-flow chunking) — recognise and linearize

A binary may slice `main` into ~thousands of tiny chunks of shape `pop r8 ; body ; call next`. Each `call` is a glorified `jmp` (the popped return address is dead). To recover the original control flow:

1. Treat the binary as a graph: each chunk is a node, each `call` a directed edge to the next chunk.
2. Walk the graph from the entry point, capturing both branches at conditional jumps. Tools: a small Python script that reads disassembly via Capstone and iterates.
3. Concatenate the chunk bodies in DFS order to reconstruct linear assembly.

Once linearized, the underlying program is usually a small VM (see above).

## MBA (Mixed Boolean-Arithmetic) operator obfuscation

After linearization, individual operators (`+`, `-`, `&`, `|`, `^`) are often wrapped as separate functions full of junk `not/and/or/imul`-with-primes and possibly `rand()` calls for noise. To identify each wrapper:

1. Probe the function with N small known inputs (e.g. all (a,b) pairs with a,b ∈ {0..7}).
2. Match outputs against tables of `+ − * & | ^ 0 a b` to identify the underlying op.

Pure Python `Unicorn` or `qiling` emulator handles 256 probe pairs per function in seconds.

## Worked example — three-layer deobfuscation

When you encounter all three layers stacked (callfuscation + custom VM + MBA): Layer 1 is ~thousands of callfuscation chunks; Layer 2 is a small-opcode (e.g. 11) stack VM with hundreds of dwords of bytecode built on the stack from constants; Layer 3 wraps each binary operator (`+ − & | ^`) in a 50–200-byte MBA function. Pipeline: linearize chunks → identify VM dispatcher → emulate to dump bytecode → probe each MBA wrapper to its underlying op → walk bytecode at the VM level. Common validator shape: `(BE_u32(block) XOR K1) − K2` for N blocks where success needs each block = `K1 XOR K2`. Pattern-match the `(K1,K2)` pairs in bytecode → answer in <1s.

## Encrypted-handler trick to watch for
Some VMs encrypt their handler functions in `.data`/`.rodata` and decrypt them at runtime to a freshly-mmap'd RWX region. Static disassembly of `.text` then shows just the dispatcher and stub jumps to the new region. Recovery:
1. Dump the encrypted bytes from the binary section (radare2 `pxx`, `objdump -s`).
2. Find the decryption loop at startup — it's usually the first thing `main()` does. Note the key (often a small repeating buffer in `.data`) and the algorithm (XOR / rolling-XOR / RC4).
3. XOR-decrypt offline, then disassemble the result with capstone. Now you have all opcode handlers.

## Anti-patterns
- Don't try to run the host binary blindly — half the time it's the wrong arch / wants a TTY / has anti-debug.
- Don't write the disassembler in Ghidra scripting unless the program is large; pure Python with the manual opcode map is faster for ≤200 instructions.
- Don't skip the validation step — small typos in opcode semantics lead to wrong flags that look plausible.
