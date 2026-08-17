# Disassembly Recipe — Function Discovery, Symbols, Decompilation

## When this applies

- You have a stripped binary (no symbols) and need to identify functions, name them, and reconstruct algorithm logic.
- Cross-platform: ELF, PE, or Mach-O.
- Trigger: any RE task where the disassembler needs guidance to find structure.

## Technique

Function discovery is mostly automatic in modern tools, but symbol recovery, type inference, and pseudo-code refinement remain manual. The workflow: auto-analyze → triage entry/main → walk imports backwards → name functions → rebuild types → decompile → annotate.

## Steps

### 1. Auto-analyze

```bash
# Ghidra: File > New Project > Import binary > "Analyze" with default options
# IDA: File > Open > "OK" through autoanalysis

# r2:
r2 -A binary
> aaaa     # the most aggressive analysis pass
```

Wait for full analysis (large binaries: 5-20 minutes in Ghidra).

### 2. Find entry and main

| Pattern | Anchor |
|---|---|
| ELF Linux x86_64 | `_start` → `__libc_start_main(main, ...)` — main is first arg |
| PE Windows | `mainCRTStartup` → `main(argc, argv, envp)` or `WinMainCRTStartup` → `WinMain` |
| ELF Statically linked Go | Look for `runtime.main` and `main.main` |
| ELF Rust | `_start` → `std::rt::lang_start` → main pointer |
| Stripped, anchor | Cross-reference well-known strings like `"%s\n"`, prompts, or library names |

### 3. Function discovery for stripped binaries

Auto-analysis catches calls but misses tail-call-only functions and ones called only via function pointers. For each:

- **Function pointer arrays**: scan `.rodata` / `.data` for tables of valid code addresses (sequences of pointers ending in `0`).
- **Tail calls**: a `jmp` to an unanalyzed address — likely a function. Mark and re-analyze.
- **Indirect calls**: `call [rax]` patterns — find the dispatch table.

```python
# Ghidra script: find all uncategorized code blobs
for f in currentProgram.functionManager.getFunctions(True):
    if f.body.numAddresses < 5:    # suspicious tiny "function"
        print(f.name, f.entryPoint)
```

### 4. Symbol recovery

For stripped Linux binaries, useful sources:

- **Strings + xrefs.** "Open log file %s" referenced from `0x401234` ⇒ that address is `open_log_file`.
- **Library function signatures.** `strcmp`, `memcpy`, `printf` patterns are recognizable; rename and the decompiler reads better.
- **FLAIR / SigKit / BinDiff signatures.** IDA FLIRT signatures, Ghidra's BSim, and Binary Ninja's signature library auto-rename library functions.
- **Public symbols from a similar binary.** If you have a non-stripped variant of a related binary, BinDiff propagates names.

### 5. Type recovery

Decompilers infer types from operations:
- 8-byte loads ⇒ pointer or `long`.
- 4-byte loads in 64-bit binary ⇒ `int`.
- Pointer arithmetic with stride 0x18 ⇒ struct of size 0x18.

Define structs in the decompiler:
```
// Ghidra: Data Type Manager > New > Structure
typedef struct {
    uint32_t id;        // +0x00
    char name[32];      // +0x04
    void *next;         // +0x24
} Node;
```

Apply via right-click "Auto Create Structure" or manually retype variables.

### 6. Decompile and annotate

In Ghidra's decompiler view:
- `L` to retype variable.
- `Ctrl+L` to rename.
- Enter on a function call to follow.

Iteratively rename + retype until pseudo-code reads as understandable C. Targets:

```c
// before
undefined8 FUN_004012a0(undefined8 param_1, char *param_2)
{
    *(int *)(DAT_006020c8 + 0x18) = strcmp(param_2, "secret");
    ...
}

// after
int verify_password(Session *session, char *input) {
    session->result = strcmp(input, "secret");
    ...
}
```

### 7. Cross-reference and document

For each interesting function, capture:
- Inputs (registers / stack args).
- Outputs (return register, side-effect memory writes).
- Invariants (state machine transitions).
- Calls made (hash, memcpy, system).

A simple `notes.md` listing each named function and its purpose accelerates the rest of the work.

## Verifying success

- Decompiler output reads as comprehensible pseudo-C.
- All "interesting" functions named with descriptive identifiers.
- A test input traces through the algorithm in your head.
- (For solver tasks) you can recompute the validation in Python and match the binary's behavior on a test vector.

## Common pitfalls

- **Trusting auto-analysis blindly.** Tail-call-only and indirect-call-only functions may be missed.
- **Over-typing.** Defining a 200-field struct when 5 fields suffice slows the work and confuses the decompiler.
- **Not cross-checking decompilers.** Ghidra and IDA disagree on edge cases (stack overlap, optimized loops); cross-check ambiguous output.
- **Skipping rename pass.** Default `FUN_xxx` / `local_42` names make even small programs incomprehensible at scale.

## Tools

- `Ghidra` — best free decompiler, scriptable in Python/Java.
- `IDA Pro` — best for niche architectures, FLIRT signatures.
- `Binary Ninja` — modern API, MLIL/HLIL.
- `radare2` / `Cutter` — CLI / GUI free pair.
- `BinDiff` / `Diaphora` — cross-binary symbol propagation.
- `BSim` (Ghidra plugin) — function-similarity search across a corpus.
