# CTF Pwn - MCP Server Integration

MCP servers accelerate the two halves of a pwn workflow: **understanding** the
binary (decompile the vulnerable function) and **debugging** the exploit
(inspect crash state, heap, registers). For static decompilation via IDA/Ghidra
MCP the authoritative reference is [../ctf-reverse/tools-mcp.md](../ctf-reverse/tools-mcp.md);
this file covers the pwn-specific angle plus **WinDbg MCP** for Windows targets.

## Table of Contents
- [WinDbg MCP (Windows Crash Dumps & Live Debugging)](#windbg-mcp-windows-crash-dumps--live-debugging)
- [IDA / Ghidra MCP for Exploit Development](#ida--ghidra-mcp-for-exploit-development)

---

## WinDbg MCP (Windows Crash Dumps & Live Debugging)

Repository: `https://github.com/svnscha/mcp-windbg` (MIT, tested v1.0.0+).
Bridges WinDbg/CDB to the agent so you can "debug in natural language" — analyze
crash dumps, walk the stack, and inspect heap state without memorizing every
`!` extension.

**Setup:**

```bash
# Requires the Windows SDK "Debugging Tools for Windows" (provides cdb.exe)
pip install mcp-server-windbg
# Point the server at cdb.exe via CDB_PATH, then connect your MCP client, e.g.:
#   set CDB_PATH=C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe
```

**Core tools:**

- `open_windbg_dump` — load a `.dmp` crash dump
- `run_windbg_cmd` — run any cdb command (`!analyze -v`, `k`, `lm`, `!heap`, `dq`, `u`)
- `list_windbg_dumps` — enumerate dumps in a directory
- `open_windbg_remote` — attach to a live/remote user-mode or kernel target
- `close_windbg_dump` — release the session

**Crash-triage loop for a Windows pwn target:**

```text
open_windbg_dump crash.dmp
run_windbg_cmd "!analyze -v"        # auto-triage: faulting instruction, exception
run_windbg_cmd "k"                  # call stack at the crash
run_windbg_cmd "r"                  # registers — did we control eip/rip?
run_windbg_cmd "!exchain"           # SEH chain (classic SEH overwrite target)
run_windbg_cmd "dds esp L20"        # stack contents to find our cyclic pattern
run_windbg_cmd "!heap -p -a <addr>" # heap block owner for UAF/overflow analysis
```

**Exploit-dev use-cases:**

- Confirm EIP/RIP control after a cyclic-pattern crash (pair with `pwntools`
  `cyclic_find`); see [SKILL.md](SKILL.md#stack-buffer-overflow).
- Inspect the SEH chain for SEH-overwrite exploits (see
  [advanced-exploits-4.md](advanced-exploits-4.md) — Windows SEH + VirtualAlloc ROP).
- Verify CFG state and locate `system()`-style call targets for CFG bypass.
- Walk the heap (`!heap`) to validate grooming/overlap primitives.

**Key insight:** `!analyze -v` gives the agent an instant crash summary
(faulting address, exception code, probable cause) that would take many manual
steps in a GUI. Drive it via `run_windbg_cmd` and let the agent parse the output
to decide the next exploit step — it turns dump analysis into an automated triage
loop. For live local debugging on Windows, x64dbg is still the interactive
alternative (see [../ctf-reverse/tools-dynamic.md](../ctf-reverse/tools-dynamic.md#x64dbg-windows-debugger)).

---

## IDA / Ghidra MCP for Exploit Development

Use the decompiler MCP servers from
[../ctf-reverse/tools-mcp.md](../ctf-reverse/tools-mcp.md) to find and understand
the vulnerability before writing the exploit — **pseudocode first, assembly only
when it fails** (same golden rule).

**Pwn-specific queries:**

```text
decompile_function <handler>        # spot the unchecked memcpy/gets/scanf("%s")
get_xrefs_to <read_input>           # every path that reaches the vulnerable buffer
decompile_function <win/backdoor>   # confirm a ret2win target + required args
list_functions                      # locate system/execve wrappers, syscall stubs
disassemble_function <gadget_area>  # ONLY when hunting exact bytes for gadgets
```

**Where MCP helps most in pwn:**

- Locating the bug: read the handler as pseudo-C to see the missing bounds check
  instead of eyeballing assembly.
- Finding ret2win / magic-value functions and their exact argument requirements.
- Recovering struct layouts (`set_function_prototype`, `declare_c_type` in IDA)
  so heap-overflow offsets are exact.
- Confirming the comparison direction for canary/flag checks before committing to
  an exploit strategy (see [SKILL.md](SKILL.md#protection-implications-for-exploit-strategy)).

**Key insight:** In pwn you eventually need exact bytes (gadgets, offsets), so you
*will* drop to assembly — but only after the decompiler has told you *which*
function and *which* check to attack. Start every pwn target by decompiling the
input handler; move to `disassemble_function` / ROPgadget once you know the target
and need instruction-level precision.
