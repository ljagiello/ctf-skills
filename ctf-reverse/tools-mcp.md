# CTF Reverse - MCP Server Integration

Model Context Protocol (MCP) servers let the agent drive a disassembler/decompiler
directly instead of copy-pasting from a GUI. For reverse engineering the three
that matter are **IDA Pro MCP**, **Ghidra MCP**, and **JADX MCP** (Android). This
file is the authoritative MCP reference — `ctf-pwn` and `ctf-malware` cross-link
here for the shared tooling and only document their own use-cases.

## Table of Contents
- [Golden Rule: Pseudocode First, Assembly Only When It Fails](#golden-rule-pseudocode-first-assembly-only-when-it-fails)
- [IDA Pro MCP (Agent-Driven Decompilation)](#ida-pro-mcp-agent-driven-decompilation)
- [Ghidra MCP (Free Decompiler, Autonomous RE)](#ghidra-mcp-free-decompiler-autonomous-re)
- [JADX MCP (Android APK / DEX)](#jadx-mcp-android-apk--dex)
- [When to Use MCP vs CLI](#when-to-use-mcp-vs-cli)

For WinDbg MCP (Windows crash dumps, live debugging) see
[../ctf-pwn/tools-mcp.md](../ctf-pwn/tools-mcp.md). For the older Ghidra
`MCP Commands` quick list see [tools.md](tools.md#mcp-commands).

---

## Golden Rule: Pseudocode First, Assembly Only When It Fails

**Always call the decompiler before touching disassembly.** IDA (Hex-Rays) and
Ghidra both expose a `decompile`/`decompile_function` tool that returns readable
pseudo-C. Read that first — it collapses hundreds of instructions into a few lines
of logic you can reason over in one pass, and it is dramatically cheaper in agent
tokens than stepping through assembly.

```text
# Preferred order for any function of interest
1. decompile <func>        # read the logic as pseudo-C   ← default
2. xrefs_to <target>       # follow data/call relationships
3. rename / set_comment    # persist understanding in the database
4. disassemble <func>      # ONLY if decompiler output is wrong/missing
```

Drop to assembly (`disassemble_function` / `disasm`) **only** when the decompiler
bails out or lies:

- Heavy obfuscation, opaque predicates, or control-flow flattening
- Hand-written assembly / shellcode with no clean C representation
- Missing or corrupt function boundaries (define the function first, then retry)
- Instruction-level details the decompiler hides (exact SIMD ops, alignment,
  timing gadgets, syscall numbers)

**Key insight:** The decompiler is the map; the disassembly is the terrain. Start
with the map. A single `decompile` call often reveals the whole flag-checking
algorithm (XOR loop, comparison target, custom hash), letting you skip 90% of the
manual assembly reading. Only zoom into instructions when the map is blank or
wrong.

---

## IDA Pro MCP (Agent-Driven Decompilation)

Repository: `https://github.com/mrexodia/ida-pro-mcp` (MIT, tested v1.4.0+).
Author is the maintainer of x64dbg — the de-facto standard IDA MCP server.

**Setup:**

```bash
pip install ida-pro-mcp
ida-pro-mcp --install        # installs the IDA plugin + registers the MCP server
# Then open the target in IDA; the plugin exposes an MCP endpoint the client connects to.
# Headless mode uses idalib (no GUI) — see the repo README for the idalib server.
```

**Core tools (names may vary slightly by version):**

- Recon: `list_functions`, `list_strings`, `list_globals`, `get_metadata`, `get_entry_points`
- Analysis: `decompile_function`, `disassemble_function`, `get_function_by_name`, `get_xrefs_to`
- Annotation: `rename_function`, `rename_local_variable`, `set_comment`, `set_function_prototype`, `declare_c_type`
- Debugging (if enabled): `dbg_start_process`, `dbg_get_registers`, `dbg_read_memory`, breakpoints

**Recon → analysis → annotation loop for a flag-checker:**

```text
list_functions                      # locate main / check / validate
list_strings                        # spot "Correct!" / "flag{" / prompts
get_xrefs_to <"Correct!" addr>      # find the function that prints success
decompile_function <check_fn>       # READ pseudo-C first (golden rule)
get_xrefs_to <cmp_target>           # where is the expected value compared?
rename_function <sub_401xxx> verify # annotate as understanding grows
set_comment <addr> "XOR key = 0x5A" # leave breadcrumbs for later queries
```

**Key insight:** MCP turns IDA into a queryable oracle. The agent reads
pseudocode and follows cross-references with no human in the loop, then writes
annotations back into the IDB so later queries build on earlier understanding.
Prefer this over `objdump`/`strings` once the binary is large or the decompiler
output is essential to understanding the logic.

---

## Ghidra MCP (Free Decompiler, Autonomous RE)

Repository: `https://github.com/LaurieWired/GhidraMCP` (Apache-2.0, tested v1.4+).
The most popular MCP bridge for the free NSA Ghidra decompiler — use it when you
do not have an IDA license.

**Setup:**

```bash
# 1. In Ghidra: File > Install Extensions > add GhidraMCP-*.zip, then restart
# 2. Enable the GhidraMCPPlugin (File > Configure > Miscellaneous)
# 3. Run the Python bridge that exposes the MCP server:
pip install mcp requests
python bridge_mcp_ghidra.py       # from the repo; connects Ghidra <-> MCP client
```

**Core tools:**

- Recon: `list_methods`, `list_classes`, `list_imports`, `list_exports`, `list_segments`, `list_strings`
- Analysis: `decompile_function`, `disassemble_function`, `get_function_by_address`, `search_functions_by_name`
- Xrefs: `get_xrefs_to`, `get_xrefs_from`, `get_function_xrefs`
- Annotation: `rename_function`, `rename_variable`, `rename_data`, `set_decompiler_comment`, `set_function_prototype`

**Autonomous triage loop:**

```text
list_methods                        # enumerate functions
search_functions_by_name check      # find candidate validators
decompile_function <FUN_00101xxx>   # pseudo-C first
get_xrefs_to <g_expected>           # trace the comparison target
rename_function <FUN_00101xxx> validate_flag
set_decompiler_comment <addr> "input[i] ^ 0x2a compared here"
```

**Key insight:** Ghidra MCP gives the same agent-driven workflow as IDA MCP for
free. Ghidra's decompiler occasionally reads a construct more clearly than
Hex-Rays (and vice versa) — if one MCP server produces confusing pseudocode,
cross-check with the other, mirroring the dogbolt.org approach in
[tools.md](tools.md#decompiler-comparison-with-dogboltorg).

---

## JADX MCP (Android APK / DEX)

Repository: `https://github.com/zinja-coder/jadx-ai-mcp` (Apache-2.0, tested
v6.4.0+). Ships as a JADX-GUI plugin (`jadx-ai-mcp`) plus a companion
`jadx-mcp-server`; install both.

**Setup:**

```bash
# 1. Drop the jadx-ai-mcp plugin jar into JADX-GUI (Plugins > install), open the APK
# 2. Run the companion server (uses uv / fastmcp) and point your MCP client at it:
uvx jadx-mcp-server        # or follow the repo README for manual launch
```

**Core tools:**

- Recon: `get_all_classes`, `search_method_by_name`, `get_main_activity`, `get_manifest`
- Source: `get_class_source`, `get_method_code`, `get_methods_of_class`, `get_fields_of_class`
- Smali/resources: `get_smali_of_class`, `get_strings`, `list_all_resource_files`, `get_resource_file`
- Live context: `fetch_current_class`, `get_selected_text` (what the analyst is viewing in JADX-GUI)

**Android flag-hunting loop:**

```text
get_manifest                        # entry activity, permissions, exported components
get_main_activity                   # where execution starts
search_method_by_name check         # locate the validator (checkFlag/verify/onClick)
get_method_code <checkFlag>         # read decompiled Java first
get_strings                         # hardcoded keys, URLs, "flag{" fragments
get_smali_of_class <Crypto>         # drop to smali only if Java decompile is broken
```

**Key insight:** Same pseudocode-first principle — read `get_method_code`
(decompiled Java) before `get_smali_of_class` (bytecode). JADX MCP pairs well with
Frida for the dynamic half: use JADX MCP to find the method statically, then hook
it with Frida to dump runtime values (see
[tools-dynamic.md](tools-dynamic.md#frida-for-androidios)).

---

## When to Use MCP vs CLI

| Situation | Use |
|-----------|-----|
| Large binary, need to read many functions as pseudo-C | MCP (IDA/Ghidra) |
| Following xrefs, renaming, building understanding iteratively | MCP |
| Quick plaintext flag / string triage | CLI (`strings`, `rabin2 -z`) — faster |
| One-off disassembly of a single function | CLI (`objdump -d`) is fine |
| Android: understand class structure and Java logic | MCP (JADX) |
| Symbolic solve of a flag-checker | angr (see [tools-dynamic.md](tools-dynamic.md#angr-symbolic-execution)) |
| Runtime value extraction from obfuscated code | Frida (see [tools-dynamic.md](tools-dynamic.md)) |

**Key insight:** MCP shines for iterative, understanding-heavy analysis where the
agent needs to read decompiler output and follow relationships. For one-shot
recon (`file`, `strings`, `checksec`) the CLI quick-wins in
[SKILL.md](SKILL.md#quick-wins-try-first) are still faster — reach for MCP once you
are past triage and actually reversing logic.
