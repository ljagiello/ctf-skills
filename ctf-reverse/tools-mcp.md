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

For WinDbg MCP (Windows crash dumps, live user-mode debugging, kernel debugging)
see [../ctf-pwn/tools-mcp.md](../ctf-pwn/tools-mcp.md#windbg-mcp-windows-crash-dumps-live--kernel-debugging).
For the older Ghidra
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

Repository: `https://github.com/mrexodia/ida-pro-mcp` (MIT). Author is the
maintainer of x64dbg — the de-facto standard IDA MCP server. It runs in **two
modes**, and the tool names differ between them:

- **GUI plugin** — `ida-pro-mcp --install` adds a plugin that serves an HTTP MCP
  endpoint (default `http://127.0.0.1:13337/mcp`) while the target is open in the
  IDA GUI. Classic short names: `list_functions`, `decompile_function`,
  `get_xrefs_to`, `rename_function`, `set_comment`.
- **idalib headless** — a standalone `idalib-mcp` server drives IDA with no GUI
  and exposes a **richer, session-based** toolset (`survey_binary`,
  `analyze_function`, `trace_data_flow`, a query DSL, `make_signature`, `patch`).
  This is the higher-leverage mode for autonomous solving; prefer it when set up.

**Setup:**

```bash
pip install ida-pro-mcp
ida-pro-mcp --install          # GUI mode: open target in IDA, client connects to :13337
# Headless (no GUI) is the idalib-mcp server; it manages IDA sessions itself. Verify:
#   claude mcp list            # the idalib server should read "Connected"
```

**Session model (idalib headless):** every call takes a `database` session id
returned by `idb_open` — open the binary first, then thread that id through.

```text
idb_open input_path=/path/to/chall   # opens + auto-analyzes + warms Hex-Rays
# -> {"success":true,"session":{"session_id":"f0bbe3af",...}}
#    the id you need is session.session_id, NOT a top-level "session" string
idb_list                             # enumerate open sessions (server_health probes one)
# pass database="f0bbe3af" to EVERY subsequent tool call
idb_save database=f0bbe3af           # persist annotations back to the .i64
```

Two `idb_open` options worth knowing:

- **`idle_ttl_sec` (default 600)** — the headless worker self-exits after 10
  minutes idle, taking the session with it. On a long challenge raise it, or
  expect `database=<id>` to start failing after a thinking break. The worker also
  holds `.id0/.id1/.nam` locks next to the binary until it exits.
- **`mode`** — `prefer_headless` (default), `force_headless`, `prefer_gui`
  (adopt a running IDA GUI if present), `force_gui`. Use `prefer_gui` when you
  want your annotations to show up in the GUI you already have open.

**Core tools (idalib names; GUI-plugin equivalent in parentheses):**

- Triage: `survey_binary` (one-call whole-binary overview), `list_funcs`
  (`list_functions`), `list_strings`, `list_imports`, `list_globals`, `list_segments`
- Query DSL: `func_query`, `insn_query`, `xref_query`, `type_query`,
  `imports_query` — filter by name regex / size / type-info with pagination
- Analysis: `decompile` (`decompile_function`), `analyze_function` (pseudocode +
  strings + constants + callers + callees + xrefs + blocks in one call), `disasm`
  (`disassemble_function`), `basic_blocks`, `callgraph`, `callees`
- Xrefs & data flow: `xrefs_to` (`get_xrefs_to`), `xrefs_to_field`,
  `trace_data_flow` (auto multi-hop, `direction=forward|backward`, `max_depth`)
- Search: `find` (one call, many targets; `type` = `string` | `immediate` |
  `data_ref` | `code_ref`), `search_text` (rendered listing, `regex=true`,
  `code_only`, `start`/`end` scoping, `limit` default 30), `find_bytes`,
  `find_regex`, `get_string`, `get_bytes`
- Annotation: `rename` (`rename_function`), `set_comments` (`set_comment`),
  `append_comments`, `add_bookmark`, `set_type`, `declare_type`,
  `set_function_prototype`, `infer_types`
- Signatures & patching: `make_signature` (shortest unique byte sig, survives
  recompile — great for library-function ID), `patch` / `patch_asm` (defeat
  anti-debug, force a branch), `make_data`, `define_func`

**`xrefs_to` does not take string content.** It resolves **addresses or
symbol/function names** only — passing the text of a string returns
`{"error":"Not found: '<text>'"}`. Always resolve the string to an address with
`find` first. This two-step is the single most common way to waste calls here:

```text
find type=string targets=["Correct!","Wrong"] database=<sid>   # -> match addresses
xrefs_to addrs=["0x140009640"] database=<sid>                  # -> the checker
```

**Fastest path to a flag-checker (idalib):**

```text
idb_open input_path=./chall                  # -> session.session_id, use as database=
survey_binary database=<sid>                 # ONE call: entry, top strings, top funcs by xref, imports
find type=string targets=["Correct","flag{"] database=<sid>    # string -> address
xrefs_to addrs=[<string_addr>] database=<sid>                  # address -> the checker
analyze_function addr=<check_fn> database=<sid>  # pseudo-C + constants + callers, one call
trace_data_flow addr=<input_buf> direction=forward database=<sid>  # input -> the compare
rename addr=<check_fn> name=verify database=<sid>
set_comments database=<sid> ...              # breadcrumbs; then idb_save
```

`survey_binary` buckets imports as `crypto` / `network` / `file_io` / `process` /
`registry` / `other` — a non-empty `crypto` bucket tells you the algorithm family
before you read a line of pseudocode. When the string hunt comes up empty,
`find type=immediate` is the constant hunter (TEA delta `0x9E3779B9`, MD5/SHA
init words, custom XOR keys); it matches on IDA's recorded immediate operands, so
a miss means "not an immediate operand", not "not in the binary".

**Token discipline** — these defaults matter on big targets:
`survey_binary detail_level="minimal"` for >10k functions,
`analyze_function include_asm=false` (already the default — leave it off),
`decompile include_addresses=false` to drop the per-line `/*0xNNNN*/` markers.
`find` paginates via a returned `cursor` (`limit` default 1000, max 10000).

**Key insight:** `survey_binary` collapses the entire triage phase (metadata,
segments, entry points, strings and functions ranked by xref count, imports by
category, call-graph summary) into a **single** call — start every headless IDA
session with it instead of separate `list_*` calls. Then `analyze_function`
returns pseudocode plus every satellite fact (callers, callees, constants, xrefs,
basic-block count and cyclomatic complexity) at once, and `trace_data_flow`
chases the input buffer to the comparison automatically. Those three replace a
dozen GUI round-trips and are the real speed-up the idalib toolset gives you over
the classic GUI-plugin names — just remember the `find` → `xrefs_to` hop, because
strings are the usual entry point and `xrefs_to` cannot start from one.

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
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
```

The bridge is only a proxy. The plugin serves HTTP on **:8080 from inside the
running Ghidra GUI**, so the GUI must be up *with the program open in a
CodeBrowser* — a headless-imported project is not enough. If every tool returns
a connection error, that is the cause, not a bad tool name.

**Core tools:**

- Recon: `list_methods`, `list_functions`, `list_classes`, `list_imports`, `list_exports`, `list_segments`, `list_strings`, `list_data_items`, `list_namespaces`
- Analysis: `decompile_function`, `decompile_function_by_address`, `disassemble_function`, `get_function_by_address`, `search_functions_by_name`
- Live GUI cursor: `get_current_function`, `get_current_address` (what the analyst is looking at)
- Xrefs: `get_xrefs_to`, `get_xrefs_from`, `get_function_xrefs`
- Annotation: `rename_function`, `rename_function_by_address`, `rename_variable`, `rename_data`, `set_decompiler_comment`, `set_disassembly_comment`, `set_function_prototype`, `set_local_variable_type`

**Name vs address — getting this wrong wastes calls.** The tools are strict and
split by argument type:

| Takes a **name** | Takes a **hex address** (`"0x00101234"`) |
|---|---|
| `decompile_function`, `get_function_xrefs`, `search_functions_by_name`, `rename_function` | `decompile_function_by_address`, `disassemble_function`, `get_function_by_address`, `get_xrefs_to`, `get_xrefs_from`, `rename_function_by_address` |

So `get_xrefs_to` on a symbol name fails — resolve the address first (via
`list_data_items` / `list_strings`), or use `get_function_xrefs` when the target
is a function you can name.

**Pagination is silent — and it will hide the flag.** Every `list_*` tool takes
`offset` and `limit`, defaulting to **100** (`list_strings` defaults to 2000).
On a real binary the interesting function is usually past entry 100, and you get
no warning that the list was truncated. Always page, or filter.

**Fastest path to a flag-checker:**

```text
list_strings filter="flag"          # ← START HERE: filter is server-side, one call
list_strings filter="Correct"       # success/failure messages are the usual anchor
get_xrefs_to address=<string_addr>  # who reads that string -> the validator
decompile_function_by_address <caller_addr>   # pseudo-C first (golden rule)
list_methods offset=0 limit=100     # only if strings gave nothing; page through
search_functions_by_name check      # candidate validators by name
rename_function FUN_00101xxx validate_flag
set_decompiler_comment <addr> "input[i] ^ 0x2a compared here"
```

**Key insight:** the `filter` argument on `list_strings` is the single
highest-leverage call in the Ghidra toolset and the one most often missed — it
does the `strings | grep` step server-side, and the resulting address feeds
straight into `get_xrefs_to` to land on the flag checker in two calls. Reach for
the string→xref→decompile chain before enumerating functions. Beyond that,
Ghidra MCP gives the same agent-driven workflow as IDA MCP for free, and Ghidra's
decompiler occasionally reads a construct more clearly than Hex-Rays (and vice
versa) — if one MCP server produces confusing pseudocode, cross-check with the
other, mirroring the dogbolt.org approach in
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

**Two processes, and both must be up.** `jadx-mcp-server` is only a proxy — it
forwards to the plugin's HTTP endpoint inside JADX-GUI at **`127.0.0.1:8650`**.
If JADX-GUI is closed (or the plugin is not active) every tool returns
`Cannot connect to JADX plugin at http://127.0.0.1:8650. Ensure JADX-GUI is
running and the AI MCP plugin is active.` — a running `jadx_mcp_server` process
proves nothing. Check with one cheap `get_cache_stats` call before starting work.

**Core tools (verified against jadx-ai-mcp v6.4.0 — the earlier short names like
`get_manifest`/`get_method_code`/`get_main_activity` do NOT exist):**

- Recon: `get_all_classes`, `get_package_tree`, `search_classes_by_keyword`,
  `search_method_by_name`, `get_main_activity_class`, `get_android_manifest`,
  `get_manifest_component`
- Source: `get_class_source`, `get_method_by_name`, `get_methods_of_class`,
  `get_fields_of_class`, `get_main_application_classes_code` (dump ALL app classes
  at once — fast triage), `get_main_application_classes_names`
- Smali/resources/strings: `get_smali_of_class`, `get_strings`,
  `get_all_resource_file_names`, `get_resource_file`
- Xrefs: `get_xrefs_to_method`, `get_xrefs_to_field`, `get_xrefs_to_class`
- Refactor: `rename_class`, `rename_method`, `rename_field`, `rename_variable`,
  `rename_package`
- Live JADX-GUI context: `fetch_current_class`, `get_selected_text`
- Cache: `get_cache_stats` (also a cheap liveness probe), `clear_cache` (use after
  renames if stale decompiled source comes back)
- Dynamic debugger (JADX debug session): `debug_get_threads`,
  `debug_get_stack_frames`, `debug_get_variables`

**Two argument traps that will cost you a challenge:**

- **`get_strings` reads `strings.xml` resources — not string constants in code.**
  A flag or key hardcoded in a Java method will *never* show up there. To find
  those, search the code scope (below).
- **`get_method_by_name` requires `class_name` AND `method_name`** (plus an
  optional `method_signature` to disambiguate overloads). You cannot call it with
  a bare method name — use `search_method_by_name` first to learn the owning
  class, then pass both.

`search_classes_by_keyword` is the workhorse and is far more capable than a
plain keyword match — `search_in` accepts `class`, `method`, `field`, `code`,
`comment`, comma-combined, and `package` narrows the scope:

```text
search_classes_by_keyword search_term="flag{" search_in="code"
search_classes_by_keyword search_term="decrypt" search_in="method,code" package="com.ctf.app"
```

Pagination applies here (`count`, default 20) and to `get_all_classes`,
`get_strings`, `get_main_application_classes_code` (`count`/`offset`) — raise
`count` or page, or you will silently analyze only the first slice of the app.

**Android flag-hunting loop:**

```text
get_cache_stats                                       # liveness probe (see setup)
get_android_manifest                                  # entry activity, exported components
search_classes_by_keyword search_term="flag{" search_in="code"   # ← direct hit, try first
search_classes_by_keyword search_term="check" search_in="method" # else: name the validator
search_method_by_name check                           # -> tells you the owning class
get_method_by_name class_name=<Cls> method_name=check # read decompiled Java (both args!)
get_xrefs_to_method <check>                           # every caller / trigger path
get_strings                                           # strings.xml resources ONLY
get_smali_of_class <Crypto>                           # smali only if Java decompile breaks
```

**Key insight:** on an APK the fastest route is a **code-scope keyword search**,
not a string dump — `search_classes_by_keyword(search_term="flag{",
search_in="code")` frequently lands on the validator in one call, whereas
`get_strings` only ever sees `strings.xml` and will look empty even when the
flag is sitting in a Java constant. After that the usual pseudocode-first rule
applies: read `get_class_source` / `get_method_by_name` (decompiled Java) before
`get_smali_of_class` (bytecode). For a small app,
`get_main_application_classes_code` dumps every app class in one call so you can
grep the whole logic at once. JADX MCP pairs well with Frida for the dynamic
half — find the method statically, then hook it to dump runtime values (see
[tools-dynamic.md](tools-dynamic.md#frida-for-androidios)), or use the built-in
`debug_get_variables` when a JADX debug session is attached.

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
