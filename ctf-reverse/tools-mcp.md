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
  - [Headless server traps](#headless-server-traps-all-hit-on-a-real-run)
  - [The decompiler has a size wall](#the-decompiler-has-a-size-wall--check-function-size-before-calling-it)
  - [The big one: default analysis silently drops call arguments](#the-big-one-default-analysis-silently-drops-call-arguments)
- [JADX MCP (Android APK / DEX)](#jadx-mcp-android-apk--dex)
  - [Crossing the JNI Boundary: Run the `.so`, Don't Reverse It](#crossing-the-jni-boundary-run-the-so-dont-reverse-it)
    - [When the harness fails — and it will](#when-the-harness-fails--and-it-will)
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

Repository: `https://github.com/bethington/ghidra-mcp` (Apache-2.0). Use it
when you do not have an IDA license. Its defining feature is a **standalone
headless server**: Ghidra MCP does *not* require the GUI here, so the agent can
stand the whole stack up from a shell.

It ships two independent front-ends over one Ghidra core:

| Mode | Needs GUI? | How it runs |
|---|---|---|
| **Headless server** (`GhidraMCPHeadlessServer`) | no | plain `java -cp ...`, HTTP on **:8089** |
| GUI plugin | yes | CodeBrowser extension, **also :8089**, and you must click *Tools > GhidraMCP > Start MCP Server* |

Both are fronted by the same `bridge-mcp-ghidra` Python bridge, an
MCP↔HTTP multiplexer that exposes **222 MCP tools**. Prefer headless: it needs
no display, starts in seconds, and takes the target on the command line.

**Both modes default to the same port**, so they collide with each other, not
with anything else — `DEFAULT_PORT = 8089` in *both* `GhidraMCPHeadlessServer`
and `GhidraMCPPlugin`. The GUI plugin walks `8089, 8090, …` when the port is
taken, so if you leave a headless server running the GUI silently lands on a
different port and `GHIDRA_MCP_URL` points at the wrong one. Run one at a time.
(Older LaurieWired-era notes say `:8080` — that number does not apply here.)

**Version floor is a hard gate.** `tools/setup/versioning.py` compares
**major.minor exactly** (`is_ghidra_version_compatible`), and the pom pins
`12.1.2` — so a Ghidra **12.1.x** install is required and 11.x silently is not
"close enough". Check with `cat $GHIDRA_HOME/Ghidra/application.properties`.

**Setup — no Maven, no Docker.** Grab the prebuilt artifacts from the repo's
[Releases page](https://github.com/bethington/ghidra-mcp/releases) (the author
bumps versions often — always take the latest; no `mvn`/Docker build needed): the
`GhidraMCP-<ver>.zip` extension (ships the headless classes) and the
`ghidra_mcp_bridge-<ver>-py3-none-any.whl` bridge. `uv tool install` the wheel
(→ `~/.local/bin/bridge-mcp-ghidra`) and `unzip` the extension to get
`GhidraMCP/lib/GhidraMCP-<ver>.jar`.

**Launch the headless server natively** (the repo only documents Docker; this is
the same classpath its `docker/entrypoint.sh` builds):

```bash
GHIDRA_HOME=~/ghidra_12.1.x_PUBLIC        # major.minor must match the release's pin
CP=/path/to/GhidraMCP.jar                 # the unzipped GhidraMCP-<ver>.jar
for d in Framework Features Processors; do
  for j in "$GHIDRA_HOME"/Ghidra/$d/*/lib/*.jar; do CP="$CP:$j"; done
done
java -Xmx4G -Dghidra.home="$GHIDRA_HOME" -Dapplication.name=GhidraMCP \
     -cp "$CP" com.xebyte.headless.GhidraMCPHeadlessServer \
     --port 8089 --bind 127.0.0.1 --file /path/to/target.bin &

curl -s http://127.0.0.1:8089/check_connection   # "Connection OK - GhidraMCP Headless Server ..."
```

Then point the MCP client at the bridge (`GHIDRA_MCP_URL` is how it finds the
HTTP server, whichever mode is up):

```jsonc
"ghidra-mcp": {
  "command": "/home/<you>/.local/bin/bridge-mcp-ghidra",
  "args": ["--transport", "stdio", "--no-lazy"],
  "env": { "GHIDRA_MCP_URL": "http://127.0.0.1:8089/" }
}
```

Use `--no-lazy`: measured, `--lazy` exposes only **96** tools (the default
`listing,function,program` groups) against **222** with `--no-lazy`. The missing
126 need a `tools/list_changed` round-trip the client may never make, and the
symptom is a tool that "does not exist" rather than an error.

**Analysis is not automatic.** A freshly `--file`-loaded program reports
`Function Count: 0` until you `POST /run_analysis` (~3-12s for a small binary).
Decompiling before that returns nothing useful.

### Headless server traps (all hit on a real run)

- **`/load_program` needs a JSON body — the README's form-encoded example is
  wrong.** `-d "file=/path"` returns `{"error":"file path required"}`; only
  `-H 'Content-Type: application/json' -d '{"file":"/path"}'` works.
- **`/load_program` adds a program but does not make it the default target.**
  It returns `{"success":true,"program":"hello"}`, yet `/get_metadata` and
  `/run_analysis` keep answering for the binary the server started with. The fix
  is not restarting: **every tool takes an optional `program=<name>`** selector,
  and that is what disambiguates them.

  ```bash
  curl -s -X POST -H 'Content-Type: application/json' \
       -d '{"file":"/bin/true"}' :8089/load_program      # -> {"program":"true"}
  curl -s ":8089/get_metadata"                           # -> Program Name: hello   (the original)
  curl -s ":8089/get_metadata?program=true"              # -> Program Name: true    (selected)
  ```

  Pass a bogus name to enumerate what is loaded — the error lists them:
  `{"error":"Program not found: __nope__ Available programs: true, hello"}`.
  **Once a second program is loaded, pass `program=` on every call** or you will
  silently analyze the wrong binary.
- **`list_functions` takes no `limit`/`offset`** — its schema is
  `list_functions(program)`, so passing them is silently ignored (`limit=10` and
  `limit=500` return identical output). It is **not** truncated, though: it
  returns every real function, verified at 2417/2417 on a statically-linked
  binary. When you need paging, `list_functions_enhanced(offset, limit, program)`
  and `search_functions(name_pattern, offset, limit, program)` both have it.
- **`Function Count` in `/get_metadata` is larger than `list_functions` — that
  gap is EXTERNAL imports, not missing functions.** Do not go hunting for
  "hidden" functions over it:

  ```text
  hello  (dynamic ELF): Function Count 32, list_functions 23  -> 9 = the 9 EXTERNAL imports
  chall  (static ELF):  Function Count 2417, list_functions 2417 -> no externals, no gap
  ```

  Cross-check with `list_imports` (entries read `EXTERNAL:0000000N`) before
  concluding anything is being hidden from you.
- **`program=` only works as a query parameter — in a JSON body it is silently
  ignored.** This one analyzes the *wrong binary without telling you*:

  ```bash
  curl -X POST -H 'Content-Type: application/json' -d '{"program":"chall"}' \
       :8089/run_analysis          # -> {"success":true,...,"program":"hello"}   ← WRONG TARGET
  curl -X POST ":8089/run_analysis?program=chall"
                                   # -> {"success":true,"total_functions":2417,"program":"chall"}
  ```

  Note the inversion against `/load_program`, which *requires* a JSON body for
  `file`. The API is inconsistent, so **always read the `"program"` field in the
  response** to confirm which binary you actually touched.
- **The MCP tool schema and the raw HTTP endpoint do not always agree — trust the
  MCP side.** `disassemble_bytes` advertises `start_address` (required) via MCP,
  yet the HTTP endpoint rejects `?start_address=...` with
  `start_address parameter required`. Through the MCP client the *same* arguments
  work and return structured JSON:

  ```text
  disassemble_bytes program="hello" start_address="0x001011a9" length=48
  # -> {"success":true,"bytes_disassembled":48,"instructions":[
  #      {"address":"001011a9","mnemonic":"ENDBR64",...}, ...],"truncated":false}
  ```

  So curl is fine for triage, but when an endpoint argues about a parameter that
  the schema clearly declares, go through MCP before assuming the tool is broken.
- **`search_functions` matches substrings, and the decoy sorts first.**
  `name_pattern="main"` returns `__libc_start_main @ 00105000` *before*
  `main @ 001011a9`. Take the first hit and you decompile a PLT stub —
  `void __libc_start_main(void) { halt_baddata(); }` — which looks like a broken
  decompiler rather than your own mistake. **Anchor on the exact name** when you
  know it.
- **MinGW/PE prefixes symbols with `_`** — the mirror image of the above: grepping
  for `\bmain\b` *misses* `_main at 00401460`. So match loosely to find
  candidates, then pick the exact symbol deliberately.

### The decompiler has a size wall — check function size before calling it

`decompile_function` returns
`{"error":"Decompilation did not complete. Reason: Exception while decompiling
<addr>: process: timeout"}` on large functions. Ghidra decompiles a **whole
function at once** (SSA construction, data-flow, type propagation, control-flow
structuring), and cost grows super-linearly with size — a single CTF binary here
had a `main` whose body was `00401110 - 004092db`, i.e. **33 KB ≈ 8,300 AArch64
instructions**, and it blew past the default timeout.

Check the size *before* you spend the call:

```text
get_function_by_address address=0x00401110
# -> Body: 00401110 - 004092db      ← 0x81CB bytes; do not expect a fast decompile
```

Statically-linked, stripped, and heavily-inlined binaries produce these routinely.
Do **not** assume it is a Ghidra boundary error and try to "split" the function
before checking — verify first, because it is often a genuinely huge function
(here it ended with a real `ret`, with the next prologue immediately after).

Three ways out, cheapest first:

1. **Read only the window you need.** The interesting code is usually right
   around a string xref. `get_xrefs_to` gives the exact address; disassemble a
   few hundred bytes around it instead of decompiling 33 KB.
2. **Raise `timeout`** (`decompile_function(address, program, timeout)`) and run
   it in the background — this *does* work: `timeout=1200` on that 33 KB function
   completed and returned **~1 MB of C**. Budget 10-20 minutes and do not block
   the session on it. Expect a wall of `undefined1 auVar[16]` SIMD temporaries
   from fully-unrolled inlined crypto, which is often less readable than the
   assembly for the few hundred bytes you actually care about.
3. **CLI fallback for one window** — `radare2` (`r2 -q -c "s <addr>; pd 50" bin`)
   is instant. Note plain `objdump` on a distro host often fails on cross-arch
   targets (`can't disassemble for architecture UNKNOWN!` on AArch64); `r2`
   handles them without extra binutils packages.

### The big one: default analysis silently drops call arguments

On a 32-bit PE the out-of-the-box analyzer set decompiles to argument-less
calls — every string constant, *including a flag*, disappears:

```c
___main();  puts();  printf();  scanf();  printf();   // ← useless
```

Two analyzers are off by default (`GET /list_analyzers` to confirm):
`Stack.Create Param Variables` and
`WindowsPE x86 Propagate External Parameters`. Turn them on and re-analyze:

```bash
for a in "WindowsPE x86 Propagate External Parameters" "Stack.Create Param Variables"; do
  curl -s -X POST --data-urlencode "name=$a" --data-urlencode "enabled=true" \
       http://127.0.0.1:8089/configure_analyzer
done
curl -s -X POST http://127.0.0.1:8089/run_analysis
```

```c
puts("Hello, World!");                    // ← same function, after the fix
printf("Input: ");
scanf(&DAT_0040507a,local_14);
printf("You entered: %d\n",local_14[0]);
```

**Do this before concluding a binary has no interesting strings.** An
argument-less decompile is not evidence of an empty program — it is a
misconfigured analyzer, and it will hide the flag from you.

**If the headless server is unavailable**, fall back to `analyzeHeadless` with a post-script
for bulk decompilation (import + full analysis of a small PE took ~13s), or to
`objdump -d` / `radare2` for a single function — both beat waiting on a GUI.

**No Burp conflict here.** [ctf-web](../ctf-web/tools-mcp.md) puts the Burp proxy
on 8080; this server uses 8089, so a web and a reversing challenge can run in the
same session. Change the GUI plugin's port under *CodeBrowser > Edit > Tool
Options > GhidraMCP HTTP Server* and set `GHIDRA_MCP_URL` to match if you ever do
need to move it.

**Core tools** (222 exposed with `--no-lazy`; these are the ones that carry a
challenge):

- Recon: `list_functions`, `list_methods`, `list_classes`, `list_imports`, `list_exports`, `list_segments`, `list_strings`, `list_data_items`, `list_namespaces`, `get_metadata`, `get_current_program_info`
- Search: `search_functions` (**`name_pattern`**, `offset`, `limit`), `search_functions_enhanced`, `search_byte_patterns`, `find_similar_functions`
- Analysis: `decompile_function`, `batch_decompile`, `force_decompile`, `disassemble_function`, `get_function_by_address`
- Xrefs: `get_xrefs_to`, `get_xrefs_from`, `get_function_xrefs`
- Annotation: `rename_function`, `rename_function_by_address`, `rename_variable`, `rename_data`, `set_decompiler_comment`, `set_disassembly_comment`, `set_function_prototype`, `set_local_variable_type`
- Lifecycle: `load_program`, `run_analysis`, `configure_analyzer`, `list_analyzers`

**Everything targets an address, not a name.** `decompile_function` is
`decompile_function(address, program, timeout)` with **`address` required** —
there is no name form, and `?name=main` / `?function=main` all return
`{"error":"Address or function name is required"}`. Resolve name → address first:

```text
search_functions name_pattern="main" limit=20      # NOT query=/name= — the param is name_pattern
# -> main at 001011a9
decompile_function address="0x001011a9"
```

Read the schema rather than guessing parameter names — this server rejects the
obvious ones (`query`, `name`, `term`, `q` all fail on `search_functions`).

**Four tool names from older GhidraMCP builds no longer exist**, and calling them
just wastes turns: `decompile_function_by_address` (folded into
`decompile_function`), `search_functions_by_name` (now `search_functions`), and
`get_current_function` / `get_current_address` (there is no GUI cursor in
headless — use `get_current_program_info`).

**Pagination is per-tool, not universal.** `list_strings(offset, limit, filter,
program)` pages and filters; `list_functions(program)` does neither (see the
traps above). Check the schema before assuming a list is complete, and prefer
`list_strings filter=` over dumping everything.

**Fastest path to a flag-checker:**

```text
run_analysis                        # MUST run first — a fresh load has 0 functions
list_strings filter="flag"          # ← START HERE: filter is server-side, one call
list_strings filter="Correct"       # success/failure messages are the usual anchor
get_xrefs_to address=<string_addr>  # who reads that string -> the validator
decompile_function address=<caller_addr>      # pseudo-C first (golden rule)
search_functions name_pattern="check" limit=50  # if strings gave nothing; note: name_pattern
decompile_function address=<candidate>
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

**Unblock it yourself — do not ask the user to click through the GUI.** The
plugin is a persistent install (`jadx plugins --list` shows `jadx-ai-mcp`), so
the only missing piece is usually a GUI process with the APK loaded. Launch it
headless-style from the shell and wait for the port, then re-probe:

```bash
jadx plugins --list                                   # confirm jadx-ai-mcp is installed
nohup jadx-gui /path/to/app.apk >/tmp/jadx.log 2>&1 & # opens the APK directly
until curl -s --max-time 2 http://127.0.0.1:8650 >/dev/null; do sleep 2; done
echo "plugin endpoint up"                             # ~2-10s; then call get_cache_stats
```

`jadx-gui <file>` takes the target as an argument, so the APK is analyzed on
startup with no clicking. A GUI window does appear (needs `$DISPLAY`), but you
never have to touch it. Passing the APK on the command line is also what makes
`get_android_manifest` and friends return data instead of an empty project.

**Core tools (verified against jadx-ai-mcp v6.4.0 — the earlier short names like
`get_manifest`/`get_method_code`/`get_main_activity` do NOT exist):**

- Recon: `get_all_classes`, `get_package_tree`, `search_classes_by_keyword`,
  `search_method_by_name`, `get_main_activity_class`, `get_android_manifest`,
  `get_manifest_component`
- Source: `get_class_source`, `get_method_by_name`, `get_methods_of_class`,
  `get_fields_of_class`, `get_main_application_classes_names`,
  `get_main_application_classes_code` (dumps ALL app classes — see the R-class
  warning below before calling it)
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

**Three traps that will cost you a challenge:**

- **`get_main_application_classes_code` is not cheap triage — start with
  `get_main_application_classes_names`.** The "main application classes" set
  includes the auto-generated `R` and `R.styleable` classes, which are thousands
  of resource-ID constants. On a *3-class* CTF app this call returned **161 KB**
  and overflowed the tool-result limit outright. The names call is a few hundred
  bytes and shows you the real targets immediately:

  ```text
  get_main_application_classes_names
  # -> BuildConfig, FlagstaffHill, MainActivity, R, R.anim, R.attr, R.bool, ...
  #    Ignore R.* and BuildConfig. Two classes carry all the logic.
  get_class_source class_name="com.x.MainActivity"    # then fetch those by name
  ```

  Rule: **filter out `R`/`R.*`/`BuildConfig`, then `get_class_source` each
  remaining class.** Only reach for the bulk dump if the app has many real
  classes *and* you page it with `count`/`offset`.

- **`get_strings` reads `strings.xml` resources — not string constants in code.**
  A flag or key hardcoded in a Java method will *never* show up there. To find
  those, search the code scope (below).

  The inverse is just as important: **when decompiled Java reads
  `ctx.getString(R.string.foo)`, `get_strings` is exactly the right tool and a
  code search will find nothing.** Comparison values are routinely parked in
  `strings.xml` to keep them out of the DEX:

  ```java
  String password = ctx.getString(R.string.password);
  return input.equals(password) ? nativeCheck(input) : "NOPE";
  ```

  ```text
  get_strings count=400     # -> <string name="password">opossum</string>
  ```

  Note `get_strings` paginates by *file*, not by string, and each item is a whole
  `strings.xml`. Decoy entries (a pile of plausible-looking animal names around
  the real `password`) are a common trick — match the resource **name** the Java
  code asked for, not a string that merely looks flag-ish.

- **`get_smali_of_class` is the deepest JADX MCP goes — it cannot see native
  code.** When the decompiled Java shows `public static native String foo(...)`
  plus `System.loadLibrary("bar")`, the flag logic lives in
  `lib/*/libbar.so` and **no JADX tool will ever show it**. Stop searching the
  DEX and switch to the native workflow below.

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
get_android_manifest                                  # entry activity, exported components, package name
get_main_application_classes_names                    # cheap: the real classes (ignore R.*, BuildConfig)
get_class_source <MainActivity>                       # entry logic + System.loadLibrary calls
get_class_source <Validator>                          # the class the button handler calls
search_classes_by_keyword search_term="flag{" search_in="code"   # direct hit when the flag is in the DEX
search_method_by_name check                           # -> tells you the owning class
get_method_by_name class_name=<Cls> method_name=check # read decompiled Java (both args!)
get_xrefs_to_method <check>                           # every caller / trigger path
get_strings count=400                                 # strings.xml — where R.string.* values live
get_smali_of_class <Crypto>                           # smali only if Java decompile breaks
# if you hit `native` methods -> leave JADX, go to "Crossing the JNI boundary"
```

**Key insight:** the APK's Java layer is usually just a *router* — it names the
check and tells you where the real comparison value lives. Read the two or three
non-`R` classes end to end (they are tiny), and the decompiled source will point
you at exactly one of three places: a constant in the DEX (`search_classes_by_
keyword ... search_in="code"`), a resource (`get_strings`), or a native library
(`native` + `System.loadLibrary` → next section). Guessing which one before
reading the class wastes calls. Then the usual pseudocode-first rule applies:
`get_class_source` / `get_method_by_name` (decompiled Java) before
`get_smali_of_class` (bytecode). JADX MCP pairs well with Frida for the dynamic
half — find the method statically, then hook it to dump runtime values (see
[tools-dynamic.md](tools-dynamic.md#frida-for-androidios)), or use the built-in
`debug_get_variables` when a JADX debug session is attached.

### Crossing the JNI Boundary: Run the `.so`, Don't Reverse It

`public static native String fenugreek(String s)` + `System.loadLibrary("hellojni")`
means the answer is in `lib/<abi>/libhellojni.so`. The reflex is to load that
`.so` into Ghidra/IDA MCP and decompile — but for a flag-*producing* function
that is the slow path. **An Android JNI `.so` is an ordinary ELF shared object;
you can `dlopen` it on the host and call the export directly**, with no
emulator, no device, and no Android at all. Minutes instead of an hour of
decompiling a custom string-scramble.

Map the Java method to its symbol with the JNI name mangling
`Java_<package with . -> _>_<Class>_<method>`, then confirm it is really exported
(if it is missing, the app uses `RegisterNatives` — see
[languages-platforms.md](languages-platforms.md#android-jni-registernatives-obfuscation-htb-wondersms)):

```bash
unzip -q app.apk 'lib/*'                    # x86_64 first: it runs natively on a normal host
objdump -T lib/x86_64/libfoo.so | grep Java_
objdump -p lib/x86_64/libfoo.so | grep NEEDED     # bionic libs you must stub
```

The harness fakes just enough of `JNIEnv` — CTF JNI functions rarely touch more
than the string calls. Build it against a real JDK's `jni.h`:

```c
/* jni_harness.c — gcc -o harness jni_harness.c -ldl \
     -I$JAVA_HOME/include -I$JAVA_HOME/include/linux
   ./harness ./libfoo.so Java_com_x_Y_method "input"                         */
#include <jni.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A jstring is an opaque pointer, so just use raw char*. Hand back a heap copy:
   native code often free()s this pointer instead of calling Release, which
   aborts on non-malloc'd memory. */
static const char *h_GetStringUTFChars(JNIEnv *e, jstring s, jboolean *copy) {
    if (copy) *copy = JNI_TRUE;
    return s ? strdup((const char *)s) : NULL;
}
static void    h_ReleaseStringUTFChars(JNIEnv *e, jstring s, const char *c) {}
static jstring h_NewStringUTF(JNIEnv *e, const char *b) { return (jstring)(b ? strdup(b) : NULL); }
static jsize   h_GetStringUTFLength(JNIEnv *e, jstring s) { return s ? (jsize)strlen((const char *)s) : 0; }
static jclass  h_FindClass(JNIEnv *e, const char *n) { return (jclass)0xdeadbeef; }
static jint    h_GetVersion(JNIEnv *e) { return JNI_VERSION_1_6; }

typedef jstring (*fn_t)(JNIEnv *, jclass, jstring);

int main(int argc, char **argv) {
    struct JNINativeInterface_ nif;              /* designated init: no slot counting */
    memset(&nif, 0, sizeof(nif));
    nif.GetVersion = h_GetVersion;               nif.FindClass = h_FindClass;
    nif.GetStringUTFChars = h_GetStringUTFChars; nif.NewStringUTF = h_NewStringUTF;
    nif.ReleaseStringUTFChars = h_ReleaseStringUTFChars;
    nif.GetStringUTFLength = h_GetStringUTFLength;
    nif.GetStringLength = h_GetStringUTFLength;

    struct JNIEnv_ env; env.functions = &nif;
    void *lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    fn_t fn = (fn_t)dlsym(lib, argv[2]);
    if (!fn) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    jstring out = fn((JNIEnv *)&env, (jclass)0, (jstring)argv[3]);
    printf("%s\n", out ? (const char *)out : "(null)");
    return 0;
}
```

**Compile as C, not C++.** In C, `JNIEnv` is `struct JNIEnv_` holding a pointer
to a plain-struct function table you can fill in by *field name*; the C++ header
makes it a class with inline methods and the trick stops compiling.

**The two errors you will hit, in order:**

1. `dlopen: libandroid.so: cannot open shared object file` — bionic libs the
   host lacks. Generate empty stubs for every `NEEDED` entry except libc:
   ```bash
   printf 'int __android_log_write(int p,const char*t,const char*m){return 0;}\n' > stub.c
   for l in liblog libandroid libm libdl; do gcc -shared -fPIC -o stubs/$l.so stub.c; done
   ```
2. `undefined symbol: __cxa_finalize, version LIBC` — the real trap. Bionic
   exports its libc symbols under a **version node literally named `LIBC`**, so a
   naive stub `libc.so` does not satisfy the `Version References` entry
   (`objdump -p lib.so` shows `required from libc.so: LIBC`). Build a stub that
   forwards to glibc *and* declares that version node:
   ```bash
   printf 'LIBC { global: *; };\n' > libc.ver
   gcc -shared -fPIC -o stubs/libc.so bionic_libc.c -Wl,--version-script=libc.ver -ldl
   ```
   In `bionic_libc.c` implement the handful of `objdump -T ... | grep UND`
   symbols: no-op `__cxa_finalize`/`__cxa_atexit`, `abort()`ing
   `__stack_chk_fail`, hand-written `strlen`/`strcmp`/`strdup`, `sprintf` via
   `vsprintf`, and `calloc`/`free` forwarded with
   `dlsym(RTLD_NEXT, "calloc")` so heap pointers stay glibc-owned.

```bash
LD_LIBRARY_PATH=$PWD/stubs ./harness ./lib/x86_64/libfoo.so \
    Java_com_hellocmu_picoctf_FlagstaffHill_fenugreek "opossum"
# picoCTF{pining.for.the.fjords}
```

**Then verify it is a real transform, not a baked-in constant** — rerun with a
wrong input. If the output changes (or the function bails), the flag is genuinely
derived from your input and the password you recovered is correct. A library
exporting several spice-named functions usually serves several challenges in a
series; sweep them all in one loop. An abort inside a *wrong-input* path is a
harness artifact (the failure branch frees a static string), not a wrong answer —
ignore it if the correct input prints cleanly.

#### When the harness fails — and it will

**The harness is a five-minute bet, not a replacement for reversing.** It only
wins in one shape: *you already hold the correct input and want the output.*
Timebox it. The moment a symptom below shows up, stop patching the harness and
switch — the fallback is usually cheaper than making the harness work.

The right fallback is not always "decompile". There are three tiers, in
increasing cost and increasing fidelity:

1. **Host harness** — no Android context at all. Fastest, most fragile.
2. **Frida on a device/emulator** — a *real* `JNIEnv`, real app state, real
   package identity. Fixes every "needs Android context" failure below, and you
   still never reverse the algorithm. See
   [tools-dynamic.md](tools-dynamic.md#frida-for-androidios).
3. **Static decompile** (Ghidra/IDA MCP) or angr — the only option when you must
   *recover an input* rather than observe an output.

| Symptom | Cause | Go to |
|---|---|---|
| `dlsym: undefined symbol: Java_...` | `RegisterNatives`, not standard mangling | Decompile `JNI_OnLoad` for the method table ([details](languages-platforms.md#android-jni-registernatives-obfuscation-htb-wondersms)) |
| APK ships only `lib/armeabi-v7a` + `lib/arm64-v8a` | no host-executable ABI | `qemu-arm64 -L <arm sysroot>`, or decompile |
| SIGSEGV on `call *%rcx` right after `mov 0x<N>(%rdx),%rdx` | native used a `JNIEnv` slot you left NULL | implement slot `N/8` (see below) |
| that slot is `GetObjectClass`/`GetFieldID`/`Call*Method` | it calls **back into Java** — unfakeable on the host | Frida (tier 2) |
| reads `/proc/self/maps`, system properties, package name, APK signature | needs real app identity | Frida (tier 2) |
| output is a fixed string regardless of input | logic gated behind `JNI_OnLoad` state that `dlopen` never ran | Frida, or call `JNI_OnLoad` manually with a fake `JavaVM` |
| returns `"try again"` / aborts for **every** input you try | function is a **validator**; you do not have the input | Decompile (tier 3) — the harness can never tell you |

**Decode a segfault into a slot number.** JNI dispatch compiles to a fixed
pattern: dereference `JNIEnv*` to get the function table, then index it. In this
challenge's library:

```asm
mov  (%rdx),%rdx          ; rdx = *env  -> function table
mov  0x548(%rdx),%rdx     ; 0x548 / 8 = 169  -> GetStringUTFChars
call *%rcx
```

So **`offset / 8` is the JNI slot index** — look it up in the
`JNINativeInterface_` layout in `jni.h` and add exactly that field to the
harness. The string cluster you will hit most: `167` `NewStringUTF`,
`168` `GetStringUTFLength`, `169` `GetStringUTFChars`, `170`
`ReleaseStringUTFChars`. Grepping the target function for
`mov 0x...(%rdx)` up front tells you which slots to implement *before* the first
crash.

**The validator wall, concretely.** In the same library `sesame()` branches on a
helper `basil(input)`, and the false branch is a dead end. Disassembling `basil`
shows a table of six static words (`weatherwax, ogg, garlick, nitt, aching,
dismass`), an index computation, and a `"%s.%s.%s..."` `sprintf` — i.e. the
password is a *computed dot-joined phrase*. No amount of harness re-running
recovers that; you have to read the code. Meanwhile `fenugreek()` on the same
library is a pure producer and falls in one call. **Same `.so`, two functions,
two different correct strategies** — so classify the function before you pick a
tool, and do not let a harness that worked once talk you out of decompiling the
next one.

---

## When to Use MCP vs CLI

| Situation | Use |
|-----------|-----|
| Large binary, need to read many functions as pseudo-C | MCP (IDA/Ghidra) |
| Following xrefs, renaming, building understanding iteratively | MCP |
| Quick plaintext flag / string triage | CLI (`strings`, `rabin2 -z`) — faster |
| One-off disassembly of a single function | CLI (`objdump -d`) is fine |
| Android: understand class structure and Java logic | MCP (JADX) |
| Android: flag produced by a `native` method in `lib/*.so` | CLI JNI harness ([above](#crossing-the-jni-boundary-run-the-so-dont-reverse-it)) — run it, don't decompile |
| Symbolic solve of a flag-checker | angr (see [tools-dynamic.md](tools-dynamic.md#angr-symbolic-execution)) |
| Runtime value extraction from obfuscated code | Frida (see [tools-dynamic.md](tools-dynamic.md)) |

**Key insight:** MCP shines for iterative, understanding-heavy analysis where the
agent needs to read decompiler output and follow relationships. For one-shot
recon (`file`, `strings`, `checksec`) the CLI quick-wins in
[SKILL.md](SKILL.md#quick-wins-try-first) are still faster — reach for MCP once you
are past triage and actually reversing logic.
