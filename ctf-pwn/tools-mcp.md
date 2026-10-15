# CTF Pwn - MCP Server Integration

MCP servers accelerate the two halves of a pwn workflow: **understanding** the
binary (decompile the vulnerable function) and **debugging** the exploit
(inspect crash state, heap, registers). For static decompilation via IDA/Ghidra
MCP the authoritative reference is [../ctf-reverse/tools-mcp.md](../ctf-reverse/tools-mcp.md);
this file covers the pwn-specific angle plus **WinDbg MCP** for Windows targets.

## Table of Contents
- [WinDbg MCP (Windows Crash Dumps, Live & Kernel Debugging)](#windbg-mcp-windows-crash-dumps-live--kernel-debugging)
- [IDA / Ghidra MCP for Exploit Development](#ida--ghidra-mcp-for-exploit-development)

---

## WinDbg MCP (Windows Crash Dumps, Live & Kernel Debugging)

Repository: `https://github.com/svnscha/mcp-windbg` (MIT). Bridges WinDbg's
`cdb.exe` (user mode) and `kd.exe` (kernel mode) to the agent, so dump triage,
live breakpoint-driven exploitation, and kernel debugging all run as tool calls.

**Setup:**

```bash
# Needs the Windows SDK "Debugging Tools for Windows" (provides cdb.exe + kd.exe),
# usually C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\
uv tool install mcp-server-windbg     # or: pip install mcp-server-windbg
claude mcp add mcp-windbg -- mcp-windbg
```

### Session model — read this first

Every tool except `list_dumps` is **session-addressed**. `open_*` returns a
`session_id`; every later command must pass it back. Open once, reuse for the
whole challenge, close at the end. This is the single most common failure mode:
calling `run_cdb_command` without a `session_id` from a live `open_*`.

**User mode (cdb.exe)** — dumps, and live targets over a debug server:

| Tool | Purpose |
|---|---|
| `list_dumps(directory_path?, recursive?)` | Enumerate `.dmp` files; no session needed |
| `open_cdb_dump(dump_path, symbols_path?, include_stack_trace?, include_modules?, include_threads?, timeout_seconds?)` | Load a dump → `session_id`. Auto-runs `.lastevent` + `!analyze -v` |
| `open_cdb_remote(connection_string, ...)` | Attach to `cdb -server tcp:port=5005 <prog>` → `session_id` |
| `run_cdb_command(session_id, command, timeout_seconds?)` | Any cdb command |
| `send_ctrl_break(session_id)` | Break into a *running* live target |
| `close_cdb_session(session_id)` | Release |

**Kernel mode (kd.exe)** — Windows kernel/driver pwn:

| Tool | Purpose |
|---|---|
| `open_kd_session(connection_string, symbols_path?, ...)` | Attach + break in → `session_id` |
| `run_kd_command(session_id, command, timeout_seconds?)` | Any kd command |
| `send_ctrl_break(session_id)` | Break into the running kernel |
| `close_kd_session(session_id, resume=true)` | Release. **`resume=false` leaves the whole target machine frozen** |

Kernel connection strings: KDNET `net:port=50000,key=1.2.3.4`, named pipe
`com:pipe,port=\\.\pipe\com_1,baud=115200,reconnect,resets=0`, serial
`com:port=COM1,baud=115200`.

**Symbols are a correctness issue, not a convenience.** Pass
`symbols_path="srv*C:\symbols*https://msdl.microsoft.com/download/symbols"` on
`open_*`. With wrong symbols `!analyze -v` does not fail loudly — it invents a
**plausible but false** answer. Verified on a real dump: `!analyze -v` reported
`PROCESS_NAME: ntdll.wrong.symbols.dll` and a bogus bugcheck code, and `k` gave
`combase!CoTaskMemRealloc+0x31a7` / `notepad+0xaf59`. After `.symfix; .reload`
the same stack read `combase!InitMainThreadWnd+0x57` / `notepad!wWinMain+0x11d`
— different functions entirely.

**Always sanity-check the auto-analysis before trusting a single frame:** if the
output contains `WRONG_SYMBOLS`, `MISSING_CRITICAL_SYMBOLS`, or
`***** OS symbols are WRONG`, run `.symfix; .reload` and re-issue `k` before
reasoning about the crash.

### Crash-dump triage loop

`open_cdb_dump` already ran `.lastevent` + `!analyze -v` for you. Set
`include_stack_trace=true, include_modules=true` to fold `kb` and `lm` into that
same first call and save two round trips.

```text
open_cdb_dump crash.dmp  include_stack_trace=true include_modules=true
run_cdb_command <sid> ".symfix; .reload"     # FIRST — see the symbol warning above
run_cdb_command <sid> "r"                    # registers — did we control rip?
run_cdb_command <sid> "!exchain"             # SEH chain (SEH-overwrite target)
run_cdb_command <sid> "dds esp L40"          # stack — locate the cyclic pattern
run_cdb_command <sid> "!heap -p -a <addr>"   # heap block owner for UAF/overflow
run_cdb_command <sid> "~*k"                  # all thread stacks, not just the faulting one
run_cdb_command <sid> "!teb"                 # TEB: stack limits, last error, SEH head
```

`list_dumps` needs an explicit `directory_path` unless the machine has a
`LocalDumps` registry path configured — otherwise it just errors.

**Flag straight out of a dump.** Before any exploitation, scan memory — many
Windows forensics/pwn hybrids hand you a dump that already contains the flag.
**Do not scan by raw address range on x64.** A 32-bit range never reaches the
heap (it sits above 4 GB, e.g. `0x246ab1a1720`), and the full 47-bit user range
`L?0x7fffffffffff` hangs the session outright. Enumerate committed regions and
search only those:

```text
run_cdb_command <sid> "!address -f:Heap -c:\"s -u %1 %2 \\\"flag{\\\"\""    # UTF-16
run_cdb_command <sid> "!address -f:Heap -c:\"s -a %1 %2 \\\"flag{\\\"\""    # ASCII
run_cdb_command <sid> "du <hit_addr>"                       # print the whole flag
run_cdb_command <sid> ".writemem C:\\out\\heap.bin <start> L<len>"  # carve for offline analysis
```

Try **`s -u` first**: Win32 stores command lines, environment blocks, and most
string data as UTF-16, so `s -a` frequently finds nothing where `s -u` hits
immediately. Swap `-f:Heap` for `-f:Stack`, `-f:Image`, or `-f:MEM_PRIVATE` to
widen the sweep. In `-c:` the placeholders are `%1` base, `%2` end+1, `%3` size;
quotes need escaping and **semicolon-separated commands are not supported**.

### Live exploitation loop (the part most people miss)

`open_cdb_remote` turns the MCP into a full interactive debugger. Start the
target under a debug server, then drive breakpoints, patch memory, and read the
flag — no GUI, no manual stepping.

```bash
cdb -server tcp:port=5005 chall.exe      # on the target box
```

```text
open_cdb_remote "tcp:Port=5005,Server=127.0.0.1"
run_cdb_command <sid> "bp chall!check_password"        # break on the gate
run_cdb_command <sid> "ba r4 <flag_buf>"               # HW watchpoint: who READS the flag?
run_cdb_command <sid> "bp chall!cmp \"du poi(esp+4); g\""  # scripted bp, auto-continues
run_cdb_command <sid> "g"  timeout_seconds=30          # run; bounded so it can't hang you
run_cdb_command <sid> "r rip=chall!print_flag"         # skip the check entirely
run_cdb_command <sid> "eb <addr> 90 90"                # NOP out a jz — patch, don't solve
run_cdb_command <sid> "!gflag +hpa"                    # page heap: overflow faults immediately
```

If the target is running and commands stop responding, `send_ctrl_break` first —
a live session cannot execute commands while the debuggee is free-running.

### Windows mitigation check (the `checksec` equivalent)

There is no `checksec` on Windows; `!dh` is it. Do this before choosing a
strategy — it decides ROP vs ret2win vs SEH overwrite:

```text
run_cdb_command <sid> "lm"                  # module list + base addresses
run_cdb_command <sid> "!dh -f chall"        # read the "DLL characteristics" block
run_cdb_command <sid> "!address -f:PAGE_EXECUTE_READWRITE"   # RWX — where shellcode can live
```

`!dh -f` prints the flags by name; these are the ones that matter:

| `!dh -f` line | Meaning |
|---|---|
| `Dynamic base` | ASLR enabled |
| `High entropy VA supported` | 64-bit ASLR entropy |
| `NX compatible` | DEP enabled |
| `Guard` | **CFG** — indirect calls are validated |

`/GS` (stack cookie) is **not** a DLL-characteristics flag and will never appear
here — it lives in the Load Configuration Directory's `SecurityCookie` field.
Confirm it separately with `dt ntdll!_IMAGE_LOAD_CONFIG_DIRECTORY64 <imgbase>+<lcd_rva>`,
or just look for the `__security_cookie` xor/compare in the function epilogue.

CFG present pushes you to a *valid call target* like `system()` rather than an
arbitrary gadget — see the CFG-bypass technique in
[advanced-exploits-4.md](advanced-exploits-4.md).

### Kernel-mode loop (HEVD-style driver challenges)

Windows kernel pwn is a recurring CTF category and `open_kd_session` is the only
way to reach it. The goal is almost always token stealing:

```text
open_kd_session "net:port=50000,key=1.2.3.4" symbols_path="srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
run_kd_command <sid> "lm m HEVD"                    # driver base → offsets for the ROP chain
run_kd_command <sid> "!drvobj HEVD 2"               # IOCTL dispatch routines = attack surface
run_kd_command <sid> "bp HEVD!TriggerStackOverflow"
run_kd_command <sid> "r cr4"                        # bit 20 set = SMEP on → must ROP in kernel
run_kd_command <sid> "!process 0 0 System"          # System EPROCESS (token source)
run_kd_command <sid> "dt nt!_EPROCESS <addr> Token ActiveProcessLinks UniqueProcessId"
run_kd_command <sid> "!pool <addr>"                 # pool chunk metadata for grooming
run_kd_command <sid> "!analyze -v"                  # after a BSOD: bugcheck code + faulting driver
close_kd_session <sid> resume=true
```

`dt nt!_EPROCESS ... Token` both gives you the exact token offset for the
exploit *and* verifies the steal landed. Kernel memory reads are slow — raise
`timeout_seconds` rather than assuming a hang.

**Key insight:** the MCP's value is not "WinDbg without the GUI" — it is that
breakpoints, memory patches, and memory scans become *agent-drivable*. The
fastest Windows CTF paths are usually not a clean exploit at all: scan committed
regions for `flag{`, set a hardware read-watchpoint on the flag buffer, or
`eb`/`r rip=` your way past the check. Reach for those before writing a ROP
chain — but fix symbols first, because a mis-symbolized `!analyze -v` will
confidently point you at the wrong function. For
interactive local work x64dbg remains the GUI alternative (see
[../ctf-reverse/tools-dynamic.md](../ctf-reverse/tools-dynamic.md#x64dbg-windows-debugger)).

---

## IDA / Ghidra MCP for Exploit Development

Use the decompiler MCP servers from
[../ctf-reverse/tools-mcp.md](../ctf-reverse/tools-mcp.md) to find and understand
the vulnerability before writing the exploit — **pseudocode first, assembly only
when it fails** (same golden rule).

**Pwn-specific queries:**

```text
list_strings filter="flag"          # free win: the flag or its file path, in one call
decompile_function <handler>        # spot the unchecked memcpy/gets/scanf("%s")
get_function_xrefs name=read_input  # every path that reaches the vulnerable buffer (by name)
get_xrefs_to address=<buf_addr>     # ...or by hex address for a data buffer
decompile_function <win/backdoor>   # confirm a ret2win target + required args
list_methods offset=0 limit=100     # locate system/execve wrappers — page past 100!
disassemble_function address=<gadget_addr>  # ONLY when hunting exact bytes for gadgets
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
