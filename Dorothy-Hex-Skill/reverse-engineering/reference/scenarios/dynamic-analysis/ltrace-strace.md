# ltrace / strace — Library and Syscall Tracing

## When this applies

- Linux binary, you want to see what it does without setting up a debugger.
- Quick triage: which files / network endpoints / processes does it touch?
- Cheaper than Frida — just one CLI invocation.
- Trigger: any Linux RE task before deeper analysis.

## Technique

`strace` traces **syscalls** (kernel boundary): `open`, `read`, `write`, `connect`, `execve`, `mmap`. `ltrace` traces **library calls** (libc / shared library boundary): `strcpy`, `malloc`, `printf`, `fopen`. Both use `ptrace` under the hood.

## Steps

### 1. Quick syscall trace

```bash
strace -f -o trace.log ./target arg1 arg2
```

`-f` follows forked children. Output is huge for non-trivial programs.

### 2. Filter by interesting syscall family

```bash
# File ops only
strace -f -e trace=file ./target

# Network only
strace -f -e trace=network ./target

# Specific syscalls
strace -f -e trace=open,openat,read,write ./target

# Exclude noisy ones
strace -f -e 'trace=!futex,clock_gettime,nanosleep' ./target
```

### 3. Show string contents fully

```bash
strace -s 256 ./target           # don't truncate strings at 32 chars
```

### 4. Library call trace

```bash
ltrace -f -o ltrace.log ./target
ltrace -e 'fopen+open*+read*' ./target
ltrace -C ./target               # demangle C++ names
ltrace -p $(pgrep target)        # attach to running process
```

### 5. Combine

```bash
strace -f -e trace=network,file -s 256 ./target 2> /tmp/trace.log
```

Search the log for interesting events:

```bash
grep -E "open|connect|execve" /tmp/trace.log
grep -F "AF_INET" /tmp/trace.log    # IPv4 socket events
```

### 6. Identify "interesting moments"

- `execve(...)` — program start; arguments from CLI.
- `open*(...)` — file accesses; useful to find config files / log files / data files.
- `connect(...)` — outbound connections; reveals C2 IPs / ports.
- `read(0, ...)` — reads from stdin.
- `write(1, ...)` / `write(2, ...)` — stdout / stderr (often what user sees).
- `ptrace(...)` — anti-debug self-trace (see `anti-debug/ptrace-bypass.md`).
- `mmap(..., PROT_EXEC)` — runtime code generation / unpacking.

### 7. Per-process timing

```bash
strace -c ./target              # syscall count + time summary
strace -T ./target              # per-syscall duration
strace -tt ./target             # absolute timestamps
```

Reveals which syscalls dominate runtime — useful for profiling.

### 8. Network-specific

```bash
# More than strace: dump packets too
tcpdump -i any -w out.pcap port 80 &
strace -e trace=network ./target
```

Pair with `Wireshark` for deep packet inspection.

## Verifying success

- You can answer: "what files does this binary touch / what hosts does it contact / what arguments to subprocess?"
- The trace is comprehensible — interesting events stand out.
- Anti-debug patterns visible (multiple `ptrace`, `prctl(PR_SET_DUMPABLE)`, etc.).

## Common pitfalls

- **strace slows the target.** Some timing-sensitive code (game loops, real-time stuff) breaks under strace overhead. Use `perf` or eBPF (`bpftrace`) for low-overhead alternatives.
- **strace blocks threads.** Multi-threaded programs serialize through ptrace; performance and behavior may differ.
- **Static binary, no ltrace.** ltrace traces PLT calls, but statically linked binaries have no PLT — ltrace shows nothing useful. Use strace instead, or add Frida.
- **System call wrappers.** `printf` in libc may be a single `write` syscall — strace doesn't show "printf"; ltrace does.
- **Privileges.** Some syscalls fail under `strace` due to ptrace permission restrictions (set-uid binaries). Use `sudo strace` or `setcap`.
- **Binary detects strace.** A `prctl(PR_SET_DUMPABLE, 0)` or check on `/proc/self/status` for tracer can detect strace too. Same bypasses as for debuggers.

## Tools

- `strace` — syscall tracing (universal Linux).
- `ltrace` — library tracing.
- `bpftrace` — eBPF-based tracing, lower overhead.
- `perf trace` — alternative low-overhead tracer.
- `dtruss` (macOS), `truss` (BSD) — equivalents.
- `strace-graph` — visualize syscall trace as a tree.
- `sysdig` — heavier, container-aware syscall tracer.
