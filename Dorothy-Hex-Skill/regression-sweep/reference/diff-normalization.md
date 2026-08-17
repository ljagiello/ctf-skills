# Regression Sweep — Diff Normalization

PoC output is rarely byte-stable across runs. To classify drift accurately, normalize both the baseline and the current re-run before comparing.

## Mandatory strips

Apply these regex substitutions (replacement: empty string) to both baseline and current output before diffing:

| Pattern | Why |
|---|---|
| `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z\|[+-]\d{2}:?\d{2})?` | ISO 8601 timestamps |
| `\b[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}\b` | RFC-2822-ish dates |
| `[a-f0-9]{32,}` | UUIDs, MD5/SHA hashes, request IDs |
| `\bsession_id=\S+` / `\bcsrf_token=\S+` | Per-request tokens |
| `\bX-Request-Id: \S+` | Server-assigned request IDs |
| `Set-Cookie: [^\r\n]+` | Cookie headers (session-bound) |
| `\bnonce=[A-Za-z0-9+/=]+` | CSP / OAuth nonces |
| `\b127\.0\.0\.1:\d{4,5}\b` / `\blocalhost:\d{4,5}\b` | Dynamic local ports (Docker-bridge findings) |

After substitution, lower-case and trim whitespace on each line, then compare as a `set` (order-independent). The exploit's *content* must be stable; ordering of e.g. headers is not.

## Tolerance threshold

A diff is **significant** if any of:

- More than 20% of lines from the baseline are missing in the current output.
- A line containing an obvious exploit-signal token (`FLAG{`, `root:x:0:0`, `__proto__`, `SyntaxError`, `password`, `secret`, etc.) present in baseline is absent in current.
- HTTP status code in any captured response line shifted from 2xx → 4xx/5xx (or vice versa) while the baseline had a clear indicator.

Below threshold = `still_valid`. Above threshold without exploit-signal token loss = `inconclusive` (e.g., transient infra issue). Above threshold with exploit-signal token loss = `newly_invalid`.

## Per-class stability heuristics

| Vuln class | Stable signal |
|---|---|
| SQLi / NoSQLi | column values, DB error strings |
| RCE | command output (`uid=0`, hostname), env vars |
| Path traversal / LFI | `/etc/passwd` lines, file structure markers |
| SSRF | response from internal endpoint (status + body keywords) |
| XSS reflected | exact payload string echo |
| Auth bypass | `Set-Cookie: auth=` or `200` after disallowed nav |
| IDOR | leaked field values from a row the test user shouldn't see |
| Deserialization | RCE artifact (same as RCE row) |

If the baseline `poc.py` does not contain an obvious exploit-signal token in its output, mark the finding `inconclusive_baseline` once during the sweep and request the validator re-emit a clearer `poc_output.txt` next run.

## False-positive guards

- **Never** mark `newly_invalid` if the re-run errored with a connection / DNS / TLS failure. That's `inconclusive`.
- **Never** mark `newly_revalidated` unless the re-run output contains the exploit-signal token *and* the prior `REJECTED` record's failure reason is something other than "exploit-signal absent" (e.g., reasoned-out false positive).
- If a finding has been `inconclusive` for 3 consecutive sweeps, escalate to a fresh validator pass — the PoC may have rotted.
