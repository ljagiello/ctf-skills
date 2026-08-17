# Webserver Log Analysis

## When this applies

Investigating webshell deployment, SQLi, file upload, scanning, and exfiltration via Apache/nginx access logs. Logs typically live in `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, or rotated `.gz` files alongside.

## Technique

Default Combined Log Format:
```
ip - user [time] "METHOD URI HTTP/x.y" status size "referrer" "ua"
```
Useful pivots: status anomalies (403→200, 404→200 sequences), unusual UA strings, request bursts, long URIs, methods other than GET/POST, and reaches into `/admin`, `/.git`, `/.env`, `/cgi-bin/`, `/upload/`. Pair with error logs which hold stack traces, PHP warnings, and module-failure messages that disclose the attacker's command output.

## Steps

1. Top sources / endpoints / UAs:
   ```bash
   awk '{print $1}'  access.log | sort | uniq -c | sort -rn | head    # IPs
   awk '{print $7}'  access.log | sort | uniq -c | sort -rn | head    # URIs
   awk -F\" '{print $6}' access.log | sort | uniq -c | sort -rn | head # UAs
   ```
2. Status-code patterns:
   ```bash
   awk '{print $9}' access.log | sort | uniq -c | sort -rn
   # Suspicious: 403 (forbidden, often sprayed by scanners) → 200 transition for same IP and path
   ```
3. Webshell hunt:
   ```bash
   grep -iE '\.(php|jsp|asp|aspx)\?(cmd|exec|shell|c=|q=)' access.log
   grep -E 'POST.*\.(jsp|jspx|war|phtml|php5|aspx)' access.log
   # Long base64-y query strings:
   awk '{print $7}' access.log | awk -F\? '{if(length($2)>200)print $0}' | head
   ```
4. Path-traversal / LFI:
   ```bash
   grep -E '\.\./|%2e%2e|%252e|/etc/passwd|wp-config|web\.config' access.log
   ```
5. SQLi tells:
   ```bash
   grep -iE 'union[ +]select|sleep\(|benchmark\(|information_schema|or[ +]1=1|--[ +]' access.log
   ```
6. Burst / scanner detection:
   ```bash
   awk '{print $1, $4}' access.log | awk '{print $1, substr($2,2,17)}' | sort | uniq -c | sort -rn | head
   # Same IP making >100 requests in one minute = scanner or brute force
   ```
7. Cross-check error log for the same IP/time:
   ```bash
   grep "203.0.113.7" /var/log/apache2/error.log
   # Stack traces here often contain `__halt_compiler`, `eval()`, base64_decode payloads
   ```
8. File upload paths (`POST` to upload endpoints):
   ```bash
   awk '$6=="\"POST" && $7 ~ /upload|file|attach/ {print $1,$4,$7,$10}' access.log
   ```

## Verifying success

- Suspect IP correlates across multiple anomaly classes (status, UA, URI shape).
- Webshell URI returns 200 only after a POST upload to a writeable path.
- Error log records confirm the corresponding access-log entry's payload (e.g., PHP warnings with attacker's printed command).

## Common pitfalls

- Reverse-proxied apps see the proxy's IP. Inspect `X-Forwarded-For` (must be enabled in log format) for the real client.
- HTTP/2 logging on nginx requires `$server_protocol` in the format; default formats may show `HTTP/1.1` only.
- Attackers rotate UAs — never key on UA alone. Combine with body length, IP, and timing.
- Compressed `.gz` rotated logs are easy to miss with naive `grep`. Always use `zgrep` / `find -exec zgrep`.
- Encoded payloads (URL-encoding, double-encoding, base64 in body) defeat raw greps. Decode the URI before scanning when feasible.

## Tools

- `awk` / `grep` / `sort` / `uniq` / `zgrep` / `goaccess` (interactive viewer)
- `lnav` — multi-log realtime tail with auto-format detection
- `mod_security` audit log if WAF was deployed (richer body content)
- `Sigma` rules `web/` selector for nginx/apache patterns
- `Sigma2SPL`, `chainsaw` — translate to Splunk / Elastic queries
