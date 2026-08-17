# Container Escape — Command & API Reference

## Enumeration Commands

| Command | Purpose |
|---------|---------|
| `amicontained` | Print capabilities, namespaces, seccomp mode, AppArmor profile |
| `grep CapEff /proc/self/status` | Read effective capability bitmask |
| `capsh --decode=<hex>` | Decode capability bitmask to names |
| `mount` / `findmnt` | List mounts; spot `docker.sock`, `hostPath`, `/host` |
| `ls -la /var/run/docker.sock` | Detect mounted Docker socket |
| `ls -la /proc/1/root` | Detect shared host PID namespace |
| `./deepce.sh` | Automated Docker enumeration + escape checks |
| `./cdk evaluate` | CDK automated container/K8s posture eval |

## Docker Daemon REST API (via /var/run/docker.sock)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/version` | GET | Confirm daemon reachability/version |
| `/containers/create?name=<n>` | POST | Create container (set `Binds`, `Privileged`) |
| `/containers/<id>/start` | POST | Start the created container |
| `/images/create?fromImage=alpine` | POST | Pull a base image |
| `/containers/<id>/logs?stdout=1` | GET | Read command output |

Create-container JSON keys of interest: `Image`, `Cmd`, `Binds` (`["/:/host"]`), `Privileged` (`true`), `HostConfig.PidMode` (`host`), `HostConfig.NetworkMode` (`host`).

## runC / Runtime Version Checks

| Command | Vulnerable Range | Patched |
|---------|------------------|---------|
| `runc --version` | 1.0.0-rc93 .. 1.1.11 (CVE-2024-21626) | >= 1.1.12 |
| `runc --version` | <= 1.2.7 / 1.3.2 / 1.4.0-rc.2 (2025 CVEs) | 1.2.8 / 1.3.3 / 1.4.0-rc.3 |
| `docker version --format '{{.Server.Version}}'` | < 25.0.2 | >= 25.0.2 |
| `containerd --version` | < 1.6.28 / 1.7.13 | >= 1.6.28 / 1.7.13 |

## Key Privileged-Escape Primitives

| File / Path | Use |
|-------------|-----|
| `/sys/fs/cgroup/.../release_agent` | Host command execution on cgroup empty (needs CAP_SYS_ADMIN) |
| `/proc/self/fd/7`, `/proc/self/fd/8` | Leaked host-cwd fd for CVE-2024-21626 |
| `/proc/sys/kernel/core_pattern` | `|/path/to/handler` runs as root on host on core dump |
| `/proc/sysrq-trigger` | Host kernel actions (DoS proof for 2025 CVEs) |
| `/etc/kubernetes/manifests/` | Drop a static pod manifest kubelet auto-runs |

## External References

- runC repo: https://github.com/opencontainers/runc
- amicontained: https://github.com/genuinetools/amicontained
- deepce: https://github.com/stealthcopter/deepce
- CDK: https://github.com/cdk-team/CDK
- Docker Engine API: https://docs.docker.com/engine/api/
