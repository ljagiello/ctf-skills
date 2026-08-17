---
name: detecting-container-runtime-threats-with-falco
description: Write and deploy Falco rules with the modern eBPF driver to detect container escape, namespace abuse, privileged mounts, and anomalous syscalls at runtime in Kubernetes and Docker.
domain: cybersecurity
subdomain: container-security
tags:
- falco
- runtime-security
- ebpf
- container-escape
- syscall-monitoring
- detection-engineering
- kubernetes
- threat-detection
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1611
---
# Detecting Container Runtime Threats with Falco

## Overview

Falco is the CNCF graduated runtime-security project (originally by Sysdig) that consumes Linux kernel syscalls and Kubernetes audit events through a driver, evaluates them against a YAML rule engine, and emits real-time alerts. It is the de facto open-source detection tool for runtime threats inside containers, including container escape (MITRE ATT&CK T1611, Escape to Host), namespace manipulation (`setns`), privileged mounts, reverse shells, and unexpected outbound connections.

Falco supports three drivers: the **modern eBPF** probe (preferred default, requires kernel >= 5.8, shipped directly inside the Falco binary so no init container is needed), the legacy eBPF probe, and the kernel module (`kmod`). Driver selection is handled by `falcoctl driver config --type {kmod|ebpf|modern_ebpf}` or `driver.kind=modern_ebpf` in the Helm chart. On Kubernetes, Falco runs as a DaemonSet so every node is monitored, and `falcoctl` automatically installs and updates rule artifacts from the Falco rules registry.

This skill covers authoring and deploying custom Falco rules to detect the container-escape primitives and anomalous-behavior signals that the breakout techniques in this collection produce. Each Falco rule has the fields `rule`, `desc`, `condition`, `output`, `priority`, and optional `tags`; reusable logic is factored into `macro` and `list` objects. Source: falco.org official documentation; falcosecurity/rules repository; Sysdig Falco detection research (e.g., CVE-2025-22224).

## When to Use

- Building runtime detections for a Kubernetes or Docker environment
- Validating that container-escape and lateral-movement attempts generate alerts (purple-team)
- Adding coverage for a newly disclosed runtime CVE
- Hardening a SOC's container telemetry pipeline (Falco -> Falcosidekick -> SIEM)

## Prerequisites

- A Linux host (kernel >= 5.8 for modern eBPF) or Kubernetes cluster you administer
- Falco install:
  ```bash
  # Helm (Kubernetes, modern eBPF, JSON output for SIEM ingest)
  helm repo add falcosecurity https://falcosecurity.github.io/charts
  helm repo update
  helm install falco falcosecurity/falco \
    --namespace falco --create-namespace \
    --set driver.kind=modern_ebpf \
    --set collectors.containerd.enabled=true \
    --set falco.json_output=true \
    --set tty=true

  # Linux package install (Debian/Ubuntu)
  curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
    sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
    https://download.falco.org/packages/deb stable main" | \
    sudo tee /etc/apt/sources.list.d/falcosecurity.list
  sudo apt-get update -y && sudo apt-get install -y falco
  ```
- Basic familiarity with Falco fields (`evt.type`, `proc.name`, `container.id`, `fd.name`)

## Objectives

- Install Falco with the modern eBPF driver
- Understand the rule/macro/list schema and key Falco filter fields
- Author custom rules for container escape, `setns`, privileged mounts, sensitive-file reads, and reverse shells
- Load custom rules and validate syntax
- Trigger and confirm detections (purple-team validation)
- Forward alerts to a SIEM via Falcosidekick

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1611 | Escape to Host | Privilege Escalation |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution |
| T1610 | Deploy Container | Defense Evasion / Execution |
| T1543 | Create or Modify System Process | Persistence |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |

## Workflow

### Step 1: Install Falco and Confirm the Driver

```bash
# Kubernetes: confirm the DaemonSet is running on every node
kubectl get pods -n falco -o wide
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i "driver"

# Linux host: configure driver and start
sudo falcoctl driver config --type modern_ebpf
sudo systemctl enable --now falco-modern-bpf.service
sudo systemctl status falco-modern-bpf.service
```

### Step 2: Learn the Rule, Macro, and List Schema

Custom rules live in `/etc/falco/falco_rules.local.yaml` or `/etc/falco/rules.d/`, referenced from `rules_files` in `/etc/falco/falco.yaml`.

```yaml
# /etc/falco/rules.d/custom-escape.yaml
- list: shell_binaries
  items: [bash, sh, zsh, dash, ash, ksh]

- macro: spawned_process
  condition: evt.type in (execve, execveat) and evt.dir = <

- macro: container
  condition: container.id != host
```

### Step 3: Write a Container-Escape Detection Rule (release_agent / cgroup)

```yaml
- rule: Container Escape via cgroup release_agent
  desc: >
    Detect a process inside a container writing to a cgroup release_agent or
    notify_on_release file, a classic privileged-container breakout primitive.
  condition: >
    container
    and spawned_process
    and (evt.type in (open, openat, openat2) or evt.type=write)
    and (fd.name endswith "release_agent"
         or fd.name endswith "notify_on_release")
    and evt.is_open_write=true
  output: >
    Container escape attempt via cgroup release_agent
    (user=%user.name command=%proc.cmdline file=%fd.name
     container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [container, mitre_privilege_escalation, T1611]
```

### Step 4: Detect Namespace Breakout (setns / nsenter)

```yaml
- rule: Namespace Change via setns to Host
  desc: >
    Detect setns/nsenter used to enter the host namespace (e.g. nsenter -t 1),
    a common container-to-host escape technique.
  condition: >
    evt.type = setns
    and container
    and proc.name in (nsenter, unshare)
  output: >
    Namespace breakout via setns/nsenter
    (user=%user.name proc=%proc.name cmd=%proc.cmdline
     container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [container, mitre_privilege_escalation, T1611]
```

### Step 5: Detect Privileged Mount and Docker Socket Abuse

```yaml
- rule: Mount Launched in Privileged Container
  desc: Detect the mount binary running inside a privileged container.
  condition: >
    spawned_process
    and container
    and container.privileged = true
    and proc.name = mount
  output: >
    Mount executed in privileged container
    (cmd=%proc.cmdline container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [container, mitre_privilege_escalation, T1611]

- rule: Docker Socket Accessed From Container
  desc: A container process reads/writes the host Docker daemon socket.
  condition: >
    container
    and (evt.type in (open, openat, openat2, connect))
    and fd.name = /var/run/docker.sock
  output: >
    Container touched docker.sock - possible daemon-API escape
    (proc=%proc.name cmd=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [container, mitre_execution, T1610]
```

### Step 6: Detect Reverse Shells and Sensitive File Reads

```yaml
- rule: Reverse Shell From Container
  desc: A shell in a container with stdin/stdout wired to a network socket.
  condition: >
    spawned_process
    and container
    and proc.name in (shell_binaries)
    and (fd.num in (0, 1, 2))
    and fd.type in (ipv4, ipv6)
  output: >
    Reverse shell detected in container
    (proc=%proc.cmdline connection=%fd.name container=%container.name)
  priority: CRITICAL
  tags: [container, mitre_execution, T1059.004]

- rule: Read Sensitive Host File From Container
  desc: Container reads /etc/shadow or similar after a likely escape.
  condition: >
    container
    and (evt.type in (open, openat, openat2))
    and evt.is_open_read=true
    and fd.name in (/etc/shadow, /etc/sudoers, /root/.ssh/id_rsa)
  output: >
    Sensitive file read from container (file=%fd.name proc=%proc.cmdline
     container=%container.name)
  priority: WARNING
  tags: [container, mitre_credential_access]
```

### Step 7: Validate Rule Syntax and Load

```bash
# Dry-run validate a rules file without starting the engine
sudo falco --validate /etc/falco/rules.d/custom-escape.yaml

# Run Falco with only the custom rules to test
sudo falco -r /etc/falco/rules.d/custom-escape.yaml

# Helm: ship custom rules via values (mounted into /etc/falco/rules.d)
helm upgrade falco falcosecurity/falco -n falco --reuse-values \
  --set-file "customRules.custom-escape\.yaml"=./custom-escape.yaml
```

### Step 8: Trigger and Confirm (Purple-Team)

```bash
# In a test container, trigger the setns rule
kubectl run pwn --rm -it --image=alpine --overrides='
{"spec":{"hostPID":true,"containers":[{"name":"pwn","image":"alpine",
"securityContext":{"privileged":true},"stdin":true,"tty":true,
"command":["sh"]}]}}' -- sh -c 'nsenter -t 1 -m -u -i -n -p -- id'

# Confirm the alert fired
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i "Namespace breakout"
```

### Step 9: Forward Alerts to a SIEM

```bash
# Deploy Falcosidekick to fan out alerts (Elastic, Slack, Splunk, etc.)
helm upgrade falco falcosecurity/falco -n falco --reuse-values \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.elasticsearch.hostport=https://elastic:9200 \
  --set falcosidekick.config.elasticsearch.index=falco
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| Falco | Runtime syscall detection engine | https://falco.org |
| falcoctl | Driver + rules artifact manager | https://github.com/falcosecurity/falcoctl |
| falcosecurity/rules | Maintained default ruleset | https://github.com/falcosecurity/rules |
| Falcosidekick | Alert fan-out to SIEM/chat | https://github.com/falcosecurity/falcosidekick |
| Falco Helm chart | Kubernetes DaemonSet deploy | https://github.com/falcosecurity/charts |

## Key Falco Filter Fields

| Field | Meaning |
|-------|---------|
| `evt.type` | Syscall name (execve, setns, open, connect) |
| `evt.dir` | Event direction (`<` exit, `>` enter) |
| `proc.name` / `proc.cmdline` | Process name / full command line |
| `container.id` / `container.privileged` | Container identity / privileged flag |
| `container.image.repository` | Image name |
| `fd.name` / `fd.type` | File/socket path / type (ipv4, ipv6) |
| `evt.is_open_write` / `evt.is_open_read` | Open intent |
| `user.name` | Acting user |

## Validation Criteria

- [ ] Falco installed with the modern eBPF driver (DaemonSet on all nodes)
- [ ] Custom rules file validated with `falco --validate`
- [ ] release_agent / setns / privileged-mount / docker.sock rules loaded
- [ ] Reverse-shell and sensitive-file-read rules loaded
- [ ] Each rule triggered in a lab and the alert confirmed in logs
- [ ] Priorities set appropriately (CRITICAL for escape primitives)
- [ ] Alerts forwarded to the SIEM via Falcosidekick
- [ ] Rule tags include the relevant MITRE technique IDs
