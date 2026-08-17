---
name: benchmarking-kubernetes-with-kube-bench
description: Run CIS Kubernetes Benchmark checks and remediate findings with kube-bench.
domain: cybersecurity
subdomain: container-security
tags:
- kubernetes
- kube-bench
- cis-benchmark
- container-security
- hardening
- compliance
- cluster-security
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.PS-01
mitre_attack:
- T1610
---
# Benchmarking Kubernetes with kube-bench

## Overview

kube-bench (by Aqua Security) is an open-source tool that checks whether a Kubernetes cluster is deployed securely by running the checks documented in the **CIS Kubernetes Benchmark**. It inspects the control-plane components (API server, controller manager, scheduler, etcd), the kubelet and worker-node configuration, and cluster-wide policy settings, then reports each check as PASS, FAIL, WARN, or INFO with a remediation recommendation drawn directly from the CIS guidance. Tests are configuration-driven YAML files, so kube-bench tracks new Kubernetes versions and benchmark revisions and supports managed distributions (EKS, GKE, AKS, ACK, OpenShift, RKE, k3s).

Hardening a cluster against the CIS Benchmark directly reduces the attack surface for **T1610 (Deploy Container)**, where an adversary deploys a container to execute code or evade defenses — for example by abusing privileged containers, host namespaces, anonymous API access, or insecure kubelet settings that an unhardened cluster leaves exposed.

kube-bench can run as a standalone binary on a node, inside a container, or — most commonly — as a Kubernetes Job whose pod has the host filesystem mounted so it can read the relevant config files. Output is available as human-readable text, JSON, JUnit, or AWS Security Finding Format (ASFF) and can be pushed to a PostgreSQL database for trend tracking.

## When to Use

- When establishing a security baseline for a new Kubernetes cluster against the CIS Kubernetes Benchmark.
- When performing periodic compliance audits of control-plane and node hardening.
- When validating remediation after applying hardening changes (re-run to confirm checks now PASS).
- When integrating cluster compliance scanning into CI/CD or a continuous monitoring pipeline.
- When preparing evidence for SOC 2, PCI DSS, or internal hardening compliance.

## Prerequisites

- Access to the cluster: either SSH access to a control-plane/worker node (binary mode) or `kubectl` with permission to create Jobs (in-cluster mode).
- Knowledge of the cluster's Kubernetes version (kube-bench auto-detects, or specify with `--version` / `--benchmark`).
- Install kube-bench (Aqua Security official methods):

```bash
# Binary release (Linux)
KB_VERSION=0.10.7
curl -L -o kube-bench.tgz \
  "https://github.com/aquasecurity/kube-bench/releases/download/v${KB_VERSION}/kube-bench_${KB_VERSION}_linux_amd64.tar.gz"
tar -xzf kube-bench.tgz
sudo mv kube-bench /usr/local/bin/
sudo cp -R cfg /etc/kube-bench/cfg

# Via Go install
go install github.com/aquasecurity/kube-bench@latest

# Run as a one-off container directly on a node (mounts host config)
docker run --rm --pid=host \
  -v /etc:/etc:ro -v /var:/var:ro \
  -t docker.io/aquasec/kube-bench:latest run --targets node

# Verify
kube-bench version
```

## Objectives

- Run kube-bench against the appropriate benchmark for the cluster's Kubernetes version.
- Scan control-plane (master), node, etcd, control-plane policies, and managed-service targets.
- Produce machine-readable JSON/JUnit output for pipelines and dashboards.
- Triage FAIL and WARN results and apply CIS remediation guidance.
- Re-run to validate that remediations now PASS.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|--------------|------|--------|-----------|
| T1610 | Deploy Container | Execution / Defense Evasion | CIS Benchmark hardening enforced by kube-bench restricts privileged/host-namespace deployments, anonymous API access, and insecure kubelet settings that adversaries abuse when deploying malicious containers. |

## Workflow

### 1. Run the default scan (auto-detect)

Run all applicable targets, letting kube-bench detect the Kubernetes version and benchmark:

```bash
sudo kube-bench
```

### 2. Run as a Kubernetes Job (in-cluster)

Apply the provided Job manifest from the kube-bench repo and read the results from the pod logs:

```bash
# General-purpose job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Wait, then retrieve results
kubectl get pods -l app=kube-bench
kubectl logs -l app=kube-bench

# Platform-specific jobs are available, e.g. EKS:
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-eks.yaml
```

### 3. Target specific components

Use `run --targets` to scope the scan to particular component groups:

```bash
# Control-plane (API server, scheduler, controller manager)
sudo kube-bench run --targets master

# Worker node (kubelet, proxy)
sudo kube-bench run --targets node

# etcd datastore
sudo kube-bench run --targets etcd

# Cluster-wide policies (RBAC, pod security, network policy)
sudo kube-bench run --targets policies

# Combine multiple targets
sudo kube-bench run --targets master,node,etcd,policies
```

### 4. Pin a specific benchmark or Kubernetes version

When auto-detection is wrong or you must audit against a specific revision, pin the benchmark explicitly:

```bash
# Pin to a specific CIS benchmark revision
sudo kube-bench run --benchmark cis-1.8

# Or map by Kubernetes version
sudo kube-bench --version 1.27

# Managed/distribution-specific benchmarks
sudo kube-bench run --benchmark eks-1.5.0
sudo kube-bench run --benchmark gke-1.6.0
sudo kube-bench run --benchmark rke2-cis-1.7
```

### 5. Run or skip individual checks

Focus on or exclude specific check IDs during remediation cycles:

```bash
# Run only specific checks
sudo kube-bench run --targets master --check 1.2.1,1.2.2

# Skip noisy/known-accepted checks
sudo kube-bench run --targets node --skip 4.2.6
```

### 6. Produce machine-readable output

Emit JSON or JUnit for ingestion into pipelines, SIEM, or dashboards, and write to a file:

```bash
# JSON to a file
sudo kube-bench run --targets master,node --json --outputfile kube-bench-report.json

# JUnit (for CI test reporting)
sudo kube-bench --junit --outputfile kube-bench-junit.xml

# AWS Security Finding Format (for Security Hub)
sudo kube-bench run --targets node --asff
```

### 7. Triage and remediate FAIL/WARN findings

Each failing check prints a remediation. Apply the CIS-recommended fix on the node/manifest, for example tightening API server flags in the static pod manifest:

```bash
# Example remediation for a common control-plane FAIL:
# CIS 1.2.x — ensure anonymous-auth is disabled on the API server.
# Edit the static pod manifest and set the flag:
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
#   - --anonymous-auth=false
# The kubelet restarts the static pod automatically.

# Example node remediation — kubelet config file permissions (CIS 4.1.x):
sudo chmod 600 /etc/kubernetes/kubelet/kubelet-config.json
sudo chown root:root /etc/kubernetes/kubelet/kubelet-config.json
```

### 8. Re-validate after remediation

Re-run the relevant target and confirm the previously failing checks now PASS, then track the score over time:

```bash
sudo kube-bench run --targets master --check 1.2.1 --json --outputfile recheck.json

# Optional: persist results to PostgreSQL for trend tracking
sudo kube-bench run --targets master,node --pgsql
```

## Tools and Resources

| Tool / Resource | Purpose | Link |
|------------------|---------|------|
| kube-bench | CIS Kubernetes Benchmark checker | https://github.com/aquasecurity/kube-bench |
| kube-bench docs | Running / platforms / flags | https://aquasecurity.github.io/kube-bench/ |
| CIS Kubernetes Benchmark | Source hardening standard | https://www.cisecurity.org/benchmark/kubernetes |
| Trivy Operator | Continuous in-cluster compliance + vuln scanning | https://github.com/aquasecurity/trivy-operator |
| kube-hunter | Complementary penetration-testing tool | https://github.com/aquasecurity/kube-hunter |

## Validation Criteria

- [ ] kube-bench installed (`kube-bench version`) or running as a Job.
- [ ] Scan run against the correct benchmark for the cluster's Kubernetes version.
- [ ] master, node, etcd, and policies targets each scanned.
- [ ] JSON/JUnit output produced for pipeline/dashboard ingestion.
- [ ] FAIL and WARN findings triaged and prioritized.
- [ ] CIS remediation applied to control-plane manifests and node configs.
- [ ] Re-run confirms previously failing checks now PASS.
- [ ] Results tracked over time (file archive or PostgreSQL).
