# kube-bench — Command and Flag Reference

## Core Commands

| Command | Description |
|---------|-------------|
| `kube-bench` | Auto-detect version and run all applicable checks |
| `kube-bench run` | Explicit run command (use with `--targets`/`--benchmark`) |
| `kube-bench version` | Print kube-bench version |

## Key Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--targets` | Component groups to test | `--targets master,node,etcd,policies,controlplane,managedservices` |
| `--benchmark` | Pin a specific benchmark revision | `--benchmark cis-1.8` |
| `--version` | Map by Kubernetes version | `--version 1.27` |
| `--check` | Run only specific check IDs (comma list) | `--check 1.2.1,1.2.2` |
| `--skip` | Skip specific check IDs | `--skip 4.2.6` |
| `--json` | Output results as JSON | `--json` |
| `--junit` | Output results as JUnit XML | `--junit` |
| `--asff` | AWS Security Finding Format (Security Hub) | `--asff` |
| `--pgsql` | Write results to PostgreSQL | `--pgsql` |
| `--outputfile` | Write output to a file | `--outputfile report.json` |
| `--config-dir` | Path to config/cfg directory | `--config-dir /etc/kube-bench/cfg` |
| `--config` | Path to alternate config.yaml | `--config ./config.yaml` |
| `--include-test-output` | Include raw command output in results | `--include-test-output` |

## Targets

| Target | Scope |
|--------|-------|
| `master` | Control-plane: API server, scheduler, controller manager |
| `etcd` | etcd datastore configuration |
| `controlplane` | Authentication/authorization and logging policies |
| `node` | kubelet and kube-proxy on worker nodes |
| `policies` | RBAC, service accounts, pod security, network policy |
| `managedservices` | Managed-service-specific controls (EKS/GKE/etc.) |

## Benchmark Profiles (examples)

| Benchmark | Platform |
|-----------|----------|
| `cis-1.8`, `cis-1.9` | Upstream Kubernetes (CIS) |
| `eks-1.5.0` | Amazon EKS |
| `gke-1.6.0` | Google GKE |
| `aks-1.7` | Azure AKS |
| `rke2-cis-1.7`, `k3s-cis-1.7` | Rancher RKE2 / k3s |
| `ocp-4.x` | OpenShift |

## In-Cluster Job Manifests

| File | Use |
|------|-----|
| `job.yaml` | Generic in-cluster run |
| `job-master.yaml` | Control-plane node checks |
| `job-node.yaml` | Worker node checks |
| `job-eks.yaml`, `job-gke.yaml`, `job-aks.yaml` | Managed-platform variants |

```bash
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -l app=kube-bench
```

## Result States

| State | Meaning |
|-------|---------|
| `PASS` | Check satisfied |
| `FAIL` | Check failed — remediation required |
| `WARN` | Manual verification needed |
| `INFO` | Informational only |

## External References

- Running: https://github.com/aquasecurity/kube-bench/blob/main/docs/running.md
- Platforms: https://github.com/aquasecurity/kube-bench/blob/main/docs/platforms.md
- Output formats: https://github.com/aquasecurity/kube-bench/blob/main/docs/output.md
