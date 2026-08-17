# Standards and References — Benchmarking Kubernetes with kube-bench

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| PR.PS-01 | Configuration management practices are established and applied | kube-bench audits Kubernetes control-plane, node, and policy configuration against the CIS Benchmark, enforcing secure configuration management. |

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1610 | Deploy Container | Execution / Defense Evasion | CIS hardening verified by kube-bench restricts privileged/host-namespace container deployment, anonymous API access, and insecure kubelet settings adversaries abuse to deploy containers. |

## Supporting Frameworks and Standards

- **CIS Kubernetes Benchmark** — the authoritative source standard kube-bench implements (control-plane, etcd, node, policy controls).
- **CIS Benchmarks for EKS / GKE / AKS / OpenShift** — managed-distribution variants kube-bench supports via dedicated benchmark profiles.
- **NSA/CISA Kubernetes Hardening Guidance** — complementary hardening recommendations overlapping CIS controls.
- **PCI DSS / SOC 2** — kube-bench JSON/JUnit output supports configuration-compliance evidence.

## Official Resources

- kube-bench: https://github.com/aquasecurity/kube-bench
- kube-bench docs: https://aquasecurity.github.io/kube-bench/
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- Running guide: https://github.com/aquasecurity/kube-bench/blob/main/docs/running.md
- Platforms guide: https://github.com/aquasecurity/kube-bench/blob/main/docs/platforms.md
